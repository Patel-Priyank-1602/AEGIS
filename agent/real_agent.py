"""
AEGIS Real Agent — Genuine OS Telemetry Collector
Collects REAL system events from your machine using psutil and sends them
to the AEGIS backend with cryptographic proof of authenticity.

Data Integrity Layers:
  1. Hardware-level collection via psutil (kernel data)
  2. HMAC-SHA256 signing per batch (proves origin)
  3. Nonce + timestamp (prevents replay attacks)
  4. Machine fingerprint (identifies the source host)
  5. Backend audit chain (immutable storage — already exists)

Usage:
    python real_agent.py                   # Normal collection
    python real_agent.py --verbose         # Show detailed event logs
    python real_agent.py --interval 5      # Custom scan interval (seconds)
    python real_agent.py --batch-size 20   # Max events per batch

Must run as Administrator/root for full process visibility.
"""

import sys
import os
import time
import json
import uuid
import hmac
import hashlib
import socket
import signal
import argparse
import platform
import requests
import psutil
from datetime import datetime, timezone
from collections import deque
from typing import List, Dict, Optional, Set

# ─── Configuration ──────────────────────────────────────────────────────────

BACKEND_URL = os.getenv("AEGIS_BACKEND_URL", "http://localhost:8000/api/events")
AGENT_SECRET = os.getenv("AGENT_SECRET", "aegis-default-agent-secret")
DEFAULT_INTERVAL = 3          # seconds between scans
DEFAULT_BATCH_SIZE = 15       # max events per batch
MAX_RETRY_DELAY = 30          # max backoff delay on connection failure
TIMESTAMP_TOLERANCE = 30      # seconds — backend should reject outside this
NONCE_CACHE_SIZE = 500        # how many sent nonces to remember locally


# ─── Machine Fingerprint ───────────────────────────────────────────────────

def get_machine_fingerprint() -> str:
    """
    Generate a unique SHA-256 fingerprint for this machine.
    Combines hostname, primary MAC address, and OS version.
    This lets the backend verify which host sent the data.
    """
    try:
        hostname = socket.gethostname()

        # Get the primary network interface MAC address
        mac = "unknown"
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                # AF_LINK (macOS) or AF_PACKET (Linux) — psutil uses family -1 on Windows
                if addr.family == psutil.AF_LINK if hasattr(psutil, 'AF_LINK') else addr.family == -1:
                    if addr.address and addr.address != "00:00:00:00:00:00":
                        mac = addr.address
                        break
            if mac != "unknown":
                break

        # Fallback: use uuid.getnode() which reads MAC from OS
        if mac == "unknown":
            mac = ':'.join(f'{(uuid.getnode() >> i) & 0xff:02x}' for i in range(0, 48, 8))

        os_info = f"{platform.system()}-{platform.release()}-{platform.machine()}"
        raw = f"{hostname}|{mac}|{os_info}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    except Exception:
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]


def get_machine_info() -> Dict:
    """Collect static machine metadata for identification."""
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": psutil.cpu_count(logical=True),
        "total_memory_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "python_version": platform.python_version(),
        "boot_time": datetime.fromtimestamp(
            psutil.boot_time(), tz=timezone.utc
        ).isoformat(),
    }


# ─── Cryptographic Signing ─────────────────────────────────────────────────

def sign_payload(payload_bytes: bytes, secret: str) -> str:
    """
    Create an HMAC-SHA256 signature of the payload.
    This proves the data came from an agent that knows the shared secret.
    """
    return hmac.new(
        secret.encode(),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()


def build_signed_headers(payload_bytes: bytes, machine_id: str) -> Dict[str, str]:
    """
    Build HTTP headers with cryptographic proof.
    The backend can verify:
      - Signature: data hasn't been tampered
      - Nonce: this exact request hasn't been seen before (anti-replay)
      - Timestamp: data is fresh (not a delayed replay)
      - Machine-ID: which host generated this data
    """
    nonce = str(uuid.uuid4())
    timestamp = str(int(time.time() * 1000))  # milliseconds

    # Sign the payload + nonce + timestamp together
    sign_material = payload_bytes + nonce.encode() + timestamp.encode()
    signature = sign_payload(sign_material, AGENT_SECRET)

    return {
        "Content-Type": "application/json",
        "X-AEGIS-Signature": f"sha256={signature}",
        "X-AEGIS-Nonce": nonce,
        "X-AEGIS-Timestamp": timestamp,
        "X-AEGIS-Machine-ID": machine_id,
        "X-AEGIS-Agent-Version": "2.0.0",
    }


# ─── Event Collection ──────────────────────────────────────────────────────

def collect_process_events(seen_pids: Set[int], batch_size: int) -> List[Dict]:
    """
    Collect genuine process events from the OS kernel via psutil.

    psutil reads directly from:
      - Windows: NtQuerySystemInformation / Performance Counters
      - Linux: /proc filesystem (kernel-maintained)
      - macOS: sysctl / proc_info

    These sources CANNOT be forged without kernel-level access.
    """
    events = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'status',
                                      'create_time', 'ppid', 'cpu_percent']):
        try:
            info = proc.info
            pid = info['pid']

            # Skip already-reported processes (deduplication within scan cycle)
            if pid in seen_pids:
                continue

            # Defaults
            ip = "127.0.0.1"
            port = 0
            event_type = "process_exec"
            file_path = info.get('exe') or ""

            # Check for active network connections for this process
            try:
                conns = proc.net_connections(kind='inet')
                for c in conns:
                    if c.status == 'ESTABLISHED' and c.raddr:
                        ip = c.raddr.ip
                        port = c.raddr.port
                        event_type = "network_connect"
                        break
                    elif c.status == 'LISTEN' and c.laddr:
                        ip = c.laddr.ip
                        port = c.laddr.port
                        event_type = "network_listen"
                        break
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass

            event = {
                "pid": pid,
                "process": info.get('name') or "unknown",
                "file": file_path,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": event_type,
                "ip": ip,
                "port": port,
                # Extended metadata for richer analysis
                "_meta": {
                    "username": info.get('username') or "unknown",
                    "ppid": info.get('ppid', 0),
                    "status": info.get('status', 'unknown'),
                    "cpu_percent": info.get('cpu_percent', 0.0),
                    "create_time": datetime.fromtimestamp(
                        info.get('create_time', 0), tz=timezone.utc
                    ).isoformat() if info.get('create_time') else None,
                }
            }
            events.append(event)
            seen_pids.add(pid)

            if len(events) >= batch_size:
                break

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return events


def collect_network_events(batch_size: int) -> List[Dict]:
    """
    Collect active network connections system-wide.
    This catches connections from ALL processes, not just iterated ones.
    """
    events = []
    seen = set()

    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue

            # Deduplicate by (pid, remote_ip, remote_port)
            key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            if key in seen:
                continue
            seen.add(key)

            # Look up the process name
            proc_name = "unknown"
            try:
                if conn.pid:
                    proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            event = {
                "pid": conn.pid or 0,
                "process": proc_name,
                "file": "",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "network_connect",
                "ip": conn.raddr.ip,
                "port": conn.raddr.port,
                "_meta": {
                    "local_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "status": conn.status,
                }
            }
            events.append(event)

            if len(events) >= batch_size:
                break

        except Exception:
            continue

    return events


def collect_system_health() -> Dict:
    """
    Collect system-wide health metrics.
    Useful for detecting resource exhaustion attacks (cryptominers, DDoS, etc.)
    """
    try:
        mem = psutil.virtual_memory()

        # OS-aware disk path: C:\ on Windows, / on Linux/macOS
        disk_path = "C:\\" if platform.system() == "Windows" else "/"
        disk = psutil.disk_usage(disk_path)

        # Logged-in users (detect unauthorized sessions)
        users = []
        for u in psutil.users():
            users.append({
                "name": u.name,
                "terminal": u.terminal or "console",
                "host": u.host or "local",
                "started": datetime.fromtimestamp(
                    u.started, tz=timezone.utc
                ).isoformat()
            })

        return {
            "memory_percent": round(mem.percent, 1),
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "disk_percent": round(disk.percent, 1),
            "disk_used_gb": round(disk.used / (1024 ** 3), 2),
            "disk_total_gb": round(disk.total / (1024 ** 3), 2),
            "active_users": users,
            "process_count": len(psutil.pids()),
            "network_connections": len(psutil.net_connections(kind='inet')),
        }
    except Exception as e:
        return {"error": str(e)}


# ─── Sending with Integrity ────────────────────────────────────────────────

class AgentSender:
    """Handles sending event batches with cryptographic integrity."""

    def __init__(self, backend_url: str, machine_id: str):
        self.backend_url = backend_url
        self.machine_id = machine_id
        self.sent_count = 0
        self.failed_count = 0
        self.retry_delay = 1
        self.sent_nonces: deque = deque(maxlen=NONCE_CACHE_SIZE)
        self.session = requests.Session()

    def _restore_meta(self, events: List[Dict], meta_store: List[Dict]):
        """Restore _meta fields back onto events after sending."""
        for e, m in zip(events, meta_store):
            e["_meta"] = m

    def send_batch(self, events: List[Dict], health: Optional[Dict] = None) -> bool:
        """
        Send a signed batch of events to the backend.
        Retries up to 3 times with exponential backoff on failure.
        Returns True if accepted, False otherwise.
        """
        if not events:
            return True

        # Strip _meta from events for the backend (it only expects OSEvent fields)
        clean_events = []
        meta_store = []
        for e in events:
            meta = e.pop("_meta", {})
            meta_store.append(meta)
            clean_events.append(e)

        payload = {
            "events": clean_events,
        }

        payload_bytes = json.dumps(payload, sort_keys=True).encode()

        # Retry up to 3 times with backoff
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            headers = build_signed_headers(payload_bytes, self.machine_id)

            try:
                response = self.session.post(
                    self.backend_url,
                    data=payload_bytes,
                    headers=headers,
                    timeout=60,  # Backend needs time for 10-layer pipeline
                )

                if response.status_code == 200:
                    self.sent_count += len(clean_events)
                    self.retry_delay = 1  # Reset backoff on success
                    self.sent_nonces.append(headers["X-AEGIS-Nonce"])
                    self._restore_meta(events, meta_store)
                    return True
                else:
                    if attempt < max_retries:
                        time.sleep(self.retry_delay)
                        self.retry_delay = min(self.retry_delay * 2, MAX_RETRY_DELAY)
                        continue

            except requests.ConnectionError:
                if attempt < max_retries:
                    print(f"  ⏳ Backend unreachable, retry {attempt}/{max_retries}...")
                    time.sleep(self.retry_delay)
                    self.retry_delay = min(self.retry_delay * 2, MAX_RETRY_DELAY)
                    continue

            except requests.Timeout:
                if attempt < max_retries:
                    print(f"  ⏳ Backend slow (AI model loading?), retry {attempt}/{max_retries}...")
                    time.sleep(self.retry_delay)
                    self.retry_delay = min(self.retry_delay * 2, MAX_RETRY_DELAY)
                    continue

            except Exception:
                break  # Unknown error, don't retry

        # All retries exhausted
        self.failed_count += len(clean_events)
        self._restore_meta(events, meta_store)
        return False


# ─── CLI Argument Parser ───────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="AEGIS Real Agent — Genuine OS Telemetry Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python real_agent.py                   Normal collection
  python real_agent.py --verbose         Detailed per-event logging
  python real_agent.py --interval 5      Scan every 5 seconds
  python real_agent.py --batch-size 20   Send up to 20 events per batch
        """
    )
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed per-event output")
    parser.add_argument("--interval", "-i", type=int, default=DEFAULT_INTERVAL,
                        help=f"Seconds between scans (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--batch-size", "-b", type=int, default=DEFAULT_BATCH_SIZE,
                        help=f"Max events per batch (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--no-sign", action="store_true",
                        help="Disable HMAC signing (for debugging only)")
    return parser.parse_args()


# ─── Display Helpers ────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║                        AEGIS Real Agent                          ║
║        Genuine OS Telemetry with Cryptographic Integrity         ║
╠══════════════════════════════════════════════════════════════════╣
║  ● Data Source:  psutil (kernel-level, unforgeable)              ║
║  ● Signing:      HMAC-SHA256 per batch                           ║
║  ● Anti-Replay:  UUID nonce + timestamp window                   ║
║  ● Fingerprint:  SHA-256 machine ID                              ║
╚══════════════════════════════════════════════════════════════════╝
"""


def print_event_line(event: Dict, verbose: bool):
    """Print a formatted event line."""
    etype = event.get("type", "unknown")
    proc = event.get("process", "?")[:14]
    pid = event.get("pid", 0)
    ip = event.get("ip", "?")
    port = event.get("port", 0)

    icons = {
        "process_exec": "⚙️ ",
        "network_connect": "🌐",
        "network_listen": "👂",
        "file_open": "📄",
    }
    icon = icons.get(etype, "❓")
    type_label = etype.replace("_", " ").upper()[:16]

    print(f"  {icon} {type_label:16s} │ {proc:14s} │ PID {pid:>6d} │ {ip}:{port}")

    if verbose:
        meta = event.get("_meta", {})
        user = meta.get("username", "?")
        ppid = meta.get("ppid", "?")
        status = meta.get("status", "?")
        cpu = meta.get("cpu_percent", 0)
        print(f"     └── user={user}  ppid={ppid}  status={status}  cpu={cpu}%")


def print_health(health: Dict):
    """Print system health summary."""
    mem = health.get("memory_percent", 0)
    disk = health.get("disk_percent", 0)
    procs = health.get("process_count", 0)
    conns = health.get("network_connections", 0)
    users = health.get("active_users", [])
    disk_total = health.get("disk_total_gb", 0)
    disk_used = health.get("disk_used_gb", 0)
    mem_used = health.get("memory_used_gb", 0)

    def make_bar(pct: float, width: int = 20) -> str:
        filled = max(0, min(width, int(pct / (100 / width))))
        return "█" * filled + "░" * (width - filled)

    mem_bar = make_bar(mem)
    disk_bar = make_bar(disk)

    print(f"  ┌── System Health ─────────────────────────────────────┐")
    print(f"  │ RAM     [{mem_bar}] {mem:5.1f}%  │ {mem_used:.1f} GB   │")
    print(f"  │ STORAGE [{disk_bar}] {disk:5.1f}%  │ {disk_used:.0f}/{disk_total:.0f} GB │")
    print(f"  │ Procs: {procs:<6d} │ Conns: {conns:<6d} │ Users: {len(users):<4d} │")
    print(f"  └─────────────────────────────────────────────────────┘")


# ─── Main Loop ──────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    print(BANNER)

    # Machine identification
    machine_id = get_machine_fingerprint()
    machine_info = get_machine_info()

    print(f"  Machine ID:    {machine_id}")
    print(f"  Hostname:      {machine_info['hostname']}")
    print(f"  OS:            {machine_info['os']} {machine_info['os_version']}")
    print(f"  CPUs:          {machine_info['cpu_count']}  │  RAM: {machine_info['total_memory_gb']} GB")
    print(f"  Backend:       {BACKEND_URL}")
    print(f"  Scan Interval: {args.interval}s  │  Batch Size: {args.batch_size}")
    print(f"  Signing:       {'HMAC-SHA256' if not args.no_sign else 'DISABLED ⚠️'}")
    print()

    # Initialize sender
    sender = AgentSender(BACKEND_URL, machine_id)

    # Test backend connection
    print("  Testing backend connection...")
    test_event = {
        "pid": 0,
        "process": "aegis-agent-heartbeat",
        "file": "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "process_exec",
        "ip": "127.0.0.1",
        "port": 0,
    }
    test_ok = sender.send_batch([test_event])
    if test_ok:
        print("  ✓ Backend connected and accepting events!")
    else:
        print(f"  ✗ Cannot reach backend at {BACKEND_URL}")
        print(f"    Make sure the backend is running:")
        print(f"      cd backend && uvicorn main:app --reload --port 8000")
        print(f"    Will keep retrying...\n")

    # Track state
    seen_pids: Set[int] = set()
    scan_count = 0
    total_events = 0
    total_process_events = 0
    total_network_events = 0
    start_time = time.time()

    # Graceful shutdown
    shutdown = False

    def signal_handler(sig, frame):
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    print("  ─" * 32)
    print("  Streaming REAL events... (Ctrl+C to stop)")
    print("  ─" * 32)
    print()

    # ─── Main Collection Loop ──────────────────────────────────────
    while not shutdown:
        scan_count += 1

        # Reset seen_pids periodically (every 10 scans) to catch new instances
        if scan_count % 10 == 0:
            seen_pids.clear()

        # 1. Collect process events
        proc_events = collect_process_events(seen_pids, args.batch_size)
        total_process_events += len(proc_events)

        # 2. Collect network events (separate pass for completeness)
        remaining = max(0, args.batch_size - len(proc_events))
        net_events = collect_network_events(remaining) if remaining > 0 else []
        total_network_events += len(net_events)

        # 3. Merge all events
        all_events = proc_events + net_events

        if not all_events:
            time.sleep(args.interval)
            continue

        # 4. Collect system health (every 3rd scan)
        health = None
        if scan_count % 3 == 0:
            health = collect_system_health()

        # 5. Print events
        for event in all_events:
            print_event_line(event, args.verbose)

        # 6. Print health if available
        if health:
            print()
            print_health(health)
            print()

        # 7. Send signed batch
        ok = sender.send_batch(all_events, health)
        total_events += len(all_events)

        status = "✓ SIGNED" if ok else "✗ FAILED"
        elapsed = time.time() - start_time
        eps = total_events / elapsed if elapsed > 0 else 0

        print(f"  ── Batch #{scan_count}: {len(all_events)} events {status}"
              f" │ Total: {total_events} │ Rate: {eps:.1f} e/s"
              f" │ Sent: {sender.sent_count} │ Failed: {sender.failed_count}")
        print()

        # 8. Wait before next scan
        time.sleep(args.interval)

    # ─── Shutdown Summary ──────────────────────────────────────────
    elapsed = time.time() - start_time
    print()
    print("  ╔════════════════════════════════════════════╗")
    print("  ║         Agent Stopped — Summary            ║")
    print("  ╠════════════════════════════════════════════╣")
    print(f"  ║  Runtime:         {elapsed:>8.1f}s                ║")
    print(f"  ║  Total Scans:     {scan_count:>8d}                 ║")
    print(f"  ║  Total Events:    {total_events:>8d}                 ║")
    print(f"  ║  Process Events:  {total_process_events:>8d}                 ║")
    print(f"  ║  Network Events:  {total_network_events:>8d}                 ║")
    print(f"  ║  Sent OK:         {sender.sent_count:>8d}                 ║")
    print(f"  ║  Send Failed:     {sender.failed_count:>8d}                 ║")
    print(f"  ║  Machine ID:      {machine_id:>16s}   ║")
    print("  ╚════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
