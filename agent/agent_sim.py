"""
AEGIS Simulated Agent
Generates realistic OS events and sends them to the backend.
Works on Windows/Mac/Linux — no eBPF required!

Usage:
    python agent_sim.py                     # Normal simulation
    python agent_sim.py --attack            # Include attack simulation
    python agent_sim.py --fast              # Faster event generation
"""

import json
import time
import random
import sys
import requests
from datetime import datetime, timezone

BACKEND_URL = "http://localhost:8000/api/events"

# ─── Normal Behavior Patterns ───────────────────────────────────
NORMAL_PROCESSES = ["code", "python3", "node", "git", "npm", "chrome", "firefox"]

NORMAL_FILES = [
    "/home/user/projects/app.py",
    "/home/user/projects/index.js",
    "/home/user/.config/Code/settings.json",
    "/tmp/build_output.log",
    "/home/user/documents/notes.md",
    "/home/user/projects/package.json",
    "/var/log/syslog",
]

NORMAL_IPS = ["127.0.0.1", "192.168.1.1", "0.0.0.0", "192.168.1.100"]
NORMAL_PORTS = [80, 443, 3000, 5173, 8000, 8080, 22, 0]

# ─── Suspicious Behavior Patterns ───────────────────────────────
ATTACK_PROCESSES = ["nc", "ncat", "nmap", "netcat", "hydra", "masscan"]
ATTACK_FILES = ["/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa", "/etc/sudoers"]
ATTACK_IPS = ["45.33.32.156", "185.220.101.1", "23.129.64.100", "91.219.29.81"]
ATTACK_PORTS = [4444, 1337, 31337, 9999]


def generate_normal_event() -> dict:
    """Generate a realistic normal OS event."""
    hour = datetime.now().hour
    return {
        "pid": random.randint(1000, 9999),
        "process": random.choice(NORMAL_PROCESSES),
        "file": random.choice(NORMAL_FILES),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": random.choice(["file_open", "file_open", "file_open", "process_exec"]),
        "ip": random.choice(NORMAL_IPS),
        "port": random.choice(NORMAL_PORTS),
    }


def generate_warning_event() -> dict:
    """Generate a mildly suspicious event."""
    return {
        "pid": random.randint(5000, 9999),
        "process": random.choice(["curl", "wget", "bash", "sh"]),
        "file": random.choice(["/etc/hostname", "/proc/cpuinfo", "/var/log/auth.log"]),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "file_open",
        "ip": random.choice(["8.8.8.8", "1.1.1.1", "104.21.0.1"]),
        "port": random.choice([80, 443, 8888]),
    }


def generate_attack_event() -> dict:
    """Generate a clearly malicious event."""
    return {
        "pid": random.randint(8000, 9999),
        "process": random.choice(ATTACK_PROCESSES),
        "file": random.choice(ATTACK_FILES),
        "timestamp": datetime.now(timezone.utc).replace(hour=random.randint(1, 4)).isoformat(),
        "type": random.choice(["file_open", "network_connect"]),
        "ip": random.choice(ATTACK_IPS),
        "port": random.choice(ATTACK_PORTS),
    }


def send_batch(events: list, timeout: int = 60) -> bool:
    """Send a batch of events to the backend."""
    try:
        r = requests.post(
            BACKEND_URL,
            json={"events": events},
            timeout=timeout,
            headers={"Content-Type": "application/json"}
        )
        return r.status_code == 200
    except requests.ConnectionError:
        return False
    except requests.Timeout:
        print("  ⏳ Backend slow (model loading?). Retrying...")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def main():
    include_attacks = "--attack" in sys.argv
    fast_mode = "--fast" in sys.argv
    interval = 0.3 if fast_mode else 1.0

    print("╔══════════════════════════════════════════════╗")
    print("║            AEGIS Simulated Agent             ║")
    print("║   Generates realistic OS events for demo     ║")
    print("╚══════════════════════════════════════════════╝")
    print()
    print(f"  Backend:  {BACKEND_URL}")
    print(f"  Mode:     {'Attack simulation' if include_attacks else 'Normal behavior'}")
    print(f"  Speed:    {'Fast' if fast_mode else 'Normal'} ({interval}s interval)")
    print()

    # Test connection
    print("  Testing backend connection...")
    test_ok = send_batch([generate_normal_event()])
    if test_ok:
        print("  ✓ Backend connected!")
    else:
        print("  ✗ Cannot reach backend at", BACKEND_URL)
        print("  Make sure the backend is running:")
        print("    cd backend && uvicorn main:app --reload --port 8000")
        print()
        print("  Retrying in 3 seconds...")
        time.sleep(3)

    print()
    print("  Streaming events... (Ctrl+C to stop)")
    print("  ─" * 25)

    event_count = 0
    danger_count = 0

    try:
        while True:
            batch = []
            batch_size = random.randint(3, 8) if fast_mode else random.randint(1, 4)

            for _ in range(batch_size):
                roll = random.random()

                if include_attacks and roll < 0.06:
                    # 6% chance of attack event
                    event = generate_attack_event()
                    event_type = "🔴 ATTACK"
                    danger_count += 1
                elif roll < 0.15:
                    # 9% chance of warning
                    event = generate_warning_event()
                    event_type = "🟡 WARN  "
                else:
                    # 85% normal events
                    event = generate_normal_event()
                    event_type = "🟢 NORMAL"

                batch.append(event)
                event_count += 1

                # Print event summary
                print(f"  {event_type} │ {event['process']:12s} │ PID {event['pid']} │ {event['file'][:40]}")

            # Send batch
            ok = send_batch(batch)
            status = "✓" if ok else "✗"
            print(f"  ── Sent {len(batch)} events {status} │ Total: {event_count} │ Threats: {danger_count}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n  Agent stopped.")
        print(f"  Total events: {event_count}")
        print(f"  Threats sent: {danger_count}")


if __name__ == "__main__":
    main()
