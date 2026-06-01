"""
AEGIS eBPF Agent
Hooks into the Linux kernel using BCC/eBPF to monitor all system activity.
Captures file access, process execution, and network connections in real time.
Sends batched events to the AEGIS backend for AI scoring.

Must be run with root privileges: sudo python3 agent.py
"""

from bcc import BPF
import json
import time
import requests
import signal
import sys
from datetime import datetime
from collector import EventCollector
from sender import EventSender

# ─── eBPF Programs ──────────────────────────────────────────────

# Program 1: Trace file opens
BPF_FILE_OPEN = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    u64 timestamp;
};

BPF_PERF_OUTPUT(file_events);

int trace_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct file_event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.fname, sizeof(event.fname), filename);
    
    file_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Program 2: Trace process execution
BPF_EXEC = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[256];
    u64 timestamp;
};

BPF_PERF_OUTPUT(exec_events);

int trace_exec(struct pt_regs *ctx) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Program 3: Trace network connections
BPF_CONNECT = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
    u64 timestamp;
};

BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct connect_event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.daddr = sk->__sk_common.skc_daddr;
    event.dport = sk->__sk_common.skc_dport;
    
    connect_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# ─── Configuration ──────────────────────────────────────────────
BACKEND_URL = "http://localhost:8000/api/events"
BATCH_SIZE = 50
SEND_INTERVAL = 1.0  # seconds


def ip_to_str(addr):
    """Convert 32-bit network-order integer to dotted IP string."""
    return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"


def main():
    print("╔══════════════════════════════════════════════╗")
    print("║           AEGIS eBPF Agent v1.0              ║")
    print("║     Real-time OS Monitoring System           ║")
    print("╚══════════════════════════════════════════════╝")
    print()

    collector = EventCollector(max_size=1000)
    sender = EventSender(
        backend_url=BACKEND_URL,
        batch_size=BATCH_SIZE,
        send_interval=SEND_INTERVAL
    )

    # ─── Initialize eBPF Programs ───────────────────────────────
    print("[1/3] Loading eBPF programs into kernel...")

    try:
        # File monitoring
        b_file = BPF(text=BPF_FILE_OPEN)
        b_file.attach_kprobe(event="do_sys_openat2", fn_name="trace_open")
        print("  ✓ File access monitor active")
    except Exception as e:
        print(f"  ✗ File monitor failed: {e}")
        b_file = None

    try:
        # Process monitoring
        b_exec = BPF(text=BPF_EXEC)
        b_exec.attach_kprobe(event="__x64_sys_execve", fn_name="trace_exec")
        print("  ✓ Process execution monitor active")
    except Exception as e:
        print(f"  ✗ Process monitor failed: {e}")
        b_exec = None

    try:
        # Network monitoring
        b_net = BPF(text=BPF_CONNECT)
        b_net.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
        print("  ✓ Network connection monitor active")
    except Exception as e:
        print(f"  ✗ Network monitor failed: {e}")
        b_net = None

    # ─── Event Callbacks ────────────────────────────────────────
    def on_file_event(cpu, data, size):
        event = b_file["file_events"].event(data)
        entry = {
            "pid": event.pid,
            "process": event.comm.decode("utf-8", "replace"),
            "file": event.fname.decode("utf-8", "replace"),
            "timestamp": datetime.utcnow().isoformat(),
            "type": "file_open",
            "ip": "127.0.0.1",
            "port": 0
        }
        collector.add(entry)
        sender.add(entry)

    def on_exec_event(cpu, data, size):
        event = b_exec["exec_events"].event(data)
        entry = {
            "pid": event.pid,
            "process": event.comm.decode("utf-8", "replace"),
            "file": "",
            "timestamp": datetime.utcnow().isoformat(),
            "type": "process_exec",
            "ip": "127.0.0.1",
            "port": 0
        }
        collector.add(entry)
        sender.add(entry)

    def on_connect_event(cpu, data, size):
        event = b_net["connect_events"].event(data)
        entry = {
            "pid": event.pid,
            "process": event.comm.decode("utf-8", "replace"),
            "file": "",
            "timestamp": datetime.utcnow().isoformat(),
            "type": "network_connect",
            "ip": ip_to_str(event.daddr),
            "port": event.dport
        }
        collector.add(entry)
        sender.add(entry)

    # ─── Register Callbacks ─────────────────────────────────────
    print("[2/3] Registering event callbacks...")
    if b_file:
        b_file["file_events"].open_perf_buffer(on_file_event)
    if b_exec:
        b_exec["exec_events"].open_perf_buffer(on_exec_event)
    if b_net:
        b_net["connect_events"].open_perf_buffer(on_connect_event)
    print("  ✓ All callbacks registered")

    # ─── Main Loop ──────────────────────────────────────────────
    print("[3/3] Monitoring active. Streaming to backend...")
    print(f"  Backend: {BACKEND_URL}")
    print(f"  Batch size: {BATCH_SIZE}")
    print()
    print("Press Ctrl+C to stop monitoring.")
    print("─" * 50)

    def signal_handler(sig, frame):
        print("\n\n[Agent] Shutting down gracefully...")
        sender.flush()
        collector.save("baseline_events.json")
        print(f"[Agent] Collected {collector.count} events total.")
        print("[Agent] Events saved to baseline_events.json")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    event_count = 0
    while True:
        if b_file:
            b_file.perf_buffer_poll(timeout=100)
        if b_exec:
            b_exec.perf_buffer_poll(timeout=100)
        if b_net:
            b_net.perf_buffer_poll(timeout=100)

        # Periodic batch send
        sender.send_if_ready()

        # Status update every 100 events
        new_count = collector.count
        if new_count - event_count >= 100:
            event_count = new_count
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] Events: {event_count} | Sent: {sender.sent_count}")


if __name__ == "__main__":
    main()
