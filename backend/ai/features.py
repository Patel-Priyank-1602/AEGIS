"""
AEGIS Feature Engineering
Converts raw OS events into numeric feature vectors for the LSTM Autoencoder.
Each event is transformed into a 10-dimensional feature vector.
"""

import numpy as np

# ─── Known Patterns ─────────────────────────────────────────────

SUSPICIOUS_FILES = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/root/.ssh", "id_rsa", ".bash_history",
    "/proc/kcore", "/dev/mem", "/boot/vmlinuz"
]

SUSPICIOUS_PROCESSES = [
    "nc", "ncat", "netcat", "nmap", "masscan",
    "hydra", "john", "hashcat", "metasploit",
    "msfconsole", "reverse", "payload", "exploit"
]

# Ambiguous processes — common tools that CAN be used maliciously but are usually benign
AMBIGUOUS_PROCESSES = ["curl", "wget", "bash", "sh", "zsh"]

KNOWN_GOOD_PROCESSES = [
    "code", "python3", "python", "node", "git",
    "npm", "chrome", "firefox", "vscode", "vim",
    "nano", "systemd", "sshd", "cron", "docker"
]

SUSPICIOUS_PORTS = [
    4444, 1337, 31337, 9999, 8888, 5555,
    6666, 7777, 1234, 12345, 54321
]

SENSITIVE_DIRS = ["/etc/", "/root/", "/proc/", "/sys/", "/dev/", "/boot/"]


def event_to_features(event: dict) -> list:
    """
    Convert a raw event dictionary into a 10-dimensional numeric feature vector.
    
    Feature breakdown:
      [0] is_suspicious_process   — 1 if process name matches suspicious patterns
      [1] is_known_good_process   — 1 if process name matches known good patterns
      [2] is_sensitive_file       — 1 if file path contains sensitive file paths
      [3] is_system_path          — 1 if accessing system directories
      [4] is_suspicious_port      — 1 if port is commonly used by malware
      [5] is_unusual_hour         — 1 if event occurs between midnight and 6 AM
      [6] is_external_ip          — 1 if IP is not localhost or private network
      [7] normalized_hour         — Hour of day scaled to [0, 1]
      [8] normalized_port         — Port number scaled to [0, 1]
      [9] file_depth              — Directory depth of file path, scaled to [0, 1]
    """
    process = event.get("process", "").lower()
    file_path = event.get("file", "")
    network_ip = event.get("ip", "127.0.0.1")
    port = event.get("port", 0)

    # Extract hour from ISO timestamp
    timestamp = event.get("timestamp", "2024-01-01T12:00:00")
    try:
        hour = int(timestamp.split("T")[1][:2])
    except (IndexError, ValueError):
        hour = 12  # default to noon if parsing fails

    is_suspicious = any(s in process for s in SUSPICIOUS_PROCESSES)
    is_ambiguous = any(a == process for a in AMBIGUOUS_PROCESSES)
    is_known_good = any(g in process for g in KNOWN_GOOD_PROCESSES)
    is_sensitive_file = any(sf in file_path for sf in SUSPICIOUS_FILES)
    is_system_path = any(file_path.startswith(d) for d in SENSITIVE_DIRS)
    is_suspicious_port = port in SUSPICIOUS_PORTS
    is_unusual_hour = hour < 6
    is_external_ip = not (
        network_ip.startswith("127.") or
        network_ip.startswith("192.168.") or
        network_ip.startswith("10.") or
        network_ip == "0.0.0.0" or
        network_ip == "::1"
    )

    features = [
        # Feature 0: Is process suspicious? (only truly malicious tools)
        1.0 if is_suspicious else (0.3 if is_ambiguous else 0.0),

        # Feature 1: Is process known good?
        1.0 if is_known_good else 0.0,

        # Feature 2: Is a sensitive file being accessed?
        1.0 if is_sensitive_file else 0.0,

        # Feature 3: Is this a system directory?
        1.0 if is_system_path else 0.0,

        # Feature 4: Is the port suspicious?
        1.0 if is_suspicious_port else 0.0,

        # Feature 5: Is this an unusual hour? (midnight to 6 AM)
        1.0 if is_unusual_hour else 0.0,

        # Feature 6: Is IP external (not localhost or private)?
        1.0 if is_external_ip else 0.0,

        # Feature 7: Normalized hour (0 to 1)
        hour / 24.0,

        # Feature 8: Normalized port (0 to 1)
        min(port / 65535.0, 1.0),

        # Feature 9: File path depth (more depth = more normal usually)
        min(file_path.count("/") / 10.0, 1.0),
    ]
    return features


def batch_to_features(events: list) -> np.ndarray:
    """Convert a batch of events to a numpy array of feature vectors."""
    features = [event_to_features(e) for e in events]
    return np.array(features, dtype=np.float32)
