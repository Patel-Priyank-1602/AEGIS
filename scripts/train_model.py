"""
AEGIS Model Training Script
Run this script to train the LSTM Autoencoder on collected baseline data.

Usage:
    python3 scripts/train_model.py                         # Uses default path
    python3 scripts/train_model.py path/to/events.json     # Custom path
    python3 scripts/train_model.py --generate 500          # Generate synthetic data
"""

import sys
import os
import json
import random
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from ai.trainer import train


def generate_synthetic_baseline(num_events: int = 500) -> list:
    """
    Generate synthetic normal behavior data for training.
    Simulates a typical developer's workday activities.
    """
    print(f"Generating {num_events} synthetic normal events...")

    normal_processes = ["code", "python3", "node", "git", "npm", "chrome", "firefox"]
    normal_files = [
        "/home/user/projects/app.py",
        "/home/user/projects/index.js",
        "/home/user/.config/Code/settings.json",
        "/tmp/build_output.log",
        "/home/user/documents/notes.md",
        "/home/user/projects/package.json",
        "/var/log/syslog",
    ]
    normal_ips = ["127.0.0.1", "192.168.1.1", "0.0.0.0"]
    normal_ports = [80, 443, 3000, 5173, 8000, 8080, 22]

    events = []
    base_time = datetime.utcnow() - timedelta(days=3)

    for i in range(num_events):
        # Normal work hours: 9 AM to 6 PM
        hour = random.choice(range(9, 18))
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        timestamp = base_time + timedelta(
            hours=i * 0.1,  # Spread events over time
        )
        timestamp = timestamp.replace(hour=hour, minute=minute, second=second)

        event = {
            "pid": random.randint(1000, 9999),
            "process": random.choice(normal_processes),
            "file": random.choice(normal_files),
            "timestamp": timestamp.isoformat(),
            "type": random.choice(["file_open", "process_exec"]),
            "ip": random.choice(normal_ips),
            "port": random.choice(normal_ports),
        }
        events.append(event)

    # Sprinkle in a few mildly unusual events (5%)
    for i in random.sample(range(num_events), num_events // 20):
        events[i]["process"] = random.choice(["curl", "wget"])
        events[i]["file"] = "/etc/hostname"

    return events


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--generate":
        num = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
        events = generate_synthetic_baseline(num)

        # Save for future use
        output_path = os.path.join(
            os.path.dirname(__file__), "..", "backend", "ai", "baseline_events.json"
        )
        with open(output_path, "w") as f:
            json.dump(events, f, indent=2)
        print(f"Saved to {output_path}")
    else:
        data_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
            os.path.dirname(__file__), "..", "agent", "baseline_events.json"
        )

        if not os.path.exists(data_file):
            print(f"No baseline data found at: {data_file}")
            print()
            print("Options:")
            print("  1. Run the agent first to collect real data:")
            print("     sudo python3 agent/agent.py")
            print()
            print("  2. Generate synthetic training data:")
            print("     python3 scripts/train_model.py --generate 500")
            sys.exit(1)

        with open(data_file) as f:
            events = json.load(f)

    # Train the model
    result = train(events)
    print()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
