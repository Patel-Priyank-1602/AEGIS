"""
AEGIS Event Collector
Collects and stores OS events in memory for baseline training data.
Can save collected events to JSON for model training.
"""

import json
import threading
from collections import deque
from datetime import datetime


class EventCollector:
    """Thread-safe event collector with persistence."""

    def __init__(self, max_size: int = 10000):
        self.events = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.count = 0

    def add(self, event: dict):
        """Add an event to the collection."""
        with self.lock:
            self.events.append(event)
            self.count += 1

    def get_recent(self, n: int = 100) -> list:
        """Get the N most recent events."""
        with self.lock:
            return list(self.events)[-n:]

    def get_all(self) -> list:
        """Get all collected events."""
        with self.lock:
            return list(self.events)

    def save(self, filepath: str = "baseline_events.json"):
        """Save all collected events to a JSON file for training."""
        with self.lock:
            events = list(self.events)

        with open(filepath, "w") as f:
            json.dump(events, f, indent=2)

        print(f"[Collector] Saved {len(events)} events to {filepath}")

    def load(self, filepath: str = "baseline_events.json"):
        """Load events from a JSON file."""
        try:
            with open(filepath, "r") as f:
                events = json.load(f)
            with self.lock:
                for event in events:
                    self.events.append(event)
                self.count += len(events)
            print(f"[Collector] Loaded {len(events)} events from {filepath}")
        except FileNotFoundError:
            print(f"[Collector] File not found: {filepath}")

    def clear(self):
        """Clear all collected events."""
        with self.lock:
            self.events.clear()
            self.count = 0
