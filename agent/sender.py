"""
AEGIS Event Sender
Batches and sends OS events to the AEGIS backend via HTTP POST.
Handles connection failures gracefully with retry logic.
"""

import requests
import threading
import time
from collections import deque


class EventSender:
    """Batches events and sends them to the backend API."""

    def __init__(self, backend_url: str, batch_size: int = 50, send_interval: float = 1.0):
        self.backend_url = backend_url
        self.batch_size = batch_size
        self.send_interval = send_interval
        self.buffer = deque(maxlen=5000)
        self.lock = threading.Lock()
        self.last_send = time.time()
        self.sent_count = 0
        self.failed_count = 0

    def add(self, event: dict):
        """Add an event to the send buffer."""
        with self.lock:
            self.buffer.append(event)

        # Auto-send if buffer reaches batch size
        if len(self.buffer) >= self.batch_size:
            self.send()

    def send_if_ready(self):
        """Send if enough time has passed since last send."""
        if time.time() - self.last_send >= self.send_interval:
            self.send()

    def send(self):
        """Send the current buffer to the backend."""
        with self.lock:
            if not self.buffer:
                return
            batch = list(self.buffer)
            self.buffer.clear()

        self.last_send = time.time()

        try:
            response = requests.post(
                self.backend_url,
                json={"events": batch},
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                self.sent_count += len(batch)
            else:
                print(f"[Sender] Backend returned {response.status_code}")
                self.failed_count += len(batch)
        except requests.ConnectionError:
            # Backend not available — silently retry later
            with self.lock:
                for event in batch:
                    self.buffer.appendleft(event)
            self.failed_count += len(batch)
        except Exception as e:
            print(f"[Sender] Error: {e}")
            self.failed_count += len(batch)

    def flush(self):
        """Force send all remaining events."""
        self.send()

    @property
    def pending(self) -> int:
        """Number of events waiting to be sent."""
        return len(self.buffer)
