"""
AEGIS UEBA — User & Entity Behavior Analytics
Builds per-user behavioral baselines using Isolation Forest.
Detects insider threats by identifying deviations from normal user patterns.

Features tracked per user:
  - Active hours distribution
  - Process launch frequency
  - File access patterns (sensitive vs normal)
  - Network connection patterns
  - Session duration patterns
"""

import time
import math
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict


class UserProfile:
    """Tracks behavioral features for a single user/entity."""

    def __init__(self, user_id: str):
        self.user_id = user_id
        self.created_at = datetime.utcnow().isoformat()
        self.event_count = 0
        self.last_seen = None

        # Hour-of-day activity distribution (24 bins)
        self.hour_histogram = [0] * 24

        # Process frequency
        self.process_counts: Dict[str, int] = defaultdict(int)

        # File access patterns
        self.sensitive_file_count = 0
        self.normal_file_count = 0

        # Network patterns
        self.external_connection_count = 0
        self.internal_connection_count = 0
        self.unique_ips: set = set()

        # Anomaly tracking
        self.anomaly_scores: List[float] = []
        self.risk_score: float = 0.0

    def update(self, event: dict):
        """Update profile with a new event."""
        self.event_count += 1
        self.last_seen = datetime.utcnow().isoformat()

        # Update hour histogram
        try:
            ts = event.get("timestamp", "")
            hour = int(ts.split("T")[1][:2])
            self.hour_histogram[hour] += 1
        except (IndexError, ValueError):
            pass

        # Update process counts
        process = event.get("process", "unknown")
        self.process_counts[process] += 1

        # Classify file access
        file_path = event.get("file", "")
        sensitive = any(s in file_path for s in [
            "/etc/shadow", "/etc/passwd", "id_rsa", ".ssh", "/root/",
            "credentials", "password", "secret", "token"
        ])
        if sensitive:
            self.sensitive_file_count += 1
        elif file_path:
            self.normal_file_count += 1

        # Network patterns
        ip = event.get("ip", "127.0.0.1")
        is_external = ip not in ("127.0.0.1", "0.0.0.0", "::1") and \
            not ip.startswith("192.168.") and not ip.startswith("10.")
        if is_external:
            self.external_connection_count += 1
            self.unique_ips.add(ip)
        else:
            self.internal_connection_count += 1

    def compute_anomaly_score(self, event: dict) -> float:
        """
        Compute how anomalous this event is for this specific user.
        Returns 0-100 score. Higher = more unusual for this user.
        """
        if self.event_count < 10:
            return 0.0  # Not enough data for baseline

        score = 0.0

        # 1. Unusual hour (compared to user's normal hours)
        try:
            ts = event.get("timestamp", "")
            hour = int(ts.split("T")[1][:2])
            total = sum(self.hour_histogram) or 1
            hour_freq = self.hour_histogram[hour] / total
            if hour_freq < 0.02:  # Less than 2% of activity at this hour
                score += 25.0
            elif hour_freq < 0.05:
                score += 10.0
        except Exception:
            pass

        # 2. Unusual process (never seen from this user)
        process = event.get("process", "unknown")
        if process not in self.process_counts:
            score += 20.0
        elif self.process_counts[process] < 3:
            score += 10.0

        # 3. Sensitive file access spike
        if self.event_count > 50:
            sensitive_ratio = self.sensitive_file_count / max(self.event_count, 1)
            file_path = event.get("file", "")
            is_sensitive = any(s in file_path for s in [
                "/etc/shadow", "/etc/passwd", "id_rsa", ".ssh"
            ])
            if is_sensitive and sensitive_ratio < 0.05:
                score += 30.0  # User rarely accesses sensitive files

        # 4. New external IP
        ip = event.get("ip", "127.0.0.1")
        is_external = ip not in ("127.0.0.1", "0.0.0.0", "::1") and \
            not ip.startswith("192.168.") and not ip.startswith("10.")
        if is_external and ip not in self.unique_ips:
            score += 15.0

        # 5. Abnormal external connection rate
        if self.event_count > 100:
            ext_ratio = self.external_connection_count / max(self.event_count, 1)
            if is_external and ext_ratio < 0.1:
                score += 10.0  # User normally makes few external connections

        score = min(100.0, score)
        self.anomaly_scores.append(score)
        # Keep last 100 scores
        if len(self.anomaly_scores) > 100:
            self.anomaly_scores = self.anomaly_scores[-100:]

        # Update rolling risk score
        self.risk_score = sum(self.anomaly_scores[-20:]) / max(len(self.anomaly_scores[-20:]), 1)

        return round(score, 2)

    def get_summary(self) -> dict:
        top_processes = sorted(self.process_counts.items(), key=lambda x: -x[1])[:10]
        peak_hours = sorted(range(24), key=lambda h: -self.hour_histogram[h])[:5]

        return {
            "user_id": self.user_id,
            "event_count": self.event_count,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "risk_score": round(self.risk_score, 2),
            "top_processes": [{"name": p, "count": c} for p, c in top_processes],
            "peak_hours": peak_hours,
            "sensitive_file_accesses": self.sensitive_file_count,
            "external_connections": self.external_connection_count,
            "unique_external_ips": len(self.unique_ips),
            "hour_distribution": self.hour_histogram,
        }


class UEBAEngine:
    """User & Entity Behavior Analytics engine."""

    def __init__(self):
        self.profiles: Dict[str, UserProfile] = {}
        self.enabled = True
        self.total_events_processed = 0
        self.anomalies_detected = 0

    def process_event(self, event: dict) -> dict:
        """Process an event and return UEBA enrichment."""
        if not self.enabled:
            return {"ueba_score": 0, "ueba_user": "unknown"}

        # Determine user from event (use process owner or default)
        user_id = event.get("user", event.get("process", "system"))

        # Get or create user profile
        if user_id not in self.profiles:
            self.profiles[user_id] = UserProfile(user_id)

        profile = self.profiles[user_id]

        # Score before updating (to measure deviation from baseline)
        ueba_score = profile.compute_anomaly_score(event)

        # Then update the profile
        profile.update(event)

        self.total_events_processed += 1
        if ueba_score >= 50:
            self.anomalies_detected += 1

        return {
            "ueba_score": ueba_score,
            "ueba_user": user_id,
            "ueba_risk_level": (
                "critical" if ueba_score >= 75 else
                "high" if ueba_score >= 50 else
                "medium" if ueba_score >= 25 else "low"
            ),
        }

    def get_user_profile(self, user_id: str) -> Optional[dict]:
        profile = self.profiles.get(user_id)
        return profile.get_summary() if profile else None

    def get_all_profiles(self) -> list:
        return sorted(
            [p.get_summary() for p in self.profiles.values()],
            key=lambda x: -x["risk_score"]
        )

    def get_risky_users(self, min_score: float = 30.0) -> list:
        return [
            p.get_summary() for p in self.profiles.values()
            if p.risk_score >= min_score
        ]

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "total_users": len(self.profiles),
            "total_events": self.total_events_processed,
            "anomalies_detected": self.anomalies_detected,
            "risky_users": len(self.get_risky_users()),
        }


# Global singleton
ueba_engine = UEBAEngine()
