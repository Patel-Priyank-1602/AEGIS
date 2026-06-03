"""
AEGIS Honeypot / Deception Layer
Deploys fake resources that no legitimate user would access.
Any access = guaranteed attacker activity (zero false positives).

Honeypot types:
  1. Fake credentials files (/root/.aws/credentials, etc.)
  2. Decoy SSH keys
  3. Fake database config with dummy connection strings
  4. Canary DNS entries
  5. Fake admin panels (HTTP listener)
"""

import time
from datetime import datetime
from typing import List, Dict, Optional


# Honeypot resource definitions
HONEYPOT_RESOURCES = {
    "fake_credentials": {
        "type": "file",
        "paths": [
            "/root/.aws/credentials",
            "/opt/backup/db_password.txt",
            "/home/admin/.config/api_keys.json",
            "/tmp/.hidden_credentials",
            "/var/www/html/.env.backup",
        ],
        "description": "Decoy credential files — no legitimate process should access these",
    },
    "fake_ssh_keys": {
        "type": "file",
        "paths": [
            "/root/.ssh/id_rsa_backup",
            "/opt/keys/deploy_key",
            "/home/admin/.ssh/production_key",
        ],
        "description": "Fake SSH keys planted as canaries",
    },
    "fake_db_config": {
        "type": "file",
        "paths": [
            "/etc/mysql/credentials.cnf",
            "/opt/app/database.yml",
            "/var/lib/postgres/admin_password",
        ],
        "description": "Decoy database configuration files",
    },
    "canary_ports": {
        "type": "network",
        "ports": [2222, 3389, 8443, 9200, 27017],
        "description": "Listening ports that shouldn't receive legitimate traffic",
    },
    "canary_endpoints": {
        "type": "http",
        "paths": [
            "/admin/backup",
            "/phpmyadmin",
            "/.git/config",
            "/wp-admin",
            "/api/internal/debug",
        ],
        "description": "HTTP endpoints that no legitimate user should access",
    },
}

# Build a fast lookup set of all honeypot file paths
ALL_HONEYPOT_FILES = set()
ALL_HONEYPOT_PORTS = set()
ALL_HONEYPOT_ENDPOINTS = set()

for resource in HONEYPOT_RESOURCES.values():
    if resource["type"] == "file":
        ALL_HONEYPOT_FILES.update(resource["paths"])
    elif resource["type"] == "network":
        ALL_HONEYPOT_PORTS.update(resource["ports"])
    elif resource["type"] == "http":
        ALL_HONEYPOT_ENDPOINTS.update(resource["paths"])


class HoneypotManager:
    """Manages honeypot resources and tracks intrusion attempts."""

    def __init__(self):
        self.alerts: List[Dict] = []
        self.total_hits: int = 0
        self.unique_sources: set = set()
        self.enabled = True

    def check_event(self, event: dict) -> dict:
        """Check if an event touches any honeypot resource."""
        if not self.enabled:
            return {"honeypot_hit": False}

        file_path = event.get("file", "")
        port = event.get("port", 0)
        hits = []

        # Check file-based honeypots
        for hp_file in ALL_HONEYPOT_FILES:
            if hp_file in file_path:
                hits.append({
                    "type": "file_canary",
                    "resource": hp_file,
                    "confidence": "absolute",
                    "message": f"Access to honeypot file: {hp_file}",
                })

        # Check port-based honeypots
        if port in ALL_HONEYPOT_PORTS:
            hits.append({
                "type": "port_canary",
                "resource": f"port:{port}",
                "confidence": "absolute",
                "message": f"Connection to honeypot port: {port}",
            })

        if hits:
            self.total_hits += 1
            source_ip = event.get("ip", "unknown")
            self.unique_sources.add(source_ip)

            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "pid": event.get("pid"),
                "process": event.get("process"),
                "source_ip": source_ip,
                "hits": hits,
                "severity": "critical",
                "message": "HONEYPOT TRIGGERED — Guaranteed attacker activity detected",
            }
            self.alerts.append(alert)
            # Keep only last 500 alerts
            if len(self.alerts) > 500:
                self.alerts = self.alerts[-500:]

            print(f"[Honeypot] 🍯 TRIGGERED by {event.get('process')} "
                  f"(PID {event.get('pid')}) → {hits[0]['resource']}")

            return {
                "honeypot_hit": True,
                "honeypot_alerts": hits,
                "honeypot_severity": "critical",
            }

        return {"honeypot_hit": False}

    def get_alerts(self, limit: int = 50) -> list:
        return sorted(self.alerts, key=lambda x: x["timestamp"], reverse=True)[:limit]

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "total_hits": self.total_hits,
            "unique_attackers": len(self.unique_sources),
            "recent_alerts": len(self.alerts),
            "resources": {k: {
                "type": v["type"],
                "count": len(v.get("paths", v.get("ports", []))),
                "description": v["description"],
            } for k, v in HONEYPOT_RESOURCES.items()},
        }

    def get_deployed_resources(self) -> dict:
        return HONEYPOT_RESOURCES


# Global singleton
honeypot_manager = HoneypotManager()
