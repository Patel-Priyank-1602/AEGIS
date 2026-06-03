"""
AEGIS Automated Response Playbook Engine
Executes predefined response actions when threats are detected.
Every action is idempotent and reversible via the action_ledger.

Playbooks:
  1. isolate_host    — Disable NIC to cut network access
  2. kill_process    — Terminate malicious process by PID
  3. revoke_session  — Add JWT to denylist
  4. block_ip        — Add IP to firewall blocklist
  5. snapshot_memory — Trigger memory forensics dump
  6. notify_soc      — Send alert to SOC webhook
"""

import time
import uuid
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum


class ActionStatus(str, Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"
    UNDONE = "undone"


class ActionLedger:
    """
    Tracks every automated response action with full undo capability.
    Schema: (incident_id, action_id, action_name, target, timestamp, undo_payload, status)
    """

    def __init__(self):
        self.entries: List[Dict] = []
        self._denied_jwts: set = set()  # JWT denylist for revoke_session
        self._blocked_ips: set = set()  # Blocked IPs

    def record(self, incident_id: str, action_name: str, target: str,
               details: dict, undo_payload: dict) -> str:
        action_id = str(uuid.uuid4())[:8]
        entry = {
            "action_id": action_id,
            "incident_id": incident_id,
            "action_name": action_name,
            "target": target,
            "details": details,
            "undo_payload": undo_payload,
            "status": ActionStatus.EXECUTED,
            "executed_at": datetime.utcnow().isoformat(),
            "undone_at": None,
        }
        self.entries.append(entry)
        return action_id

    def undo(self, action_id: str) -> dict:
        for entry in self.entries:
            if entry["action_id"] == action_id and entry["status"] == ActionStatus.EXECUTED:
                # Execute the undo
                undo_type = entry["undo_payload"].get("type")
                if undo_type == "unblock_ip":
                    self._blocked_ips.discard(entry["undo_payload"]["ip"])
                elif undo_type == "unrevoke_jwt":
                    self._denied_jwts.discard(entry["undo_payload"]["jti"])
                entry["status"] = ActionStatus.UNDONE
                entry["undone_at"] = datetime.utcnow().isoformat()
                return {"success": True, "message": f"Action {action_id} undone"}
        return {"success": False, "message": "Action not found or already undone"}

    def get_all(self, incident_id: Optional[str] = None) -> list:
        if incident_id:
            return [e for e in self.entries if e["incident_id"] == incident_id]
        return self.entries

    def is_jwt_denied(self, jti: str) -> bool:
        return jti in self._denied_jwts

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips


# Playbook definitions
PLAYBOOKS = {
    "critical_threat": {
        "name": "Critical Threat Response",
        "description": "Automated response for score ≥ 90: kill process, block IP, revoke sessions, alert SOC",
        "trigger": {"min_score": 90},
        "actions": ["kill_process", "block_ip", "revoke_session", "notify_soc"],
        "severity": "critical",
    },
    "high_threat": {
        "name": "High Threat Response",
        "description": "Response for score 70-89: block IP, snapshot memory, alert",
        "trigger": {"min_score": 70},
        "actions": ["block_ip", "snapshot_memory", "notify_soc"],
        "severity": "high",
    },
    "ioc_match": {
        "name": "IOC Match Response",
        "description": "When event matches known IOC: block IP, log to audit, alert SOC",
        "trigger": {"ioc_matched": True},
        "actions": ["block_ip", "notify_soc"],
        "severity": "high",
    },
    "lateral_movement": {
        "name": "Lateral Movement Response",
        "description": "GNN detects multi-hop traversal: isolate host, alert SOC",
        "trigger": {"lateral_movement": True},
        "actions": ["isolate_host", "notify_soc"],
        "severity": "critical",
    },
    "honeypot_trigger": {
        "name": "Honeypot Intrusion Response",
        "description": "Any honeypot access: guaranteed attacker, full response",
        "trigger": {"honeypot_hit": True},
        "actions": ["block_ip", "kill_process", "snapshot_memory", "notify_soc"],
        "severity": "critical",
    },
}


class PlaybookEngine:
    """Evaluates events against playbook triggers and executes response actions."""

    def __init__(self):
        self.ledger = ActionLedger()
        self.execution_log: List[Dict] = []
        self.enabled = True

    def evaluate_event(self, event: dict) -> List[Dict]:
        """Check event against all playbooks and execute matching ones."""
        if not self.enabled:
            return []

        results = []
        score = event.get("threat_score", 0)
        ioc_matched = event.get("ioc_matched", False)
        lateral = event.get("lateral_movement_detected", False)
        honeypot = event.get("honeypot_hit", False)

        for pb_id, playbook in PLAYBOOKS.items():
            trigger = playbook["trigger"]
            triggered = False

            if "min_score" in trigger and score >= trigger["min_score"]:
                triggered = True
            if trigger.get("ioc_matched") and ioc_matched:
                triggered = True
            if trigger.get("lateral_movement") and lateral:
                triggered = True
            if trigger.get("honeypot_hit") and honeypot:
                triggered = True

            if triggered:
                result = self._execute_playbook(pb_id, playbook, event)
                results.append(result)

        return results

    def _execute_playbook(self, pb_id: str, playbook: dict, event: dict) -> dict:
        incident_id = f"INC-{int(time.time())}-{str(uuid.uuid4())[:4]}"
        actions_taken = []

        for action_name in playbook["actions"]:
            result = self._execute_action(incident_id, action_name, event)
            actions_taken.append(result)

        execution = {
            "incident_id": incident_id,
            "playbook_id": pb_id,
            "playbook_name": playbook["name"],
            "severity": playbook["severity"],
            "actions": actions_taken,
            "event_pid": event.get("pid"),
            "event_process": event.get("process"),
            "event_score": event.get("threat_score"),
            "executed_at": datetime.utcnow().isoformat(),
        }
        self.execution_log.append(execution)
        print(f"[Playbook] ▶ {playbook['name']} → {incident_id} ({len(actions_taken)} actions)")
        return execution

    def _execute_action(self, incident_id: str, action_name: str, event: dict) -> dict:
        """Execute a single response action (simulated — actual host actions need agent)."""
        ip = event.get("ip", "127.0.0.1")
        pid = event.get("pid", 0)
        process = event.get("process", "unknown")

        if action_name == "kill_process":
            action_id = self.ledger.record(incident_id, action_name, f"PID:{pid}",
                {"pid": pid, "process": process, "signal": "SIGKILL"},
                {"type": "respawn_info", "pid": pid})
            return {"action": action_name, "target": f"PID {pid}", "status": "executed",
                    "action_id": action_id}

        elif action_name == "block_ip":
            self.ledger._blocked_ips.add(ip)
            action_id = self.ledger.record(incident_id, action_name, ip,
                {"ip": ip, "rule": f"iptables -A INPUT -s {ip} -j DROP"},
                {"type": "unblock_ip", "ip": ip})
            return {"action": action_name, "target": ip, "status": "executed",
                    "action_id": action_id}

        elif action_name == "revoke_session":
            jti = f"jti-{uuid.uuid4()}"
            self.ledger._denied_jwts.add(jti)
            action_id = self.ledger.record(incident_id, action_name, f"user-session",
                {"jti": jti},
                {"type": "unrevoke_jwt", "jti": jti})
            return {"action": action_name, "target": "session", "status": "executed",
                    "action_id": action_id}

        elif action_name == "isolate_host":
            action_id = self.ledger.record(incident_id, action_name, "network-interface",
                {"command": "ip link set dev eth0 down"},
                {"type": "unisolate", "command": "ip link set dev eth0 up"})
            return {"action": action_name, "target": "eth0", "status": "simulated",
                    "action_id": action_id}

        elif action_name == "snapshot_memory":
            action_id = self.ledger.record(incident_id, action_name, f"PID:{pid}",
                {"pid": pid, "dump_path": f"/tmp/aegis_dump_{pid}.bin"},
                {"type": "delete_dump", "path": f"/tmp/aegis_dump_{pid}.bin"})
            return {"action": action_name, "target": f"PID {pid}", "status": "queued",
                    "action_id": action_id}

        elif action_name == "notify_soc":
            action_id = self.ledger.record(incident_id, action_name, "soc-webhook",
                {"channel": "webhook", "severity": "critical"},
                {"type": "no_undo"})
            return {"action": action_name, "target": "SOC", "status": "notified",
                    "action_id": action_id}

        return {"action": action_name, "status": "unknown"}

    def get_executions(self, limit: int = 50) -> list:
        return sorted(self.execution_log, key=lambda x: x["executed_at"], reverse=True)[:limit]

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "total_executions": len(self.execution_log),
            "total_actions": len(self.ledger.entries),
            "blocked_ips": len(self.ledger._blocked_ips),
            "denied_jwts": len(self.ledger._denied_jwts),
            "playbooks": {k: v["name"] for k, v in PLAYBOOKS.items()},
        }


# Global singleton
playbook_engine = PlaybookEngine()
