"""
AEGIS LLM Alert Explainer with RAG over MITRE ATT&CK
Generates plain-English kill chain explanations for security alerts.

Uses Ollama locally (no data leaves your network) or falls back to
template-based explanations when Ollama is unavailable.
"""

import json
from typing import Optional, Dict, List
from datetime import datetime

# Try Ollama — falls back gracefully
_ollama_available = False
try:
    import requests as http_requests
    r = http_requests.get("http://localhost:11434/api/tags", timeout=2)
    if r.status_code == 200:
        _ollama_available = True
        print("[LLM] Ollama detected at localhost:11434")
except Exception:
    print("[LLM] Ollama not available. Using template-based explanations.")


# Template-based explanations (no LLM required)
EXPLANATION_TEMPLATES = {
    "T1003.008": (
        "The attacker attempted to read {file}, which contains Linux user account "
        "credentials. This maps to MITRE ATT&CK technique T1003.008 (OS Credential Dumping: "
        "/etc/passwd and /etc/shadow). Immediate action: verify the process {process} is "
        "legitimate, check for unauthorized account additions, and rotate all passwords."
    ),
    "T1552.004": (
        "Process {process} accessed SSH private key files ({file}). This maps to T1552.004 "
        "(Unsecured Credentials: Private Keys). The attacker may use stolen keys for "
        "lateral movement to other hosts. Action: rotate all SSH keys, check authorized_keys "
        "on all servers, and review recent SSH login history."
    ),
    "T1046": (
        "Network scanning tool {process} was detected (T1046: Network Service Discovery). "
        "The attacker is mapping your network to identify vulnerable services on port {port}. "
        "Action: block the source IP {ip}, check firewall logs for scan patterns, and verify "
        "all exposed services are patched."
    ),
    "T1095": (
        "Process {process} established a connection on suspicious port {port} to {ip}. "
        "This matches T1095 (Non-Application Layer Protocol), commonly used for reverse "
        "shells and C2 communication. Action: immediately terminate the process, block the "
        "IP at the firewall, and conduct a full host forensic analysis."
    ),
    "T1110": (
        "Brute force tool {process} detected (T1110: Brute Force). The attacker is attempting "
        "to crack passwords through automated guessing. Action: enable account lockout policies, "
        "check for compromised accounts, and implement MFA on all critical systems."
    ),
    "T1059.004": (
        "Unix shell execution detected via {process} (T1059.004: Command and Scripting "
        "Interpreter: Unix Shell). While shell usage can be legitimate, the threat score of "
        "{score} indicates suspicious context. Action: review the command history, check for "
        "downloaded scripts, and verify the user's identity."
    ),
    "T1071": (
        "Process {process} communicated with external IP {ip} using application-layer "
        "protocols (T1071). This may indicate C2 communication or data exfiltration. "
        "Action: capture network traffic for analysis, block the destination IP, and review "
        "DNS logs for domain generation algorithm (DGA) patterns."
    ),
    "T1041": (
        "Potential data exfiltration detected: {process} sending data to {ip} (T1041: "
        "Exfiltration Over C2 Channel). The attacker may be stealing sensitive data. "
        "Action: immediately isolate the host, capture network traffic, quantify data "
        "transferred, and initiate incident response procedures."
    ),
    "T1548": (
        "Privilege escalation attempt detected via {file} access (T1548: Abuse Elevation "
        "Control Mechanism). The attacker is trying to gain root/admin privileges. "
        "Action: verify sudoers file integrity, check for SUID binary modifications, "
        "and review recent privilege escalation logs."
    ),
}

# Generic template for techniques without specific templates
GENERIC_TEMPLATE = (
    "Security alert: Process '{process}' (PID {pid}) triggered {technique_count} MITRE "
    "ATT&CK technique(s): {techniques}. Threat score: {score}/100 ({level}). "
    "The behavior pattern suggests {tactic_summary}. "
    "Recommended action: investigate the process origin, check for lateral movement, "
    "and follow your incident response playbook for {severity} severity events."
)

HONEYPOT_TEMPLATE = (
    "🍯 HONEYPOT TRIGGERED: Process '{process}' (PID {pid}) accessed a decoy resource. "
    "This is CONFIRMED attacker activity — honeypot resources have zero legitimate "
    "access patterns. The attacker accessed {resource}, which was planted as a canary. "
    "Immediate action: isolate the host, capture memory dump, block the source IP {ip}, "
    "and begin full incident response. This is not a false positive."
)

IOC_TEMPLATE = (
    "⚠️ THREAT INTEL MATCH: Process '{process}' communicated with known malicious IP {ip}, "
    "which is listed in threat intelligence feeds as a {ioc_confidence}-confidence indicator "
    "of compromise. This likely represents active C2 (Command and Control) communication. "
    "Immediate action: terminate the connection, isolate the host, dump process memory for "
    "analysis, and check other hosts for connections to the same IP."
)


class AlertExplainer:
    """Generates human-readable explanations for security alerts."""

    def __init__(self):
        self.explanations_generated: int = 0
        self.ollama_model: str = "qwen2.5-coder:7b"
        self.use_ollama: bool = _ollama_available

    def explain(self, event: dict) -> dict:
        """Generate an explanation for a security alert event."""
        explanation = ""
        method = "template"

        # Check special cases first
        if event.get("honeypot_hit"):
            explanation = self._explain_honeypot(event)
        elif event.get("ioc_matched"):
            explanation = self._explain_ioc(event)
        elif self.use_ollama:
            try:
                explanation = self._explain_with_ollama(event)
                method = "ollama"
            except Exception:
                explanation = self._explain_with_templates(event)
        else:
            explanation = self._explain_with_templates(event)

        self.explanations_generated += 1

        return {
            "explanation": explanation,
            "method": method,
            "generated_at": datetime.utcnow().isoformat(),
            "model": self.ollama_model if method == "ollama" else "template-engine",
        }

    def _explain_honeypot(self, event: dict) -> str:
        alerts = event.get("honeypot_alerts", [{}])
        resource = alerts[0].get("resource", "unknown") if alerts else "unknown"
        return HONEYPOT_TEMPLATE.format(
            process=event.get("process", "unknown"),
            pid=event.get("pid", 0),
            resource=resource,
            ip=event.get("ip", "unknown"),
        )

    def _explain_ioc(self, event: dict) -> str:
        return IOC_TEMPLATE.format(
            process=event.get("process", "unknown"),
            ip=event.get("ip", "unknown"),
            ioc_confidence=event.get("ioc_confidence", "unknown"),
        )

    def _explain_with_templates(self, event: dict) -> str:
        techniques = event.get("mitre_techniques", [])
        if not techniques:
            return self._generic_explanation(event)

        # Use the most specific template available
        for tech in techniques:
            tid = tech.get("id", "")
            if tid in EXPLANATION_TEMPLATES:
                return EXPLANATION_TEMPLATES[tid].format(
                    process=event.get("process", "unknown"),
                    pid=event.get("pid", 0),
                    file=event.get("file", "N/A"),
                    ip=event.get("ip", "127.0.0.1"),
                    port=event.get("port", 0),
                    score=event.get("threat_score", 0),
                )

        return self._generic_explanation(event)

    def _generic_explanation(self, event: dict) -> str:
        techniques = event.get("mitre_techniques", [])
        tech_names = ", ".join(f"{t['id']} ({t['name']})" for t in techniques[:3])
        if not tech_names:
            tech_names = "unknown technique"

        tactics = set(t.get("tactic", "") for t in techniques)
        tactic_summary = ", ".join(tactics) if tactics else "suspicious activity"

        level = event.get("threat_level", "unknown")
        severity = "critical" if level == "danger" else "medium" if level == "warning" else "low"

        return GENERIC_TEMPLATE.format(
            process=event.get("process", "unknown"),
            pid=event.get("pid", 0),
            technique_count=len(techniques),
            techniques=tech_names,
            score=event.get("threat_score", 0),
            level=level,
            tactic_summary=tactic_summary,
            severity=severity,
        )

    def _explain_with_ollama(self, event: dict) -> str:
        """Call local Ollama for LLM-powered explanation."""
        techniques = event.get("mitre_techniques", [])
        tech_context = "\n".join(
            f"- {t['id']}: {t['name']} ({t['tactic']}) - {t['description']}"
            for t in techniques[:5]
        )

        prompt = (
            f"Given this security event:\n"
            f"  Process: {event.get('process')} (PID {event.get('pid')})\n"
            f"  File: {event.get('file', 'N/A')}\n"
            f"  IP: {event.get('ip', '127.0.0.1')}:{event.get('port', 0)}\n"
            f"  Threat Score: {event.get('threat_score', 0)}/100\n"
            f"  Level: {event.get('threat_level', 'unknown')}\n\n"
            f"Related MITRE ATT&CK techniques:\n{tech_context}\n\n"
            f"Explain in 3 sentences: what the attacker likely did, "
            f"what technique it maps to, and what to do next."
        )

        r = http_requests.post(
            "http://localhost:11434/api/generate",
            json={"model": self.ollama_model, "prompt": prompt, "stream": False},
            timeout=30,
        )

        if r.status_code == 200:
            return r.json().get("response", self._generic_explanation(event))
        raise Exception(f"Ollama returned {r.status_code}")

    def get_stats(self) -> dict:
        return {
            "explanations_generated": self.explanations_generated,
            "ollama_available": self.use_ollama,
            "model": self.ollama_model,
            "method": "ollama" if self.use_ollama else "template",
            "template_count": len(EXPLANATION_TEMPLATES),
        }


# Global singleton
alert_explainer = AlertExplainer()
