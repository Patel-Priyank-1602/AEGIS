"""
AEGIS MITRE ATT&CK Tagger
Maps security events to MITRE ATT&CK technique IDs automatically.
Uses the free MITRE ATT&CK STIX dataset for technique matching.
"""

# Embedded MITRE ATT&CK technique database (key techniques for endpoint detection)
MITRE_TECHNIQUES = {
    # Initial Access
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "description": "Adversary sends phishing messages to gain access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Exploitation of a vulnerability in an internet-facing application"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Abuse of command and script interpreters to execute commands"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "description": "Abuse of PowerShell for execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution", "description": "Abuse of Unix shell for command execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution", "description": "Abuse of task scheduling for persistence or execution"},
    # Persistence
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence", "description": "Manipulation of accounts to maintain access"},
    "T1136": {"name": "Create Account", "tactic": "Persistence", "description": "Create new account for persistent access"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence", "description": "Create or modify system processes for persistence"},
    # Privilege Escalation
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "description": "Bypass UAC or sudo to escalate privileges"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "description": "Exploit vulnerability for elevated privileges"},
    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "description": "Delete or modify artifacts to hide activity"},
    "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion", "description": "Delete files to remove indicators"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion", "description": "Manipulate features of artifacts to make them appear legitimate"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "description": "Encrypt, encode, or obfuscate content"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Dump credentials from the operating system"},
    "T1003.008": {"name": "/etc/passwd and /etc/shadow", "tactic": "Credential Access", "description": "Access password files on Linux"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access", "description": "Search for insecurely stored credentials"},
    "T1552.004": {"name": "Private Keys", "tactic": "Credential Access", "description": "Search for private key files like SSH keys"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Attempt to gain access via brute-force password guessing"},
    # Discovery
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "description": "Scan network to find services and open ports"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "description": "Collect detailed system information"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "description": "Enumerate files and directories"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "description": "Use remote services to move between systems"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement", "description": "Use SSH to move between systems"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "description": "Transfer tools between compromised systems"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "Collection", "description": "Collect data from the local system"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection", "description": "Compress or encrypt collected data before exfil"},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Use application protocols for C2 communication"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control", "description": "Use non-standard protocols for C2"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control", "description": "Tunnel C2 through legitimate protocols"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control", "description": "Encrypt C2 communications"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Exfiltrate data over the C2 channel"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Exfiltrate data using a different protocol"},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Encrypt data on target systems (ransomware)"},
    "T1489": {"name": "Service Stop", "tactic": "Impact", "description": "Stop services to cause impact"},
    "T1529": {"name": "System Shutdown/Reboot", "tactic": "Impact", "description": "Shutdown or reboot systems for impact"},
}

# Mapping rules: process names, files, and behaviors → technique IDs
PROCESS_RULES = {
    "nmap": ["T1046"],
    "masscan": ["T1046"],
    "nc": ["T1095", "T1059.004"],
    "ncat": ["T1095", "T1059.004"],
    "netcat": ["T1095", "T1059.004"],
    "hydra": ["T1110"],
    "john": ["T1110"],
    "hashcat": ["T1110"],
    "metasploit": ["T1190", "T1068"],
    "msfconsole": ["T1190", "T1068"],
    "reverse": ["T1095"],
    "payload": ["T1059"],
    "exploit": ["T1068"],
    "bash": ["T1059.004"],
    "sh": ["T1059.004"],
    "zsh": ["T1059.004"],
    "powershell": ["T1059.001"],
    "pwsh": ["T1059.001"],
    "curl": ["T1071"],
    "wget": ["T1071"],
    "ssh": ["T1021.004"],
    "scp": ["T1570"],
    "rsync": ["T1570"],
    "tar": ["T1560"],
    "gzip": ["T1560"],
    "zip": ["T1560"],
    "crontab": ["T1053"],
    "at": ["T1053"],
}

FILE_RULES = {
    "/etc/shadow": ["T1003.008"],
    "/etc/passwd": ["T1003.008"],
    "/etc/sudoers": ["T1548"],
    "id_rsa": ["T1552.004"],
    ".ssh": ["T1552.004"],
    ".bash_history": ["T1552", "T1083"],
    "/proc/kcore": ["T1003"],
    "/dev/mem": ["T1003"],
    "/boot/vmlinuz": ["T1082"],
    "/etc/crontab": ["T1053"],
    "/var/spool/cron": ["T1053"],
}

PORT_RULES = {
    4444: ["T1095"],   # Default Metasploit
    1337: ["T1095"],   # Leet port
    31337: ["T1095"],  # Back Orifice
    5555: ["T1095"],   # Typical reverse shell
    8888: ["T1572"],   # Proxy/tunnel
    9999: ["T1095"],   # Reverse shell
    1234: ["T1095"],   # Generic backdoor
}


def tag_event(event: dict) -> dict:
    """
    Tag a security event with matching MITRE ATT&CK technique IDs.
    Returns enrichment data to attach to the event.
    """
    techniques = []
    seen_ids = set()

    process = event.get("process", "").lower()
    file_path = event.get("file", "")
    port = event.get("port", 0)
    ip = event.get("ip", "127.0.0.1")
    ioc_matched = event.get("ioc_matched", False)

    # Process-based matching
    for proc_name, tech_ids in PROCESS_RULES.items():
        if proc_name in process:
            for tid in tech_ids:
                if tid not in seen_ids and tid in MITRE_TECHNIQUES:
                    seen_ids.add(tid)
                    techniques.append({
                        "id": tid,
                        **MITRE_TECHNIQUES[tid],
                        "match_source": "process",
                        "match_value": process,
                    })

    # File-based matching
    for file_pattern, tech_ids in FILE_RULES.items():
        if file_pattern in file_path:
            for tid in tech_ids:
                if tid not in seen_ids and tid in MITRE_TECHNIQUES:
                    seen_ids.add(tid)
                    techniques.append({
                        "id": tid,
                        **MITRE_TECHNIQUES[tid],
                        "match_source": "file",
                        "match_value": file_path,
                    })

    # Port-based matching
    if port in PORT_RULES:
        for tid in PORT_RULES[port]:
            if tid not in seen_ids and tid in MITRE_TECHNIQUES:
                seen_ids.add(tid)
                techniques.append({
                    "id": tid,
                    **MITRE_TECHNIQUES[tid],
                    "match_source": "port",
                    "match_value": str(port),
                })

    # IOC match implies C2
    if ioc_matched:
        for tid in ["T1071", "T1573"]:
            if tid not in seen_ids:
                seen_ids.add(tid)
                techniques.append({
                    "id": tid,
                    **MITRE_TECHNIQUES[tid],
                    "match_source": "ioc",
                    "match_value": ip,
                })

    # External IP with suspicious process suggests exfiltration
    is_external = ip not in ("127.0.0.1", "0.0.0.0", "::1") and \
        not ip.startswith("192.168.") and not ip.startswith("10.")
    if is_external and process in ("curl", "wget", "nc", "ncat"):
        tid = "T1041"
        if tid not in seen_ids:
            seen_ids.add(tid)
            techniques.append({
                "id": tid,
                **MITRE_TECHNIQUES[tid],
                "match_source": "behavior",
                "match_value": f"{process} → {ip}",
            })

    return {
        "mitre_techniques": techniques,
        "mitre_tactic_count": len(set(t["tactic"] for t in techniques)),
        "mitre_technique_count": len(techniques),
    }


def get_technique_info(technique_id: str) -> dict:
    """Get details for a specific MITRE ATT&CK technique."""
    return MITRE_TECHNIQUES.get(technique_id, {"error": "Unknown technique"})


def get_coverage_matrix() -> dict:
    """Get ATT&CK coverage — which tactics AEGIS can detect."""
    tactics = {}
    for tid, info in MITRE_TECHNIQUES.items():
        tactic = info["tactic"]
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append({"id": tid, "name": info["name"]})
    return tactics
