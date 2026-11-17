"""Map detection types to MITRE ATT&CK techniques."""

MITRE_MAPPINGS = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "subtechnique": "T1110.001 - Password Guessing",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "credential_stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Credential Stuffing",
        "tactic": "Credential Access",
        "subtechnique": "T1110.004 - Credential Stuffing",
        "url": "https://attack.mitre.org/techniques/T1110/004/",
    },
    "impossible_travel": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "subtechnique": "T1078.001 - Default Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "sudo_root_shell": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "subtechnique": "T1548.003 - Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "sudo_command": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "subtechnique": "T1548.003 - Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "sudo_group_add": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "subtechnique": "T1098 - Account Manipulation",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "new_user_created": {
        "technique_id": "T1136.001",
        "technique_name": "Create Account: Local Account",
        "tactic": "Persistence",
        "subtechnique": "T1136.001 - Local Account",
        "url": "https://attack.mitre.org/techniques/T1136/001/",
    },
    "su_root_success": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "subtechnique": "T1548.003 - Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "su_root_failed": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "subtechnique": "T1548.003 - Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "sudoers_modified": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Defense Evasion",
        "subtechnique": "T1548.003 - Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "cron_modified": {
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "subtechnique": "T1053.003 - Cron",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "privilege_escalation": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "subtechnique": "T1548 - Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
}


def enrich_alert(alert) -> dict:
    """
    Takes any alert dataclass and returns a dict enriched with MITRE fields.
    Looks up by alert_type first, then technique field.
    """
    alert_dict = vars(alert).copy() if hasattr(alert, "__dict__") else dict(alert)

    # Prefer the specific technique (e.g. "sudo_group_add") over the broad
    # alert type ("privilege_escalation") so each alert gets its exact ATT&CK ID.
    technique = alert_dict.get("technique") or ""
    lookup_key = technique if technique in MITRE_MAPPINGS else (alert_dict.get("alert_type") or "")
    mapping = MITRE_MAPPINGS.get(lookup_key, MITRE_MAPPINGS.get("privilege_escalation", {}))

    alert_dict["mitre_technique_id"] = mapping.get("technique_id", "")
    alert_dict["mitre_technique_name"] = mapping.get("technique_name", "")
    alert_dict["mitre_tactic"] = mapping.get("tactic", "")
    alert_dict["mitre_subtechnique"] = mapping.get("subtechnique", "")
    alert_dict["mitre_url"] = mapping.get("url", "")

    return alert_dict


def get_mitre_badge(technique_id: str) -> str:
    """Return a markdown-style badge string."""
    return f"[{technique_id}](https://attack.mitre.org/techniques/{technique_id.replace('.','/')})"
