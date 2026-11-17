"""Detect privilege escalation patterns in auth and syslog."""
import re
from dataclasses import dataclass, field
from datetime import datetime
import pandas as pd

_SUDO_RE = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+)\s*:.*COMMAND=(.*)")
_SUDO_ROOT_RE = re.compile(
    r"sudo(?:\[\d+\])?:\s+(\S+)\s*:.*USER=root.*COMMAND=\S*(?:/bin/(?:ba)?sh|/bin/su|/usr/bin/su|\bsu\b|sudo -i|sudo -s)"
)
_SU_RE = re.compile(r"su\[.*\]:\s+(Successful|FAILED) su for (\S+) by (\S+)")
_USERADD_RE = re.compile(r"useradd\[.*\]:\s+new user: name=([^,\s]+)")
_USERMOD_SUDO_RE = re.compile(
    r"usermod\[.*\]:.*(?:add '?(?P<user>[\w.-]+)'? to (?:shadow )?group '?(?:sudo|wheel|admin)'?|(?:-aG|--append.*--groups).*(?:sudo|wheel|admin))"
)
_CRON_USER_RE = re.compile(r"\((\S+)\)\s+CMD")
_SSHD_NOPASSWD_RE = re.compile(r"NOPASSWD.*(\S+)")
_SUDOERS_MOD_RE = re.compile(r"(sudoedit|visudo|/etc/sudoers)")
_CRON_MOD_RE = re.compile(r"(crontab.*-e|/etc/cron|/var/spool/cron)")


@dataclass
class PrivEscAlert:
    alert_type: str = "privilege_escalation"
    username: str = ""
    technique: str = ""
    severity: str = "HIGH"
    evidence_lines: list = field(default_factory=list)
    timestamp: datetime = None
    mitre_subtechnique: str = ""


_TECHNIQUE_SEVERITY = {
    "sudo_root_shell":    "CRITICAL",
    "su_root_success":    "HIGH",
    "new_user_created":   "HIGH",
    "sudo_group_add":     "CRITICAL",
    "sudoers_modified":   "CRITICAL",
    "sudo_command":       "MEDIUM",
    "su_root_failed":     "LOW",
    "cron_modified":      "MEDIUM",
}

_TECHNIQUE_SUBTECHNIQUE = {
    "sudo_root_shell":   "T1548.003 - Sudo and Sudo Caching",
    "sudo_command":      "T1548.003 - Sudo and Sudo Caching",
    "sudo_group_add":    "T1098 - Account Manipulation",
    "new_user_created":  "T1136.001 - Local Account",
    "su_root_success":   "T1548.003 - Sudo and Sudo Caching",
    "su_root_failed":    "T1548.003 - Sudo and Sudo Caching",
    "sudoers_modified":  "T1548.003 - Sudo and Sudo Caching",
    "cron_modified":     "T1053.003 - Cron",
}


def detect_privilege_escalation(df: pd.DataFrame) -> list[PrivEscAlert]:
    alerts = []
    if df.empty or "message" not in df.columns:
        return alerts

    seen: set = set()

    for _, row in df.iterrows():
        # The parser splits "sudo[2001]: msg" into process/pid/message.
        # Rebuild the full line so the patterns below see the program name.
        process = str(row.get("process", "") or "")
        pid = row.get("pid")
        prefix = f"{process}[{pid}]" if pid and str(pid) != "nan" else process
        msg = f"{prefix}: {row['message']}" if process else str(row["message"])
        ts = row["timestamp"]

        # sudo root shell escalation
        if _SUDO_ROOT_RE.search(msg):
            m = _SUDO_RE.search(msg)
            user = m.group(1) if m else "unknown"
            key = ("sudo_root_shell", user)
            if key not in seen:
                seen.add(key)
                alerts.append(PrivEscAlert(
                    username=user,
                    technique="sudo_root_shell",
                    severity="CRITICAL",
                    evidence_lines=[msg],
                    timestamp=ts,
                    mitre_subtechnique="T1548.003 - Sudo and Sudo Caching",
                ))
            continue

        # Regular sudo command
        m = _SUDO_RE.search(msg)
        if m:
            user = m.group(1)
            command = m.group(2).strip()
            key = ("sudo_command", user, command)
            if key not in seen:
                seen.add(key)
                alerts.append(PrivEscAlert(
                    username=user,
                    technique="sudo_command",
                    severity="MEDIUM",
                    evidence_lines=[f"{user} ran: sudo {command}"],
                    timestamp=ts,
                    mitre_subtechnique="T1548.003 - Sudo and Sudo Caching",
                ))
            continue

        # su root
        m = _SU_RE.search(msg)
        if m:
            status = m.group(1)
            target = m.group(2)
            by_user = m.group(3)
            if target in ("root", "0"):
                technique = "su_root_success" if status == "Successful" else "su_root_failed"
                key = (technique, by_user)
                if key not in seen:
                    seen.add(key)
                    alerts.append(PrivEscAlert(
                        username=by_user,
                        technique=technique,
                        severity=_TECHNIQUE_SEVERITY.get(technique, "MEDIUM"),
                        evidence_lines=[msg],
                        timestamp=ts,
                        mitre_subtechnique=_TECHNIQUE_SUBTECHNIQUE.get(technique, ""),
                    ))
            continue

        # New user creation
        m = _USERADD_RE.search(msg)
        if m:
            new_user = m.group(1)
            key = ("new_user_created", new_user)
            if key not in seen:
                seen.add(key)
                alerts.append(PrivEscAlert(
                    username=new_user,
                    technique="new_user_created",
                    severity="HIGH",
                    evidence_lines=[f"New account created: {new_user}"],
                    timestamp=ts,
                    mitre_subtechnique="T1136.001 - Local Account",
                ))
            continue

        # sudo/wheel group add
        m = _USERMOD_SUDO_RE.search(msg)
        if m:
            key = ("sudo_group_add", msg[:60])
            if key not in seen:
                seen.add(key)
                alerts.append(PrivEscAlert(
                    username=m.group("user") or "unknown",
                    technique="sudo_group_add",
                    severity="CRITICAL",
                    evidence_lines=[msg],
                    timestamp=ts,
                    mitre_subtechnique="T1098 - Account Manipulation",
                ))
            continue

        # sudoers modification
        if _SUDOERS_MOD_RE.search(msg):
            key = ("sudoers_modified", msg[:60])
            if key not in seen:
                seen.add(key)
                alerts.append(PrivEscAlert(
                    username="unknown",
                    technique="sudoers_modified",
                    severity="CRITICAL",
                    evidence_lines=[msg],
                    timestamp=ts,
                    mitre_subtechnique="T1548.003 - Sudo and Sudo Caching",
                ))
            continue

        # Cron modification
        if _CRON_MOD_RE.search(msg):
            key = ("cron_modified", msg[:60])
            if key not in seen:
                seen.add(key)
                cron_user = _CRON_USER_RE.search(msg)
                alerts.append(PrivEscAlert(
                    username=cron_user.group(1) if cron_user else "unknown",
                    technique="cron_modified",
                    severity="MEDIUM",
                    evidence_lines=[msg],
                    timestamp=ts,
                    mitre_subtechnique="T1053.003 - Cron",
                ))

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return sorted(alerts, key=lambda a: sev_order.index(a.severity) if a.severity in sev_order else 99)
