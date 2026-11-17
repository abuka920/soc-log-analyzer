"""Collect, deduplicate, and export SOC alerts."""
import json
import csv
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .mitre_mapper import enrich_alert

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class EnrichedAlert:
    alert_id: str
    alert_type: str
    severity: str
    timestamp: datetime
    summary: str
    source_ip: str = ""
    username: str = ""
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    mitre_url: str = ""
    raw_evidence: list = field(default_factory=list)


class AlertManager:
    def __init__(self):
        self._alerts: list[EnrichedAlert] = []
        self._dedup_keys: set = set()
        self._counter: int = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"ALERT-{self._counter:04d}"

    def _dedup_key(self, alert_type: str, source_ip: str, username: str) -> str:
        return f"{alert_type}|{source_ip}|{username}"

    def add_brute_force(self, alert) -> Optional[EnrichedAlert]:
        from .detectors.brute_force import BruteForceAlert
        key = self._dedup_key("brute_force", alert.source_ip, alert.target_user)
        if key in self._dedup_keys:
            return None
        self._dedup_keys.add(key)

        enriched_dict = enrich_alert(alert)
        success_note = ""
        if alert.success_after_attack:
            success_note = f" ⚠️ SUCCESSFUL LOGIN after attack as '{alert.successful_user}'!"

        ea = EnrichedAlert(
            alert_id=self._next_id(),
            alert_type="brute_force",
            severity=alert.severity,
            timestamp=alert.first_seen,
            summary=(
                f"{alert.attempt_count} failed SSH attempts from {alert.source_ip} "
                f"targeting '{alert.target_user}' in {alert.timespan_seconds:.0f}s.{success_note}"
            ),
            source_ip=alert.source_ip,
            username=alert.target_user,
            mitre_technique_id=enriched_dict.get("mitre_technique_id", "T1110"),
            mitre_technique_name=enriched_dict.get("mitre_technique_name", "Brute Force"),
            mitre_tactic=enriched_dict.get("mitre_tactic", "Credential Access"),
            mitre_url=enriched_dict.get("mitre_url", ""),
            raw_evidence=alert.evidence_lines[:5],
        )
        self._alerts.append(ea)
        return ea

    def add_impossible_travel(self, alert) -> Optional[EnrichedAlert]:
        key = self._dedup_key("impossible_travel", alert.ip1, alert.username)
        if key in self._dedup_keys:
            return None
        self._dedup_keys.add(key)

        enriched_dict = enrich_alert(alert)
        ea = EnrichedAlert(
            alert_id=self._next_id(),
            alert_type="impossible_travel",
            severity=alert.severity,
            timestamp=alert.timestamp1,
            summary=alert.evidence,
            source_ip=f"{alert.ip1} → {alert.ip2}",
            username=alert.username,
            mitre_technique_id=enriched_dict.get("mitre_technique_id", "T1078"),
            mitre_technique_name=enriched_dict.get("mitre_technique_name", "Valid Accounts"),
            mitre_tactic=enriched_dict.get("mitre_tactic", "Initial Access"),
            mitre_url=enriched_dict.get("mitre_url", ""),
            raw_evidence=[alert.evidence],
        )
        self._alerts.append(ea)
        return ea

    def add_priv_esc(self, alert) -> Optional[EnrichedAlert]:
        key = self._dedup_key(alert.technique, "", alert.username)
        if key in self._dedup_keys:
            return None
        self._dedup_keys.add(key)

        enriched_dict = enrich_alert(alert)
        ea = EnrichedAlert(
            alert_id=self._next_id(),
            alert_type="privilege_escalation",
            severity=alert.severity,
            timestamp=alert.timestamp,
            summary=f"[{alert.technique}] by user '{alert.username}': {' '.join(alert.evidence_lines[:1])}",
            username=alert.username,
            mitre_technique_id=enriched_dict.get("mitre_technique_id", "T1548"),
            mitre_technique_name=enriched_dict.get("mitre_technique_name", ""),
            mitre_tactic=enriched_dict.get("mitre_tactic", "Privilege Escalation"),
            mitre_url=enriched_dict.get("mitre_url", ""),
            raw_evidence=alert.evidence_lines,
        )
        self._alerts.append(ea)
        return ea

    def get_alerts(self, severity: Optional[str] = None) -> list[EnrichedAlert]:
        alerts = self._alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return sorted(alerts, key=lambda a: (
            SEVERITY_ORDER.index(a.severity) if a.severity in SEVERITY_ORDER else 99,
            a.timestamp or datetime.min,
        ))

    def get_timeline(self) -> list[EnrichedAlert]:
        return sorted(
            [a for a in self._alerts if a.timestamp],
            key=lambda a: a.timestamp,
        )

    def generate_summary(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        by_type: dict = {}
        for a in self._alerts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
            by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1
        return {
            "total": len(self._alerts),
            "by_severity": counts,
            "by_type": by_type,
        }

    def export_json(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for a in self._alerts:
            d = {k: v for k, v in vars(a).items()}
            if d.get("timestamp"):
                d["timestamp"] = str(d["timestamp"])
            rows.append(d)
        with open(path, "w") as f:
            json.dump(rows, f, indent=2, default=str)

    def export_csv(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not self._alerts:
            return
        fieldnames = [k for k in vars(self._alerts[0]).keys() if k != "raw_evidence"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in self._alerts:
                row = {k: v for k, v in vars(a).items() if k in fieldnames}
                writer.writerow(row)
