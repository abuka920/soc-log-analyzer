"""Detect SSH/RDP brute force and credential stuffing from auth logs."""
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import pandas as pd

SEVERITY_THRESHOLDS = [(5, "LOW"), (20, "MEDIUM"), (50, "HIGH"), (100, "CRITICAL")]

_FAILED_RE = re.compile(
    r"Failed (password|publickey) for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port \d+"
)
_SUCCESS_RE = re.compile(
    r"Accepted (password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+"
)


@dataclass
class BruteForceAlert:
    alert_type: str = "brute_force"
    source_ip: str = ""
    target_user: str = ""
    attempt_count: int = 0
    timespan_seconds: float = 0.0
    severity: str = "LOW"
    success_after_attack: bool = False
    successful_user: str = ""
    successful_time: datetime = None
    evidence_lines: list = field(default_factory=list)
    first_seen: datetime = None
    last_seen: datetime = None


def _get_severity(count: int) -> str:
    sev = "INFO"
    for threshold, label in SEVERITY_THRESHOLDS:
        if count >= threshold:
            sev = label
    return sev


def detect_brute_force(
    df: pd.DataFrame,
    window_seconds: int = 60,
    min_attempts: int = 5,
) -> list[BruteForceAlert]:
    alerts = []
    if df.empty or "message" not in df.columns:
        return alerts

    # Extract failed login events
    failed_events = []
    for _, row in df.iterrows():
        m = _FAILED_RE.search(row["message"])
        if m:
            failed_events.append({
                "timestamp": row["timestamp"],
                "user": m.group(3),
                "ip": m.group(4),
                "raw": row["message"],
            })

    # Extract successful logins
    success_events = []
    for _, row in df.iterrows():
        m = _SUCCESS_RE.search(row["message"])
        if m:
            success_events.append({
                "timestamp": row["timestamp"],
                "user": m.group(2),
                "ip": m.group(3),
            })

    if not failed_events:
        return alerts

    failed_df = pd.DataFrame(failed_events)
    success_df = pd.DataFrame(success_events) if success_events else pd.DataFrame()

    seen_ips: set = set()

    for ip, group in failed_df.groupby("ip"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].tolist()

        # Sliding window
        i = 0
        while i < len(timestamps):
            window_start = timestamps[i]
            window_end = window_start + timedelta(seconds=window_seconds)
            window = group[
                (group["timestamp"] >= window_start) &
                (group["timestamp"] <= window_end)
            ]

            if len(window) >= min_attempts and ip not in seen_ips:
                seen_ips.add(ip)
                top_user = window["user"].value_counts().idxmax()
                timespan = (window["timestamp"].max() - window["timestamp"].min()).total_seconds()
                severity = _get_severity(len(window))

                # Check for successful login after attack
                success_after = False
                successful_user = ""
                successful_time = None
                if not success_df.empty:
                    after_success = success_df[
                        (success_df["ip"] == ip) &
                        (success_df["timestamp"] > window_start)
                    ]
                    if not after_success.empty:
                        success_after = True
                        first_success = after_success.sort_values("timestamp").iloc[0]
                        successful_user = first_success["user"]
                        successful_time = first_success["timestamp"]
                        severity = "CRITICAL"

                alerts.append(BruteForceAlert(
                    source_ip=ip,
                    target_user=top_user,
                    attempt_count=len(window),
                    timespan_seconds=timespan,
                    severity=severity,
                    success_after_attack=success_after,
                    successful_user=successful_user,
                    successful_time=successful_time,
                    evidence_lines=window["raw"].tolist()[:10],
                    first_seen=window["timestamp"].min(),
                    last_seen=window["timestamp"].max(),
                ))
                break
            i += 1

    return sorted(alerts, key=lambda a: (
        ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(a.severity)
    ), reverse=True)
