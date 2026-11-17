"""Detect impossible travel: same user logging in from geographically distant IPs too quickly."""
import re
from dataclasses import dataclass, field
from datetime import datetime
import pandas as pd

from ..geo_lookup import lookup, travel_possible, GeoInfo

_LOGIN_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+"
)


@dataclass
class ImpossibleTravelAlert:
    alert_type: str = "impossible_travel"
    username: str = ""
    ip1: str = ""
    location1: str = ""
    country1: str = ""
    ip2: str = ""
    location2: str = ""
    country2: str = ""
    time_gap_minutes: float = 0.0
    severity: str = "HIGH"
    evidence: str = ""
    timestamp1: datetime = None
    timestamp2: datetime = None


def detect_impossible_travel(
    df: pd.DataFrame,
    max_gap_minutes: float = 60.0,
) -> list[ImpossibleTravelAlert]:
    alerts = []
    if df.empty or "message" not in df.columns:
        return alerts

    logins = []
    for _, row in df.iterrows():
        m = _LOGIN_RE.search(str(row["message"]))
        if m:
            logins.append({
                "timestamp": row["timestamp"],
                "username": m.group(1),
                "ip": m.group(2),
            })

    if not logins:
        return alerts

    login_df = pd.DataFrame(logins).sort_values("timestamp")

    seen_pairs: set = set()

    for username, group in login_df.groupby("username"):
        events = group.sort_values("timestamp").to_dict("records")
        for i in range(len(events) - 1):
            e1 = events[i]
            e2 = events[i + 1]

            gap = (e2["timestamp"] - e1["timestamp"]).total_seconds() / 60.0
            if gap < 0 or gap > max_gap_minutes:
                continue

            geo1 = lookup(e1["ip"])
            geo2 = lookup(e2["ip"])

            if geo1.country == "Private" or geo2.country == "Private":
                continue
            if geo1.country == geo2.country and geo1.city == geo2.city:
                continue

            if not travel_possible(geo1, geo2, gap):
                pair_key = (username, e1["ip"], e2["ip"])
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                severity = "CRITICAL" if gap < 15 else "HIGH"
                loc1 = f"{geo1.city}, {geo1.country}"
                loc2 = f"{geo2.city}, {geo2.country}"

                alerts.append(ImpossibleTravelAlert(
                    username=username,
                    ip1=e1["ip"],
                    location1=loc1,
                    country1=geo1.country,
                    ip2=e2["ip"],
                    location2=loc2,
                    country2=geo2.country,
                    time_gap_minutes=round(gap, 1),
                    severity=severity,
                    evidence=(
                        f"User '{username}' logged in from {loc1} ({e1['ip']}) at "
                        f"{e1['timestamp'].strftime('%H:%M:%S')}, then from {loc2} ({e2['ip']}) "
                        f"{gap:.0f} minutes later — impossible given geography."
                    ),
                    timestamp1=e1["timestamp"],
                    timestamp2=e2["timestamp"],
                ))

    return sorted(alerts, key=lambda a: a.time_gap_minutes)
