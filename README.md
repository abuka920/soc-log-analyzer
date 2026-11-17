# SOC Log Analyzer with MITRE ATT&CK Mapping

Parses Linux `auth.log` and `syslog` to detect brute-force attacks, impossible travel, and privilege escalation — with every alert mapped to the MITRE ATT&CK framework.

## Detections

| Detection | Method | MITRE Technique |
|-----------|--------|----------------|
| SSH Brute Force | Sliding-window failed auth count | T1110 — Brute Force |
| Credential Stuffing | Success after burst failure | T1110.004 — Credential Stuffing |
| Impossible Travel | GeoIP + Haversine + speed check | T1078 — Valid Accounts |
| Privilege Escalation (sudo) | Log pattern matching | T1548.003 — Sudo Caching |
| New User Creation | useradd log events | T1136.001 — Local Account |
| Sudo Group Modification | usermod events | T1098 — Account Manipulation |
| Sudoers File Modification | visudo / sudoedit events | T1548.003 — Sudo Caching |
| Cron Job Modification | crontab events | T1053.003 — Cron |

## Quick Start

```bash
pip install -r requirements.txt

# Analyze sample logs (included)
python analyze.py --logs sample_logs/

# Launch interactive dashboard
python analyze.py --logs sample_logs/ --dashboard

# Or launch dashboard directly
streamlit run app/dashboard.py

# Filter by severity
python analyze.py --logs sample_logs/ --severity HIGH
```

## Sample Alert Output

Running `python analyze.py` on the included sample logs finds a full attack story:

```
Severity  Type                  MITRE      Summary
CRITICAL  brute_force           T1110      50 failed SSH attempts from 185.220.101.47 targeting 'root' in 26s.
                                           SUCCESSFUL LOGIN after attack as 'ubuntu'!
CRITICAL  impossible_travel     T1078      'admin' logged in from Toronto, then Moscow 10 minutes later
CRITICAL  privilege_escalation  T1548.003  www-data ran sudo /bin/bash (web server user got a root shell)
CRITICAL  privilege_escalation  T1098      'backdoor' account added to the sudo group
HIGH      privilege_escalation  T1136.001  New local account created: backdoor
MEDIUM    privilege_escalation  T1548.003  jsmith ran sudo apt-get update
MEDIUM    privilege_escalation  T1053.003  www-data edited a crontab (persistence)
LOW       brute_force           T1110      6 failed SSH attempts from 45.142.212.100
```

Read top to bottom, that's an intrusion: password guessing gets in, the attacker escalates to root,
then creates a backdoor admin account and a cron job so they can come back.

## Impossible travel and IP geolocation

Locations come from a small built-in table (`src/geo_lookup.py`), so the project runs offline with no
API keys. Distance uses the haversine formula, and travel faster than 900 km/h (a commercial flight)
is flagged. For production you would swap `lookup()` for a real GeoIP database such as MaxMind GeoLite2.
Private IPs (10.x, 192.168.x) are skipped, since they don't tell you where someone is.

## Dashboard Tabs

| Tab | Content |
|-----|---------|
| Alert Summary | Severity counter cards + alert type bar chart |
| Timeline | Chronological event list |
| Brute Force | IP, target user, attempt count, MITRE badge |
| Impossible Travel | User, location path, time gap |
| Privilege Escalation | Technique, user, MITRE ATT&CK technique ID + name |

## Tech Stack

- **Python** — log parsing with regex
- **Pandas** — time-series analysis
- **Rich** — CLI output formatting
- **Streamlit** — analyst dashboard
- **MITRE ATT&CK** — technique mapping (offline, no API calls)
