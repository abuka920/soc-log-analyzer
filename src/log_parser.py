"""Parse Linux auth.log and syslog formats into structured DataFrames."""
import re
import pandas as pd
from pathlib import Path
from datetime import datetime

# auth.log pattern: "Nov 15 14:23:01 hostname process[pid]: message"
_AUTHLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s+(?P<message>.+)$"
)

MONTHS = {m: i+1 for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
)}


def _parse_line(line: str, year: int = 2024) -> dict | None:
    m = _AUTHLOG_RE.match(line.strip())
    if not m:
        return None
    try:
        month_num = MONTHS.get(m.group("month"), 1)
        day = int(m.group("day"))
        time_str = m.group("time")
        h, mi, s = map(int, time_str.split(":"))
        ts = datetime(year, month_num, day, h, mi, s)
    except (ValueError, KeyError):
        return None

    return {
        "timestamp": ts,
        "hostname": m.group("hostname"),
        "process": m.group("process"),
        "pid": m.group("pid"),
        "message": m.group("message"),
        "raw_line": line.strip(),
    }


def parse_string(text: str, year: int = 2024) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = _parse_line(line, year)
        if parsed:
            rows.append(parsed)
    if not rows:
        return pd.DataFrame(columns=["timestamp","hostname","process","pid","message","raw_line"])
    return pd.DataFrame(rows)


def parse_file(path: str | Path, year: int = 2024) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        return pd.DataFrame()
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_string(text, year)


def parse_directory(dir_path: str | Path, year: int = 2024) -> pd.DataFrame:
    dir_path = Path(dir_path)
    frames = []
    for f in dir_path.glob("*"):
        if f.is_file() and f.suffix not in {".py", ".png", ".json", ".csv"}:
            df = parse_file(f, year)
            if not df.empty:
                df["source_file"] = f.name
                frames.append(df)
    if not frames:
        return pd.DataFrame()
    combined = pd.concat(frames, ignore_index=True)
    return combined.sort_values("timestamp").reset_index(drop=True)
