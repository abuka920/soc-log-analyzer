"""
SOC Log Analyzer — Streamlit Dashboard
Run: streamlit run app/dashboard.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd
from datetime import datetime

from src.log_parser import parse_directory, parse_file
from src.detectors.brute_force import detect_brute_force
from src.detectors.impossible_travel import detect_impossible_travel
from src.detectors.privilege_escalation import detect_privilege_escalation
from src.alert_manager import AlertManager
from src.mitre_mapper import get_mitre_badge

st.set_page_config(page_title="SOC Log Analyzer", page_icon="🛡️", layout="wide")

SAMPLE_LOGS = Path(__file__).resolve().parent.parent / "sample_logs"
SEVERITY_COLORS = {
    "CRITICAL": "#D62728",
    "HIGH": "#FF7F0E",
    "MEDIUM": "#FDD835",
    "LOW": "#2CA02C",
    "INFO": "#AEC7E8",
}


@st.cache_data
def run_analysis(log_dir: str):
    df = parse_directory(log_dir)
    if df.empty:
        return None, None

    manager = AlertManager()
    bf_alerts = detect_brute_force(df)
    it_alerts = detect_impossible_travel(df)
    pe_alerts = detect_privilege_escalation(df)

    for a in bf_alerts:
        manager.add_brute_force(a)
    for a in it_alerts:
        manager.add_impossible_travel(a)
    for a in pe_alerts:
        manager.add_priv_esc(a)

    return manager, df


def severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#888")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{sev}</span>'


def render_summary(manager: AlertManager):
    summary = manager.generate_summary()
    st.title("🛡️ SOC Log Analysis Dashboard")

    cols = st.columns(5)
    for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
        count = summary["by_severity"].get(sev, 0)
        color = SEVERITY_COLORS.get(sev, "#888")
        cols[i].markdown(
            f'<div style="background:{color};padding:12px;border-radius:8px;text-align:center">'
            f'<h2 style="color:white;margin:0">{count}</h2>'
            f'<p style="color:white;margin:0;font-size:12px">{sev}</p></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    by_type = summary["by_type"]
    if by_type:
        type_df = pd.DataFrame(list(by_type.items()), columns=["Alert Type", "Count"])
        st.bar_chart(type_df.set_index("Alert Type"))


def render_timeline(manager: AlertManager):
    st.header("🕐 Event Timeline")
    alerts = manager.get_timeline()
    if not alerts:
        st.info("No alerts in timeline.")
        return

    rows = []
    for a in alerts:
        rows.append({
            "Time": str(a.timestamp)[:19] if a.timestamp else "",
            "Severity": a.severity,
            "Type": a.alert_type,
            "Summary": a.summary[:120],
            "MITRE": a.mitre_technique_id,
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, width="stretch", height=400)


def render_brute_force(manager: AlertManager):
    st.header("💥 Brute Force Attacks")
    st.caption("MITRE ATT&CK T1110 — Credential Access")

    alerts = [a for a in manager.get_alerts() if a.alert_type == "brute_force"]
    if not alerts:
        st.success("No brute force alerts detected.")
        return

    for a in alerts:
        with st.expander(
            f"[{a.severity}] {a.source_ip} — {a.summary[:80]}",
            expanded=(a.severity in ["CRITICAL", "HIGH"]),
        ):
            col1, col2, col3 = st.columns(3)
            col1.metric("Source IP", a.source_ip)
            col2.metric("Target User", a.username)
            col3.metric("MITRE", a.mitre_technique_id)
            st.markdown(f"**Tactic:** {a.mitre_tactic} | **Technique:** [{a.mitre_technique_id}]({a.mitre_url}) {a.mitre_technique_name}")
            st.markdown(f"**Summary:** {a.summary}")
            if a.raw_evidence:
                st.code("\n".join(a.raw_evidence[:5]), language="text")


def render_impossible_travel(manager: AlertManager):
    st.header("✈️ Impossible Travel")
    st.caption("MITRE ATT&CK T1078 — Valid Accounts / Initial Access")

    alerts = [a for a in manager.get_alerts() if a.alert_type == "impossible_travel"]
    if not alerts:
        st.success("No impossible travel detected.")
        return

    rows = []
    for a in alerts:
        rows.append({
            "Severity": a.severity,
            "User": a.username,
            "IP Path": a.source_ip,
            "Summary": a.summary,
            "MITRE": f"{a.mitre_technique_id} — {a.mitre_technique_name}",
            "Time": str(a.timestamp)[:19] if a.timestamp else "",
        })
    st.dataframe(pd.DataFrame(rows), width="stretch")


def render_priv_esc(manager: AlertManager):
    st.header("⬆️ Privilege Escalation")
    st.caption("MITRE ATT&CK T1548, T1136, T1098 — Privilege Escalation / Persistence")

    alerts = [a for a in manager.get_alerts() if a.alert_type == "privilege_escalation"]
    if not alerts:
        st.success("No privilege escalation detected.")
        return

    rows = []
    for a in alerts:
        rows.append({
            "Severity": a.severity,
            "User": a.username,
            "Summary": a.summary[:100],
            "MITRE ID": a.mitre_technique_id,
            "MITRE Name": a.mitre_technique_name,
            "Tactic": a.mitre_tactic,
        })
    st.dataframe(pd.DataFrame(rows), width="stretch")


def main():
    st.sidebar.title("🛡️ SOC Log Analyzer")
    log_source = st.sidebar.radio("Log Source", ["Sample Logs", "Upload Logs"])

    if log_source == "Upload Logs":
        uploaded = st.sidebar.file_uploader("Upload auth.log", type=["log", "txt"])
        if uploaded:
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".log", delete=False) as f:
                f.write(uploaded.read())
                tmp_path = f.name
            from src.log_parser import parse_file
            df = parse_file(tmp_path)
            os.unlink(tmp_path)
            manager = AlertManager()
            for a in detect_brute_force(df):
                manager.add_brute_force(a)
            for a in detect_impossible_travel(df):
                manager.add_impossible_travel(a)
            for a in detect_privilege_escalation(df):
                manager.add_priv_esc(a)
        else:
            st.info("Upload a log file to analyze.")
            return
    else:
        manager, df = run_analysis(str(SAMPLE_LOGS))
        if manager is None:
            st.error("No log files found in sample_logs/. Run sample_logs/generate_logs.py first.")
            return

    page = st.sidebar.radio("View", [
        "📊 Alert Summary",
        "🕐 Timeline",
        "💥 Brute Force",
        "✈️ Impossible Travel",
        "⬆️ Privilege Escalation",
    ])

    if page == "📊 Alert Summary":
        render_summary(manager)
    elif page == "🕐 Timeline":
        render_timeline(manager)
    elif page == "💥 Brute Force":
        render_brute_force(manager)
    elif page == "✈️ Impossible Travel":
        render_impossible_travel(manager)
    elif page == "⬆️ Privilege Escalation":
        render_priv_esc(manager)


if __name__ == "__main__":
    main()
