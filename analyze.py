"""
SOC Log Analyzer — CLI
Usage: python analyze.py --logs sample_logs/ [--output reports/] [--dashboard]
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.markup import escape

from src.log_parser import parse_directory
from src.detectors.brute_force import detect_brute_force
from src.detectors.impossible_travel import detect_impossible_travel
from src.detectors.privilege_escalation import detect_privilege_escalation
from src.alert_manager import AlertManager

console = Console()

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFO": "dim",
}


@click.command()
@click.option("--logs", default="sample_logs/", show_default=True,
              help="Directory of log files to analyze")
@click.option("--output", default="reports/", show_default=True,
              help="Output directory for JSON/CSV reports")
@click.option("--dashboard", is_flag=True, default=False,
              help="Launch Streamlit dashboard after analysis")
@click.option("--severity", default=None,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
              help="Minimum severity to display")
def main(logs, output, dashboard, severity):
    """SOC Log Analyzer — detect brute force, impossible travel, privilege escalation."""

    console.print(Panel.fit(
        "[bold cyan]SOC Log Analyzer[/bold cyan]\n"
        "MITRE ATT&CK mapped detections",
        border_style="cyan",
    ))

    # Parse
    console.print(f"\n[dim]Parsing logs from [cyan]{logs}[/cyan]...[/dim]")
    df = parse_directory(logs)
    if df.empty:
        console.print("[bold red]No log entries parsed. Check the log directory.[/bold red]")
        sys.exit(1)
    console.print(f"  Parsed [green]{len(df):,}[/green] log entries")

    # Detect
    console.print("\n[dim]Running detectors...[/dim]")
    manager = AlertManager()

    bf_alerts = detect_brute_force(df)
    console.print(f"  Brute force        : [{'red' if bf_alerts else 'green'}]{len(bf_alerts)} alerts[/]")
    for a in bf_alerts:
        manager.add_brute_force(a)

    it_alerts = detect_impossible_travel(df)
    console.print(f"  Impossible travel  : [{'red' if it_alerts else 'green'}]{len(it_alerts)} alerts[/]")
    for a in it_alerts:
        manager.add_impossible_travel(a)

    pe_alerts = detect_privilege_escalation(df)
    console.print(f"  Privilege escalation: [{'red' if pe_alerts else 'green'}]{len(pe_alerts)} alerts[/]")
    for a in pe_alerts:
        manager.add_priv_esc(a)

    # Summary table
    all_alerts = manager.get_alerts(severity=severity)
    summary = manager.generate_summary()

    console.print()
    table = Table(title="Alert Summary", box=box.ROUNDED, border_style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Types")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary["by_severity"].get(sev, 0)
        if count > 0:
            types = sorted({a.alert_type.replace("_", " ") for a in all_alerts if a.severity == sev})
            table.add_row(
                f"[{SEV_COLORS.get(sev, '')}]{sev}[/]",
                str(count),
                ", ".join(types),
            )
    console.print(table)

    # Detailed alert table
    if all_alerts:
        detail_table = Table(title="Alerts", box=box.SIMPLE, border_style="dim")
        detail_table.add_column("ID", style="dim", width=10)
        detail_table.add_column("Severity", width=10)
        detail_table.add_column("Type", width=20)
        detail_table.add_column("MITRE", width=10)
        detail_table.add_column("Summary", width=70)

        for a in all_alerts[:30]:
            sev_style = SEV_COLORS.get(a.severity, "")
            detail_table.add_row(
                a.alert_id,
                f"[{sev_style}]{a.severity}[/]",
                a.alert_type,
                a.mitre_technique_id or "",
                escape(a.summary[:68]),
            )
        console.print(detail_table)

    # Export
    out_dir = Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)
    manager.export_json(out_dir / "alerts.json")
    manager.export_csv(out_dir / "alerts.csv")
    console.print(f"\n[dim]Reports saved to [cyan]{out_dir}/[/cyan][/dim]")

    console.print(Panel.fit(
        f"[bold green]Scan complete[/bold green]\n"
        f"CRITICAL: {summary['by_severity'].get('CRITICAL',0)} | "
        f"HIGH: {summary['by_severity'].get('HIGH',0)} | "
        f"MEDIUM: {summary['by_severity'].get('MEDIUM',0)} | "
        f"LOW: {summary['by_severity'].get('LOW',0)}",
        border_style="green",
    ))

    if dashboard:
        import subprocess
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app/dashboard.py"])


if __name__ == "__main__":
    main()
