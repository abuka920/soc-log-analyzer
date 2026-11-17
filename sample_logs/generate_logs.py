"""Regenerate sample log files with fresh synthetic data."""
import random
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path(__file__).parent


def generate_auth_log(path: Path, seed: int = 42):
    random.seed(seed)
    lines = []
    base = datetime(2024, 11, 15, 6, 0, 0)

    def fmt(ts: datetime, host: str, proc: str, pid: int, msg: str) -> str:
        return f"{ts.strftime('%b %d %H:%M:%S')} {host} {proc}[{pid}]: {msg}"

    brute_ip = "185.220.101.47"
    users = ["root", "admin", "ubuntu", "testuser", "deploy", "postgres", "oracle", "ec2-user", "centos"]
    ts = base
    for i in range(50):
        user = random.choice(users)
        lines.append(fmt(ts, "prod-server", "sshd", 1234+i,
                         f"Failed password for {user} from {brute_ip} port {51234+i} ssh2"))
        ts += timedelta(seconds=random.uniform(0.5, 1.5))

    # Success after brute force
    lines.append(fmt(ts, "prod-server", "sshd", 1284,
                     f"Accepted password for ubuntu from {brute_ip} port 51284 ssh2"))

    # Normal login from Toronto
    ts = base + timedelta(hours=4, minutes=15)
    lines.append(fmt(ts, "prod-server", "sshd", 3001,
                     "Accepted password for admin from 142.250.80.1 port 55001 ssh2"))

    # Impossible travel: same user from Moscow 10 min later
    ts += timedelta(minutes=10)
    lines.append(fmt(ts, "prod-server", "sshd", 3002,
                     "Accepted password for admin from 95.108.213.42 port 55002 ssh2"))

    # Privilege escalation
    ts = base + timedelta(hours=3, minutes=30)
    lines.append(fmt(ts, "prod-server", "sudo", 2001,
                     "jsmith : TTY=pts/1 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/apt-get update"))
    lines.append(fmt(ts + timedelta(minutes=1), "prod-server", "sudo", 2002,
                     "www-data : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash"))

    # New user + sudo group add
    ts = base + timedelta(hours=5, minutes=15)
    lines.append(fmt(ts, "prod-server", "useradd", 4001,
                     "new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash"))
    lines.append(fmt(ts + timedelta(seconds=30), "prod-server", "usermod", 4002,
                     "add backdoor to group sudo"))

    lines.sort()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated {len(lines)} lines → {path}")


if __name__ == "__main__":
    generate_auth_log(LOG_DIR / "auth.log")
    print("Done.")
