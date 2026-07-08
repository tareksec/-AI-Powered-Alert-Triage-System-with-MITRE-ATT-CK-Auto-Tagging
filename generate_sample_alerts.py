"""
generate_sample_alerts.py — Produce realistic, raw (pre-AI-triage) security
alert events for testing the pipeline without a live Wazuh deployment.

Replit cannot run Docker/containers, so a real local Wazuh manager isn't
available in this environment. This script fills that gap with plausible
raw alerts across a handful of common scenarios (failed SSH logins,
suspicious process execution, port scanning, etc.) — enough variety to
exercise the AI triage step and the dashboard end to end. Swap this out for
`wazuh_fetcher.py` output once you point the pipeline at a real Wazuh
Indexer.

Each generated event has the shape `ai_triage.py` and `database.py` expect:
    {
        "alert_id": str,     # unique id
        "rule_description": str,
        "level": int,        # raw Wazuh/Sigma-style severity level
        "agent_name": str,   # host that generated the event
        "raw_log": str       # a raw log line, given to the AI for context
    }

Usage:
    python generate_sample_alerts.py
    python generate_sample_alerts.py --count 30 --output data/raw_alerts.json
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_OUTPUT = "data/raw_alerts.json"
DEFAULT_COUNT = 25

AGENTS = ["web-01", "web-02", "db-primary", "vpn-gateway", "finance-ws-07", "hr-laptop-14", "build-runner-3"]

USERS = ["root", "admin", "svc_backup", "jsmith", "deploy", "guest", "administrator"]

SCENARIOS = [
    {
        "kind": "ssh_bruteforce",
        "description": "Multiple failed SSH login attempts from a single source",
        "level": lambda: random.choice([8, 9, 10, 11]),
        "log": lambda: (
            f"sshd[{random.randint(1000, 9999)}]: Failed password for "
            f"{random.choice(USERS)} from {_random_ip()} port {random.randint(1024, 65000)} ssh2"
        ),
    },
    {
        "kind": "suspicious_process",
        "description": "Suspicious process execution with encoded command-line arguments",
        "level": lambda: random.choice([10, 12, 13, 14]),
        "log": lambda: (
            "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand "
            f"{_random_b64_like()}  (parent: {random.choice(['winword.exe', 'excel.exe', 'explorer.exe'])})"
        ),
    },
    {
        "kind": "port_scan",
        "description": "Port scan detected against internal host",
        "level": lambda: random.choice([5, 6, 7]),
        "log": lambda: (
            f"IDS: TCP SYN scan from {_random_ip()} touched {random.randint(15, 400)} ports "
            f"on {random.choice(AGENTS)} within {random.randint(2, 20)}s"
        ),
    },
    {
        "kind": "privilege_escalation",
        "description": "Local user added to administrators/sudoers group",
        "level": lambda: random.choice([11, 12, 13]),
        "log": lambda: (
            f"usermod: user '{random.choice(USERS)}' added to group "
            f"'{random.choice(['sudo', 'wheel', 'Administrators'])}' by {random.choice(USERS)}"
        ),
    },
    {
        "kind": "file_integrity",
        "description": "Critical system file modified outside of a maintenance window",
        "level": lambda: random.choice([9, 10, 11]),
        "log": lambda: (
            "syscheck: File '"
            + random.choice(
                [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/etc/sudoers",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts",
                ]
            )
            + "' checksum changed"
        ),
    },
    {
        "kind": "outbound_beacon",
        "description": "Periodic outbound connection to a newly observed external domain",
        "level": lambda: random.choice([7, 8, 9]),
        "log": lambda: (
            f"netflow: {random.choice(AGENTS)} -> {_random_ip()}:{random.choice([443, 8080, 4444, 53])} "
            f"every {random.choice([30, 60, 120])}s, domain first_seen=today"
        ),
    },
    {
        "kind": "benign_login",
        "description": "Successful interactive login during business hours",
        "level": lambda: random.choice([2, 3]),
        "log": lambda: f"sshd: Accepted publickey for {random.choice(USERS)} from {_random_ip()} port {random.randint(1024, 65000)} ssh2",
    },
    {
        "kind": "software_update",
        "description": "Routine package manager update completed",
        "level": lambda: random.choice([1, 2]),
        "log": lambda: f"apt: upgraded {random.randint(1, 12)} package(s) on {random.choice(AGENTS)}",
    },
]


def _random_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_b64_like(length: int = 48) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.choice(alphabet) for _ in range(length)) + "=="


def generate_alerts(count: int, seed: int | None = None) -> list:
    if seed is not None:
        random.seed(seed)

    now = datetime.now(timezone.utc)
    alerts = []
    for _ in range(count):
        scenario = random.choice(SCENARIOS)
        timestamp = now - timedelta(minutes=random.randint(0, 60 * 24))
        alerts.append(
            {
                "alert_id": str(uuid.uuid4()),
                "rule_description": scenario["description"],
                "level": scenario["level"](),
                "agent_name": random.choice(AGENTS),
                "raw_log": scenario["log"](),
                "timestamp": timestamp.isoformat(),
            }
        )
    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    return alerts


def write_output(alerts: list, output_path: str) -> None:
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate sample raw security alerts for the SOC Sentinel pipeline.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help=f"Number of alerts to generate (default: {DEFAULT_COUNT})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Output JSON path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    args = parser.parse_args()

    alerts = generate_alerts(args.count, seed=args.seed)
    write_output(alerts, args.output)
    print(f"Generated {len(alerts)} sample raw alert(s) and wrote them to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
