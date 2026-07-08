"""
load_sample_alerts.py — Generate sample raw alerts and load them into the
database as pending rows, ready for `ai_triage.py`.

This is the "no live Wazuh" on-ramp for the pipeline: it combines
`generate_sample_alerts.py` (creates realistic raw events) with
`database.insert_raw_alert()` (loads them as pending) in one step, so you
can go from an empty database to a populated dashboard with:

    python load_sample_alerts.py
    python ai_triage.py

Usage:
    python load_sample_alerts.py --count 30
"""

import argparse

import database
from generate_sample_alerts import generate_alerts, DEFAULT_COUNT


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and load sample raw alerts into the database.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help=f"Number of alerts to generate (default: {DEFAULT_COUNT})")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible output")
    args = parser.parse_args()

    database.init_schema()
    alerts = generate_alerts(args.count, seed=args.seed)

    inserted = sum(1 for alert in alerts if database.insert_raw_alert(alert) is not None)
    print(f"Generated {len(alerts)} sample alert(s), inserted {inserted} new pending row(s) into the database.")
    print("Run `python ai_triage.py` next to classify them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
