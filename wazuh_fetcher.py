"""
wazuh_fetcher.py — Pull alerts from a live Wazuh deployment and write them
into the schema the SOC Sentinel dashboard (app.py) reads from
(`data/enriched_alerts.json`).

Wazuh stores alerts in the Wazuh Indexer (OpenSearch), not in the manager
API, so this script queries the indexer's `_search` REST endpoint directly
and maps each hit into:

    {
        "alert_id": str,
        "rule_description": str,
        "level": int,
        "technique_id": str,      # first MITRE ATT&CK technique on the rule,
                                   # or "UNCLASSIFIED" if the rule has none
        "agent_name": str
    }

Configuration (environment variables — see environment-secrets, do not
hardcode credentials):
    WAZUH_INDEXER_URL       Base URL of the Wazuh Indexer, e.g.
                             "https://localhost:9200" (required)
    WAZUH_INDEXER_USER      Basic-auth username (required)
    WAZUH_INDEXER_PASSWORD  Basic-auth password (required)
    WAZUH_ALERTS_INDEX      Index pattern to query (default: "wazuh-alerts-*")
    WAZUH_VERIFY_SSL        "true"/"false" — verify the indexer's TLS cert
                             (default: "false", since Wazuh ships with a
                             self-signed cert out of the box)

Usage:
    python wazuh_fetcher.py
    python wazuh_fetcher.py --output data/enriched_alerts.json --size 500 --min-level 3
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

DEFAULT_INDEX = "wazuh-alerts-*"
DEFAULT_OUTPUT = "data/enriched_alerts.json"
DEFAULT_SIZE = 500
DEFAULT_MIN_LEVEL = 0
UNCLASSIFIED = "UNCLASSIFIED"


class WazuhFetchError(RuntimeError):
    """Raised for any recoverable failure while talking to the indexer."""


def _env_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_config() -> dict:
    """Read Wazuh Indexer connection settings from the environment."""
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    user = os.environ.get("WAZUH_INDEXER_USER")
    password = os.environ.get("WAZUH_INDEXER_PASSWORD")

    missing = [
        name
        for name, val in (
            ("WAZUH_INDEXER_URL", url),
            ("WAZUH_INDEXER_USER", user),
            ("WAZUH_INDEXER_PASSWORD", password),
        )
        if not val
    ]
    if missing:
        raise WazuhFetchError(
            "Missing required environment variable(s): "
            + ", ".join(missing)
            + ". Set these to your Wazuh Indexer connection details before running this script."
        )

    return {
        "url": url,
        "user": user,
        "password": password,
        "index": os.environ.get("WAZUH_ALERTS_INDEX", DEFAULT_INDEX),
        "verify_ssl": _env_bool(os.environ.get("WAZUH_VERIFY_SSL"), False),
    }


def fetch_alerts(config: dict, size: int, min_level: int, timeout: int = 30) -> list:
    """Query the Wazuh Indexer for recent alerts at or above `min_level`."""
    search_url = f"{config['url']}/{config['index']}/_search"
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": min_level}}},
    }

    if not config["verify_ssl"]:
        # Wazuh's default self-signed cert triggers noisy warnings; the user
        # has explicitly opted into skipping verification via WAZUH_VERIFY_SSL.
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    try:
        response = requests.get(
            search_url,
            json=query,
            auth=HTTPBasicAuth(config["user"], config["password"]),
            verify=config["verify_ssl"],
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        raise WazuhFetchError(f"Could not reach the Wazuh Indexer at {config['url']}: {exc}") from exc

    if response.status_code == 401:
        raise WazuhFetchError("Authentication failed — check WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD.")
    if not response.ok:
        raise WazuhFetchError(f"Wazuh Indexer returned HTTP {response.status_code}: {response.text[:500]}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise WazuhFetchError("Wazuh Indexer response was not valid JSON.") from exc

    hits = payload.get("hits", {}).get("hits", [])
    return hits


def map_hit(hit: dict) -> dict:
    """Convert one Wazuh Indexer search hit into the dashboard's alert schema."""
    source = hit.get("_source", {})
    rule = source.get("rule", {}) or {}
    agent = source.get("agent", {}) or {}

    mitre_ids = rule.get("mitre", {}).get("id") if isinstance(rule.get("mitre"), dict) else None
    if isinstance(mitre_ids, list) and mitre_ids:
        technique_id = str(mitre_ids[0])
    elif isinstance(mitre_ids, str) and mitre_ids:
        technique_id = mitre_ids
    else:
        technique_id = UNCLASSIFIED

    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0

    return {
        "alert_id": str(hit.get("_id", "unknown")),
        "rule_description": str(rule.get("description", "No description provided")),
        "level": level,
        "technique_id": technique_id,
        "agent_name": str(agent.get("name", "unknown")),
    }


def write_output(alerts: list, output_path: str) -> None:
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch alerts from a Wazuh Indexer into the SOC Sentinel schema.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Output JSON path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE, help=f"Max alerts to fetch (default: {DEFAULT_SIZE})")
    parser.add_argument(
        "--min-level",
        type=int,
        default=DEFAULT_MIN_LEVEL,
        help=f"Only fetch alerts with rule.level >= this value (default: {DEFAULT_MIN_LEVEL})",
    )
    args = parser.parse_args()

    try:
        config = load_config()
        hits = fetch_alerts(config, size=args.size, min_level=args.min_level)
    except WazuhFetchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    alerts = [map_hit(hit) for hit in hits]
    write_output(alerts, args.output)

    print(f"Fetched {len(alerts)} alert(s) from '{config['index']}' and wrote them to {args.output}")
    unclassified = sum(1 for a in alerts if a["technique_id"] == UNCLASSIFIED)
    if unclassified:
        print(f"Note: {unclassified} alert(s) had no MITRE ATT&CK tag and were marked '{UNCLASSIFIED}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
