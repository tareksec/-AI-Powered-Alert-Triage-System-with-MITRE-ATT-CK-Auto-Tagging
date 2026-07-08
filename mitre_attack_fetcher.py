"""
mitre_attack_fetcher.py — Build a local MITRE ATT&CK Enterprise reference
table (`mitre_data.json`) from the official MITRE ATT&CK STIX bundle.

The official dataset is published by the MITRE ATT&CK team on GitHub as a
STIX 2.1 bundle (JSON). This script downloads it once and distills it into a
flat lookup keyed by technique ID:

    {
      "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques ...",
        "sub_techniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        "mitigations": ["Account Use Policies", "Multi-factor Authentication", ...]
      },
      ...
    }

This flat file is what `app.py` and `ai_triage.py` read at runtime — neither
of them talks to the network, so the dashboard keeps working offline once
this file has been generated.

Usage:
    python mitre_attack_fetcher.py
    python mitre_attack_fetcher.py --output mitre_data.json
"""

import argparse
import json
import sys
from pathlib import Path

import requests

# Official MITRE ATT&CK Enterprise STIX bundle, published by the ATT&CK team.
ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUTPUT = "mitre_data.json"


class MitreFetchError(RuntimeError):
    """Raised for any recoverable failure while building the reference table."""


def _technique_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _is_deprecated_or_revoked(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def download_bundle(timeout: int = 60) -> dict:
    try:
        response = requests.get(ENTERPRISE_ATTACK_URL, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        raise MitreFetchError(f"Could not download the MITRE ATT&CK bundle: {exc}") from exc

    if not response.ok:
        raise MitreFetchError(f"MITRE ATT&CK bundle download returned HTTP {response.status_code}")

    try:
        return response.json()
    except ValueError as exc:
        raise MitreFetchError("MITRE ATT&CK bundle response was not valid JSON.") from exc


def build_reference_table(bundle: dict) -> dict:
    """Distill the raw STIX bundle into the flat technique lookup table."""
    objects = bundle.get("objects", [])

    techniques_by_stix_id: dict = {}
    mitigation_names_by_stix_id: dict = {}
    relationships: list = []

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            techniques_by_stix_id[obj["id"]] = obj
        elif obj_type == "course-of-action":
            mitigation_names_by_stix_id[obj["id"]] = obj.get("name", "")
        elif obj_type == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append(obj)

    # technique STIX id -> list of mitigation names
    mitigations_by_technique_stix_id: dict = {}
    for rel in relationships:
        target_id = rel.get("target_ref")
        source_id = rel.get("source_ref")
        if target_id in techniques_by_stix_id and source_id in mitigation_names_by_stix_id:
            mitigations_by_technique_stix_id.setdefault(target_id, []).append(
                mitigation_names_by_stix_id[source_id]
            )

    result: dict = {}
    # First pass: register every non-deprecated technique.
    for stix_id, obj in techniques_by_stix_id.items():
        if _is_deprecated_or_revoked(obj):
            continue
        tid = _technique_id(obj)
        if not tid:
            continue

        tactics = [phase.get("phase_name", "").replace("-", " ").title() for phase in obj.get("kill_chain_phases", [])]
        description = (obj.get("description") or "").split("\n")[0].strip()

        result[tid] = {
            "name": obj.get("name", tid),
            "tactic": tactics[0] if tactics else "",
            "tactics": tactics,
            "description": description[:600],
            "sub_techniques": [],
            "mitigations": sorted(set(mitigations_by_technique_stix_id.get(stix_id, []))),
        }

    # Second pass: attach sub-techniques (e.g. T1110.001) to their parent (T1110).
    for tid in list(result.keys()):
        if "." in tid:
            parent_id = tid.split(".")[0]
            if parent_id in result:
                result[parent_id]["sub_techniques"].append(tid)

    for info in result.values():
        info["sub_techniques"].sort()

    return dict(sorted(result.items()))


def write_output(table: dict, output_path: str) -> None:
    out_path = Path(output_path)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download the official MITRE ATT&CK Enterprise dataset and build mitre_data.json."
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Output JSON path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()

    try:
        bundle = download_bundle()
        table = build_reference_table(bundle)
    except MitreFetchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    write_output(table, args.output)
    print(f"Wrote {len(table)} MITRE ATT&CK technique(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
