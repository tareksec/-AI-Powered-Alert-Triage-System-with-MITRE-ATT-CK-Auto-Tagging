"""
ai_triage.py — AI-powered alert triage.

Reads raw (pending) alerts from the `alerts` table, sends each one to the
OpenAI API with a senior-SOC-analyst prompt, and stores the structured
verdict back in Postgres:
    - is_real_threat (bool)   — real threat vs. false positive
    - severity (str)          — Critical / High / Medium / Low / Info
    - mitre_technique_id (str)— best-matching MITRE ATT&CK technique, or ""
    - confidence (0-100)
    - reasoning (1-2 sentences)

Requires the OPENAI_API_KEY from config.py. If it's missing, this script exits with a clear
error instead of silently skipping triage.

Usage:
    python ai_triage.py                # triage all pending alerts
    python ai_triage.py --limit 10     # triage at most 10
"""

import argparse
import json
import os
import sys
from pathlib import Path

from openai import OpenAI

import config
import database

MITRE_DATA_PATH = Path("mitre_data.json")
MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with deep expertise \
in the MITRE ATT&CK framework. You will be given one raw security alert (a rule description, a \
numeric severity level from the source sensor, the host it fired on, and a raw log line). \

Decide:
1. Whether this is a REAL security threat or a FALSE POSITIVE / benign/expected activity.
2. The severity you'd assign as an analyst: one of "Critical", "High", "Medium", "Low", "Info".
3. The single MITRE ATT&CK Enterprise technique ID (e.g. "T1110" or "T1059.001") that best matches \
the observed behavior. If this is a false positive or no technique clearly applies, use an empty string.
4. Your confidence in this verdict, 0-100.
5. A one to two sentence justification a human analyst could read at a glance.

Respond ONLY with a JSON object with exactly these keys:
{"is_real_threat": bool, "severity": string, "mitre_technique_id": string, "confidence": number, "reasoning": string}
"""


def load_mitre_ids() -> set:
    """Load known MITRE technique IDs, used to validate the AI's output."""
    if not MITRE_DATA_PATH.exists():
        return set()
    with open(MITRE_DATA_PATH, "r", encoding="utf-8") as f:
        return set(json.load(f).keys())


VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def build_user_prompt(alert: dict) -> str:
    return (
        f"Rule description: {alert['rule_description']}\n"
        f"Source severity level (0-15 scale): {alert['level']}\n"
        f"Agent/host: {alert['agent_name']}\n"
        f"Raw log: {alert.get('raw_log') or 'N/A'}\n"
    )


def classify_alert(client: OpenAI, alert: dict, known_technique_ids: set) -> dict:
    """Call the OpenAI API and return a validated triage result dict."""
    response = client.chat.completions.create(
        model=MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(alert)},
        ],
        temperature=0.2,
    )
    content = response.choices[0].message.content
    try:
        result = json.loads(content)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Model returned non-JSON content: {content!r}") from exc

    # Validate/sanitize before it ever reaches the database. Be strict about
    # is_real_threat: some models return it as a string ("true"/"false")
    # rather than a JSON boolean, and a naive bool(...) coercion would treat
    # the string "false" as truthy, silently flipping the verdict.
    raw_verdict = result.get("is_real_threat")
    if isinstance(raw_verdict, bool):
        is_real_threat = raw_verdict
    elif isinstance(raw_verdict, str):
        normalized = raw_verdict.strip().lower()
        if normalized in ("true", "yes", "1"):
            is_real_threat = True
        elif normalized in ("false", "no", "0"):
            is_real_threat = False
        else:
            raise ValueError(f"Model returned an unrecognized is_real_threat value: {raw_verdict!r}")
    else:
        raise ValueError(f"Model returned a non-boolean is_real_threat value: {raw_verdict!r}")

    severity = str(result.get("severity", "")).strip().title()
    if severity not in VALID_SEVERITIES:
        severity = "Medium" if is_real_threat else "Info"

    technique_id = str(result.get("mitre_technique_id", "") or "").strip().upper()
    if technique_id and known_technique_ids and technique_id not in known_technique_ids:
        technique_id = ""

    try:
        confidence = float(result.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(100.0, confidence))

    reasoning = str(result.get("reasoning", "")).strip()[:1000]

    return {
        "is_real_threat": is_real_threat,
        "severity": severity,
        "mitre_technique_id": technique_id,
        "confidence": confidence,
        "reasoning": reasoning,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AI triage over pending alerts in the database.")
    parser.add_argument("--limit", type=int, default=200, help="Max number of pending alerts to triage (default: 200)")
    args = parser.parse_args()

    api_key = config.OPENAI_API_KEY
    if not api_key or api_key == "PASTE_YOUR_API_KEY_HERE":
        print(
            "Error: OPENAI_API_KEY is not set in config.py. Update it, then re-run this script.",
            file=sys.stderr,
        )
        return 1

    client = OpenAI(api_key=api_key)
    known_technique_ids = load_mitre_ids()

    database.init_schema()
    pending = database.get_pending_alerts(limit=args.limit)
    if not pending:
        print("No pending alerts to triage.")
        return 0

    triaged, failed = 0, 0
    for alert in pending:
        try:
            result = classify_alert(client, alert, known_technique_ids)
            database.save_triage_result(alert["id"], result, status="triaged")
            triaged += 1
        except Exception as exc:  # noqa: BLE001 — keep the batch going on a per-row failure
            print(f"  Failed to triage alert {alert['id']} ({alert['source_alert_id']}): {exc}", file=sys.stderr)
            database.save_triage_result(alert["id"], {}, status="failed")
            failed += 1

    print(f"Triaged {triaged} alert(s), {failed} failed, out of {len(pending)} pending.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
