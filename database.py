"""
database.py — Postgres access layer for SOC Sentinel.

Uses Replit's built-in PostgreSQL database (connection details come from the
standard `DATABASE_URL` / `PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` /
`PGDATABASE` environment variables — never hardcode credentials).

Schema (table `alerts`):
    id                  SERIAL PRIMARY KEY
    source_alert_id     VARCHAR — id from Wazuh/sample generator (unique)
    rule_description    TEXT — human-readable description of the raw event
    level               INTEGER — raw Wazuh/Sigma-style severity level
    agent_name          VARCHAR — host that generated the alert
    raw_log             TEXT — raw log line/payload, kept for audit
    is_real_threat      BOOLEAN — AI verdict (NULL until triaged)
    severity            VARCHAR — AI-assigned severity label
    mitre_technique_id  VARCHAR — AI-assigned MITRE ATT&CK technique id
    ai_confidence       NUMERIC — AI confidence score 0-100
    ai_reasoning        TEXT — one/two sentence AI justification
    triage_status       VARCHAR — 'pending' | 'triaged' | 'failed'
    created_at          TIMESTAMPTZ — when the raw alert was ingested
    triaged_at          TIMESTAMPTZ — when the AI triage completed
"""

import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    source_alert_id VARCHAR(128) NOT NULL,
    rule_description TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,
    agent_name VARCHAR(255) NOT NULL DEFAULT 'unknown',
    raw_log TEXT,
    is_real_threat BOOLEAN,
    severity VARCHAR(20),
    mitre_technique_id VARCHAR(20),
    ai_confidence NUMERIC(5,2),
    ai_reasoning TEXT,
    triage_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    triaged_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_triage_status ON alerts (triage_status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_source_id ON alerts (source_alert_id);
"""


def get_connection():
    """Open a new connection to the Replit-managed Postgres database."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not set. This project expects Replit's built-in "
            "PostgreSQL database to be provisioned."
        )
    return psycopg2.connect(database_url)


@contextmanager
def get_cursor(commit: bool = False):
    """Context manager yielding a dict-cursor; commits on success if requested."""
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema() -> None:
    """Create the `alerts` table and indexes if they don't already exist."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def insert_raw_alert(alert: dict) -> int | None:
    """Insert one raw (pre-AI) alert as 'pending'. Returns the new row id,
    or None if an alert with the same source_alert_id already exists."""
    with get_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO alerts (source_alert_id, rule_description, level, agent_name, raw_log, triage_status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
            ON CONFLICT (source_alert_id) DO NOTHING
            RETURNING id
            """,
            (
                alert["alert_id"],
                alert["rule_description"],
                alert["level"],
                alert.get("agent_name", "unknown"),
                alert.get("raw_log"),
            ),
        )
        row = cur.fetchone()
        return row["id"] if row else None


def get_pending_alerts(limit: int = 200) -> list:
    """Return raw alerts that have not yet been AI-triaged."""
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM alerts WHERE triage_status = 'pending' ORDER BY created_at ASC LIMIT %s",
            (limit,),
        )
        return cur.fetchall()


def save_triage_result(alert_id: int, result: dict, status: str = "triaged") -> None:
    """Persist the AI triage verdict for one alert row."""
    with get_cursor(commit=True) as cur:
        cur.execute(
            """
            UPDATE alerts
            SET is_real_threat = %s,
                severity = %s,
                mitre_technique_id = %s,
                ai_confidence = %s,
                ai_reasoning = %s,
                triage_status = %s,
                triaged_at = NOW()
            WHERE id = %s
            """,
            (
                result.get("is_real_threat"),
                result.get("severity"),
                result.get("mitre_technique_id"),
                result.get("confidence"),
                result.get("reasoning"),
                status,
                alert_id,
            ),
        )


def get_all_alerts(limit: int = 1000) -> list:
    """Return all alerts (triaged and pending), most recent first."""
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT %s",
            (limit,),
        )
        return cur.fetchall()


def get_summary_stats() -> dict:
    """Aggregate counts used for the dashboard KPI row (today = last 24h)."""
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') AS total_today,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND is_real_threat = TRUE) AS real_threats_today,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND is_real_threat = FALSE) AS false_positives_today,
                COUNT(*) FILTER (WHERE triage_status = 'pending') AS pending_triage
            FROM alerts
            """
        )
        return cur.fetchone()
