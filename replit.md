# SOC Sentinel — AI-Powered Alert Triage System

## Overview
A Streamlit-based Security Operations Center (SOC) console that triages
security alerts using OpenAI and auto-tags them with MITRE ATT&CK
techniques. Built end-to-end: raw alert ingestion → AI triage → MITRE
enrichment → Postgres storage → live dashboard.

## Pipeline
1. **Ingest** — raw (pre-AI) alerts land in Postgres as `pending` rows, from either:
   - `wazuh_fetcher.py` — pulls real alerts from a live Wazuh Indexer (OpenSearch REST API). Requires `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` env vars.
   - `load_sample_alerts.py` — generates realistic sample alerts (SSH brute force, suspicious process execution, port scans, privilege escalation, etc.) via `generate_sample_alerts.py` and loads them directly. Use this since Replit cannot run Docker/a local Wazuh manager.
2. **AI Triage** — `ai_triage.py` reads pending alerts and calls the OpenAI API (`gpt-4o-mini`) with a senior-SOC-analyst prompt. For each alert it returns: real-threat verdict, severity, best-matching MITRE ATT&CK technique ID, confidence, and a short reasoning string. Requires the `OPENAI_API_KEY` secret — **not currently set**; add it in the Secrets pane to enable triage (until then, alerts stay in `pending`).
3. **MITRE Enrichment** — `mitre_attack_fetcher.py` downloads the official MITRE ATT&CK Enterprise STIX bundle and distills it into `mitre_data.json` (technique → name, tactic, description, sub-techniques, mitigations). The dashboard and `ai_triage.py` read this local file; re-run the fetcher occasionally to pick up MITRE dataset updates.
4. **Storage** — `database.py` holds all Postgres access (schema, insert, triage update, summary stats) against Replit's built-in PostgreSQL database (`DATABASE_URL`).
5. **Dashboard** — `app.py` reads directly from Postgres: KPI row (24h totals, real threats, false positives, pending triage), top MITRE techniques chart, top affected agents, a full alert queue table, and a click-through detail panel per alert (AI reasoning + MITRE technique/tactic/mitigations).

## Structure
- `app.py` — Streamlit dashboard (reads from Postgres via `database.py`)
- `database.py` — Postgres schema + query helpers (`alerts` table)
- `ai_triage.py` — OpenAI-powered alert classification
- `wazuh_fetcher.py` — live Wazuh Indexer ingestion (optional, requires real Wazuh)
- `generate_sample_alerts.py` / `load_sample_alerts.py` — sample data generator + loader (no live Wazuh needed)
- `mitre_attack_fetcher.py` — builds `mitre_data.json` from the official MITRE ATT&CK STIX dataset
- `mitre_data.json` — generated MITRE ATT&CK Enterprise reference table (697 techniques)
- `.streamlit/config.toml` — dark theme + server config

## Running
- The "Streamlit Dashboard" workflow runs `streamlit run app.py --server.port 5000` (port 5000, webview).
- To (re)populate data: `python load_sample_alerts.py --count 30` then `python ai_triage.py` (needs `OPENAI_API_KEY`).
- To refresh the MITRE reference table: `python mitre_attack_fetcher.py`.

## Known limitations
- Replit cannot run Docker/containers, so a real local Wazuh-in-Docker setup isn't possible here. `wazuh_fetcher.py` works against a real *external* Wazuh Indexer if the user has one; otherwise use the sample generator.
- `OPENAI_API_KEY` is intentionally left unset in this project (public/shared project) — the user adds it privately via the Secrets pane when they want AI triage to run. Until set, alerts stay `pending` and the dashboard shows a banner instead of AI results.

## User preferences
- This is a public project — never hardcode or request the OpenAI API key to be filled into chat/code; the user adds `OPENAI_API_KEY` privately via Replit Secrets on their own.
