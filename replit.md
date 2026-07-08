# SOC Sentinel — Security Intelligence Dashboard

## Overview
A Streamlit-based Security Operations Center (SOC) console for triaging
security alerts enriched with MITRE ATT&CK technique tags. Built as a
dark-mode, enterprise-grade dashboard.

## Stack
- Python 3.11
- Streamlit (UI framework)
- Pandas (data processing)
- Plotly (charts)

## Structure
- `app.py` — main Streamlit app (dashboard layout, styling, data logic)
- `data/enriched_alerts.json` — sample alert feed (alert_id, rule_description,
  level, technique_id, agent_name). Replace with real SIEM/enrichment output
  to go live.
- `.streamlit/config.toml` — dark theme + server config

## Running
The "Streamlit Dashboard" workflow runs `streamlit run app.py --server.port 5000`.
It serves on port 5000 (webview).

## Data logic
- `level` (int, e.g. from Wazuh/Sigma-style rules) maps to a `Severity` label
  via `map_severity()`: Critical (≥13), High (≥10), Medium (≥7), Low (≥4), Info (<4).
- `technique_id` is resolved to a friendly name via a local MITRE ATT&CK
  lookup table (`TECHNIQUE_NAMES`); alerts are flagged "enriched" once resolved.
- Data loading is wrapped in `@st.cache_data` for fast reloads.

## Notes
- The alert data is currently a static sample file. To connect a real feed,
  point `DATA_PATH` in `app.py` at a live-updating `enriched_alerts.json`
  (or swap `load_alerts()` for a DB/API call).

## User preferences
None recorded yet.
