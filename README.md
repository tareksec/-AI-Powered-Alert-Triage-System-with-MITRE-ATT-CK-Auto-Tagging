# 🛡️ SOC Sentinel — AI-Powered Alert Triage with MITRE ATT&CK Auto-Tagging

A Security Operations Center (SOC) console that ingests raw security alerts, classifies each one with **OpenAI (gpt-4o-mini)** as a real threat or false positive, auto-tags real threats with the matching **MITRE ATT&CK** technique, and renders everything in a live, dark-mode Streamlit dashboard — backed end-to-end by PostgreSQL.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B)
![OpenAI](https://img.shields.io/badge/OpenAI-gpt--4o--mini-412991)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-336791)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
## Demo

![SOC Sentinel Dashboard](docs/screenshots/Screenshot_6.png)
*Live triage queue with MITRE ATT&CK auto-tagging, running against a real Wazuh SIEM feed.*

![Wazuh source data](docs/screenshots/Screenshot_2.png)
*Underlying Wazuh Threat Hunting view — 11,893 alerts, brute-force/SSH activity mapped to MITRE ATT&CK.*

---

## Problem

SOC analysts spend a huge chunk of their day manually deciding whether an alert is a real threat or noise — one third of the average SOC workday goes to investigating alerts that turn out to be false positives. Most alert-triage tools stop at severity (Critical/High/Medium/Low), leaving the analyst to figure out *what kind of attack* they're actually looking at.

**SOC Sentinel** goes a step further: every alert is classified by an LLM acting as a senior SOC analyst, and every confirmed real threat is auto-tagged with its **MITRE ATT&CK technique ID** — so the analyst knows immediately what adversary behavior to investigate (e.g. `T1059` — Command and Scripting Interpreter), not just how urgent it looks.

## What it does

- **Ingests raw alerts** from a live Wazuh SIEM (via the Indexer's REST API) or from a synthetic sample generator, and lands them in PostgreSQL as `pending`
- **Classifies each alert with OpenAI** (`gpt-4o-mini`) using a structured, senior-SOC-analyst prompt that returns a strict JSON verdict: real threat vs. false positive, severity, MITRE technique ID, confidence score, and a one-to-two sentence justification
- **Enriches MITRE technique IDs** into human-readable names, tactics, and mitigations using a locally-cached copy of the official MITRE ATT&CK Enterprise dataset — no external API call needed at render time
- **Serves a live dashboard** that queries PostgreSQL directly on every load: KPI cards, a top-techniques chart, top affected agents, and a full triage queue

## Architecture

```
                 ┌─────────────────────┐
Wazuh Indexer ──▶│ wazuh_fetcher.py     │──┐
(OpenSearch API) └─────────────────────┘  │
                                            ├──▶ database.insert_raw_alert()
                 ┌─────────────────────┐  │        │
Sample data ────▶│ load_sample_alerts.py│──┘        ▼
generator        └─────────────────────┘   PostgreSQL `alerts` table
                                             (triage_status = 'pending')
                                                     │
                                                     ▼
                                            ai_triage.py
                                            ├─ database.get_pending_alerts()
                                            ├─ OpenAI (gpt-4o-mini) verdict
                                            └─ database.save_triage_result()
                                                     │
                                          (same row updated in place,
                                           triage_status = 'triaged')
                                                     │
                                                     ▼
                                            app.py (Streamlit)
                                            ├─ database.get_all_alerts()
                                            └─ database.get_summary_stats()
                                                     │
                                                     ▼
                                          SOC Sentinel Dashboard
```

MITRE ATT&CK enrichment (`mitre_attack_fetcher.py` → `mitre_data.json`) runs independently and is consulted by both `ai_triage.py` (to validate technique IDs) and `app.py` (to resolve technique names/tactics for display).

## Tech Stack

| Layer | Tool |
|---|---|
| SIEM data source | Wazuh (Indexer / OpenSearch REST API) — or synthetic sample alerts |
| Database | PostgreSQL |
| AI classification | OpenAI API (`gpt-4o-mini`) |
| Threat framework data | MITRE ATT&CK Enterprise (official STIX dataset, cached locally) |
| Dashboard | Streamlit + Plotly |

## Repo structure

```
.
├── app.py                      # Streamlit dashboard — queries Postgres live, renders UI
├── database.py                 # All Postgres access: schema, insert, fetch, save-triage, stats
├── ai_triage.py                 # Pulls pending alerts, classifies via OpenAI, writes verdicts back
├── config.py                    # OPENAI_API_KEY + model name
├── wazuh_fetcher.py              # Pulls alerts from a live Wazuh Indexer into Postgres
├── load_sample_alerts.py         # Generates/loads synthetic alerts into Postgres for demo/testing
├── generate_sample_alerts.py     # Synthetic alert generator used by load_sample_alerts.py
├── mitre_attack_fetcher.py       # Builds mitre_data.json from the official MITRE ATT&CK STIX bundle
├── mitre_data.json               # Local technique_id -> {name, tactic, ...} lookup table
├── .streamlit/                   # Dark theme + server config
└── pyproject.toml / uv.lock      # Dependencies
```

## Database schema (`alerts` table, via `database.py`)

Key columns include: `source_alert_id`, `rule_description`, `level`, `agent_name`, `raw_log`, `triage_status` (`pending` / `triaged` / `failed`), `is_real_threat`, `severity`, `mitre_technique_id`, `ai_confidence`, `ai_reasoning`.

| Function | Purpose |
|---|---|
| `init_schema()` | Creates the `alerts` table + indexes if missing |
| `insert_raw_alert(alert)` | Inserts one pending raw alert, deduplicated on `source_alert_id` |
| `get_pending_alerts(limit=200)` | Fetches untriaged rows for `ai_triage.py` |
| `save_triage_result(alert_id, result, status)` | Writes the AI's verdict onto an existing row |
| `get_all_alerts(limit=1000)` | Fetches everything (pending + triaged) for the dashboard |
| `get_summary_stats()` | Aggregate query for the KPI counts |

## Getting Started

### 1. Clone and install

```bash
git clone https://github.com/tareksec/-AI-Powered-Alert-Triage-System-with-MITRE-ATT-CK-Auto-Tagging.git
cd -AI-Powered-Alert-Triage-System-with-MITRE-ATT-CK-Auto-Tagging
pip install -r requirements.txt   # or: uv sync
```

### 2. Configure secrets

Set your PostgreSQL connection string as an environment variable:

```bash
export DATABASE_URL="postgresql://user:password@host:port/dbname"
```

Add your OpenAI API key to `config.py`:

```python
OPENAI_API_KEY = "sk-..."   # never commit a real key — use an env var or secrets manager in production
MODEL_NAME = "gpt-4o"
```

> ⚠️ `config.py` currently holds the key as a plain string for local/demo use. For any real deployment, replace this with an environment variable (`os.environ["OPENAI_API_KEY"]`) or your platform's secrets manager, and make sure `config.py` is in `.gitignore` if it ever contains a real key.

### 3. Load alerts

Either pull from a live Wazuh Indexer:

```bash
export WAZUH_INDEXER_URL="https://localhost:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="your-password"
python wazuh_fetcher.py
```

...or load synthetic sample alerts for a quick demo:

```bash
python load_sample_alerts.py --count 50
```

Both write directly into the Postgres `alerts` table with `triage_status = 'pending'`.

### 4. (Optional) Refresh the MITRE ATT&CK reference data

```bash
python mitre_attack_fetcher.py
```

### 5. Run AI triage

```bash
python ai_triage.py
```

This pulls pending alerts, sends each to OpenAI, and writes the verdict (real threat, severity, MITRE technique, confidence, reasoning) back onto the same row.

### 6. Launch the dashboard

```bash
streamlit run app.py --server.port 5000
```

Open `http://localhost:5000`. The dashboard queries PostgreSQL live (15s cache) — no intermediate file, no manual export step.

## Dashboard features

- **KPI row** — total alerts, confirmed real threats, false positives, pending triage
- **Top MITRE ATT&CK Techniques** — bar chart ranked by alert volume
- **Top Affected Agents** — which hosts are generating the most alerts
- **Alert Triage Queue** — full table with severity badges, real-threat rows highlighted, click-through detail with AI reasoning + MITRE context

## Severity mapping

| Source `level` | Severity |
|---|---|
| ≥ 13 | Critical |
| ≥ 10 | High |
| ≥ 7 | Medium |
| ≥ 4 | Low |
| < 4 | Info |

The AI can also assign severity independently as part of its verdict when a technique's real-world impact doesn't match the raw sensor level.

## Roadmap

- [ ] Mitigation recommendations surfaced per MITRE technique in the detail panel
- [ ] Docker Compose for one-command Wazuh + Postgres + dashboard spin-up
- [ ] Scheduled `wazuh_fetcher.py` + `ai_triage.py` runs (cron) instead of manual invocation
- [ ] Multi-page Streamlit app with a dedicated "Project Details" page

## License

MIT
