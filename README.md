# 🛡️ SOC Sentinel — AI-Powered Alert Triage with MITRE ATT&CK Auto-Tagging

![Preview of this project](docs/screenshots/Gemini_Generated_Image_824our824our824o.png)

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B)
![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-1BA0D7)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![OpenAI](https://img.shields.io/badge/AI-OpenAI%20GPT--4o--mini-412991)

A fully operational SOC triage console that ingests live alerts from a **Wazuh** SIEM deployment, classifies each alert as a **real threat or false positive** using an **OpenAI LLM**, auto-tags it with its **MITRE ATT&CK** technique, and surfaces everything in a dark-mode **Streamlit** dashboard — built for fast analyst triage.

Deployed and tested end-to-end on a live Wazuh instance (Azure VM), ingesting real alert traffic with 11,893+ alerts processed.

---

## 📸 Screenshots

**SOC Sentinel — KPI Overview & Top Techniques**

![SOC Sentinel dashboard overview](docs/screenshots/Screenshot_6.png)
*Live KPI cards (total alerts, real threats, false positives, pending triage), top-10 MITRE ATT&CK techniques by volume, and top affected agents — running against a real Wazuh feed.*

**Alert Triage Queue**

![Alert triage queue table](docs/screenshots/Screenshot_5.png)
*Full alert table with severity badges, AI verdict badges, and MITRE technique tags. Real threats glow red — false positives stay muted.*

**Single Alert Detail Panel**

![Single alert detail](docs/screenshots/Screenshot_4.png)
*Per-alert detail: AI verdict, confidence score, reasoning, MITRE technique name + tactic + description, sub-techniques, and suggested mitigations.*

**Underlying Wazuh Source Feed**

![Wazuh Threat Hunting dashboard](docs/screenshots/Screenshot_2.png)
*Wazuh's native Threat Hunting view — the raw SIEM feed SOC Sentinel ingests, re-classifies with AI, and re-presents in a triage-focused UI.*

---

## 🚨 Problem

SOC analysts spend a disproportionate amount of time staring at raw alert queues — walls of rule descriptions and severity numbers with no framework context and no distinction between real threats and noise. Studies estimate **70–80% of SIEM alerts are false positives**, yet each one must be manually reviewed.

**SOC Sentinel** addresses this at two levels:

1. **AI classification** — an LLM acts as a first-pass analyst, deciding whether each alert is a genuine threat or a false positive, with a confidence score and written reasoning.
2. **MITRE enrichment** — every alert is tagged with its ATT&CK technique ID and name, so analysts immediately know *what adversary behavior* the alert represents, not just which rule fired.

---

## ⚙️ Architecture

```
┌─────────────────────┐     ┌──────────────────────┐
│   Wazuh Indexer     │     │   Sample Generator   │
│  (OpenSearch API)   │     │  (offline/dev mode)  │
└──────────┬──────────┘     └──────────┬───────────┘
           │                           │
           └─────────────┬─────────────┘
                         ▼
              ┌─────────────────────┐
              │     database.py     │  ← PostgreSQL `alerts` table
              │    (PostgreSQL)     │      status: pending
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │     ai_triage.py    │  ← OpenAI GPT-4o-mini
              │   (AI classifier)   │      is_real_threat, severity,
              │                     │      mitre_technique_id,
              │                     │      confidence, reasoning
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  mitre_data.json    │  ← Local MITRE ATT&CK lookup
              │  (697 techniques)   │      name, tactic, description,
              │                     │      sub-techniques, mitigations
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │       app.py        │  ← Streamlit dark-mode dashboard
              │    (Dashboard)      │
              └─────────────────────┘
```

---

## ✨ Key Features

### AI-Powered Triage (`ai_triage.py`)
- Prompts OpenAI GPT-4o-mini with a senior SOC analyst persona
- Returns structured JSON: `is_real_threat`, `severity`, `mitre_technique_id`, `confidence`, `reasoning`
- Validates all fields defensively — malformed responses are caught, logged, and marked `failed` without crashing the batch
- Batch processing with per-row failure isolation

### MITRE ATT&CK Enrichment
- Local reference table of **697 techniques** from the official MITRE ATT&CK Enterprise STIX bundle
- Every AI-classified alert is enriched with: technique name, tactic, full description, sub-techniques, and suggested mitigations
- No external API call at render time — all lookups are local

### Streamlit Dashboard (`app.py`)
- **KPI row** — total alerts (24h), real threats, false positives, pending triage
- **Top 10 MITRE ATT&CK Techniques** — horizontal Plotly bar chart ranked by alert volume
- **Top Affected Agents** — ranked host list with gradient bars
- **Alert Triage Queue** — full HTML table; real threats have a red left-border glow, false positives are muted
- **Detail Panel** — click any alert for full AI reasoning, confidence score, MITRE technique details, and mitigations

### Dual Ingestion Mode
- **Live mode** — `wazuh_fetcher.py` queries a Wazuh Indexer (OpenSearch REST API) and loads raw alerts into PostgreSQL
- **Offline mode** — `generate_sample_alerts.py` + `load_sample_alerts.py` generate realistic synthetic events (SSH brute force, suspicious PowerShell, port scans, privilege escalation) without needing a live SIEM

---

## 🗂️ Repository Structure

```
.
├── app.py                      # Streamlit dashboard
├── ai_triage.py                # OpenAI classification engine
├── database.py                 # PostgreSQL schema, insert & query helpers
├── wazuh_fetcher.py            # Live Wazuh Indexer ingestion
├── mitre_attack_fetcher.py     # Downloads & compiles MITRE STIX bundle
├── generate_sample_alerts.py   # Realistic synthetic alert generator
├── load_sample_alerts.py       # Wrapper: generate + insert into DB
├── config.py                   # API key + model config
├── mitre_data.json             # Cached MITRE ATT&CK lookup (697 techniques)
├── data/
│   └── enriched_alerts.json    # Static alert snapshot (legacy/fallback)
├── .streamlit/
│   └── config.toml             # Dark theme + server settings
└── pyproject.toml / uv.lock    # Dependencies
```

---

## 🗃️ Database Schema

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | Internal row ID |
| `source_alert_id` | varchar unique | Alert ID from Wazuh or sample generator |
| `rule_description` | text | Human-readable rule that fired |
| `level` | int | Wazuh numeric severity (1–15) |
| `agent_name` | varchar | Hostname that generated the alert |
| `raw_log` | jsonb | Full raw alert payload |
| `is_real_threat` | boolean | AI verdict |
| `severity` | varchar | AI-assigned label (Critical / High / Medium / Low / Info) |
| `mitre_technique_id` | varchar | Best-matching ATT&CK technique (e.g. `T1110`) |
| `ai_confidence` | float | Model confidence score (0.0–1.0) |
| `ai_reasoning` | text | LLM explanation of the verdict |
| `triage_status` | varchar | `pending` / `triaged` / `failed` |
| `created_at` | timestamp | Alert ingestion time |
| `triaged_at` | timestamp | AI classification time |

---

## 🧰 Tech Stack

| Layer | Tool |
|-------|------|
| SIEM source | Wazuh (Indexer / OpenSearch REST API) |
| AI classification | OpenAI GPT-4o-mini |
| Threat framework | MITRE ATT&CK Enterprise (local JSON, 697 techniques) |
| Database | PostgreSQL + psycopg2-binary |
| Data processing | Pandas |
| Dashboard | Streamlit |
| Charts | Plotly |
| Language | Python 3.11 |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- PostgreSQL running locally or via a managed service
- OpenAI API key
- *(Optional)* A Wazuh Indexer for live alert ingestion

### 1. Clone and install

```bash
git clone https://github.com/tareksec/-AI-Powered-Alert-Triage-System-with-MITRE-ATT-CK-Auto-Tagging.git
cd -AI-Powered-Alert-Triage-System-with-MITRE-ATT-CK-Auto-Tagging
pip install -r requirements.txt   # or: uv sync
```

### 2. Configure environment variables

```bash
export OPENAI_API_KEY="sk-..."
export DATABASE_URL="postgresql://user:password@localhost:5432/soc_sentinel"

# Only needed for live Wazuh ingestion:
export WAZUH_INDEXER_URL="https://<your-wazuh-host>:9200"
export WAZUH_INDEXER_USER="admin"
export WAZUH_INDEXER_PASSWORD="your-password"
```

### 3. Option A — Run with sample data (no Wazuh needed)

```bash
# Generate and load realistic synthetic alerts into PostgreSQL
python load_sample_alerts.py

# Run AI triage on pending alerts
python ai_triage.py

# Launch the dashboard
streamlit run app.py --server.port 8501
```

### 4. Option B — Run with live Wazuh data

```bash
# Pull live alerts from your Wazuh Indexer into PostgreSQL
python wazuh_fetcher.py --output data/enriched_alerts.json --size 500 --min-level 3

# Run AI triage on pending alerts
python ai_triage.py

# Launch the dashboard
streamlit run app.py --server.port 8501
```

Open `http://localhost:8501` in your browser.

---

## 📊 Severity Mapping

| Wazuh `level` | Severity |
|---------------|----------|
| ≥ 13 | Critical |
| ≥ 10 | High |
| ≥ 7 | Medium |
| ≥ 4 | Low |
| < 4 | Info |

---

## 🗺️ Roadmap

- [ ] Replace OpenAI with self-hosted DeepSeek R1 for cost-free, privacy-preserving triage
- [ ] Live alert polling (scheduled `wazuh_fetcher.py` via cron or APScheduler)
- [ ] Alert deduplication and near-duplicate clustering before AI classification
- [ ] Automatic mitigation recommendation export (per MITRE technique)
- [ ] Docker Compose for one-command Wazuh + PostgreSQL + dashboard spin-up
- [ ] Human-in-the-loop approval gate for any auto-remediation actions

---

## ⚠️ Known Limitations

- `wazuh_fetcher.py` must be run manually — no live polling yet (roadmap item)
- OpenAI API key must be set by the user — not included in the repo
- No alert deduplication before AI classification — near-identical alerts are sent as separate requests
- No automated remediation actions — the system classifies and advises, but does not act

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
