"""
SOC Sentinel — Security Intelligence Dashboard
Enterprise-grade Security Operations Center console built with Streamlit.

Pipeline this dashboard sits on top of:
    1. Raw alerts arrive via `wazuh_fetcher.py` (live Wazuh) or
       `load_sample_alerts.py` (sample data) and land as PENDING rows in
       Postgres (see `database.py`).
    2. `ai_triage.py` classifies each pending alert with the OpenAI API:
       real threat vs. false positive, severity, and MITRE ATT&CK technique.
    3. This app (`app.py`) reads the triaged alerts straight from Postgres
       and renders the SOC console below.

Data source: Postgres `alerts` table (see database.py). Requires
DATABASE_URL, provided automatically by Replit's built-in database.
"""

import html
import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import database

# --------------------------------------------------------------------------
# Page configuration
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Sentinel | Security Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

MITRE_DATA_PATH = Path("mitre_data.json")
REFRESH_TTL_SECONDS = 15

# --------------------------------------------------------------------------
# Theme / palette
# --------------------------------------------------------------------------
BG_COLOR = "#0E1117"
CARD_COLOR = "#1F2937"
CARD_BORDER = "#2D3748"
TEXT_MUTED = "#94A3B8"
TEXT_MAIN = "#E2E8F0"
ACCENT_CYAN = "#22D3EE"
ACCENT_GREEN = "#34D399"
ACCENT_RED = "#FF3B5C"

SEVERITY_STYLE = {
    "Critical": {"color": "#FF3B5C", "glow": "rgba(255, 59, 92, 0.55)"},
    "High": {"color": "#FF8A3D", "glow": "rgba(255, 138, 61, 0.45)"},
    "Medium": {"color": "#FFD23D", "glow": "rgba(255, 210, 61, 0.35)"},
    "Low": {"color": "#22D3EE", "glow": "rgba(34, 211, 238, 0.3)"},
    "Info": {"color": "#94A3B8", "glow": "rgba(148, 163, 184, 0.2)"},
}

# --------------------------------------------------------------------------
# Custom CSS injection — dark theme, rounded cards, glow, responsive table
# --------------------------------------------------------------------------
st.markdown(
    f"""
    <style>
        .stApp {{
            background-color: {BG_COLOR};
            color: {TEXT_MAIN};
        }}
        #MainMenu, footer, header {{ visibility: hidden; }}
        .block-container {{
            padding-top: 1.6rem;
            padding-bottom: 2rem;
            max-width: 1400px;
        }}

        /* ---- Header ---- */
        .soc-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 26px;
            border-radius: 16px;
            background: linear-gradient(135deg, #16202E 0%, #101826 100%);
            border: 1px solid {CARD_BORDER};
            box-shadow: 0 8px 24px rgba(0,0,0,0.35);
            margin-bottom: 22px;
        }}
        .soc-title {{
            font-size: 26px;
            font-weight: 800;
            letter-spacing: 0.5px;
            color: {TEXT_MAIN};
            margin: 0;
        }}
        .soc-subtitle {{
            font-size: 13px;
            color: {TEXT_MUTED};
            margin-top: 2px;
        }}
        .status-pill {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(52, 211, 153, 0.12);
            border: 1px solid rgba(52, 211, 153, 0.4);
            padding: 8px 16px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 600;
            color: {ACCENT_GREEN};
        }}
        .status-dot {{
            width: 9px;
            height: 9px;
            border-radius: 50%;
            background: {ACCENT_GREEN};
            box-shadow: 0 0 8px 2px {ACCENT_GREEN};
            animation: pulse 1.8s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.35; }}
            100% {{ opacity: 1; }}
        }}

        /* ---- KPI Cards ---- */
        .kpi-card {{
            background: {CARD_COLOR};
            border: 1px solid {CARD_BORDER};
            border-radius: 16px;
            padding: 18px 20px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.30);
            transition: transform 0.15s ease, box-shadow 0.15s ease;
        }}
        .kpi-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 26px rgba(0,0,0,0.45);
        }}
        .kpi-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: {TEXT_MUTED};
            margin-bottom: 8px;
        }}
        .kpi-value {{
            font-size: 32px;
            font-weight: 800;
            line-height: 1;
        }}
        .kpi-foot {{
            margin-top: 10px;
            font-size: 12px;
            color: {TEXT_MUTED};
        }}

        /* ---- Section panels ---- */
        .panel {{
            background: {CARD_COLOR};
            border: 1px solid {CARD_BORDER};
            border-radius: 16px;
            padding: 20px 22px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.30);
            height: 100%;
        }}
        .panel-title {{
            font-size: 15px;
            font-weight: 700;
            color: {TEXT_MAIN};
            margin-bottom: 4px;
        }}
        .panel-subtitle {{
            font-size: 12px;
            color: {TEXT_MUTED};
            margin-bottom: 14px;
        }}

        /* ---- Agent list ---- */
        .agent-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 12px;
            border-radius: 10px;
            background: rgba(255,255,255,0.02);
            border: 1px solid {CARD_BORDER};
            margin-bottom: 8px;
        }}
        .agent-name {{
            font-size: 13px;
            font-weight: 600;
            color: {TEXT_MAIN};
        }}
        .agent-bar-bg {{
            flex: 1;
            margin: 0 12px;
            height: 6px;
            background: rgba(255,255,255,0.06);
            border-radius: 6px;
            overflow: hidden;
        }}
        .agent-bar-fg {{
            height: 100%;
            border-radius: 6px;
            background: linear-gradient(90deg, {ACCENT_CYAN}, #6366F1);
        }}
        .agent-count {{
            font-size: 13px;
            font-weight: 700;
            color: {TEXT_MUTED};
            min-width: 26px;
            text-align: right;
        }}

        /* ---- Data table ---- */
        .table-wrapper {{
            overflow-x: auto;
            border-radius: 14px;
            border: 1px solid {CARD_BORDER};
        }}
        table.soc-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            min-width: 760px;
        }}
        table.soc-table thead th {{
            text-align: left;
            padding: 12px 14px;
            background: #161E2C;
            color: {TEXT_MUTED};
            text-transform: uppercase;
            letter-spacing: 0.6px;
            font-size: 11px;
            position: sticky;
            top: 0;
        }}
        table.soc-table tbody td {{
            padding: 11px 14px;
            border-top: 1px solid {CARD_BORDER};
            color: {TEXT_MAIN};
        }}
        table.soc-table tbody tr:hover {{
            background: rgba(255,255,255,0.03);
        }}
        .sev-badge {{
            display: inline-block;
            padding: 4px 11px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }}
        .verdict-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 700;
        }}
        code.tid {{
            background: rgba(255,255,255,0.06);
            padding: 2px 6px;
            border-radius: 6px;
            font-size: 12px;
            color: {ACCENT_CYAN};
        }}
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------
# Data layer — reads triaged alerts straight from Postgres
# --------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_mitre_data(_cache_key: float) -> dict:
    """Load the local MITRE ATT&CK technique reference table.

    Maps technique_id -> {"name", "tactic", "description", ...}.
    """
    if not MITRE_DATA_PATH.exists():
        return {}
    with open(MITRE_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


MITRE_DATA = load_mitre_data(MITRE_DATA_PATH.stat().st_mtime if MITRE_DATA_PATH.exists() else 0)
TECHNIQUE_NAMES = {tid: info.get("name", tid) for tid, info in MITRE_DATA.items()}


@st.cache_data(ttl=REFRESH_TTL_SECONDS, show_spinner=False)
def load_alerts() -> pd.DataFrame:
    """Load all alerts from Postgres, most recent first."""
    rows = database.get_all_alerts(limit=1000)
    df = pd.DataFrame(rows)
    return df


@st.cache_data(ttl=REFRESH_TTL_SECONDS, show_spinner=False)
def load_summary() -> dict:
    return database.get_summary_stats()


try:
    database.init_schema()
    df = load_alerts()
    summary = load_summary()
except Exception as exc:  # noqa: BLE001 — surface any DB connectivity issue clearly
    st.error(
        "Could not connect to the database. Make sure the Postgres database is "
        f"provisioned and reachable.\n\nDetails: {exc}"
    )
    st.stop()

if df.empty:
    st.warning(
        "No alerts in the database yet. Run `python load_sample_alerts.py` to load sample data, "
        "then `python ai_triage.py` to classify it (requires the `OPENAI_API_KEY` secret)."
    )
    st.stop()

df["level"] = pd.to_numeric(df["level"], errors="coerce").fillna(0).astype(int)
df["severity_display"] = df["severity"].fillna("Pending")

# `is_real_threat` comes back from Postgres as Python/NumPy bool or None; normalize
# to a plain nullable boolean so `is True` / `is False` comparisons behave correctly
# everywhere below (avoids numpy.bool_ identity pitfalls and NaN-is-truthy bugs).
df["is_real_threat"] = df["is_real_threat"].apply(lambda v: bool(v) if pd.notna(v) else None)

# `mitre_technique_id` may be None/NaN (pending/failed rows) or "" (AI found no
# match) — treat both as "no technique" rather than relying on truthiness, which
# would let NaN render as the literal string "nan".
df["has_technique"] = df["mitre_technique_id"].apply(lambda v: pd.notna(v) and str(v).strip() != "")
df["mitre_technique_id"] = df["mitre_technique_id"].where(df["has_technique"], "")
df["technique_name"] = df["mitre_technique_id"].map(TECHNIQUE_NAMES).fillna(df["mitre_technique_id"])
df["technique_name"] = df["technique_name"].where(df["has_technique"], "—")

pending_count = int((df["triage_status"] == "pending").sum())
failed_count = int((df["triage_status"] == "failed").sum())

# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="soc-header">
        <div>
            <p class="soc-title">🛡️ SOC Sentinel — AI-Powered Alert Triage</p>
            <p class="soc-subtitle">MITRE ATT&amp;CK Auto-Tagging · OpenAI Triage · Live Postgres Pipeline</p>
        </div>
        <div class="status-pill"><span class="status-dot"></span> All Systems Operational</div>
    </div>
    """,
    unsafe_allow_html=True,
)

if pending_count:
    st.info(
        f"{pending_count} alert(s) are awaiting AI triage. Run `python ai_triage.py` to classify them."
    )
if failed_count:
    st.warning(f"{failed_count} alert(s) failed AI triage (check OPENAI_API_KEY / logs) and were skipped.")

# --------------------------------------------------------------------------
# KPI Row — today's totals, real threats vs. false positives
# --------------------------------------------------------------------------
total_today = int(summary.get("total_today") or 0)
real_threats_today = int(summary.get("real_threats_today") or 0)
false_positives_today = int(summary.get("false_positives_today") or 0)
db_pending = int(summary.get("pending_triage") or 0)

kpi_data = [
    ("Total Alerts (24h)", f"{total_today:,}", ACCENT_CYAN, "Ingested in the last 24 hours"),
    ("Real Threats (24h)", f"{real_threats_today:,}", ACCENT_RED, "AI-confirmed real threats"),
    ("False Positives (24h)", f"{false_positives_today:,}", ACCENT_GREEN, "AI-dismissed as benign"),
    ("Pending Triage", f"{db_pending:,}", SEVERITY_STYLE["Medium"]["color"], "Awaiting AI classification"),
]

kpi_cols = st.columns(4, gap="medium")
for col, (label, value, color, foot) in zip(kpi_cols, kpi_data):
    with col:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">{label}</div>
                <div class="kpi-value" style="color:{color};">{value}</div>
                <div class="kpi-foot">{foot}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Main section — top MITRE tactics/techniques + top affected agents
# --------------------------------------------------------------------------
left_col, right_col = st.columns([1.4, 1], gap="medium")

triaged_df = df[df["has_technique"]]

with left_col:
    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">Top MITRE ATT&CK Techniques</div>
            <div class="panel-subtitle">Ranked by AI-classified alert volume</div>
        """,
        unsafe_allow_html=True,
    )

    if triaged_df.empty:
        st.info("No AI-classified techniques yet.")
    else:
        technique_counts = (
            triaged_df.groupby(["mitre_technique_id", "technique_name"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(10)
            .sort_values("count")  # ascending for horizontal bar readability
        )
        labels = technique_counts["mitre_technique_id"] + " · " + technique_counts["technique_name"]

        fig = go.Figure(
            go.Bar(
                x=technique_counts["count"],
                y=labels,
                orientation="h",
                marker=dict(
                    color=technique_counts["count"],
                    colorscale=[[0, "#22D3EE"], [1, "#FF3B5C"]],
                    line=dict(width=0),
                ),
                hovertemplate="%{y}<br>Alerts: %{x}<extra></extra>",
                text=technique_counts["count"],
                textposition="outside",
                textfont=dict(color=TEXT_MAIN, size=11),
            )
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color=TEXT_MUTED, size=12),
            margin=dict(l=0, r=20, t=6, b=6),
            height=360,
            xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.06)", zeroline=False),
            yaxis=dict(showgrid=False),
            showlegend=False,
        )
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    st.markdown("</div>", unsafe_allow_html=True)

with right_col:
    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">Top Affected Agents</div>
            <div class="panel-subtitle">Hosts generating the most alerts</div>
        """,
        unsafe_allow_html=True,
    )

    agent_counts = df["agent_name"].value_counts().head(6)
    max_count = int(agent_counts.max()) if len(agent_counts) else 1
    rows_html = ""
    for agent, count in agent_counts.items():
        pct = int(100 * count / max_count)
        safe_agent = html.escape(str(agent))
        rows_html += f"""
        <div class="agent-row">
            <span class="agent-name">🖥️ {safe_agent}</span>
            <div class="agent-bar-bg"><div class="agent-bar-fg" style="width:{pct}%;"></div></div>
            <span class="agent-count">{count}</span>
        </div>
        """
    st.markdown(rows_html, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Alert triage queue — table + click-through detail
# --------------------------------------------------------------------------
st.markdown(
    """
    <div class="panel">
        <div class="panel-title">Alert Triage Queue</div>
        <div class="panel-subtitle">Real threats glow red · click a row below the table for full AI + MITRE detail</div>
    """,
    unsafe_allow_html=True,
)

table_df = df.sort_values(["created_at"], ascending=False).reset_index(drop=True)

rows_html = ""
for _, row in table_df.iterrows():
    sev = row["severity_display"]
    style = SEVERITY_STYLE.get(sev, SEVERITY_STYLE["Info"])
    is_real_threat = row["is_real_threat"] is True
    row_style = (
        f"box-shadow: inset 3px 0 0 0 {ACCENT_RED}, 0 0 14px rgba(255,59,92,0.35);"
        if is_real_threat
        else f"box-shadow: inset 3px 0 0 0 {style['color']};"
    )
    if row["triage_status"] == "pending":
        verdict_html = '<span class="verdict-badge" style="background:rgba(148,163,184,0.15); color:#94A3B8;">Pending</span>'
    elif row["triage_status"] == "failed":
        verdict_html = '<span class="verdict-badge" style="background:rgba(255,138,61,0.15); color:#FF8A3D;">Triage Failed</span>'
    elif is_real_threat:
        verdict_html = '<span class="verdict-badge" style="background:rgba(255,59,92,0.15); color:#FF3B5C;">Real Threat</span>'
    else:
        verdict_html = '<span class="verdict-badge" style="background:rgba(52,211,153,0.15); color:#34D399;">False Positive</span>'

    safe_id = html.escape(str(row["source_alert_id"])[:8])
    safe_description = html.escape(str(row["rule_description"]))
    safe_agent = html.escape(str(row["agent_name"]))
    safe_technique_id = html.escape(str(row["mitre_technique_id"]) if row["has_technique"] else "—")
    safe_technique_name = html.escape(str(row["technique_name"]))
    safe_sev = html.escape(str(sev))
    rows_html += f"""
        <tr style="{row_style}">
            <td><code class="tid">{safe_id}</code></td>
            <td>{safe_description}</td>
            <td>{safe_agent}</td>
            <td>{row['level']}</td>
            <td><span class="sev-badge" style="background:{style['glow']}; color:{style['color']}; border:1px solid {style['color']};">{safe_sev}</span></td>
            <td><code class="tid">{safe_technique_id}</code> <span style="color:{TEXT_MUTED}; font-size:12px;">{safe_technique_name}</span></td>
            <td>{verdict_html}</td>
        </tr>
    """

st.markdown(
    f"""
    <div class="table-wrapper">
        <table class="soc-table">
            <thead>
                <tr>
                    <th>Alert ID</th>
                    <th>Rule Description</th>
                    <th>Agent</th>
                    <th>Level</th>
                    <th>Severity</th>
                    <th>Technique</th>
                    <th>Verdict</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("</div>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Click-through detail — expandable per-alert AI + MITRE breakdown
# --------------------------------------------------------------------------
st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)
st.markdown('<div class="panel"><div class="panel-title">Alert Detail</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="panel-subtitle">Pick an alert to see the full AI verdict and MITRE ATT&CK context</div>',
    unsafe_allow_html=True,
)

option_labels = {
    int(row["id"]): f"{str(row['source_alert_id'])[:8]} · {row['rule_description'][:60]}"
    for _, row in table_df.iterrows()
}
selected_id = st.selectbox(
    "Select an alert",
    options=list(option_labels.keys()),
    format_func=lambda i: option_labels[i],
    label_visibility="collapsed",
)

selected = table_df[table_df["id"] == selected_id].iloc[0]
detail_col1, detail_col2 = st.columns([1, 1.4], gap="large")

with detail_col1:
    st.markdown(f"**Rule description**  \n{selected['rule_description']}")
    st.markdown(f"**Agent**  \n{selected['agent_name']}")
    st.markdown(f"**Raw level**  \n{selected['level']}")
    st.markdown(f"**Triage status**  \n{selected['triage_status']}")
    if selected["raw_log"]:
        st.code(selected["raw_log"], language="text")

with detail_col2:
    if selected["triage_status"] == "triaged":
        verdict = "Real Threat" if selected["is_real_threat"] else "False Positive"
        st.markdown(f"**AI verdict**  \n{verdict}  (confidence: {selected['ai_confidence']}%)")
        st.markdown(f"**AI severity**  \n{selected['severity']}")
        st.markdown(f"**AI reasoning**  \n{selected['ai_reasoning']}")

        tid = selected["mitre_technique_id"]
        if tid and tid in MITRE_DATA:
            info = MITRE_DATA[tid]
            st.markdown(f"**MITRE technique**  \n`{tid}` — {info.get('name', '')}")
            st.markdown(f"**Tactic**  \n{info.get('tactic', '—')}")
            if info.get("description"):
                st.markdown(f"**Description**  \n{info['description']}")
            if info.get("sub_techniques"):
                st.markdown("**Sub-techniques**  \n" + ", ".join(info["sub_techniques"]))
            if info.get("mitigations"):
                st.markdown("**Suggested mitigations**  \n" + ", ".join(info["mitigations"]))
        else:
            st.markdown("**MITRE technique**  \nNo technique matched for this alert.")
    else:
        st.info("This alert hasn't been AI-triaged yet. Run `python ai_triage.py`.")

st.markdown("</div>", unsafe_allow_html=True)
