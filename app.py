"""
SOC Sentinel — Security Intelligence Dashboard
Enterprise-grade Security Operations Center console built with Streamlit.

Data source: data/enriched_alerts.json
"""

import html
import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# --------------------------------------------------------------------------
# Page configuration
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="SOC Sentinel | Security Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DATA_PATH = Path("data/enriched_alerts.json")

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
            min-width: 720px;
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
        .enriched-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 700;
            background: rgba(34, 211, 238, 0.12);
            color: {ACCENT_CYAN};
            border: 1px solid rgba(34, 211, 238, 0.35);
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
# Data layer
# --------------------------------------------------------------------------
def map_severity(level: int) -> str:
    """Map a numeric alert 'level' to a human-readable Severity label."""
    if level >= 13:
        return "Critical"
    if level >= 10:
        return "High"
    if level >= 7:
        return "Medium"
    if level >= 4:
        return "Low"
    return "Info"


# A small set of MITRE ATT&CK technique IDs get a friendly display name.
# Anything outside this map still renders correctly using the raw ID.
TECHNIQUE_NAMES = {
    "T1059.001": "PowerShell",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1053.005": "Scheduled Task",
    "T1053.003": "Cron Job",
    "T1071.001": "Web Protocols (C2)",
    "T1071.004": "DNS (C2)",
    "T1547.001": "Registry Run Keys",
    "T1218.011": "Rundll32",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1021.002": "SMB/Admin Shares",
    "T1562.001": "Disable Security Tools",
    "T1562.004": "Disable Firewall",
    "T1055": "Process Injection",
    "T1136.001": "Local Account Creation",
    "T1560.001": "Archive via Utility",
    "T1105": "Ingress Tool Transfer",
    "T1558.003": "Kerberoasting",
    "T1558.001": "Golden Ticket",
    "T1505.003": "Web Shell",
    "T1070.001": "Clear Windows Event Logs",
    "T1041": "Exfil Over C2 Channel",
    "T1546.003": "WMI Event Subscription",
    "T1548.003": "Sudo Abuse",
    "T1134": "Access Token Manipulation",
    "T1046": "Network Service Discovery",
    "T1204.002": "Malicious File Execution",
    "T1027": "Obfuscated Files",
    "T1048": "Exfil Over Alt Protocol",
    "T1082": "System Information Discovery",
    "T1078": "Valid Accounts",
    "T1078.003": "Cloud/Local Accounts",
    "T1574.002": "DLL Side-Loading",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1140": "Deobfuscate/Decode",
}


REQUIRED_COLUMNS = {"alert_id", "rule_description", "level", "technique_id"}


@st.cache_data(show_spinner=False)
def load_alerts(path: str, _cache_key: float) -> pd.DataFrame:
    """Load and enrich the alert feed. Cached for fast reloads.

    `_cache_key` (the source file's mtime) is included purely so that
    Streamlit's cache is invalidated whenever the underlying file changes,
    even though the `path` string itself stays the same.
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list) or not raw:
        raise ValueError("Alert feed must be a non-empty JSON array of alert objects.")

    df = pd.DataFrame(raw)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Alert feed is missing required column(s): {', '.join(sorted(missing))}")

    # Coerce/validate the level column instead of letting a single bad value
    # crash the whole dashboard.
    df["level"] = pd.to_numeric(df["level"], errors="coerce")
    invalid_rows = int(df["level"].isna().sum())
    if invalid_rows:
        df = df.dropna(subset=["level"])
    df["level"] = df["level"].astype(int)

    df["alert_id"] = df["alert_id"].astype(str)
    df["rule_description"] = df["rule_description"].astype(str)
    df["technique_id"] = df["technique_id"].astype(str)
    if "agent_name" in df.columns:
        df["agent_name"] = df["agent_name"].astype(str)

    df["Severity"] = df["level"].apply(map_severity)
    df["technique_name"] = df["technique_id"].map(TECHNIQUE_NAMES).fillna(df["technique_id"])
    # A technique is treated as "enriched" once it has a resolved friendly name
    # and/or MITRE mapping — used to flag rows in the table.
    df["is_enriched"] = df["technique_id"].isin(TECHNIQUE_NAMES.keys())
    df.attrs["skipped_rows"] = invalid_rows
    return df


if not DATA_PATH.exists():
    st.error(f"Data file not found: `{DATA_PATH}`. Place your alert feed there and reload.")
    st.stop()

try:
    df = load_alerts(str(DATA_PATH), DATA_PATH.stat().st_mtime)
except (ValueError, KeyError, json.JSONDecodeError) as exc:
    st.error(f"Could not load alert feed `{DATA_PATH}`: {exc}")
    st.stop()

if df.attrs.get("skipped_rows"):
    st.warning(f"Skipped {df.attrs['skipped_rows']} alert(s) with an invalid `level` value.")

# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="soc-header">
        <div>
            <p class="soc-title">🛡️ SOC Sentinel — Alert Triage Console</p>
            <p class="soc-subtitle">MITRE ATT&amp;CK Auto-Tagging · Live Enrichment Pipeline</p>
        </div>
        <div class="status-pill"><span class="status-dot"></span> All Systems Operational</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------------------------------
# KPI Row
# --------------------------------------------------------------------------
total_alerts = len(df)
critical_threats = int((df["Severity"] == "Critical").sum())
pending_triage = int((df["Severity"].isin(["Critical", "High"])).sum())
enrichment_score = round(100 * df["is_enriched"].mean(), 1) if total_alerts else 0.0

kpi_data = [
    ("Total Alerts", f"{total_alerts:,}", ACCENT_CYAN, "Last 24 hours"),
    ("Critical Threats", f"{critical_threats:,}", SEVERITY_STYLE["Critical"]["color"], "Level ≥ 13"),
    ("Pending Triage", f"{pending_triage:,}", SEVERITY_STYLE["High"]["color"], "Critical + High"),
    ("Enrichment Score (%)", f"{enrichment_score:.1f}%", ACCENT_GREEN, "MITRE-tagged coverage"),
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
# Main section — technique bar chart + top affected agents
# --------------------------------------------------------------------------
left_col, right_col = st.columns([1.4, 1], gap="medium")

with left_col:
    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">Top 10 MITRE ATT&CK Techniques</div>
            <div class="panel-subtitle">Ranked by alert volume across the current feed</div>
        """,
        unsafe_allow_html=True,
    )

    technique_counts = (
        df.groupby(["technique_id", "technique_name"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .head(10)
        .sort_values("count")  # ascending for horizontal bar readability
    )
    labels = technique_counts["technique_id"] + " · " + technique_counts["technique_name"]

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

    if "agent_name" in df.columns:
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
    else:
        st.info("No `agent_name` field found in the alert feed.")

    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div style='height:22px'></div>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Data table with conditional formatting
# --------------------------------------------------------------------------
st.markdown(
    """
    <div class="panel">
        <div class="panel-title">Alert Triage Queue</div>
        <div class="panel-subtitle">High severity rows glow red · enriched techniques are tagged</div>
    """,
    unsafe_allow_html=True,
)

table_df = df.sort_values(["level"], ascending=False).reset_index(drop=True)

rows_html = ""
for _, row in table_df.iterrows():
    sev = row["Severity"]
    style = SEVERITY_STYLE[sev]
    is_high_sev = sev in ("Critical", "High")
    row_style = (
        f"box-shadow: inset 3px 0 0 0 {style['color']}, 0 0 14px {style['glow']};"
        if is_high_sev
        else f"box-shadow: inset 3px 0 0 0 {style['color']};"
    )
    enriched_html = (
        '<span class="enriched-badge">✓ Enriched</span>'
        if row["is_enriched"]
        else '<span style="color:#64748B; font-size:12px;">—</span>'
    )
    safe_alert_id = html.escape(str(row["alert_id"]))
    safe_description = html.escape(str(row["rule_description"]))
    safe_technique_id = html.escape(str(row["technique_id"]))
    safe_technique_name = html.escape(str(row["technique_name"]))
    safe_sev = html.escape(str(sev))
    rows_html += f"""
        <tr style="{row_style}">
            <td><code class="tid">{safe_alert_id}</code></td>
            <td>{safe_description}</td>
            <td>{row['level']}</td>
            <td><span class="sev-badge" style="background:{style['glow']}; color:{style['color']}; border:1px solid {style['color']};">{safe_sev}</span></td>
            <td><code class="tid">{safe_technique_id}</code> <span style="color:{TEXT_MUTED}; font-size:12px;">{safe_technique_name}</span></td>
            <td>{enriched_html}</td>
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
                    <th>Level</th>
                    <th>Severity</th>
                    <th>Technique</th>
                    <th>Enrichment</th>
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
