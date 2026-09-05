"""
app.py

The investigator-facing dashboard. Reuses the original LinkMirror X
visual theme (dimmed background GIF, dark panel styling, Poppins font)
and adds matplotlib charts for scores and the threat correlation graph.

Run with:
    streamlit run app.py
    (or: py -m streamlit run app.py   on Windows if the streamlit
     command itself isn't on PATH)
"""

from __future__ import annotations
import os
import sys
import tempfile
import base64

import streamlit as st
import matplotlib.pyplot as plt
import networkx as nx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from case.case_manager import process_email, Case
from correlation.correlation_engine import (
    CaseIndicators, build_threat_graph, find_shared_infrastructure
)
from intelligence.domain_intel import lookup_ip
from reporting.report_generator import generate_case_report

st.set_page_config(page_title="LinkMirror Forensics", page_icon="🪞", layout="wide")

SEVERITY_COLOR = {"high": "#ef5350", "warning": "#fb8c00", "info": "#2979FF"}
VERDICT_COLOR_MAP = {"green": "#2e7d32", "red": "#ef5350", "orange": "#fb8c00", "blue": "#1976d2"}

# ---------------------------
# Original LinkMirror X background + theme (reused as-is)
# ---------------------------
def set_bg_gif(gif_file: str):
    if not os.path.exists(gif_file):
        return
    with open(gif_file, "rb") as f:
        data = f.read()
    data_url = base64.b64encode(data).decode("utf-8")
    st.markdown(
        f"""
        <style>
        [data-testid="stAppViewContainer"] {{
            background: linear-gradient(rgba(0,0,0,0.55), rgba(0,0,0,0.55)),
                        url("data:image/gif;base64,{data_url}");
            background-size: cover;
            background-position: center;
        }}
        [data-testid="stHeader"], [data-testid="stToolbar"] {{
            background: transparent;
        }}
        [data-testid="stSidebar"] > div:first-child {{
            background: rgba(10,10,25,0.75);
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

set_bg_gif(os.path.join(os.path.dirname(__file__), "linkmirror_bg.gif"))

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Poppins', sans-serif; color: #dbe9ff; }
    .header {
      position: relative; padding: 18px; overflow: hidden;
      background: linear-gradient(90deg, #081426, #071a2b);
      border-radius: 12px; margin-bottom: 14px; border: 1px solid rgba(41,121,255,0.12);
    }
    .header-title { font-size:28px; color:#2979FF; font-weight:700; }
    .header-sub { color: #9fbbe8; font-size:14px; }
    .panel {
      background:#071026; padding:12px 16px; border-radius:10px;
      border:1px solid rgba(41,121,255,0.06); margin-bottom:10px;
    }
    .finding-box { padding:10px 14px; border-radius:6px; margin-bottom:6px; background:#0b1a2b; }
    .verdict-box { padding:14px; border-radius:8px; color:white; font-weight:600; }
    .small-muted { color:#9fbbe8; font-size:13px; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="header">
      <span style="font-size:40px; margin-right:10px;">🪞</span>
      <span class="header-title">LinkMirror Forensics</span><br>
      <span class="header-sub">SIH26106 — AI-assisted email threat detection & forensic investigation</span>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------
# Matplotlib helpers, styled to match the dark theme
# ---------------------------
plt.rcParams.update({
    "figure.facecolor": "#071026",
    "axes.facecolor": "#071026",
    "axes.edgecolor": "#2979FF",
    "text.color": "#dbe9ff",
    "axes.labelcolor": "#dbe9ff",
    "xtick.color": "#9fbbe8",
    "ytick.color": "#9fbbe8",
})


def plot_score_bar(labels, values, title, ylabel="Score"):
    fig, ax = plt.subplots(figsize=(5, 3))
    colors = ["#ef5350" if v >= 70 else "#fb8c00" if v >= 40 else "#2e7d32" for v in values]
    ax.bar(labels, values, color=colors)
    ax.set_ylim(0, 100)
    ax.set_ylabel(ylabel)
    ax.set_title(title, color="#dbe9ff", fontsize=11)
    fig.tight_layout()
    return fig


def plot_severity_breakdown(header_findings):
    counts = {"high": 0, "warning": 0, "info": 0}
    for f in header_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    fig, ax = plt.subplots(figsize=(4, 3))
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [SEVERITY_COLOR[l] for l in labels]
    ax.bar(labels, values, color=colors)
    ax.set_title("Header finding severity", color="#dbe9ff", fontsize=11)
    ax.set_ylabel("Count")
    fig.tight_layout()
    return fig


def plot_threat_graph(graph):
    G = nx.Graph()
    color_map = {"case": "#2979FF", "domain": "#ef5350", "ip": "#fb8c00", "email": "#9fbbe8"}
    node_colors = []
    for n in graph.nodes:
        G.add_node(n.id, label=n.label, type=n.type)
        node_colors.append(color_map.get(n.type, "#888"))
    for e in graph.edges:
        G.add_edge(e.source, e.target)

    fig, ax = plt.subplots(figsize=(7, 5))
    if len(G.nodes) == 0:
        ax.text(0.5, 0.5, "No data yet", ha="center", va="center", color="#dbe9ff")
        ax.axis("off")
        return fig

    pos = nx.spring_layout(G, seed=42, k=0.9)
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#2979FF", alpha=0.4, width=1.2)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=500, edgecolors="#0b1a2b")
    labels = {n: G.nodes[n]["label"] for n in G.nodes}
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=8, font_color="#dbe9ff")
    ax.set_title("Threat graph — shared infrastructure", color="#dbe9ff", fontsize=12)
    ax.axis("off")
    fig.tight_layout()
    return fig


# ---------------------------
# Session state
# ---------------------------
if "cases" not in st.session_state:
    st.session_state.cases: list[Case] = []


def add_case_from_path(path: str, display_name: str):
    try:
        case = process_email(path)
        st.session_state.cases.append(case)
        st.success(f"Processed: {display_name}")
    except Exception as e:
        st.error(f"Failed to process {display_name}: {e}")


# ---------------------------
# Sidebar
# ---------------------------
st.sidebar.markdown("### Load cases")
demo_dir = os.path.join(os.path.dirname(__file__), "demo_data", "emails")
if os.path.isdir(demo_dir) and st.sidebar.button("Load all 5 demo emails"):
    for fname in sorted(os.listdir(demo_dir)):
        if fname.endswith(".eml"):
            add_case_from_path(os.path.join(demo_dir, fname), fname)

st.sidebar.markdown("### Upload your own email")
uploaded = st.sidebar.file_uploader("Upload .eml file", type=["eml"])
if uploaded is not None and st.sidebar.button("Process uploaded email"):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded.getvalue())
        tmp_path = tmp.name
    add_case_from_path(tmp_path, uploaded.name)

if st.session_state.cases and st.sidebar.button("Clear all cases"):
    st.session_state.cases = []
    st.rerun()

if not st.session_state.cases:
    st.markdown("<div class='panel'>No cases loaded yet. Use the sidebar to load the demo dataset or upload an email.</div>", unsafe_allow_html=True)
    st.stop()

tab_overview, tab_cases, tab_graph = st.tabs(
    ["📋 Overview", "🔍 Case details", "🕸 Threat graph"]
)

# ---------------------------
# Overview tab
# ---------------------------
with tab_overview:
    st.markdown(f"<div class='panel'><b>{len(st.session_state.cases)} case(s) loaded</b></div>", unsafe_allow_html=True)

    labels = [c.case_id for c in st.session_state.cases]
    fused_scores = [
        max((ua.result.fused for ua in c.url_analyses), default=0)
        for c in st.session_state.cases
    ]
    st.pyplot(plot_score_bar(labels, fused_scores, "Fused trust score by case (lower = more suspicious)"))

    for case in st.session_state.cases:
        color = SEVERITY_COLOR.get(case.highest_severity, "#888")
        st.markdown(
            f"<div class='panel' style='border-left:4px solid {color};'>"
            f"<b>{case.parsed.subject}</b><br>"
            f"<span class='small-muted'>From: {case.parsed.from_address} &middot; "
            f"Case ID: {case.case_id} &middot; Severity: {case.highest_severity.upper()}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

# ---------------------------
# Case details tab
# ---------------------------
with tab_cases:
    case_labels = [f"{c.parsed.subject} ({c.case_id})" for c in st.session_state.cases]
    selected_idx = st.selectbox("Select a case", range(len(case_labels)), format_func=lambda i: case_labels[i])
    case = st.session_state.cases[selected_idx]

    st.markdown(f"### {case.parsed.subject}")
    col1, col2 = st.columns(2)
    with col1:
        st.write("**From (display name):**", case.parsed.from_display_name)
        st.write("**From (address):**", case.parsed.from_address)
        st.write("**Reply-To:**", case.parsed.reply_to or "(none)")
    with col2:
        st.write("**Date:**", case.parsed.date)
        st.write("**Attachments:**", len(case.parsed.attachments))

    colA, colB = st.columns(2)
    with colA:
        st.pyplot(plot_severity_breakdown(case.header_findings))
    with colB:
        if case.url_analyses:
            ua_labels = [f"URL {i+1}" for i in range(len(case.url_analyses))]
            ua_scores = [ua.result.fused for ua in case.url_analyses]
            st.pyplot(plot_score_bar(ua_labels, ua_scores, "Fused score per URL"))

    st.markdown("#### Header forensics findings")
    for f in case.header_findings:
        color = SEVERITY_COLOR.get(f.severity, "#888")
        st.markdown(
            f"<div class='finding-box' style='border-left:3px solid {color};'>"
            f"<b>{f.severity.upper()}</b> — {f.message}</div>",
            unsafe_allow_html=True,
        )

    st.markdown("#### Extracted indicators")
    st.write("**URLs:**", case.indicators.urls or "(none)")
    st.write("**Domains:**", case.indicators.domains or "(none)")
    st.write("**IPs:**", case.indicators.ips or "(none)")

    if case.indicators.ips:
        st.markdown("#### Infrastructure intelligence")
        for ip in case.indicators.ips:
            intel = lookup_ip(ip)
            demo_tag = " (synthetic demo data)" if intel.is_demo else ""
            st.write(f"**{ip}** — {intel.org}, {intel.country}{demo_tag}")

    st.markdown("#### LinkMirror engine verdicts")
    for ua in case.url_analyses:
        color_hex = VERDICT_COLOR_MAP.get(ua.result.verdict_color, "#1976d2")
        st.markdown(f"**{ua.url}**")
        st.markdown(f"<div class='verdict-box' style='background:{color_hex};'>{ua.result.verdict}</div>", unsafe_allow_html=True)
        with st.expander("Why this verdict"):
            for r in ua.result.verdict_reasons:
                st.write("-", r)

    st.markdown("#### Forensic report")
    case_indicators_all = [
        CaseIndicators(case_id=c.case_id, label=c.parsed.subject, indicators=c.indicators)
        for c in st.session_state.cases
    ]
    shared_map = find_shared_infrastructure(case_indicators_all)
    shared_with = []
    for indicator, case_ids in shared_map.items():
        if case.case_id in case_ids:
            shared_with.extend(
                c.parsed.subject for c in st.session_state.cases
                if c.case_id in case_ids and c.case_id != case.case_id
            )
    shared_with = list(dict.fromkeys(shared_with))  # dedupe, keep order

    report_text = generate_case_report(case, shared_with=shared_with or None)
    st.download_button(
        "Download forensic report (.md)",
        data=report_text,
        file_name=f"forensic_report_{case.case_id}.md",
        mime="text/markdown",
    )
    with st.expander("Preview report"):
        st.markdown(report_text)

# ---------------------------
# Threat graph tab
# ---------------------------
with tab_graph:
    case_indicators = [
        CaseIndicators(case_id=c.case_id, label=c.parsed.subject, indicators=c.indicators)
        for c in st.session_state.cases
    ]
    shared = find_shared_infrastructure(case_indicators)
    graph = build_threat_graph(case_indicators)

    st.pyplot(plot_threat_graph(graph))

    if not shared:
        st.markdown("<div class='panel'>No shared infrastructure found across the currently loaded cases.</div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div class='panel' style='border-left:4px solid #ef5350;'>Found {len(shared)} indicator(s) shared across multiple cases — possible campaign.</div>", unsafe_allow_html=True)
        for indicator, case_ids in shared.items():
            matching_subjects = [c.parsed.subject for c in st.session_state.cases if c.case_id in case_ids]
            st.markdown(f"**{indicator}** shared by:")
            for subj in matching_subjects:
                st.write("  -", subj)
