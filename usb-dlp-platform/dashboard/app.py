"""
dashboard/app.py
-------------------
Secure USB DLP System - Streamlit Dashboard (Home / Overview Page).

Run with:
    streamlit run dashboard/app.py
or via the provided run_dashboard.sh script.

This is the entry point for Streamlit's multi-page app feature; the
`pages/` directory next to this file is auto-discovered by Streamlit
and rendered in the sidebar navigation (USB Devices, File Activities,
Incidents, Risk Reports).

This page itself implements the "Dashboard" page from the specification:
    - Total USB Events
    - Total Files Scanned
    - Total Alerts
    - Risk Distribution (chart)
    - Recent Incidents (table)
    with a real-time auto-refresh control.
"""

from __future__ import annotations

import time

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.db_helper import get_db, rows_to_dicts
from config.settings import settings

# ---------------------------------------------------------------------------
# Page configuration (must be the first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title=settings.dashboard_page_title,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def render_header() -> None:
    st.title("🛡️ Secure USB Monitoring & Data Exfiltration Prevention")
    st.caption(
        f"{settings.app_name} • Phase 1 • v{settings.app_version} • "
        f"Environment: {settings.app_env}"
    )
    st.divider()


def render_kpi_row(summary: dict) -> None:
    """Top-line counters: Total USB Events, Total Files Scanned, Total Alerts, Open Alerts."""
    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total USB Events", summary.get("total_usb_events", 0))
    col2.metric("Total Files Scanned", summary.get("total_files_scanned", 0))
    col3.metric("Total Alerts", summary.get("total_alerts", 0))
    col4.metric("Open Alerts", summary.get("open_alerts", 0))
    col5.metric("Blocked Transfers", summary.get("blocked_transfers", 0))


def render_risk_distribution(distribution: dict) -> None:
    """Pie/bar chart of LOW/MEDIUM/HIGH sensitivity counts using Plotly."""
    st.subheader("📊 Risk Distribution")

    df = pd.DataFrame(
        {"Sensitivity": list(distribution.keys()), "Count": list(distribution.values())}
    )

    if df["Count"].sum() == 0:
        st.info("No files have been scanned yet. Risk distribution will appear here once activity is detected.")
        return

    color_map = {"LOW": "#2ECC71", "MEDIUM": "#F1C40F", "HIGH": "#E74C3C"}

    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(
            df, names="Sensitivity", values="Count",
            color="Sensitivity", color_discrete_map=color_map,
            title="Scanned Files by Sensitivity",
            hole=0.4,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with col2:
        fig_bar = px.bar(
            df, x="Sensitivity", y="Count",
            color="Sensitivity", color_discrete_map=color_map,
            title="File Counts by Sensitivity",
            text="Count",
        )
        fig_bar.update_layout(showlegend=False)
        st.plotly_chart(fig_bar, use_container_width=True)


def render_recent_incidents(incidents: list) -> None:
    """Table of the most recent alerts."""
    st.subheader("🚨 Recent Incidents")

    if not incidents:
        st.success("No incidents recorded yet. The system is clear.")
        return

    df = pd.DataFrame(incidents)
    display_cols = ["timestamp", "alert_type", "severity", "risk_score", "os_user", "file_name", "status"]
    display_cols = [c for c in display_cols if c in df.columns]
    df = df[display_cols].rename(
        columns={
            "timestamp": "Time",
            "alert_type": "Alert Type",
            "severity": "Severity",
            "risk_score": "Risk Score",
            "os_user": "User",
            "file_name": "File",
            "status": "Status",
        }
    )

    def _highlight_severity(val):
        colors = {"HIGH": "background-color: #FDEDEC", "MEDIUM": "background-color: #FEF9E7", "LOW": "background-color: #EAFAF1"}
        return colors.get(val, "")

    styled = df.style.applymap(_highlight_severity, subset=["Severity"]) if "Severity" in df.columns else df
    st.dataframe(styled, use_container_width=True, hide_index=True)


def main() -> None:
    db = get_db()

    render_header()

    with st.sidebar:
        st.header("⚙️ Controls")
        auto_refresh = st.toggle("Real-time auto-refresh", value=True)
        refresh_secs = st.slider(
            "Refresh interval (seconds)", min_value=2, max_value=30,
            value=settings.dashboard_refresh_seconds,
        )
        if st.button("🔄 Refresh now"):
            st.rerun()
        st.divider()
        st.caption("Navigate using the pages listed above (USB Devices, File Activities, Incidents, Risk Reports).")

    summary = db.fetch_dashboard_summary()
    distribution = db.fetch_risk_distribution()
    incidents = rows_to_dicts(db.fetch_recent_incidents(limit=10))

    render_kpi_row(summary)
    st.divider()
    render_risk_distribution(distribution)
    st.divider()
    render_recent_incidents(incidents)

    st.divider()
    st.caption(
        "⚠️ Phase 1 scope: rule-based detection only. No machine learning, "
        "no anomaly detection, no approval workflow. These are planned for Phase 2."
    )

    if auto_refresh:
        time.sleep(refresh_secs)
        st.rerun()


if __name__ == "__main__":
    main()
