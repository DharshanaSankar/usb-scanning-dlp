"""
dashboard/pages/incidents.py
-------------------------------
Incidents Page.

Displays every alert raised by the Alert Engine, with filtering by
severity/status/type, and allows analysts to acknowledge or resolve
alerts directly from the dashboard (updates `alerts.status` via
DatabaseManager.update_alert_status).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.db_helper import get_db, rows_to_dicts  # noqa: E402

st.set_page_config(page_title="Incidents", page_icon="🚨", layout="wide")

st.title("🚨 Incidents")
st.caption("Alerts raised by the Policy and Alert Engines for sensitive-data transfers and blocked actions.")

db = get_db()
alerts = rows_to_dicts(db.fetch_alerts(limit=2000))

if not alerts:
    st.success("No incidents recorded. The system is currently clear.")
else:
    df = pd.DataFrame(alerts)

    # -----------------------------------------------------------------
    # KPI row
    # -----------------------------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Alerts", len(df))
    col2.metric("Open", int((df["status"] == "OPEN").sum()))
    col3.metric("High Severity", int((df["severity"] == "HIGH").sum()))
    col4.metric("Blocked Transfers", int((df["alert_type"] == "TRANSFER_BLOCKED").sum()))

    st.divider()

    # -----------------------------------------------------------------
    # Severity breakdown chart
    # -----------------------------------------------------------------
    severity_counts = df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    color_map = {"LOW": "#2ECC71", "MEDIUM": "#F1C40F", "HIGH": "#E74C3C"}
    fig = px.bar(
        severity_counts, x="Severity", y="Count", color="Severity",
        color_discrete_map=color_map, text="Count", title="Alerts by Severity",
    )
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # -----------------------------------------------------------------
    # Filters
    # -----------------------------------------------------------------
    st.subheader("📋 Incident List")
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.multiselect(
            "Severity", options=["LOW", "MEDIUM", "HIGH"], default=["LOW", "MEDIUM", "HIGH"]
        )
    with col2:
        status_filter = st.multiselect(
            "Status", options=["OPEN", "ACKNOWLEDGED", "RESOLVED"],
            default=["OPEN", "ACKNOWLEDGED", "RESOLVED"],
        )
    with col3:
        type_filter = st.multiselect(
            "Alert Type", options=sorted(df["alert_type"].unique().tolist()),
            default=sorted(df["alert_type"].unique().tolist()),
        )

    filtered = df[
        df["severity"].isin(severity_filter)
        & df["status"].isin(status_filter)
        & df["alert_type"].isin(type_filter)
    ]

    display_df = filtered[[
        "id", "timestamp", "alert_type", "severity", "risk_score",
        "os_user", "file_name", "status", "message",
    ]].rename(columns={
        "id": "Alert ID", "timestamp": "Time", "alert_type": "Type",
        "severity": "Severity", "risk_score": "Risk Score",
        "os_user": "User", "file_name": "File", "status": "Status",
        "message": "Details",
    })

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(display_df)} of {len(df)} total incidents.")

    st.divider()

    # -----------------------------------------------------------------
    # Manual alert status update
    # -----------------------------------------------------------------
    st.subheader("✅ Update Alert Status")
    open_alerts = df[df["status"] != "RESOLVED"]
    if open_alerts.empty:
        st.info("No open or acknowledged alerts to update.")
    else:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            options = [
                f"{row['id']} — {row['alert_type']} — {row['file_name'] or 'N/A'}"
                for _, row in open_alerts.iterrows()
            ]
            selected = st.selectbox("Select alert", options=options)
        with col2:
            new_status = st.selectbox("New status", options=["ACKNOWLEDGED", "RESOLVED"])
        with col3:
            st.write("")
            st.write("")
            if st.button("Apply", use_container_width=True):
                alert_id = selected.split(" — ")[0]
                success = db.update_alert_status(alert_id, new_status)
                if success:
                    st.success(f"Alert {alert_id} updated to {new_status}.")
                    st.rerun()
                else:
                    st.error("Failed to update alert status.")
