"""
dashboard/pages/blocked_devices.py
-------------------------------------
Blocked Devices Page.

Surfaces, at the device level, which USB devices have had one or more
file transfers BLOCKED by the Policy Engine (risk_score > threshold).

This view answers a different question than the Incidents page:
    - Incidents page  -> "What alerts have fired?" (file/event-centric)
    - Blocked Devices  -> "Which physical USB devices are risky?"
                           (device-centric rollup)

Data is derived by joining risk_logs (decision='BLOCK') -> file_events
-> usb_events, using DatabaseManager.fetch_blocked_device_summary() and
fetch_blocked_transfers(), which require no schema changes since the
foreign-key chain linking these three tables already exists.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.db_helper import get_db, rows_to_dicts  # noqa: E402

st.set_page_config(page_title="Blocked Devices", page_icon="🚫", layout="wide")

st.title("🚫 Blocked Devices")
st.caption("USB devices that have had one or more file transfers blocked by the Policy Engine.")

db = get_db()
device_summary = rows_to_dicts(db.fetch_blocked_device_summary())
blocked_transfers = rows_to_dicts(db.fetch_blocked_transfers(limit=2000))

if not device_summary:
    st.success("✅ No blocked transfers recorded. No USB device has triggered a BLOCK decision yet.")
else:
    summary_df = pd.DataFrame(device_summary)

    # -----------------------------------------------------------------
    # KPI row
    # -----------------------------------------------------------------
    col1, col2, col3 = st.columns(3)
    col1.metric("Devices with Blocked Transfers", len(summary_df))
    col2.metric("Total Blocked Transfers", int(summary_df["blocked_count"].sum()))
    col3.metric("Highest Risk Score Seen", int(summary_df["max_risk_score"].max()))

    st.divider()

    # -----------------------------------------------------------------
    # Device-level cards / table
    # -----------------------------------------------------------------
    st.subheader("📟 Devices Currently Flagged")

    currently_connected_serials = set(
        row["serial_number"] for row in rows_to_dicts(db.fetch_usb_events(limit=1000))
        if row["event_type"] == "INSERTED"
    ) - set(
        row["serial_number"] for row in rows_to_dicts(db.fetch_usb_events(limit=1000))
        if row["event_type"] == "REMOVED"
    )

    for _, row in summary_df.iterrows():
        is_connected = row["serial_number"] in currently_connected_serials
        status_badge = "🔌 Currently Connected" if is_connected else "⏏️ Not Connected"

        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
            with c1:
                st.markdown(f"**{row['device_name']}**")
                st.caption(f"Serial: `{row['serial_number']}`")
            with c2:
                st.metric("Blocked Transfers", int(row["blocked_count"]))
            with c3:
                st.metric("Max Risk Score", int(row["max_risk_score"]))
            with c4:
                st.markdown(status_badge)
                st.caption(f"Last blocked: {row['last_blocked_at']}")

    st.divider()

    # -----------------------------------------------------------------
    # Chart: blocked transfers per device
    # -----------------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        chart_df = summary_df.rename(columns={"device_name": "Device", "blocked_count": "Blocked Transfers"})
        fig = px.bar(
            chart_df, x="Device", y="Blocked Transfers", text="Blocked Transfers",
            color="Blocked Transfers", color_continuous_scale="Reds",
            title="Blocked Transfers by Device",
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        fig2 = px.bar(
            chart_df, x="Device", y="max_risk_score" if "max_risk_score" in summary_df.columns else "Blocked Transfers",
            title="Highest Risk Score by Device",
            labels={"max_risk_score": "Max Risk Score"},
            color_discrete_sequence=["#E74C3C"],
        )
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # -----------------------------------------------------------------
    # Full blocked-transfer log (file-level detail, joined with device)
    # -----------------------------------------------------------------
    st.subheader("📋 Blocked Transfer Log")

    if not blocked_transfers:
        st.info("No individual blocked transfer records found.")
    else:
        detail_df = pd.DataFrame(blocked_transfers)

        device_filter = st.multiselect(
            "Filter by device",
            options=sorted(detail_df["device_name"].fillna("Unknown Device").unique().tolist()),
            default=sorted(detail_df["device_name"].fillna("Unknown Device").unique().tolist()),
        )
        filtered = detail_df[detail_df["device_name"].fillna("Unknown Device").isin(device_filter)]

        display_cols = [
            "timestamp", "device_name", "serial_number", "file_name",
            "risk_score", "sensitivity", "os_user", "matched_rules",
        ]
        display_cols = [c for c in display_cols if c in filtered.columns]
        display_df = filtered[display_cols].rename(columns={
            "timestamp": "Time", "device_name": "Device", "serial_number": "Serial",
            "file_name": "File", "risk_score": "Risk Score", "sensitivity": "Sensitivity",
            "os_user": "User", "matched_rules": "Matched Rules",
        })

        st.dataframe(display_df, use_container_width=True, hide_index=True)
        st.caption(f"Showing {len(display_df)} of {len(detail_df)} blocked transfer records.")

        csv_bytes = display_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Blocked Transfers (CSV)", data=csv_bytes,
            file_name="blocked_transfers.csv", mime="text/csv",
        )