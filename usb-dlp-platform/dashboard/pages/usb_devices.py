"""
dashboard/pages/usb_devices.py
---------------------------------
USB Devices Page.

Lists every USB insertion/removal event recorded in the `usb_events`
table, with filtering by event type and a derived "currently connected"
view (devices whose most recent event is INSERTED with no later
REMOVED for the same serial number).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.db_helper import get_db, rows_to_dicts  # noqa: E402

st.set_page_config(page_title="USB Devices", page_icon="💾", layout="wide")

st.title("💾 USB Devices")
st.caption("All detected USB storage device insertion and removal events.")

db = get_db()
events = rows_to_dicts(db.fetch_usb_events(limit=1000))

if not events:
    st.info("No USB events have been recorded yet. Insert a USB device while the agent is running to see data here.")
else:
    df = pd.DataFrame(events)

    # -----------------------------------------------------------------
    # Currently connected devices (latest event per serial == INSERTED)
    # -----------------------------------------------------------------
    st.subheader("🔌 Currently Connected Devices")
    latest_per_serial = (
        df.sort_values("id", ascending=False)
        .drop_duplicates(subset=["serial_number"], keep="first")
    )
    connected = latest_per_serial[latest_per_serial["event_type"] == "INSERTED"]

    if connected.empty:
        st.info("No USB devices are currently connected.")
    else:
        st.dataframe(
            connected[["device_name", "vendor_id", "product_id", "serial_number", "mount_path", "timestamp"]]
            .rename(columns={
                "device_name": "Device Name", "vendor_id": "Vendor ID",
                "product_id": "Product ID", "serial_number": "Serial Number",
                "mount_path": "Mount Path", "timestamp": "Connected At",
            }),
            use_container_width=True, hide_index=True,
        )

    st.divider()

    # -----------------------------------------------------------------
    # Filters
    # -----------------------------------------------------------------
    st.subheader("📜 Full Event History")
    col1, col2 = st.columns(2)
    with col1:
        event_filter = st.multiselect(
            "Filter by event type", options=["INSERTED", "REMOVED"], default=["INSERTED", "REMOVED"]
        )
    with col2:
        search_term = st.text_input("Search device name / serial number")

    filtered = df[df["event_type"].isin(event_filter)] if event_filter else df
    if search_term:
        mask = (
            filtered["device_name"].fillna("").str.contains(search_term, case=False)
            | filtered["serial_number"].fillna("").str.contains(search_term, case=False)
        )
        filtered = filtered[mask]

    display_df = filtered[[
        "id", "event_type", "device_name", "vendor_id", "product_id",
        "serial_number", "mount_path", "platform", "timestamp",
    ]].rename(columns={
        "id": "ID", "event_type": "Event", "device_name": "Device Name",
        "vendor_id": "Vendor ID", "product_id": "Product ID",
        "serial_number": "Serial Number", "mount_path": "Mount Path",
        "platform": "Platform", "timestamp": "Timestamp",
    })

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(display_df)} of {len(df)} total events.")
