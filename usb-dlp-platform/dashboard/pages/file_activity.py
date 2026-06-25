"""
dashboard/pages/file_activity.py
-----------------------------------
File Activities Page.

Displays every file-level event (CREATE, COPY, MODIFY, DELETE, RENAME)
captured by the File Activity Monitor, with filtering by action type
and file extension, plus summary charts (activity by action type, and
activity volume over time) using Plotly.
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

st.set_page_config(page_title="File Activities", page_icon="📁", layout="wide")

st.title("📁 File Activities")
st.caption("Create, Copy, Modify, Delete, and Rename events on monitored USB devices.")

db = get_db()
events = rows_to_dicts(db.fetch_file_events(limit=2000))

if not events:
    st.info("No file activity has been recorded yet.")
else:
    df = pd.DataFrame(events)
    df["file_size_kb"] = (df["file_size_bytes"] / 1024).round(2)

    # -----------------------------------------------------------------
    # Summary charts
    # -----------------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        action_counts = df["action"].value_counts().reset_index()
        action_counts.columns = ["Action", "Count"]
        fig = px.bar(action_counts, x="Action", y="Count", color="Action", text="Count",
                     title="File Activity by Action Type")
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        ext_counts = df["extension"].fillna("(none)").replace("", "(none)").value_counts().head(10).reset_index()
        ext_counts.columns = ["Extension", "Count"]
        fig2 = px.pie(ext_counts, names="Extension", values="Count", title="Top File Extensions", hole=0.35)
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # -----------------------------------------------------------------
    # Filters + table
    # -----------------------------------------------------------------
    st.subheader("📜 Activity Log")
    col1, col2, col3 = st.columns(3)
    with col1:
        action_filter = st.multiselect(
            "Action", options=sorted(df["action"].unique().tolist()),
            default=sorted(df["action"].unique().tolist()),
        )
    with col2:
        ext_options = sorted(df["extension"].fillna("(none)").replace("", "(none)").unique().tolist())
        ext_filter = st.multiselect("Extension", options=ext_options, default=ext_options)
    with col3:
        search_term = st.text_input("Search filename / path")

    filtered = df[df["action"].isin(action_filter)] if action_filter else df
    filtered = filtered[
        filtered["extension"].fillna("(none)").replace("", "(none)").isin(ext_filter)
    ] if ext_filter else filtered

    if search_term:
        mask = (
            filtered["file_name"].fillna("").str.contains(search_term, case=False)
            | filtered["file_path"].fillna("").str.contains(search_term, case=False)
        )
        filtered = filtered[mask]

    display_df = filtered[[
        "id", "action", "file_name", "extension", "file_size_kb",
        "file_path", "os_user", "timestamp",
    ]].rename(columns={
        "id": "ID", "action": "Action", "file_name": "File Name",
        "extension": "Extension", "file_size_kb": "Size (KB)",
        "file_path": "Path", "os_user": "User", "timestamp": "Timestamp",
    })

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {len(display_df)} of {len(df)} total file events.")
