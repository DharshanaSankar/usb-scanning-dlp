"""
dashboard/pages/reports.py
------------------------------
Risk Reports Page.

Aggregated reporting view over the `risk_logs` table: score
distributions, decision breakdown (ALLOW vs BLOCK), top matched rules,
and a time-series of risk scores using Plotly + Pandas, satisfying the
"Risk Reports" page and "Charts: Plotly / Pandas" requirements.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from dashboard.db_helper import get_db, rows_to_dicts  # noqa: E402

st.set_page_config(page_title="Risk Reports", page_icon="📈", layout="wide")

st.title("📈 Risk Reports")
st.caption("Aggregated risk scoring analytics across all scanned files.")

db = get_db()
risk_logs = rows_to_dicts(db.fetch_risk_logs(limit=5000))

if not risk_logs:
    st.info("No risk scoring data available yet. Scan results will appear here once files are transferred.")
else:
    df = pd.DataFrame(risk_logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # -----------------------------------------------------------------
    # KPI row
    # -----------------------------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Files Scanned", len(df))
    col2.metric("Average Risk Score", round(df["risk_score"].mean(), 1))
    col3.metric("Highest Risk Score", int(df["risk_score"].max()))
    col4.metric("Blocked", int((df["decision"] == "BLOCK").sum()))

    st.divider()

    # -----------------------------------------------------------------
    # Score distribution histogram
    # -----------------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        fig_hist = px.histogram(
            df, x="risk_score", nbins=20, color="sensitivity",
            color_discrete_map={"LOW": "#2ECC71", "MEDIUM": "#F1C40F", "HIGH": "#E74C3C"},
            title="Risk Score Distribution",
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    with col2:
        decision_counts = df["decision"].value_counts().reset_index()
        decision_counts.columns = ["Decision", "Count"]
        fig_decision = px.pie(
            decision_counts, names="Decision", values="Count",
            color="Decision", color_discrete_map={"ALLOW": "#2ECC71", "BLOCK": "#E74C3C"},
            title="Policy Decisions", hole=0.4,
        )
        st.plotly_chart(fig_decision, use_container_width=True)

    st.divider()

    # -----------------------------------------------------------------
    # Risk score over time
    # -----------------------------------------------------------------
    st.subheader("📉 Risk Score Trend Over Time")
    if df["timestamp"].notna().any():
        trend_df = df.dropna(subset=["timestamp"]).sort_values("timestamp")
        fig_trend = px.scatter(
            trend_df, x="timestamp", y="risk_score", color="sensitivity",
            color_discrete_map={"LOW": "#2ECC71", "MEDIUM": "#F1C40F", "HIGH": "#E74C3C"},
            hover_data=["file_name", "decision"],
            title="Risk Score by Event Time",
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("Not enough timestamped data to render a trend chart.")

    st.divider()

    # -----------------------------------------------------------------
    # Most frequently matched rules
    # -----------------------------------------------------------------
    st.subheader("🔎 Most Frequently Matched Rules")
    rule_counter: Counter = Counter()
    for raw in df["matched_rules"].dropna():
        try:
            rules = json.loads(raw)
            for rule in rules:
                # Strip the "(+N)" suffix for cleaner grouping in the chart.
                rule_name = rule.split("(")[0]
                rule_counter[rule_name] += 1
        except (json.JSONDecodeError, TypeError):
            continue

    if rule_counter:
        rules_df = pd.DataFrame(rule_counter.items(), columns=["Rule", "Occurrences"]).sort_values(
            "Occurrences", ascending=False
        )
        fig_rules = px.bar(rules_df, x="Rule", y="Occurrences", text="Occurrences", title="Rule Trigger Frequency")
        st.plotly_chart(fig_rules, use_container_width=True)
    else:
        st.info("No rules have been triggered yet.")

    st.divider()

    # -----------------------------------------------------------------
    # Full data table + CSV export
    # -----------------------------------------------------------------
    st.subheader("📋 Full Risk Log")
    display_df = df[[
        "id", "timestamp", "file_name", "sensitivity", "risk_score",
        "decision", "os_user", "matched_rules",
    ]].rename(columns={
        "id": "ID", "timestamp": "Time", "file_name": "File",
        "sensitivity": "Sensitivity", "risk_score": "Risk Score",
        "decision": "Decision", "os_user": "User", "matched_rules": "Matched Rules",
    })
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    csv_bytes = display_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Risk Report (CSV)", data=csv_bytes,
        file_name="risk_report.csv", mime="text/csv",
    )
