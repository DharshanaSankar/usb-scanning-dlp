"""
dashboard/db_helper.py
-------------------------
Shared, Streamlit-cached database accessor used by every dashboard page.

Centralizing this here avoids each page re-implementing its own
`DatabaseManager()` instantiation and lets us apply a single
`st.cache_resource` decorator so all pages reuse the same connection
manager instance within a Streamlit session, rather than re-opening
SQLite connections on every widget interaction.

All pages import `get_db()` from this module rather than constructing
`DatabaseManager` directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Ensure the project root is importable when Streamlit launches
# dashboard/app.py directly (its CWD may differ from the project root).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from database.db import DatabaseManager  # noqa: E402


@st.cache_resource(show_spinner=False)
def get_db() -> DatabaseManager:
    """Return a singleton DatabaseManager shared across the Streamlit session."""
    return DatabaseManager()


def rows_to_dicts(rows) -> list:
    """Convert a list of sqlite3.Row objects into a list of plain dicts."""
    return [dict(row) for row in rows]
