"""
Database package for the Secure USB DLP System.

Exposes the `DatabaseManager` class (see db.py), which is the single
gateway through which the agent and dashboard read/write SQLite data.
"""

from database.db import DatabaseManager  # noqa: F401
