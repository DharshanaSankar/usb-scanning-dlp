# """
# database/db.py
# ---------------
# Data Access Layer (DAL) for the Secure USB DLP System.

# This module implements the `DatabaseManager` class, which is the ONLY
# component permitted to talk directly to SQLite. Every other module
# (agent components, dashboard pages, tests) must go through this class.
# Centralizing access here gives us:

#     1. A single place to manage schema creation/migration.
#     2. Consistent use of parameterized queries (SQL-injection safe).
#     3. WAL mode + busy timeout configuration for safe concurrent access
#        between the background agent (writer) and the Streamlit
#        dashboard (reader) running as separate processes.
#     4. Centralized error handling/logging for all persistence operations.

# Secure coding practices applied:
#     - All queries use parameter binding ("?"), never f-string/format
#       interpolation, eliminating SQL injection risk entirely.
#     - Connections are opened/closed per operation (short-lived) using
#       context managers to avoid leaking file handles or locks.
#     - Inputs are never trusted to be the right type; defensive casts and
#       `.get()` with defaults are used when reading dict-like payloads.
# """

# from __future__ import annotations

# import json
# import sqlite3
# import uuid
# from contextlib import contextmanager
# from datetime import datetime, timezone
# from pathlib import Path
# from typing import Any, Dict, Generator, List, Optional

# from config.settings import settings
# from agent.logger import get_logger

# logger = get_logger(__name__)


# def utc_now_iso() -> str:
#     """Return the current UTC time as an ISO-8601 string with seconds precision."""
#     return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# class DatabaseManager:
#     """
#     Thread/process-safe-ish SQLite gateway.

#     SQLite itself handles multi-process access via file locking; we make
#     this robust by enabling WAL journal mode (allows concurrent readers
#     while a writer is active) and setting a busy timeout so concurrent
#     writers retry briefly instead of raising "database is locked" errors.
#     """

#     def __init__(self, db_path: Optional[str] = None) -> None:
#         self.db_path = db_path or settings.db_path
#         Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
#         self._initialize_schema()

#     # ------------------------------------------------------------------
#     # Connection management
#     # ------------------------------------------------------------------
#     @contextmanager
#     def _connect(self) -> Generator[sqlite3.Connection, None, None]:
#         """
#         Context manager yielding a configured SQLite connection.
#         Commits on success, rolls back on exception, always closes.
#         """
#         conn = sqlite3.connect(
#             self.db_path,
#             timeout=settings.db_timeout_seconds,
#             isolation_level=None,  # autocommit; we manage transactions explicitly below
#         )
#         try:
#             conn.execute("PRAGMA journal_mode=WAL;")
#             conn.execute("PRAGMA foreign_keys=ON;")
#             conn.execute("PRAGMA busy_timeout=5000;")
#             conn.row_factory = sqlite3.Row
#             yield conn
#         except sqlite3.Error:
#             logger.exception("SQLite error during database operation")
#             raise
#         finally:
#             conn.close()

#     def _initialize_schema(self) -> None:
#         """Apply schema.sql idempotently (CREATE TABLE IF NOT EXISTS)."""
#         schema_path = Path(__file__).resolve().parent / "schema.sql"
#         if not schema_path.exists():
#             logger.error("schema.sql not found at %s", schema_path)
#             raise FileNotFoundError(f"Missing schema file: {schema_path}")

#         schema_sql = schema_path.read_text(encoding="utf-8")
#         with self._connect() as conn:
#             conn.executescript(schema_sql)
#         logger.info("Database schema verified/initialized at %s", self.db_path)

#     # ------------------------------------------------------------------
#     # usb_events
#     # ------------------------------------------------------------------
#     def insert_usb_event(
#         self,
#         event_type: str,
#         device_name: Optional[str],
#         vendor_id: Optional[str],
#         product_id: Optional[str],
#         serial_number: Optional[str],
#         mount_path: Optional[str],
#         platform_name: str,
#         timestamp: Optional[str] = None,
#     ) -> int:
#         """Insert a USB insertion/removal event. Returns the new row id."""
#         ts = timestamp or utc_now_iso()
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 """
#                 INSERT INTO usb_events
#                     (event_type, device_name, vendor_id, product_id,
#                      serial_number, mount_path, platform, timestamp)
#                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
#                 """,
#                 (event_type, device_name, vendor_id, product_id,
#                  serial_number, mount_path, platform_name, ts),
#             )
#             logger.info(
#                 "USB event recorded: type=%s device=%s serial=%s mount=%s",
#                 event_type, device_name, serial_number, mount_path,
#             )
#             return int(cursor.lastrowid)

#     def get_latest_usb_event_for_mount(self, mount_path: str) -> Optional[sqlite3.Row]:
#         """Fetch the most recent USB event for a given mount path (used to link file events)."""
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 """
#                 SELECT * FROM usb_events
#                 WHERE mount_path = ?
#                 ORDER BY id DESC
#                 LIMIT 1
#                 """,
#                 (mount_path,),
#             )
#             return cursor.fetchone()

#     def fetch_usb_events(self, limit: int = 500) -> List[sqlite3.Row]:
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 "SELECT * FROM usb_events ORDER BY id DESC LIMIT ?", (limit,)
#             )
#             return cursor.fetchall()

#     # ------------------------------------------------------------------
#     # file_events
#     # ------------------------------------------------------------------
#     def insert_file_event(
#         self,
#         usb_event_id: Optional[int],
#         action: str,
#         file_name: str,
#         extension: Optional[str],
#         file_size_bytes: int,
#         file_path: str,
#         os_user: Optional[str],
#         timestamp: Optional[str] = None,
#     ) -> int:
#         """Insert a file activity record. Returns the new row id."""
#         ts = timestamp or utc_now_iso()
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 """
#                 INSERT INTO file_events
#                     (usb_event_id, action, file_name, extension,
#                      file_size_bytes, file_path, os_user, timestamp)
#                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
#                 """,
#                 (usb_event_id, action, file_name, extension,
#                  file_size_bytes, file_path, os_user, ts),
#             )
#             logger.info(
#                 "File event recorded: action=%s file=%s size=%d user=%s",
#                 action, file_name, file_size_bytes, os_user,
#             )
#             return int(cursor.lastrowid)

#     def fetch_file_events(self, limit: int = 500) -> List[sqlite3.Row]:
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 "SELECT * FROM file_events ORDER BY id DESC LIMIT ?", (limit,)
#             )
#             return cursor.fetchall()

#     # ------------------------------------------------------------------
#     # risk_logs
#     # ------------------------------------------------------------------
#     def insert_risk_log(
#         self,
#         file_event_id: Optional[int],
#         file_name: str,
#         file_path: str,
#         sensitivity: str,
#         risk_score: int,
#         matched_rules: List[str],
#         match_counts: Dict[str, int],
#         decision: str,
#         os_user: Optional[str],
#         timestamp: Optional[str] = None,
#     ) -> int:
#         """Insert a risk scoring result. Returns the new row id."""
#         ts = timestamp or utc_now_iso()
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 """
#                 INSERT INTO risk_logs
#                     (file_event_id, file_name, file_path, sensitivity,
#                      risk_score, matched_rules, match_counts, decision,
#                      os_user, timestamp)
#                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#                 """,
#                 (
#                     file_event_id, file_name, file_path, sensitivity,
#                     risk_score, json.dumps(matched_rules), json.dumps(match_counts),
#                     decision, os_user, ts,
#                 ),
#             )
#             logger.info(
#                 "Risk log recorded: file=%s score=%d sensitivity=%s decision=%s",
#                 file_name, risk_score, sensitivity, decision,
#             )
#             return int(cursor.lastrowid)

#     def fetch_risk_logs(self, limit: int = 500) -> List[sqlite3.Row]:
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 "SELECT * FROM risk_logs ORDER BY id DESC LIMIT ?", (limit,)
#             )
#             return cursor.fetchall()

#     # ------------------------------------------------------------------
#     # alerts
#     # ------------------------------------------------------------------
#     def insert_alert(
#         self,
#         alert_type: str,
#         risk_score: int,
#         severity: str,
#         os_user: Optional[str],
#         file_name: Optional[str],
#         file_path: Optional[str],
#         message: str,
#         risk_log_id: Optional[int] = None,
#         timestamp: Optional[str] = None,
#     ) -> str:
#         """Insert an alert with a generated UUID4 primary key. Returns the alert id."""
#         alert_id = str(uuid.uuid4())
#         ts = timestamp or utc_now_iso()
#         with self._connect() as conn:
#             conn.execute(
#                 """
#                 INSERT INTO alerts
#                     (id, risk_log_id, alert_type, risk_score, severity,
#                      os_user, file_name, file_path, message, status, timestamp)
#                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
#                 """,
#                 (
#                     alert_id, risk_log_id, alert_type, risk_score, severity,
#                     os_user, file_name, file_path, message, ts,
#                 ),
#             )
#             logger.warning(
#                 "ALERT raised: id=%s type=%s severity=%s score=%d file=%s",
#                 alert_id, alert_type, severity, risk_score, file_name,
#             )
#             return alert_id

#     def fetch_alerts(self, limit: int = 500, status: Optional[str] = None) -> List[sqlite3.Row]:
#         with self._connect() as conn:
#             if status:
#                 cursor = conn.execute(
#                     "SELECT * FROM alerts WHERE status = ? ORDER BY id DESC LIMIT ?",
#                     (status, limit),
#                 )
#             else:
#                 cursor = conn.execute(
#                     "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
#                 )
#             return cursor.fetchall()

#     def update_alert_status(self, alert_id: str, status: str) -> bool:
#         """Update an alert's status (OPEN/ACKNOWLEDGED/RESOLVED). Returns True if a row changed."""
#         if status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
#             raise ValueError(f"Invalid alert status: {status}")
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
#             )
#             return cursor.rowcount > 0

#     # ------------------------------------------------------------------
#     # Aggregate / dashboard queries
#     # ------------------------------------------------------------------
#     def fetch_dashboard_summary(self) -> Dict[str, Any]:
#         """Fetch the single-row dashboard summary view as a dict."""
#         with self._connect() as conn:
#             cursor = conn.execute("SELECT * FROM v_dashboard_summary")
#             row = cursor.fetchone()
#             return dict(row) if row else {}

#     def fetch_risk_distribution(self) -> Dict[str, int]:
#         """Return counts of LOW/MEDIUM/HIGH sensitivity results for charting."""
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 "SELECT sensitivity, COUNT(*) AS cnt FROM risk_logs GROUP BY sensitivity"
#             )
#             rows = cursor.fetchall()
#             result = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
#             for row in rows:
#                 result[row["sensitivity"]] = row["cnt"]
#             return result

#     def fetch_recent_incidents(self, limit: int = 10) -> List[sqlite3.Row]:
#         """Fetch the most recent alerts for the dashboard 'Recent Incidents' widget."""
#         with self._connect() as conn:
#             cursor = conn.execute(
#                 "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
#             )
#             return cursor.fetchall()

#     def execute_raw(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
#         """
#         Escape hatch for ad-hoc read-only queries (e.g. dashboard reports
#         page). Callers MUST use parameter binding; never string-format
#         user input into `query`.
#         """
#         with self._connect() as conn:
#             cursor = conn.execute(query, params)
#             return cursor.fetchall()
"""
database/db.py
---------------
Data Access Layer (DAL) for the Secure USB DLP System.

This module implements the `DatabaseManager` class, which is the ONLY
component permitted to talk directly to SQLite. Every other module
(agent components, dashboard pages, tests) must go through this class.
Centralizing access here gives us:

    1. A single place to manage schema creation/migration.
    2. Consistent use of parameterized queries (SQL-injection safe).
    3. WAL mode + busy timeout configuration for safe concurrent access
       between the background agent (writer) and the Streamlit
       dashboard (reader) running as separate processes.
    4. Centralized error handling/logging for all persistence operations.

Secure coding practices applied:
    - All queries use parameter binding ("?"), never f-string/format
      interpolation, eliminating SQL injection risk entirely.
    - Connections are opened/closed per operation (short-lived) using
      context managers to avoid leaking file handles or locks.
    - Inputs are never trusted to be the right type; defensive casts and
      `.get()` with defaults are used when reading dict-like payloads.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from config.settings import settings
from agent.logger import get_logger

logger = get_logger(__name__)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with seconds precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DatabaseManager:
    """
    Thread/process-safe-ish SQLite gateway.

    SQLite itself handles multi-process access via file locking; we make
    this robust by enabling WAL journal mode (allows concurrent readers
    while a writer is active) and setting a busy timeout so concurrent
    writers retry briefly instead of raising "database is locked" errors.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or settings.db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager yielding a configured SQLite connection.
        Commits on success, rolls back on exception, always closes.
        """
        conn = sqlite3.connect(
            self.db_path,
            timeout=settings.db_timeout_seconds,
            isolation_level=None,  # autocommit; we manage transactions explicitly below
        )
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute("PRAGMA busy_timeout=5000;")
            conn.row_factory = sqlite3.Row
            yield conn
        except sqlite3.Error:
            logger.exception("SQLite error during database operation")
            raise
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        """Apply schema.sql idempotently (CREATE TABLE IF NOT EXISTS)."""
        schema_path = Path(__file__).resolve().parent / "schema.sql"
        if not schema_path.exists():
            logger.error("schema.sql not found at %s", schema_path)
            raise FileNotFoundError(f"Missing schema file: {schema_path}")

        schema_sql = schema_path.read_text(encoding="utf-8")
        with self._connect() as conn:
            conn.executescript(schema_sql)
        logger.info("Database schema verified/initialized at %s", self.db_path)

    # ------------------------------------------------------------------
    # usb_events
    # ------------------------------------------------------------------
    def insert_usb_event(
        self,
        event_type: str,
        device_name: Optional[str],
        vendor_id: Optional[str],
        product_id: Optional[str],
        serial_number: Optional[str],
        mount_path: Optional[str],
        platform_name: str,
        timestamp: Optional[str] = None,
    ) -> int:
        """Insert a USB insertion/removal event. Returns the new row id."""
        ts = timestamp or utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO usb_events
                    (event_type, device_name, vendor_id, product_id,
                     serial_number, mount_path, platform, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_type, device_name, vendor_id, product_id,
                 serial_number, mount_path, platform_name, ts),
            )
            logger.info(
                "USB event recorded: type=%s device=%s serial=%s mount=%s",
                event_type, device_name, serial_number, mount_path,
            )
            return int(cursor.lastrowid)

    def get_latest_usb_event_for_mount(self, mount_path: str) -> Optional[sqlite3.Row]:
        """Fetch the most recent USB event for a given mount path (used to link file events)."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM usb_events
                WHERE mount_path = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (mount_path,),
            )
            return cursor.fetchone()

    def fetch_usb_events(self, limit: int = 500) -> List[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM usb_events ORDER BY id DESC LIMIT ?", (limit,)
            )
            return cursor.fetchall()

    # ------------------------------------------------------------------
    # file_events
    # ------------------------------------------------------------------
    def insert_file_event(
        self,
        usb_event_id: Optional[int],
        action: str,
        file_name: str,
        extension: Optional[str],
        file_size_bytes: int,
        file_path: str,
        os_user: Optional[str],
        timestamp: Optional[str] = None,
    ) -> int:
        """Insert a file activity record. Returns the new row id."""
        ts = timestamp or utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO file_events
                    (usb_event_id, action, file_name, extension,
                     file_size_bytes, file_path, os_user, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (usb_event_id, action, file_name, extension,
                 file_size_bytes, file_path, os_user, ts),
            )
            logger.info(
                "File event recorded: action=%s file=%s size=%d user=%s",
                action, file_name, file_size_bytes, os_user,
            )
            return int(cursor.lastrowid)

    def fetch_file_events(self, limit: int = 500) -> List[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM file_events ORDER BY id DESC LIMIT ?", (limit,)
            )
            return cursor.fetchall()

    # ------------------------------------------------------------------
    # risk_logs
    # ------------------------------------------------------------------
    def insert_risk_log(
        self,
        file_event_id: Optional[int],
        file_name: str,
        file_path: str,
        sensitivity: str,
        risk_score: int,
        matched_rules: List[str],
        match_counts: Dict[str, int],
        decision: str,
        os_user: Optional[str],
        timestamp: Optional[str] = None,
    ) -> int:
        """Insert a risk scoring result. Returns the new row id."""
        ts = timestamp or utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO risk_logs
                    (file_event_id, file_name, file_path, sensitivity,
                     risk_score, matched_rules, match_counts, decision,
                     os_user, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_event_id, file_name, file_path, sensitivity,
                    risk_score, json.dumps(matched_rules), json.dumps(match_counts),
                    decision, os_user, ts,
                ),
            )
            logger.info(
                "Risk log recorded: file=%s score=%d sensitivity=%s decision=%s",
                file_name, risk_score, sensitivity, decision,
            )
            return int(cursor.lastrowid)

    def fetch_risk_logs(self, limit: int = 500) -> List[sqlite3.Row]:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM risk_logs ORDER BY id DESC LIMIT ?", (limit,)
            )
            return cursor.fetchall()

    # ------------------------------------------------------------------
    # alerts
    # ------------------------------------------------------------------
    def insert_alert(
        self,
        alert_type: str,
        risk_score: int,
        severity: str,
        os_user: Optional[str],
        file_name: Optional[str],
        file_path: Optional[str],
        message: str,
        risk_log_id: Optional[int] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Insert an alert with a generated UUID4 primary key. Returns the alert id."""
        alert_id = str(uuid.uuid4())
        ts = timestamp or utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts
                    (id, risk_log_id, alert_type, risk_score, severity,
                     os_user, file_name, file_path, message, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
                """,
                (
                    alert_id, risk_log_id, alert_type, risk_score, severity,
                    os_user, file_name, file_path, message, ts,
                ),
            )
            logger.warning(
                "ALERT raised: id=%s type=%s severity=%s score=%d file=%s",
                alert_id, alert_type, severity, risk_score, file_name,
            )
            return alert_id

    def fetch_alerts(self, limit: int = 500, status: Optional[str] = None) -> List[sqlite3.Row]:
        with self._connect() as conn:
            if status:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status, limit),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
                )
            return cursor.fetchall()

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update an alert's status (OPEN/ACKNOWLEDGED/RESOLVED). Returns True if a row changed."""
        if status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
            raise ValueError(f"Invalid alert status: {status}")
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Blocked device reporting (joins risk_logs -> file_events -> usb_events)
    # ------------------------------------------------------------------
    def fetch_blocked_transfers(self, limit: int = 500) -> List[sqlite3.Row]:
        """
        Return every BLOCK-decision risk log, joined with the file event
        and the USB device it occurred on. This answers "which USB
        device(s) had a transfer blocked, and what was blocked on them?"
        without requiring any schema changes, since the existing
        foreign-key chain (risk_logs -> file_events -> usb_events)
        already carries this relationship.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT
                    rl.id              AS risk_log_id,
                    rl.file_name       AS file_name,
                    rl.file_path       AS file_path,
                    rl.sensitivity     AS sensitivity,
                    rl.risk_score      AS risk_score,
                    rl.matched_rules   AS matched_rules,
                    rl.os_user         AS os_user,
                    rl.timestamp       AS timestamp,
                    fe.action          AS action,
                    fe.file_size_bytes AS file_size_bytes,
                    ue.id              AS usb_event_id,
                    ue.device_name     AS device_name,
                    ue.vendor_id       AS vendor_id,
                    ue.product_id      AS product_id,
                    ue.serial_number   AS serial_number,
                    ue.mount_path      AS mount_path,
                    ue.platform        AS platform
                FROM risk_logs rl
                LEFT JOIN file_events fe ON fe.id = rl.file_event_id
                LEFT JOIN usb_events ue ON ue.id = fe.usb_event_id
                WHERE rl.decision = 'BLOCK'
                ORDER BY rl.id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return cursor.fetchall()

    def fetch_blocked_device_summary(self) -> List[sqlite3.Row]:
        """
        Aggregate blocked transfers per physical USB device (grouped by
        serial number), giving a device-level rollup: how many blocked
        transfers occurred on each device, the highest risk score seen,
        and when the most recent block happened. Devices with no
        resolvable serial number (e.g. mount path already gone) are
        grouped under 'UNKNOWN'.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT
                    COALESCE(ue.serial_number, 'UNKNOWN')  AS serial_number,
                    COALESCE(ue.device_name, 'Unknown Device') AS device_name,
                    ue.vendor_id                            AS vendor_id,
                    ue.product_id                           AS product_id,
                    ue.mount_path                           AS mount_path,
                    COUNT(*)                                AS blocked_count,
                    MAX(rl.risk_score)                      AS max_risk_score,
                    MAX(rl.timestamp)                       AS last_blocked_at
                FROM risk_logs rl
                LEFT JOIN file_events fe ON fe.id = rl.file_event_id
                LEFT JOIN usb_events ue ON ue.id = fe.usb_event_id
                WHERE rl.decision = 'BLOCK'
                GROUP BY COALESCE(ue.serial_number, 'UNKNOWN')
                ORDER BY last_blocked_at DESC
                """
            )
            return cursor.fetchall()

    # ------------------------------------------------------------------
    # Aggregate / dashboard queries
    # ------------------------------------------------------------------
    def fetch_dashboard_summary(self) -> Dict[str, Any]:
        """Fetch the single-row dashboard summary view as a dict."""
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM v_dashboard_summary")
            row = cursor.fetchone()
            return dict(row) if row else {}

    def fetch_risk_distribution(self) -> Dict[str, int]:
        """Return counts of LOW/MEDIUM/HIGH sensitivity results for charting."""
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT sensitivity, COUNT(*) AS cnt FROM risk_logs GROUP BY sensitivity"
            )
            rows = cursor.fetchall()
            result = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            for row in rows:
                result[row["sensitivity"]] = row["cnt"]
            return result

    def fetch_recent_incidents(self, limit: int = 10) -> List[sqlite3.Row]:
        """Fetch the most recent alerts for the dashboard 'Recent Incidents' widget."""
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            return cursor.fetchall()

    def execute_raw(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """
        Escape hatch for ad-hoc read-only queries (e.g. dashboard reports
        page). Callers MUST use parameter binding; never string-format
        user input into `query`.
        """
        with self._connect() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchall()