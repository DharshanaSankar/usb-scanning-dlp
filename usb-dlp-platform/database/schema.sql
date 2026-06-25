-- =============================================================================
-- Secure USB Monitoring and Data Exfiltration Prevention System - Phase 1
-- SQLite Schema Definition
-- File: database/schema.sql
-- -----------------------------------------------------------------------------
-- This schema is applied automatically by database/db.py on first run.
-- It defines four core tables as required by the project specification:
--   1. usb_events  - USB insertion / removal events
--   2. file_events - File create / copy / modify / delete / rename activity
--   3. alerts      - Generated security alerts
--   4. risk_logs   - Risk scoring audit trail
--
-- Design notes:
--   - All timestamps are stored as ISO-8601 strings (UTC) for portability
--     and human readability when inspecting the DB directly.
--   - Foreign keys link file_events/alerts/risk_logs back to the USB event
--     they belong to, enabling full forensic traceability of "which file
--     moved through which device".
--   - WAL journal mode is enabled by db.py at connection time (not here)
--     to allow the agent (writer) and dashboard (reader) to access the
--     database concurrently without locking errors.
-- =============================================================================

PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------------
-- Table: usb_events
-- Captures every USB storage device insertion and removal event.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usb_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT    NOT NULL CHECK (event_type IN ('INSERTED', 'REMOVED')),
    device_name     TEXT,
    vendor_id       TEXT,
    product_id      TEXT,
    serial_number   TEXT,
    mount_path      TEXT,
    platform        TEXT,                       -- 'linux' or 'windows'
    timestamp       TEXT    NOT NULL,            -- ISO-8601 UTC
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_usb_events_timestamp ON usb_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_usb_events_serial ON usb_events (serial_number);
CREATE INDEX IF NOT EXISTS idx_usb_events_event_type ON usb_events (event_type);

-- -----------------------------------------------------------------------------
-- Table: file_events
-- Captures every file-level activity observed on a mounted USB device.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    usb_event_id    INTEGER,                     -- FK -> usb_events.id (nullable: device may have been unplugged)
    action          TEXT    NOT NULL CHECK (action IN ('CREATE', 'COPY', 'MODIFY', 'DELETE', 'RENAME')),
    file_name       TEXT    NOT NULL,
    extension       TEXT,
    file_size_bytes INTEGER DEFAULT 0,
    file_path       TEXT    NOT NULL,
    os_user         TEXT,
    timestamp       TEXT    NOT NULL,            -- ISO-8601 UTC
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (usb_event_id) REFERENCES usb_events (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_file_events_action ON file_events (action);
CREATE INDEX IF NOT EXISTS idx_file_events_extension ON file_events (extension);
CREATE INDEX IF NOT EXISTS idx_file_events_usb_event_id ON file_events (usb_event_id);

-- -----------------------------------------------------------------------------
-- Table: risk_logs
-- Stores the outcome of the Risk Scoring Engine for every scanned file
-- transfer, including which detectors fired and the resulting score/level.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_event_id   INTEGER,                     -- FK -> file_events.id
    file_name       TEXT    NOT NULL,
    file_path       TEXT    NOT NULL,
    sensitivity     TEXT    NOT NULL CHECK (sensitivity IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_score      INTEGER NOT NULL DEFAULT 0,
    matched_rules   TEXT,                         -- JSON array of rule names that contributed to the score
    match_counts    TEXT,                         -- JSON object: {"PAN": 1, "EMAIL": 2, ...}
    decision        TEXT    NOT NULL CHECK (decision IN ('ALLOW', 'BLOCK')),
    os_user         TEXT,
    timestamp       TEXT    NOT NULL,             -- ISO-8601 UTC
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (file_event_id) REFERENCES file_events (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_logs_timestamp ON risk_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_risk_logs_sensitivity ON risk_logs (sensitivity);
CREATE INDEX IF NOT EXISTS idx_risk_logs_decision ON risk_logs (decision);

-- -----------------------------------------------------------------------------
-- Table: alerts
-- Stores security alerts raised by the Alert Engine, typically as a result
-- of the Policy Engine blocking a transfer or flagging sensitive content.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT    PRIMARY KEY,          -- UUID4 string, generated by alert_manager.py
    risk_log_id     INTEGER,                       -- FK -> risk_logs.id
    alert_type      TEXT    NOT NULL,              -- e.g. PAN_DETECTED, AADHAAR_DETECTED, TRANSFER_BLOCKED
    risk_score      INTEGER NOT NULL DEFAULT 0,
    severity        TEXT    NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    os_user         TEXT,
    file_name       TEXT,
    file_path       TEXT,
    message         TEXT,
    status          TEXT    NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    timestamp       TEXT    NOT NULL,              -- ISO-8601 UTC
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (risk_log_id) REFERENCES risk_logs (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (alert_type);

-- -----------------------------------------------------------------------------
-- View: v_dashboard_summary
-- Convenience view used by the Streamlit dashboard's home page to fetch
-- top-line counters in a single query instead of four separate round trips.
-- -----------------------------------------------------------------------------
DROP VIEW IF EXISTS v_dashboard_summary;
CREATE VIEW v_dashboard_summary AS
SELECT
    (SELECT COUNT(*) FROM usb_events)                          AS total_usb_events,
    (SELECT COUNT(*) FROM file_events)                         AS total_file_events,
    (SELECT COUNT(*) FROM risk_logs)                           AS total_files_scanned,
    (SELECT COUNT(*) FROM alerts)                              AS total_alerts,
    (SELECT COUNT(*) FROM alerts WHERE status = 'OPEN')        AS open_alerts,
    (SELECT COUNT(*) FROM risk_logs WHERE sensitivity='HIGH')  AS high_risk_files,
    (SELECT COUNT(*) FROM risk_logs WHERE decision='BLOCK')    AS blocked_transfers;
