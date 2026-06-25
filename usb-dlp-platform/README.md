# Secure USB Monitoring and Data Exfiltration Prevention System — Phase 1

A modular, enterprise-grade **Data Loss Prevention (DLP)** prototype that
monitors USB storage devices, inspects transferred files for sensitive
data, scores the risk of each transfer, and raises alerts on suspicious
or policy-violating activity.

> **Scope: Phase 1 only.** This system is intentionally **rule-based**.
> It does **not** include machine learning, Isolation Forest anomaly
> detection, or a manager approval workflow. Those capabilities are
> explicitly reserved for Phase 2 of this project.

---

## 1. Project Objective

Build a DLP system that:
1. Detects USB storage device insertion/removal.
2. Monitors file activity (create, copy, modify, delete, rename) on
   mounted USB volumes.
3. Inspects copied/created/modified text-based files for sensitive data
   (PAN, Aadhaar, credit card numbers, email addresses, phone numbers).
4. Computes a deterministic, rule-based risk score (0–100) for every
   scanned file.
5. Applies a simple block/allow policy based on the score.
6. Raises structured alerts and stores a full audit trail in SQLite.
7. Visualizes everything in a real-time Streamlit dashboard.

---

## 2. Architecture

```
                    ┌────────────────────┐
                    │     USB Monitor     │  pyudev (Linux) / psutil (Windows)
                    └─────────┬──────────┘
                              │ INSERTED / REMOVED
                              ▼
                    ┌────────────────────┐
                    │    File Monitor     │  watchdog (cross-platform)
                    └─────────┬──────────┘
                              │ CREATE / COPY / MODIFY / DELETE / RENAME
                              ▼
                    ┌────────────────────┐
                    │  Sensitive Data      │  Regex: PAN, Aadhaar, Card,
                    │  Detection Engine    │  Email, Phone
                    └─────────┬──────────┘
                              ▼
                    ┌────────────────────┐
                    │  Risk Scoring Engine │  Rule-based, 0–100
                    └─────────┬──────────┘
                              ▼
                    ┌────────────────────┐
                    │   Policy Engine      │  score > 60 → BLOCK, else ALLOW
                    └─────────┬──────────┘
                              ▼
                    ┌────────────────────┐
                    │   Alert Engine       │  → alerts table
                    └─────────┬──────────┘
                              ▼
                    ┌────────────────────┐
                    │   SQLite Database    │  usb_dlp.db
                    │ usb_events/file_events│
                    │ risk_logs/alerts      │
                    └─────────┬──────────┘
                              ▼
                    ┌────────────────────┐
                    │ Streamlit Dashboard  │  Dashboard / USB Devices /
                    │                      │  File Activities / Incidents /
                    │                      │  Risk Reports
                    └────────────────────┘
```

The **agent** (background monitoring process) and the **dashboard**
(Streamlit web UI) are two independent processes that share the same
SQLite database file, configured in WAL mode so both can read/write
concurrently without locking errors.

---

## 3. Folder Structure

```
usb-dlp-platform/
├── agent/
│   ├── __init__.py
│   ├── usb_monitor.py       # USB insertion/removal detection
│   ├── file_monitor.py      # File activity monitoring (watchdog)
│   ├── scanner.py           # Sensitive Data Detection Engine (regex)
│   ├── risk_engine.py       # Rule-based Risk Scoring Engine
│   ├── policy_engine.py     # Allow/Block decision engine
│   ├── alert_manager.py     # Alert generation & persistence
│   ├── logger.py            # Centralized logging configuration
│   └── main.py              # Agent entry point / orchestrator
├── dashboard/
│   ├── __init__.py
│   ├── app.py                  # Dashboard home page (Streamlit entry point)
│   ├── db_helper.py             # Shared cached DB accessor for all pages
│   └── pages/
│       ├── usb_devices.py
│       ├── file_activity.py
│       ├── incidents.py
│       └── reports.py
├── database/
│   ├── __init__.py
│   ├── schema.sql            # Full SQLite DDL (4 tables + summary view)
│   ├── db.py                 # Data Access Layer (DatabaseManager)
│   └── usb_dlp.db            # Created automatically on first run
├── config/
│   ├── __init__.py
│   ├── settings.py           # Centralized settings loader
│   └── .env.example          # Environment variable template
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_risk_engine.py
│   └── test_policy.py
├── sample_data/
│   ├── sample_sensitive.txt
│   ├── sample_clean.txt
│   ├── sample_customers.csv
│   ├── sample_app.log
│   └── README.md
├── logs/                     # Created automatically (rotating log files)
├── requirements.txt
├── README.md
├── install.sh
├── run_agent.sh
├── run_dashboard.sh
├── setup.py
├── pytest.ini
└── .gitignore
```

---

## 4. Installation

### Prerequisites
- Python 3.10+ (Python 3.12 recommended, matches the project's target runtime)
- Linux: `libudev` development headers for `pyudev` (Debian/Ubuntu:
  `sudo apt-get install libudev-dev`)
- Windows: no additional system packages required (psutil/watchdog ship
  as pure wheels)

### Quick install (Linux/macOS)

```bash
chmod +x install.sh run_agent.sh run_dashboard.sh
./install.sh
```

This will:
1. Verify your Python version.
2. Create a virtual environment in `./venv`.
3. Install all dependencies from `requirements.txt`.
4. Create `.env` from `config/.env.example` if missing.
5. Initialize `database/usb_dlp.db` by applying `schema.sql`.

### Manual install (any OS, including Windows PowerShell)

```bash
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
copy config\.env.example .env   # Windows
cp config/.env.example .env     # Linux/macOS

python -c "from database.db import DatabaseManager; DatabaseManager()"
```

---

## 5. Running the System

### Start the monitoring agent
```bash
./run_agent.sh
# or directly:
python -m agent.main
```

The agent runs continuously, watching for USB insertion/removal and
file activity. Press `Ctrl+C` to stop it gracefully.

### Start the dashboard (in a separate terminal)
```bash
./run_dashboard.sh
# or directly:
streamlit run dashboard/app.py
```

Open the URL printed in the terminal (typically `http://localhost:8501`).

### Try it without a real USB device
See `sample_data/README.md` for a script that runs sample files through
the scanning → scoring → policy pipeline directly, useful for demos and
grading without needing physical hardware.

---

## 6. Database Schema

| Table | Purpose |
|---|---|
| `usb_events` | Every USB insertion/removal: device name, vendor ID, product ID, serial number, mount path, timestamp |
| `file_events` | Every file create/copy/modify/delete/rename: filename, extension, size, path, user, timestamp |
| `risk_logs` | Every scoring result: sensitivity, score, matched rules, decision |
| `alerts` | Every raised alert: type, severity, score, user, file, message, status |

A convenience view, `v_dashboard_summary`, pre-aggregates top-line
counters for the dashboard home page in a single query.

Full DDL: see [`database/schema.sql`](database/schema.sql).

---

## 7. Sensitive Data Detection Patterns

| Type | Pattern |
|---|---|
| PAN | `[A-Z]{5}[0-9]{4}[A-Z]` |
| Aadhaar | `\b\d{4}\s\d{4}\s\d{4}\b` |
| Credit Card | `\b(?:\d[ -]*?){13,16}\b` |
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| Phone (India) | `\b[6-9]\d{9}\b` |

Scanned extensions: `.txt`, `.csv`, `.log`, `.json`, `.xml` (configurable
via `SCAN_EXTENSIONS` in `.env`). Detected values are **masked** before
ever being logged or stored — only types and counts persist, never raw
PAN/Aadhaar/card numbers.

---

## 8. Risk Scoring Rules

| Rule | Points |
|---|---|
| PAN detected | +30 |
| Aadhaar detected | +40 |
| Credit Card detected | +50 |
| Email detected | +10 |
| Phone detected | +10 |
| File size > 50MB | +20 |
| Multiple files in one USB session | +15 |

Score is clamped to `0–100` and banded:

| Score | Sensitivity |
|---|---|
| 0–30 | LOW |
| 31–60 | MEDIUM |
| 61–100 | HIGH |

## 9. Policy

```
if risk_score > 60:
    decision = BLOCK
else:
    decision = ALLOW
    # an informational alert is still raised for MEDIUM/HIGH findings
```

There is **no approval workflow** in Phase 1 — every decision is
automatic and final. Manager-review/override queues are Phase 2 scope.

---

## 10. Dashboard Pages

| Page | Contents |
|---|---|
| **Dashboard** (`app.py`) | Total USB events, files scanned, alerts, risk distribution, recent incidents |
| **USB Devices** | Currently connected devices + full insertion/removal history |
| **File Activities** | Full file activity log with action/extension filters and charts |
| **Incidents** | All alerts, severity breakdown, manual status updates (Open → Acknowledged → Resolved) |
| **Risk Reports** | Score distributions, decision breakdown, trend-over-time, top triggered rules, CSV export |

All charts use **Plotly**; all tabular processing uses **Pandas**. The
dashboard supports real-time auto-refresh (configurable interval).

---

## 11. Running Tests

```bash
source venv/bin/activate
pytest
# or with coverage:
pytest --cov=agent --cov-report=term-missing
```

Test coverage includes:
- `test_scanner.py` — every regex detector, masking behavior, file-size
  and extension skip logic.
- `test_risk_engine.py` — every scoring rule individually and combined,
  clamping behavior, multiple-files session logic, banding boundaries.
- `test_policy.py` — block/allow boundary behavior, informational
  alerting for allowed-but-sensitive transfers, and an explicit guard
  test asserting no approval-workflow fields exist (Phase 1 scope).

---

## 12. Security & Engineering Practices Applied

- **Parameterized SQL everywhere** — zero string-interpolated queries;
  SQL injection is structurally not possible through this codebase.
- **Sensitive values are masked before logging/storage** — raw PAN,
  Aadhaar, and card numbers are never persisted in plaintext anywhere,
  including log files.
- **Defensive I/O** — every file read, OS call, and database operation
  is wrapped in narrow try/except blocks with structured logging so a
  single malformed file or transient OS error cannot crash the agent.
- **WAL-mode SQLite** with busy-timeout — safe concurrent access between
  the agent (writer) and dashboard (reader) processes.
- **`.env`-based configuration**, never hardcoded secrets or paths.
- **OOP + factory pattern** — `create_usb_monitor()` returns the correct
  platform implementation (`LinuxUSBMonitor` / `WindowsUSBMonitor`)
  without callers branching on `platform.system()`.
- **Modular package boundaries** — `config`, `database`, `agent`, and
  `dashboard` each have a single, well-defined responsibility and only
  depend on the layers below them.

---

## 13. Known Limitations (Phase 1)

- **No physical write-blocking.** A `BLOCK` decision is logged and
  alerted on, but Phase 1 does not install an OS-level filesystem
  filter driver to physically prevent the copy operation — that
  requires elevated, OS-specific kernel driver development that is out
  of scope for a Python/SQLite/Streamlit stack. Phase 1 is a
  **detection and alerting** system; physical interception is a
  natural Phase 2/3 extension.
- **No machine learning / anomaly detection.** All scoring is
  deterministic and rule-based, by design.
- **No approval workflow.** All policy decisions are automatic.
- **Regex-based detection only** — no NLP/contextual disambiguation;
  false positives are possible (e.g., a 16-digit invoice number could
  match the credit-card pattern). This is an accepted trade-off for
  Phase 1 and a documented Phase 2 improvement area.
- **Windows device metadata is limited** — without WMI/pywin32 (kept
  out of scope to respect the project's stated dependency list),
  Windows cannot report a true hardware serial number, vendor ID, or
  product ID the way Linux's pyudev can; a synthetic identifier is used
  instead.

---

## 14. Roadmap (Phase 2 — Not Implemented Here)

- Isolation Forest-based behavioral anomaly detection.
- Manager/approval-based access control workflow.
- NLP-assisted sensitive data classification (reducing false positives).
- OS-level filter driver for true write-blocking.
- SIEM integration and centralized multi-endpoint deployment.

---

## 15. License

Academic / Proprietary use for this Final Year Cyber Security Project.
