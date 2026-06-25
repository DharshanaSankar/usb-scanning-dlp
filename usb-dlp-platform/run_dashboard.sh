#!/usr/bin/env bash
# =============================================================================
# run_dashboard.sh
# ------------------
# Launches the Streamlit dashboard for the Secure USB DLP System.
#
# Usage:
#   chmod +x run_dashboard.sh
#   ./run_dashboard.sh
#
# The dashboard reads from the same SQLite database (database/usb_dlp.db)
# that the agent (run_agent.sh) writes to. Both can run concurrently
# thanks to WAL journal mode configured in database/db.py.
# =============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [ -d "venv" ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

echo "Starting Secure USB DLP Dashboard (Phase 1)..."
echo "Open the URL shown below in your browser."
echo ""

export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"
streamlit run dashboard/app.py
