#!/usr/bin/env bash
# =============================================================================
# run_agent.sh
# -------------
# Launches the Secure USB DLP background monitoring agent.
#
# Usage:
#   chmod +x run_agent.sh
#   ./run_agent.sh
#
# On Linux, USB monitoring via pyudev typically requires permission to
# read netlink uevents; if you encounter permission errors, try running
# with sudo, or add your user to the appropriate group (e.g. 'plugdev'
# on Debian/Ubuntu) instead of running as root.
# =============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [ -d "venv" ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

echo "Starting Secure USB DLP Agent (Phase 1)..."
echo "Press Ctrl+C to stop."
echo ""

export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"
python -m agent.main
