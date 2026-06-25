#!/usr/bin/env bash
# =============================================================================
# install.sh
# -----------
# Installation script for the Secure USB Monitoring and Data Exfiltration
# Prevention System (Phase 1).
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# What this script does:
#   1. Verifies Python 3.10+ is available.
#   2. Creates a local virtual environment (./venv) if one doesn't exist.
#   3. Activates it and installs all dependencies from requirements.txt.
#   4. Copies config/.env.example to .env if no .env exists yet.
#   5. Initializes the SQLite database by importing database.db (which
#      applies schema.sql automatically).
#
# This script is idempotent: re-running it is safe and will not destroy
# existing data or configuration.
# =============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo " Secure USB DLP System - Phase 1 - Installation"
echo "============================================================"

# -----------------------------------------------------------------------------
# 1. Check Python version
# -----------------------------------------------------------------------------
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON_BIN not found. Please install Python 3.10 or newer."
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "Detected Python version: $PY_VERSION"

REQUIRED_MAJOR=3
REQUIRED_MINOR=10
PY_MAJOR="$(echo "$PY_VERSION" | cut -d. -f1)"
PY_MINOR="$(echo "$PY_VERSION" | cut -d. -f2)"

if [ "$PY_MAJOR" -lt "$REQUIRED_MAJOR" ] || { [ "$PY_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$PY_MINOR" -lt "$REQUIRED_MINOR" ]; }; then
    echo "ERROR: Python 3.10+ is required. Found $PY_VERSION."
    exit 1
fi

# -----------------------------------------------------------------------------
# 2. Create virtual environment
# -----------------------------------------------------------------------------
if [ ! -d "venv" ]; then
    echo "Creating virtual environment in ./venv ..."
    "$PYTHON_BIN" -m venv venv
else
    echo "Virtual environment already exists, skipping creation."
fi

# shellcheck disable=SC1091
source venv/bin/activate

# -----------------------------------------------------------------------------
# 3. Install dependencies
# -----------------------------------------------------------------------------
echo "Upgrading pip..."
pip install --upgrade pip --quiet

echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Linux-only system dependency note for pyudev
if [ "$(uname -s)" = "Linux" ]; then
    if ! python -c "import pyudev" >/dev/null 2>&1; then
        echo "NOTE: pyudev failed to import. On Debian/Ubuntu you may need:"
        echo "      sudo apt-get install -y libudev-dev"
    fi
fi

# -----------------------------------------------------------------------------
# 4. Configure environment file
# -----------------------------------------------------------------------------
if [ ! -f ".env" ]; then
    echo "Creating .env from config/.env.example ..."
    cp config/.env.example .env
else
    echo ".env already exists, leaving it untouched."
fi

# -----------------------------------------------------------------------------
# 5. Initialize database
# -----------------------------------------------------------------------------
echo "Initializing SQLite database (schema creation)..."
python -c "from database.db import DatabaseManager; DatabaseManager(); print('Database ready.')"

echo "============================================================"
echo " Installation complete!"
echo ""
echo " Next steps:"
echo "   1. Review and edit .env if needed."
echo "   2. Start the monitoring agent:    ./run_agent.sh"
echo "   3. Start the dashboard (new tab): ./run_dashboard.sh"
echo "============================================================"
