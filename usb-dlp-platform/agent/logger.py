"""
agent/logger.py
----------------
Centralized logging configuration for the Secure USB DLP System.

All modules call `get_logger(__name__)` to obtain a properly configured
logger instance instead of calling `logging.basicConfig` independently,
which avoids duplicate handlers and inconsistent formatting across the
agent and dashboard processes.

Output destinations:
    1. Rotating file handler -> logs/usb_dlp_agent.log (size-based rotation)
    2. Console (stdout) handler -> useful when running the agent in a
       terminal during development/demo.

Security note:
    Log messages must never contain full file *contents* (only metadata
    such as filenames, paths, sizes, and detection counts) to avoid the
    log file itself becoming a sensitive-data exposure vector.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure_root_logging() -> None:
    """
    Configure the root logger exactly once per process. Subsequent calls
    are no-ops, guarded by the module-level `_configured` flag, so that
    importing this module from many places never results in duplicate
    log lines.
    """
    global _configured
    if _configured:
        return

    # Lazy import to avoid a circular import between config <-> logger,
    # since settings.py does not depend on logger.py.
    try:
        from config.settings import settings
        log_dir = settings.log_dir
        log_file = settings.log_file
        log_level = settings.log_level
        max_bytes = settings.log_max_bytes
        backup_count = settings.log_backup_count
    except Exception:
        # Fallback defaults if settings could not be imported for any
        # reason (e.g. during isolated unit tests) — logging should
        # never be a hard dependency that crashes the app.
        log_dir = "logs"
        log_file = "usb_dlp_agent.log"
        log_level = "INFO"
        max_bytes = 5 * 1024 * 1024
        backup_count = 5

    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = os.path.join(log_dir, log_file)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, str(log_level).upper(), logging.INFO))

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a module-scoped logger, configuring the root logger on first
    use. This is the ONLY supported way to obtain a logger in this
    project; do not call `logging.getLogger()` directly elsewhere.
    """
    _configure_root_logging()
    return logging.getLogger(name)
