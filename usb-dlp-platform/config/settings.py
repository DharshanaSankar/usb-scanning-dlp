"""
config/settings.py
-------------------
Centralized application configuration for the Secure USB DLP System.

All other modules MUST read configuration through the `settings` singleton
exported from this module instead of calling `os.getenv` directly. This
gives the project a single source of truth, makes unit testing easier
(settings can be monkey-patched), and avoids configuration drift across
the agent and dashboard processes.

Design notes
~~~~~~~~~~~~
- Values are loaded from a `.env` file (via python-dotenv) if present,
  falling back to real OS environment variables, and finally to safe
  built-in defaults so the application can run out-of-the-box even
  without an .env file (useful for first-run / demo scenarios).
- This module performs NO I/O against the database or filesystem beyond
  reading the .env file, keeping it side-effect-light and import-safe.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Resolve project root and load .env (if present) before reading any vars.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = PROJECT_ROOT / ".env"
if _ENV_PATH.exists():
    load_dotenv(dotenv_path=_ENV_PATH)
else:
    # Still attempt default lookup (e.g. .env in CWD) without raising.
    load_dotenv()


def _get_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable safely."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    """Parse an integer environment variable safely, falling back on error."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_list(name: str, default: List[str]) -> List[str]:
    """Parse a comma-separated environment variable into a clean list."""
    raw = os.getenv(name)
    if not raw:
        return default
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _resolve_path(raw_path: str) -> str:
    """Resolve a possibly-relative path against the project root."""
    p = Path(raw_path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    return str(p)


@dataclass(frozen=True)
class Settings:
    """
    Immutable settings object. Frozen to prevent accidental mutation at
    runtime, which could otherwise cause subtle bugs if one module changed
    a setting that another module had already cached.
    """

    # General
    app_env: str = field(default_factory=lambda: os.getenv("APP_ENV", "development"))
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "Secure USB DLP System"))
    app_version: str = field(default_factory=lambda: os.getenv("APP_VERSION", "1.0.0-phase1"))

    # Database
    db_path: str = field(default_factory=lambda: _resolve_path(os.getenv("DB_PATH", "database/usb_dlp.db")))
    db_timeout_seconds: int = field(default_factory=lambda: _get_int("DB_TIMEOUT_SECONDS", 30))

    # Agent / monitoring
    poll_interval_seconds: int = field(default_factory=lambda: _get_int("POLL_INTERVAL_SECONDS", 2))
    linux_media_root: str = field(default_factory=lambda: os.getenv("LINUX_MEDIA_ROOT", "/media"))
    windows_removable_label: str = field(
        default_factory=lambda: os.getenv("WINDOWS_REMOVABLE_LABEL", "Removable")
    )

    # File scanning
    scan_extensions: List[str] = field(
        default_factory=lambda: _get_list("SCAN_EXTENSIONS", ["txt", "csv", "log", "json", "xml"])
    )
    max_scan_size_mb: int = field(default_factory=lambda: _get_int("MAX_SCAN_SIZE_MB", 50))
    file_read_chunk_size: int = field(default_factory=lambda: _get_int("FILE_READ_CHUNK_SIZE", 65536))

    # Risk scoring thresholds
    risk_low_max: int = field(default_factory=lambda: _get_int("RISK_LOW_MAX", 30))
    risk_medium_max: int = field(default_factory=lambda: _get_int("RISK_MEDIUM_MAX", 60))

    # Policy engine
    policy_block_threshold: int = field(default_factory=lambda: _get_int("POLICY_BLOCK_THRESHOLD", 60))

    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_dir: str = field(default_factory=lambda: _resolve_path(os.getenv("LOG_DIR", "logs")))
    log_file: str = field(default_factory=lambda: os.getenv("LOG_FILE", "usb_dlp_agent.log"))
    log_max_bytes: int = field(default_factory=lambda: _get_int("LOG_MAX_BYTES", 5 * 1024 * 1024))
    log_backup_count: int = field(default_factory=lambda: _get_int("LOG_BACKUP_COUNT", 5))

    # Dashboard
    dashboard_refresh_seconds: int = field(
        default_factory=lambda: _get_int("DASHBOARD_REFRESH_SECONDS", 5)
    )
    dashboard_page_title: str = field(
        default_factory=lambda: os.getenv("DASHBOARD_PAGE_TITLE", "Secure USB DLP Dashboard")
    )

    @property
    def max_scan_size_bytes(self) -> int:
        """Convenience conversion of the max scan size to bytes."""
        return self.max_scan_size_mb * 1024 * 1024

    @property
    def is_windows(self) -> bool:
        return platform.system().lower() == "windows"

    @property
    def is_linux(self) -> bool:
        return platform.system().lower() == "linux"

    def ensure_directories(self) -> None:
        """Create directories required by the application if missing."""
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)


# Single, process-wide settings instance used throughout the codebase.
settings = Settings()
settings.ensure_directories()
