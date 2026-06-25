"""
agent/scanner.py
------------------
Sensitive Data Detection Engine.

Inspects the textual content of files copied/created/modified on a USB
device for patterns matching common sensitive data types found in
Indian enterprise/compliance contexts (as specified by the project
requirements):

    - PAN (Permanent Account Number)
    - Aadhaar number
    - Credit/Debit card number
    - Email address
    - Indian mobile phone number

Design notes
~~~~~~~~~~~~
- Only files whose extension is in `settings.scan_extensions`
  (txt, csv, log, json, xml by default) are content-scanned. Other file
  types are still logged as file_events but are not opened for content
  inspection in Phase 1.
- Files larger than `settings.max_scan_size_mb` are NOT read into memory
  for content scanning (to avoid memory exhaustion); they are still
  flagged by the Risk Scoring Engine via the "large file" rule based on
  size alone.
- All file reads are wrapped in try/except and use errors="ignore" decoding
  so that binary or malformed files never crash the scanning pipeline.
- Regex patterns are pre-compiled once at module import time for
  performance, since the scanner runs on every file event.

Output contract (per project specification):
    {
        "sensitivity": "HIGH" | "MEDIUM" | "LOW",
        "matches": [ {"type": "PAN", "value_masked": "ABCDE****F"}, ... ]
    }
    Note: `sensitivity` in the raw scan result returned by `scan_file()`
    is a preliminary, match-count-based signal; the authoritative
    LOW/MEDIUM/HIGH classification used throughout the rest of the
    system comes from risk_engine.py, which also factors in file size
    and multi-file context.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern

from config.settings import settings
from agent.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Detection patterns (compiled once at import time)
# =============================================================================
# NOTE ON PATTERN CHOICE: these patterns intentionally match the exact
# specification provided for this project. PAN numbers in the real world
# follow the format AAAAA9999A; Aadhaar is commonly displayed in 4-4-4
# space-separated groups; credit/debit cards are 13-16 digits optionally
# separated by spaces/hyphens; email follows standard RFC-like structure;
# Indian mobile numbers are 10 digits starting 6-9.
PATTERNS: Dict[str, Pattern[str]] = {
    "PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "AADHAAR": re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "PHONE": re.compile(r"\b[6-9]\d{9}\b"),
}

# Order in which detectors are evaluated; also used for deterministic
# reporting order in the UI.
DETECTOR_ORDER: List[str] = ["PAN", "AADHAAR", "CREDIT_CARD", "EMAIL", "PHONE"]


def _mask_value(detector: str, value: str) -> str:
    """
    Mask a matched sensitive value before it is logged or stored anywhere,
    so that raw PAN/Aadhaar/card numbers never persist in plaintext in
    logs or the database — only counts and types do.
    """
    value = value.strip()
    if len(value) <= 4:
        return "*" * len(value)
    if detector == "EMAIL":
        local, _, domain = value.partition("@")
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"
    visible_prefix = value[:2]
    visible_suffix = value[-2:]
    return f"{visible_prefix}{'*' * (len(value) - 4)}{visible_suffix}"


@dataclass
class ScanMatch:
    """A single sensitive-data match found within a file."""
    detector: str
    masked_value: str


@dataclass
class ScanResult:
    """
    Structured result of scanning one file, matching the project's
    required output contract while adding a few convenience fields used
    internally by the risk engine.
    """
    file_path: str
    scanned: bool                      # False if file was skipped (too large / wrong extension / unreadable)
    sensitivity: str = "LOW"           # preliminary signal; see module docstring
    matches: List[ScanMatch] = field(default_factory=list)
    match_counts: Dict[str, int] = field(default_factory=dict)
    skip_reason: str = ""

    def to_dict(self) -> dict:
        """Serialize to the exact dict shape required by the specification."""
        return {
            "sensitivity": self.sensitivity,
            "matches": [
                {"type": m.detector, "value_masked": m.masked_value} for m in self.matches
            ],
        }


class SensitiveDataScanner:
    """
    Stateless scanner object exposing `scan_file()` and `scan_text()`.

    Kept as a class (rather than free functions) to allow future Phase 2
    extension (e.g., NLP-based detectors, custom regex injection) without
    changing the calling convention used by the rest of the agent.
    """

    def __init__(self) -> None:
        self.patterns = PATTERNS
        self.scan_extensions = set(settings.scan_extensions)
        self.max_scan_size_bytes = settings.max_scan_size_bytes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def is_scannable_extension(self, extension: str) -> bool:
        """Return True if the given extension (without dot) is eligible for content scanning."""
        return extension.lower().lstrip(".") in self.scan_extensions

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file on disk for sensitive data patterns.

        Returns a ScanResult. Never raises — all I/O and decoding errors
        are caught and reflected in `skip_reason` so the calling pipeline
        (risk_engine) can continue processing other files unaffected.
        """
        extension = os.path.splitext(file_path)[1].lstrip(".").lower()

        if not self.is_scannable_extension(extension):
            return ScanResult(file_path=file_path, scanned=False, skip_reason="unsupported_extension")

        try:
            file_size = os.path.getsize(file_path)
        except OSError as exc:
            logger.warning("Unable to stat file for scanning: %s (%s)", file_path, exc)
            return ScanResult(file_path=file_path, scanned=False, skip_reason="stat_failed")

        if file_size > self.max_scan_size_bytes:
            logger.info(
                "Skipping content scan for %s: size %d bytes exceeds limit %d bytes",
                file_path, file_size, self.max_scan_size_bytes,
            )
            return ScanResult(file_path=file_path, scanned=False, skip_reason="file_too_large")

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("Unable to read file for scanning: %s (%s)", file_path, exc)
            return ScanResult(file_path=file_path, scanned=False, skip_reason="read_failed")

        return self.scan_text(content, file_path=file_path)

    def scan_text(self, content: str, file_path: str = "<in-memory>") -> ScanResult:
        """
        Run all detectors against a raw text string. Exposed separately
        from `scan_file` so unit tests can exercise detection logic
        without needing real files on disk.
        """
        matches: List[ScanMatch] = []
        match_counts: Dict[str, int] = {}

        for detector_name in DETECTOR_ORDER:
            pattern = self.patterns[detector_name]
            found = pattern.findall(content)
            if not found:
                continue
            match_counts[detector_name] = len(found)
            for raw_value in found:
                matches.append(ScanMatch(detector=detector_name, masked_value=_mask_value(detector_name, raw_value)))

        sensitivity = self._preliminary_sensitivity(match_counts)

        if matches:
            logger.info(
                "Sensitive data detected in %s: %s",
                file_path, {k: v for k, v in match_counts.items()},
            )

        return ScanResult(
            file_path=file_path,
            scanned=True,
            sensitivity=sensitivity,
            matches=matches,
            match_counts=match_counts,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _preliminary_sensitivity(match_counts: Dict[str, int]) -> str:
        """
        Lightweight, scanner-local sensitivity hint used only for quick
        reporting/logging. The authoritative score comes from
        risk_engine.RiskEngine, which this method does NOT replace.
        """
        if any(k in match_counts for k in ("PAN", "AADHAAR", "CREDIT_CARD")):
            return "HIGH"
        if "EMAIL" in match_counts or "PHONE" in match_counts:
            return "MEDIUM"
        return "LOW"
