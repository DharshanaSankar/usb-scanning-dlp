"""
agent/risk_engine.py
----------------------
Risk Scoring Engine.

Implements the rule-based scoring model defined in the project
specification:

    PAN detected            -> +30
    Aadhaar detected        -> +40
    Credit Card detected    -> +50
    Email detected          -> +10
    Phone detected          -> +10
    Large file (> 50MB)     -> +20
    Multiple files (context)-> +15

Score is clamped to the range 0-100 and mapped to a sensitivity band:

    0-30   -> LOW
    31-60  -> MEDIUM
    61-100 -> HIGH

This module is intentionally rule-based and deterministic per the
Phase 1 scope — no machine learning, no statistical anomaly detection.
Those are explicitly reserved for Phase 2 (Isolation Forest, behavioral
profiling) and are NOT implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from config.settings import settings
from agent.scanner import ScanResult
from agent.logger import get_logger

logger = get_logger(__name__)


# Points awarded per detector hit. Each detector contributes its point
# value ONCE per file regardless of how many times that pattern matched,
# matching the specification's "PAN detected: +30" phrasing (a flag, not
# a per-occurrence multiplier) while `match_counts` still preserves how
# many occurrences were found for analyst review.
DETECTOR_SCORES: Dict[str, int] = {
    "PAN": 30,
    "AADHAAR": 40,
    "CREDIT_CARD": 50,
    "EMAIL": 10,
    "PHONE": 10,
}

LARGE_FILE_THRESHOLD_MB = 50
LARGE_FILE_SCORE = 20
MULTIPLE_FILES_SCORE = 15

MAX_SCORE = 100
MIN_SCORE = 0


@dataclass
class RiskAssessment:
    """Result of scoring a single file transfer/activity event."""
    file_path: str
    risk_score: int
    sensitivity: str                      # LOW / MEDIUM / HIGH
    matched_rules: List[str] = field(default_factory=list)
    match_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "risk_score": self.risk_score,
            "sensitivity": self.sensitivity,
            "matched_rules": self.matched_rules,
            "match_counts": self.match_counts,
        }


class RiskEngine:
    """
    Stateful-per-session scoring engine. Tracks how many files have been
    processed in the current "batch" (e.g. a burst of file events on the
    same USB device within a short window) so the "multiple files"
    contextual rule can be applied. The orchestrator (main.py) is
    responsible for calling `reset_session()` when a USB device is
    removed, ending that device's transfer session.
    """

    def __init__(
        self,
        low_max: int = None,
        medium_max: int = None,
    ) -> None:
        self.low_max = low_max if low_max is not None else settings.risk_low_max
        self.medium_max = medium_max if medium_max is not None else settings.risk_medium_max
        self._files_in_session = 0

    def reset_session(self) -> None:
        """Reset the multi-file counter (call when a USB device is removed)."""
        self._files_in_session = 0

    def score(self, scan_result: ScanResult, file_size_bytes: int) -> RiskAssessment:
        """
        Compute a risk score for a single file given its scan result and
        size. Increments the internal session file counter so subsequent
        calls within the same device session can trigger the
        "multiple files" rule.
        """
        self._files_in_session += 1

        score = 0
        matched_rules: List[str] = []

        # --- Sensitive-content rules -------------------------------------------------
        for detector, points in DETECTOR_SCORES.items():
            if scan_result.match_counts.get(detector, 0) > 0:
                score += points
                matched_rules.append(f"{detector}_DETECTED(+{points})")

        # --- Large file rule -----------------------------------------------------------
        size_mb = file_size_bytes / (1024 * 1024)
        if size_mb > LARGE_FILE_THRESHOLD_MB:
            score += LARGE_FILE_SCORE
            matched_rules.append(f"LARGE_FILE(+{LARGE_FILE_SCORE})")

        # --- Multiple files in session rule --------------------------------------------
        if self._files_in_session > 1:
            score += MULTIPLE_FILES_SCORE
            matched_rules.append(f"MULTIPLE_FILES(+{MULTIPLE_FILES_SCORE})")

        score = max(MIN_SCORE, min(MAX_SCORE, score))
        sensitivity = self._score_to_sensitivity(score)

        assessment = RiskAssessment(
            file_path=scan_result.file_path,
            risk_score=score,
            sensitivity=sensitivity,
            matched_rules=matched_rules,
            match_counts=dict(scan_result.match_counts),
        )

        logger.info(
            "Risk assessment: file=%s score=%d sensitivity=%s rules=%s",
            scan_result.file_path, score, sensitivity, matched_rules,
        )

        return assessment

    def _score_to_sensitivity(self, score: int) -> str:
        """Map a numeric score to its LOW/MEDIUM/HIGH band per configured thresholds."""
        if score <= self.low_max:
            return "LOW"
        if score <= self.medium_max:
            return "MEDIUM"
        return "HIGH"
