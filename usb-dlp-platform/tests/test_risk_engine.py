"""
tests/test_risk_engine.py
----------------------------
Unit tests for agent.risk_engine.RiskEngine.

Validates the rule-based scoring model exactly as specified:
    PAN +30, Aadhaar +40, Credit Card +50, Email +10, Phone +10,
    Large file (>50MB) +20, Multiple files +15,
    and the LOW (0-30) / MEDIUM (31-60) / HIGH (61-100) banding.
"""

from __future__ import annotations

import pytest

from agent.risk_engine import RiskEngine
from agent.scanner import ScanResult


def make_scan_result(match_counts: dict, file_path: str = "test.txt") -> ScanResult:
    """Helper to build a ScanResult with specific detector counts, bypassing real scanning."""
    return ScanResult(
        file_path=file_path,
        scanned=True,
        sensitivity="LOW",  # irrelevant here; risk_engine computes its own banding
        matches=[],
        match_counts=match_counts,
    )


@pytest.fixture()
def engine() -> RiskEngine:
    return RiskEngine()


# ---------------------------------------------------------------------------
# Individual rule scoring
# ---------------------------------------------------------------------------
def test_pan_adds_30(engine: RiskEngine):
    result = make_scan_result({"PAN": 1})
    assessment = engine.score(result, file_size_bytes=1000)
    assert assessment.risk_score == 30
    assert assessment.sensitivity == "LOW"  # score range 0-30 is LOW per spec (boundary inclusive)


def test_aadhaar_adds_40(engine: RiskEngine):
    result = make_scan_result({"AADHAAR": 1})
    assessment = engine.score(result, file_size_bytes=1000)
    assert assessment.risk_score == 40
    assert assessment.sensitivity == "MEDIUM"


def test_credit_card_adds_50(engine: RiskEngine):
    result = make_scan_result({"CREDIT_CARD": 1})
    assessment = engine.score(result, file_size_bytes=1000)
    assert assessment.risk_score == 50
    assert assessment.sensitivity == "MEDIUM"


def test_email_adds_10(engine: RiskEngine):
    result = make_scan_result({"EMAIL": 1})
    assessment = engine.score(result, file_size_bytes=1000)
    assert assessment.risk_score == 10
    assert assessment.sensitivity == "LOW"


def test_phone_adds_10(engine: RiskEngine):
    result = make_scan_result({"PHONE": 1})
    assessment = engine.score(result, file_size_bytes=1000)
    assert assessment.risk_score == 10
    assert assessment.sensitivity == "LOW"


def test_large_file_adds_20(engine: RiskEngine):
    result = make_scan_result({})
    big_size = 51 * 1024 * 1024  # 51MB > 50MB threshold
    assessment = engine.score(result, file_size_bytes=big_size)
    assert assessment.risk_score == 20
    assert "LARGE_FILE(+20)" in assessment.matched_rules


def test_file_at_exactly_50mb_does_not_trigger_large_file_rule(engine: RiskEngine):
    result = make_scan_result({})
    exact_size = 50 * 1024 * 1024
    assessment = engine.score(result, file_size_bytes=exact_size)
    assert assessment.risk_score == 0  # rule is strictly > 50MB


# ---------------------------------------------------------------------------
# Combined rules and clamping
# ---------------------------------------------------------------------------
def test_pan_and_aadhaar_combined(engine: RiskEngine):
    result = make_scan_result({"PAN": 1, "AADHAAR": 1})
    assessment = engine.score(result, file_size_bytes=1000)
    assert assessment.risk_score == 70
    assert assessment.sensitivity == "HIGH"


def test_score_clamped_to_100(engine: RiskEngine):
    result = make_scan_result({"PAN": 1, "AADHAAR": 1, "CREDIT_CARD": 1, "EMAIL": 1, "PHONE": 1})
    big_size = 60 * 1024 * 1024
    assessment = engine.score(result, file_size_bytes=big_size)
    # 30+40+50+10+10 = 140, +20 large file = 160, clamped to 100
    assert assessment.risk_score == 100
    assert assessment.sensitivity == "HIGH"


def test_multiple_files_rule_triggers_on_second_file(engine: RiskEngine):
    result1 = make_scan_result({}, file_path="a.txt")
    result2 = make_scan_result({}, file_path="b.txt")

    assessment1 = engine.score(result1, file_size_bytes=100)
    assert "MULTIPLE_FILES(+15)" not in assessment1.matched_rules
    assert assessment1.risk_score == 0

    assessment2 = engine.score(result2, file_size_bytes=100)
    assert "MULTIPLE_FILES(+15)" in assessment2.matched_rules
    assert assessment2.risk_score == 15


def test_reset_session_clears_multiple_files_counter(engine: RiskEngine):
    result1 = make_scan_result({}, file_path="a.txt")
    result2 = make_scan_result({}, file_path="b.txt")

    engine.score(result1, file_size_bytes=100)
    engine.reset_session()
    assessment_after_reset = engine.score(result2, file_size_bytes=100)

    assert "MULTIPLE_FILES(+15)" not in assessment_after_reset.matched_rules
    assert assessment_after_reset.risk_score == 0


# ---------------------------------------------------------------------------
# Sensitivity banding boundaries
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "score,expected_band",
    [(0, "LOW"), (30, "LOW"), (31, "MEDIUM"), (60, "MEDIUM"), (61, "HIGH"), (100, "HIGH")],
)
def test_sensitivity_banding(engine: RiskEngine, score, expected_band):
    assert engine._score_to_sensitivity(score) == expected_band
