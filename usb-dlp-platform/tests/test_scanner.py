"""
tests/test_scanner.py
------------------------
Unit tests for agent.scanner.SensitiveDataScanner.

Run with:
    pytest tests/test_scanner.py -v
or simply:
    pytest
from the project root (pytest auto-discovers all test_*.py files).
"""

from __future__ import annotations

import os
import tempfile

import pytest

from agent.scanner import SensitiveDataScanner


@pytest.fixture()
def scanner() -> SensitiveDataScanner:
    return SensitiveDataScanner()


# ---------------------------------------------------------------------------
# Individual detector tests
# ---------------------------------------------------------------------------
def test_detects_pan(scanner: SensitiveDataScanner):
    result = scanner.scan_text("Customer PAN is ABCDE1234F for verification.")
    assert result.match_counts.get("PAN") == 1
    assert result.sensitivity == "HIGH"


def test_detects_aadhaar(scanner: SensitiveDataScanner):
    result = scanner.scan_text("Aadhaar number: 1234 5678 9123 recorded.")
    assert result.match_counts.get("AADHAAR") == 1
    assert result.sensitivity == "HIGH"


def test_detects_credit_card(scanner: SensitiveDataScanner):
    result = scanner.scan_text("Card on file: 4111 1111 1111 1111")
    assert result.match_counts.get("CREDIT_CARD", 0) >= 1
    assert result.sensitivity == "HIGH"


def test_detects_email(scanner: SensitiveDataScanner):
    result = scanner.scan_text("Contact us at support@example.com for help.")
    assert result.match_counts.get("EMAIL") == 1


def test_detects_phone(scanner: SensitiveDataScanner):
    result = scanner.scan_text("Call me at 9876543210 today.")
    assert result.match_counts.get("PHONE") == 1


def test_no_match_on_clean_text(scanner: SensitiveDataScanner):
    result = scanner.scan_text("This is a perfectly ordinary sentence with no PII at all.")
    assert result.match_counts == {}
    assert result.sensitivity == "LOW"


def test_multiple_detectors_in_one_file(scanner: SensitiveDataScanner):
    content = (
        "Employee PAN: ABCDE1234F\n"
        "Aadhaar: 1234 5678 9123\n"
        "Email: jdoe@example.com\n"
        "Phone: 9123456780\n"
    )
    result = scanner.scan_text(content)
    assert set(result.match_counts.keys()) == {"PAN", "AADHAAR", "EMAIL", "PHONE"}
    assert result.sensitivity == "HIGH"


# ---------------------------------------------------------------------------
# Masking behavior
# ---------------------------------------------------------------------------
def test_matched_values_are_masked(scanner: SensitiveDataScanner):
    result = scanner.scan_text("PAN: ABCDE1234F")
    assert len(result.matches) == 1
    masked = result.matches[0].masked_value
    assert "ABCDE1234F" not in masked
    assert masked.startswith("AB")
    assert masked.endswith("4F") or "*" in masked


def test_to_dict_contract(scanner: SensitiveDataScanner):
    result = scanner.scan_text("Email me at test@domain.com")
    payload = result.to_dict()
    assert "sensitivity" in payload
    assert "matches" in payload
    assert isinstance(payload["matches"], list)
    if payload["matches"]:
        assert "type" in payload["matches"][0]
        assert "value_masked" in payload["matches"][0]


# ---------------------------------------------------------------------------
# File-based scanning
# ---------------------------------------------------------------------------
def test_scan_file_reads_and_detects(scanner: SensitiveDataScanner, tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("PAN ABCDE1234F found in this leaked file.", encoding="utf-8")

    result = scanner.scan_file(str(file_path))
    assert result.scanned is True
    assert result.match_counts.get("PAN") == 1


def test_scan_file_skips_unsupported_extension(scanner: SensitiveDataScanner, tmp_path):
    file_path = tmp_path / "image.png"
    file_path.write_bytes(b"\x89PNG\r\n fake binary content")

    result = scanner.scan_file(str(file_path))
    assert result.scanned is False
    assert result.skip_reason == "unsupported_extension"


def test_scan_file_skips_oversized_file(scanner: SensitiveDataScanner, tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "max_scan_size_bytes", 10)  # force tiny limit
    file_path = tmp_path / "big.txt"
    file_path.write_text("a" * 100, encoding="utf-8")

    result = scanner.scan_file(str(file_path))
    assert result.scanned is False
    assert result.skip_reason == "file_too_large"


def test_scan_file_missing_file_handled_gracefully(scanner: SensitiveDataScanner):
    result = scanner.scan_file("/nonexistent/path/does_not_exist.txt")
    assert result.scanned is False
    assert result.skip_reason == "stat_failed"
