"""
agent/alert_manager.py
-------------------------
Alert Engine.

Generates structured alert records matching the project's required
output contract:

    {
        "id": "",
        "type": "PAN_DETECTED",
        "risk_score": 80,
        "user": "",
        "file": "",
        "time": ""
    }

Alerts are persisted to the `alerts` table via DatabaseManager and are
the primary data source for the dashboard's "Incidents" page.

Alert type selection logic:
    - If a BLOCK decision was made, the primary alert type is
      "TRANSFER_BLOCKED".
    - Additionally (or otherwise, for ALLOW decisions with sensitive
      content), one alert is raised per highest-priority detector that
      fired, e.g. "PAN_DETECTED", "AADHAAR_DETECTED", "CREDIT_CARD_DETECTED".
    - If no specific detector fired but the file was still large enough
      to merit attention, a generic "SUSPICIOUS_TRANSFER" alert is used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from database.db import DatabaseManager, utc_now_iso
from agent.risk_engine import RiskAssessment
from agent.policy_engine import PolicyDecision, DECISION_BLOCK
from agent.logger import get_logger

logger = get_logger(__name__)

# Priority order used to pick the "headline" detector-based alert type
# when multiple sensitive data types are found in the same file.
DETECTOR_PRIORITY = ["CREDIT_CARD", "AADHAAR", "PAN", "EMAIL", "PHONE"]

DETECTOR_ALERT_TYPE = {
    "PAN": "PAN_DETECTED",
    "AADHAAR": "AADHAAR_DETECTED",
    "CREDIT_CARD": "CREDIT_CARD_DETECTED",
    "EMAIL": "EMAIL_DETECTED",
    "PHONE": "PHONE_DETECTED",
}


@dataclass
class Alert:
    """In-memory representation of a generated alert (mirrors the alerts table)."""
    id: str
    alert_type: str
    risk_score: int
    severity: str
    os_user: Optional[str]
    file_name: Optional[str]
    file_path: Optional[str]
    message: str
    timestamp: str

    def to_dict(self) -> dict:
        """Serialize to the exact dict shape required by the specification."""
        return {
            "id": self.id,
            "type": self.alert_type,
            "risk_score": self.risk_score,
            "user": self.os_user,
            "file": self.file_name,
            "time": self.timestamp,
        }


class AlertManager:
    """
    Generates and persists alerts based on RiskAssessment + PolicyDecision
    pairs produced by the upstream engines.
    """

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def raise_alerts(
        self,
        assessment: RiskAssessment,
        decision: PolicyDecision,
        file_name: str,
        file_path: str,
        os_user: Optional[str],
        risk_log_id: Optional[int] = None,
    ) -> List[Alert]:
        """
        Inspect the assessment/decision pair and create zero or more
        Alert records as appropriate. Returns the list of Alerts created
        (empty if `decision.should_alert` is False and no BLOCK occurred).
        """
        if not decision.should_alert and decision.decision != DECISION_BLOCK:
            return []

        alerts: List[Alert] = []
        timestamp = utc_now_iso()

        # 1) Transfer-blocked alert takes priority when applicable.
        if decision.decision == DECISION_BLOCK:
            message = (
                f"Transfer of '{file_name}' was BLOCKED. Risk score "
                f"{assessment.risk_score} ({assessment.sensitivity}). "
                f"Matched rules: {', '.join(assessment.matched_rules) or 'N/A'}."
            )
            alerts.append(
                self._create_alert(
                    alert_type="TRANSFER_BLOCKED",
                    assessment=assessment,
                    os_user=os_user,
                    file_name=file_name,
                    file_path=file_path,
                    message=message,
                    timestamp=timestamp,
                    risk_log_id=risk_log_id,
                )
            )

        # 2) Detector-specific alert for the highest-priority sensitive
        #    data type found (kept separate from TRANSFER_BLOCKED so the
        #    dashboard can show *what* was found, not just *that* it was
        #    blocked).
        headline_detector = self._pick_headline_detector(assessment.match_counts)
        if headline_detector:
            alert_type = DETECTOR_ALERT_TYPE[headline_detector]
            count = assessment.match_counts.get(headline_detector, 0)
            message = (
                f"{headline_detector} pattern detected {count} time(s) in "
                f"'{file_name}'. Risk score {assessment.risk_score} "
                f"({assessment.sensitivity})."
            )
            alerts.append(
                self._create_alert(
                    alert_type=alert_type,
                    assessment=assessment,
                    os_user=os_user,
                    file_name=file_name,
                    file_path=file_path,
                    message=message,
                    timestamp=timestamp,
                    risk_log_id=risk_log_id,
                )
            )

        # 3) Fallback generic alert if nothing specific fired but the
        #    policy engine still flagged this for review (e.g. large file).
        if not alerts:
            message = (
                f"Suspicious transfer detected for '{file_name}'. Risk score "
                f"{assessment.risk_score} ({assessment.sensitivity}). "
                f"Matched rules: {', '.join(assessment.matched_rules) or 'N/A'}."
            )
            alerts.append(
                self._create_alert(
                    alert_type="SUSPICIOUS_TRANSFER",
                    assessment=assessment,
                    os_user=os_user,
                    file_name=file_name,
                    file_path=file_path,
                    message=message,
                    timestamp=timestamp,
                    risk_log_id=risk_log_id,
                )
            )

        return alerts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _create_alert(
        self,
        alert_type: str,
        assessment: RiskAssessment,
        os_user: Optional[str],
        file_name: str,
        file_path: str,
        message: str,
        timestamp: str,
        risk_log_id: Optional[int],
    ) -> Alert:
        """Persist a single alert via DatabaseManager and return the in-memory Alert object."""
        alert_id = self.db.insert_alert(
            alert_type=alert_type,
            risk_score=assessment.risk_score,
            severity=assessment.sensitivity,
            os_user=os_user,
            file_name=file_name,
            file_path=file_path,
            message=message,
            risk_log_id=risk_log_id,
            timestamp=timestamp,
        )
        return Alert(
            id=alert_id,
            alert_type=alert_type,
            risk_score=assessment.risk_score,
            severity=assessment.sensitivity,
            os_user=os_user,
            file_name=file_name,
            file_path=file_path,
            message=message,
            timestamp=timestamp,
        )

    @staticmethod
    def _pick_headline_detector(match_counts: dict) -> Optional[str]:
        """Return the highest-priority detector name present in match_counts, or None."""
        for detector in DETECTOR_PRIORITY:
            if match_counts.get(detector, 0) > 0:
                return detector
        return None
