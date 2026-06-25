"""
agent/policy_engine.py
------------------------
Policy Engine.

Implements the simple rule-based access decision required for Phase 1:

    if risk_score > POLICY_BLOCK_THRESHOLD (default 60):
        BLOCK the transfer
    else:
        ALLOW the transfer
        (an informational alert may still be raised for MEDIUM/HIGH
         sensitivity findings even when allowed, for audit purposes)

NOTE: There is intentionally NO approval workflow in Phase 1 (no manager
review/override queue). The policy decision is final and automatic.
Approval-based workflows are explicitly scoped to Phase 2 per the
project requirements.

"Blocking" in Phase 1 means: the transfer is flagged, logged, and an
alert is raised with decision=BLOCK. Phase 1 is a *monitoring and
detection* system; it does not implement kernel-level write interception
(e.g. a filesystem filter driver) to physically prevent the copy, since
that requires elevated OS-specific driver development out of scope for
a regex/SQLite/Streamlit stack. This is documented clearly in the README
"Scope and Limitations" section.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from config.settings import settings
from agent.risk_engine import RiskAssessment
from agent.logger import get_logger

logger = get_logger(__name__)

DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"


@dataclass
class PolicyDecision:
    """Outcome of evaluating the policy engine against a RiskAssessment."""
    decision: str             # ALLOW or BLOCK
    risk_score: int
    sensitivity: str
    reason: str
    should_alert: bool        # whether an alert should be raised regardless of decision


class PolicyEngine:
    """
    Stateless decision engine. Pure function-like behavior wrapped in a
    class for consistency with the rest of the OOP-structured agent and
    to allow the block threshold to be overridden per-instance (useful
    in unit tests).
    """

    def __init__(self, block_threshold: Optional[int] = None) -> None:
        self.block_threshold = (
            block_threshold if block_threshold is not None else settings.policy_block_threshold
        )

    def evaluate(self, assessment: RiskAssessment) -> PolicyDecision:
        """
        Apply the block-threshold rule to a RiskAssessment and return a
        PolicyDecision describing the outcome.
        """
        if assessment.risk_score > self.block_threshold:
            decision = DECISION_BLOCK
            reason = (
                f"Risk score {assessment.risk_score} exceeds block threshold "
                f"{self.block_threshold} (sensitivity={assessment.sensitivity})"
            )
            should_alert = True
        else:
            decision = DECISION_ALLOW
            reason = (
                f"Risk score {assessment.risk_score} is within the allowed threshold "
                f"{self.block_threshold} (sensitivity={assessment.sensitivity})"
            )
            # Still raise an informational alert for MEDIUM/HIGH findings
            # even when allowed, so security teams have full audit
            # visibility -- this does not change the allow decision itself.
            should_alert = assessment.sensitivity in ("MEDIUM", "HIGH")

        logger.info(
            "Policy decision: file=%s decision=%s score=%d threshold=%d",
            assessment.file_path, decision, assessment.risk_score, self.block_threshold,
        )

        return PolicyDecision(
            decision=decision,
            risk_score=assessment.risk_score,
            sensitivity=assessment.sensitivity,
            reason=reason,
            should_alert=should_alert,
        )
