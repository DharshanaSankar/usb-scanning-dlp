"""
tests/test_policy.py
-----------------------
Unit tests for agent.policy_engine.PolicyEngine.

Validates the Phase 1 policy rule:
    score > threshold (default 60) -> BLOCK
    else                            -> ALLOW (with alert if MEDIUM/HIGH)

Also confirms there is NO approval workflow / override mechanism present,
consistent with the Phase 1 scope.
"""

from __future__ import annotations

import pytest

from agent.policy_engine import PolicyEngine, DECISION_ALLOW, DECISION_BLOCK
from agent.risk_engine import RiskAssessment


def make_assessment(score: int, sensitivity: str) -> RiskAssessment:
    return RiskAssessment(
        file_path="test.txt",
        risk_score=score,
        sensitivity=sensitivity,
        matched_rules=[],
        match_counts={},
    )


@pytest.fixture()
def policy_engine() -> PolicyEngine:
    return PolicyEngine(block_threshold=60)


def test_score_above_threshold_is_blocked(policy_engine: PolicyEngine):
    assessment = make_assessment(score=61, sensitivity="HIGH")
    decision = policy_engine.evaluate(assessment)
    assert decision.decision == DECISION_BLOCK
    assert decision.should_alert is True


def test_score_at_threshold_is_allowed(policy_engine: PolicyEngine):
    """Boundary check: rule is strictly '> threshold', so exactly 60 must ALLOW."""
    assessment = make_assessment(score=60, sensitivity="MEDIUM")
    decision = policy_engine.evaluate(assessment)
    assert decision.decision == DECISION_ALLOW


def test_score_below_threshold_is_allowed(policy_engine: PolicyEngine):
    assessment = make_assessment(score=10, sensitivity="LOW")
    decision = policy_engine.evaluate(assessment)
    assert decision.decision == DECISION_ALLOW
    assert decision.should_alert is False  # LOW sensitivity + allowed = no alert needed


def test_allowed_medium_sensitivity_still_raises_informational_alert(policy_engine: PolicyEngine):
    assessment = make_assessment(score=45, sensitivity="MEDIUM")
    decision = policy_engine.evaluate(assessment)
    assert decision.decision == DECISION_ALLOW
    assert decision.should_alert is True  # MEDIUM/HIGH always informs even when allowed


def test_custom_threshold_is_respected():
    custom_engine = PolicyEngine(block_threshold=80)
    assessment = make_assessment(score=70, sensitivity="HIGH")
    decision = custom_engine.evaluate(assessment)
    assert decision.decision == DECISION_ALLOW  # 70 <= 80 custom threshold


def test_no_approval_workflow_attributes_exist(policy_engine: PolicyEngine):
    """
    Phase 1 explicitly excludes approval workflows. This test guards
    against accidental scope creep by asserting the PolicyDecision
    object never exposes approval-queue-related fields.
    """
    assessment = make_assessment(score=90, sensitivity="HIGH")
    decision = policy_engine.evaluate(assessment)
    forbidden_attrs = ["approval_required", "approver", "pending_approval", "approved_by"]
    for attr in forbidden_attrs:
        assert not hasattr(decision, attr)
