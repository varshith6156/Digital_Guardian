"""Tests for Central Risk Scoring Engine."""

import pytest
from core.risk_engine import RiskEngine, DetectedIndicator


def test_empty_indicators():
    evaluation = RiskEngine.evaluate([])
    assert evaluation.score == 0
    assert evaluation.level == "LOW"
    assert "No suspicious indicators" in evaluation.explanation
    assert len(evaluation.indicators) == 0


def test_low_indicators():
    indicators = [
        DetectedIndicator(
            rule_id="RULE_LOW_1",
            title="Low Test 1",
            category="Test",
            severity="LOW",
            description="Testing low rule",
            matched_text="hello",
        ),
        DetectedIndicator(
            rule_id="RULE_LOW_2",
            title="Low Test 2",
            category="Test",
            severity="LOW",
            description="Testing low rule 2",
            matched_text="world",
        ),
    ]
    evaluation = RiskEngine.evaluate(indicators)
    assert 0 <= evaluation.score <= 24
    assert evaluation.level == "LOW"


def test_medium_indicators():
    indicators = [
        DetectedIndicator(
            rule_id="RULE_MED_1",
            title="Medium Test",
            category="Test",
            severity="MEDIUM",
            description="Testing medium rule",
            matched_text="verify now",
        )
    ]
    evaluation = RiskEngine.evaluate(indicators)
    assert 25 <= evaluation.score <= 49
    assert evaluation.level == "MEDIUM"


def test_high_indicators():
    indicators = [
        DetectedIndicator(
            rule_id="RULE_HIGH_1",
            title="High Test",
            category="Test",
            severity="HIGH",
            description="Testing high rule",
            matched_text="account blocked",
        )
    ]
    evaluation = RiskEngine.evaluate(indicators)
    assert 50 <= evaluation.score <= 74
    assert evaluation.level == "HIGH"


def test_critical_indicators():
    indicators = [
        DetectedIndicator(
            rule_id="RULE_CRIT_1",
            title="Critical Test",
            category="Test",
            severity="CRITICAL",
            description="Testing critical rule",
            matched_text="share your otp",
        )
    ]
    evaluation = RiskEngine.evaluate(indicators)
    assert 75 <= evaluation.score <= 100
    assert evaluation.level == "CRITICAL"


def test_score_never_exceeds_100():
    # Many heavy indicators
    indicators = []
    for i in range(25):
        indicators.append(
            DetectedIndicator(
                rule_id=f"RULE_CRIT_{i}",
                title=f"Critical {i}",
                category="Extortion",
                severity="CRITICAL",
                description="Heavy attack",
                matched_text=f"attack snippet {i}",
            )
        )
    evaluation = RiskEngine.evaluate(indicators)
    assert evaluation.score == 100
    assert evaluation.level == "CRITICAL"


def test_deduplication():
    ind1 = DetectedIndicator(
        rule_id="SAME_RULE",
        title="Same Title",
        category="Test",
        severity="MEDIUM",
        weight=20,
        description="Desc",
        matched_text="urgent",
    )
    ind2 = DetectedIndicator(
        rule_id="SAME_RULE",
        title="Same Title",
        category="Test",
        severity="MEDIUM",
        weight=25,
        description="Desc",
        matched_text="urgent",
    )
    deduped = RiskEngine.deduplicate_indicators([ind1, ind2])
    assert len(deduped) == 1
    assert deduped[0].weight == 25

