"""Central Risk Scoring Engine for Digital Guardian AI.

Evaluates detected indicators, deduplicates them, calculates a bounded 0-100
risk score with transparent severity tiers, and generates plain-language
explanations for users.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional


SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

SEVERITY_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 35,
    "CRITICAL": 55,
}

RISK_TIERS = [
    (0, 24, "LOW", "#10B981", "Minimal or no suspicious indicators detected."),
    (25, 49, "MEDIUM", "#F59E0B", "Suspicious patterns detected. Exercise caution and verify."),
    (50, 74, "HIGH", "#F97316", "Strong indicators of fraud or deception. Do not proceed without strict verification."),
    (75, 100, "CRITICAL", "#EF4444", "Severe danger flags detected. Highly probable scam or attack. Avoid engaging."),
]


@dataclass
class DetectedIndicator:
    """Represents a single suspicious pattern detected in user content."""
    rule_id: str
    title: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    matched_text: str = ""
    span: Tuple[int, int] = (0, 0)
    weight: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in SEVERITY_LEVELS:
            self.severity = "MEDIUM"
        if self.weight is None:
            self.weight = SEVERITY_WEIGHTS.get(self.severity, 20)


@dataclass
class RiskEvaluation:
    """Complete result of the risk engine's evaluation."""
    score: int
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    color: str
    summary_verdict: str
    explanation: str
    indicators: List[DetectedIndicator]
    indicators_by_severity: Dict[str, List[DetectedIndicator]]
    raw_points: int


class RiskEngine:
    """Central risk calculator for all fraud detection modules."""

    @staticmethod
    def get_tier(score: int) -> Tuple[str, str, str]:
        """Returns (level, color, summary_verdict) for a given 0-100 score."""
        clamped_score = max(0, min(100, int(score)))
        for min_val, max_val, level, color, verdict in RISK_TIERS:
            if min_val <= clamped_score <= max_val:
                return level, color, verdict
        return "CRITICAL", "#EF4444", RISK_TIERS[-1][4]

    @classmethod
    def deduplicate_indicators(
        cls, indicators: List[DetectedIndicator]
    ) -> List[DetectedIndicator]:
        """Deduplicates indicators based on rule_id and matched text overlap."""
        seen: Dict[str, DetectedIndicator] = {}
        for ind in indicators:
            key = f"{ind.rule_id}::{ind.matched_text.strip().lower()}"
            if key not in seen:
                seen[key] = ind
            else:
                # Keep the one with higher weight if duplicate
                if (ind.weight or 0) > (seen[key].weight or 0):
                    seen[key] = ind
        return list(seen.values())

    @classmethod
    def evaluate(cls, indicators: List[DetectedIndicator]) -> RiskEvaluation:
        """Evaluates detected indicators and calculates an explainable risk score (0-100)."""
        unique_indicators = cls.deduplicate_indicators(indicators)

        by_severity: Dict[str, List[DetectedIndicator]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for ind in unique_indicators:
            by_severity[ind.severity].append(ind)

        crit_count = len(by_severity["CRITICAL"])
        high_count = len(by_severity["HIGH"])
        med_count = len(by_severity["MEDIUM"])
        low_count = len(by_severity["LOW"])

        raw_points = sum(ind.weight or 0 for ind in unique_indicators)

        if not unique_indicators:
            score = 0
            explanation = "No suspicious indicators were identified. The content appears normal, but always stay vigilant."
        elif crit_count > 0:
            # Baseline is 75 (CRITICAL threshold).
            # Each additional critical adds up to 10; remaining high/med/low add fractional points.
            bonus = min(25, (crit_count - 1) * 8 + high_count * 5 + med_count * 2 + low_count * 1)
            score = min(100, 75 + bonus)
            explanation = (
                f"Assigned CRITICAL risk ({score}/100) because {crit_count} critical safety violation(s) "
                f"were detected, such as direct requests for credentials, money transfers, or severe threats."
            )
        elif high_count > 0:
            # Baseline is 50 (HIGH threshold).
            bonus = min(24, (high_count - 1) * 8 + med_count * 4 + low_count * 2)
            score = min(74, 50 + bonus)
            explanation = (
                f"Assigned HIGH risk ({score}/100) because {high_count} significant deception flag(s) "
                f"were identified without confirmed critical credentials leakage."
            )
        elif med_count > 0:
            # Baseline is 25 (MEDIUM threshold).
            bonus = min(24, (med_count - 1) * 6 + low_count * 3)
            score = min(49, 25 + bonus)
            explanation = (
                f"Assigned MEDIUM risk ({score}/100) due to {med_count} ambiguous or mildly suspicious pattern(s). "
                f"Verification is recommended before responding."
            )
        else:
            # Only LOW indicators
            score = min(24, max(5, low_count * 6))
            explanation = (
                f"Assigned LOW risk ({score}/100) with minor informational flags ({low_count} low-severity item(s)). "
                f"No immediate scam patterns detected."
            )

        level, color, verdict = cls.get_tier(score)

        return RiskEvaluation(
            score=score,
            level=level,
            color=color,
            summary_verdict=verdict,
            explanation=explanation,
            indicators=unique_indicators,
            indicators_by_severity=by_severity,
            raw_points=raw_points,
        )

