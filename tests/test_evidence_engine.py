"""Tests for Evidence Highlighting & Extraction Engine."""

import pytest
from core.risk_engine import DetectedIndicator
from core.evidence_engine import EvidenceEngine


def test_empty_text_evidence():
    evidence = EvidenceEngine.extract_evidence("", [])
    assert evidence == []

    html = EvidenceEngine.render_highlighted_html("", [])
    assert "empty-text-notice" in html


def test_no_indicator_text():
    text = "This is a normal message with no threat indicators."
    evidence = EvidenceEngine.extract_evidence(text, [])
    assert len(evidence) == 0

    html = EvidenceEngine.render_highlighted_html(text, [])
    assert "safe-text-preview" in html
    assert "normal message" in html


def test_accurate_phrase_matching():
    text = "Please share your OTP immediately to avoid account suspension."
    indicators = [
        DetectedIndicator(
            rule_id="RULE_OTP",
            title="OTP Request",
            category="Credentials",
            severity="CRITICAL",
            description="Requests OTP",
            matched_text="share your OTP",
        ),
        DetectedIndicator(
            rule_id="RULE_URGENCY",
            title="Urgency",
            category="Psychology",
            severity="MEDIUM",
            description="Urgent deadline",
            matched_text="immediately",
        ),
    ]

    evidence = EvidenceEngine.extract_evidence(text, indicators)
    assert len(evidence) == 2
    # Verify that matched text is an exact substring of the original text
    for ev in evidence:
        assert text[ev.start:ev.end] == ev.matched_text


def test_overlapping_phrases_html_safety():
    text = "Your bank account has been blocked immediately."
    # Overlapping phrases: "bank account" and "account has been blocked"
    indicators = [
        DetectedIndicator(
            rule_id="RULE_A",
            title="Rule A",
            category="Category A",
            severity="HIGH",
            description="Desc A",
            matched_text="bank account",
            span=(5, 17),
        ),
        DetectedIndicator(
            rule_id="RULE_B",
            title="Rule B",
            category="Category B",
            severity="CRITICAL",
            description="Desc B",
            matched_text="account has been blocked",
            span=(10, 34),
        ),
    ]

    html_out = EvidenceEngine.render_highlighted_html(text, indicators)
    assert "<mark" in html_out
    assert "</mark>" in html_out
    # Tag balance check: number of opening marks equals closing marks
    assert html_out.count("<mark") == html_out.count("</mark>")

