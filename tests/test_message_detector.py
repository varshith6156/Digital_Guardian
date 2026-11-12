"""Tests for Message Scam Detector."""

import pytest
from modules.message_detector import MessageScamDetector


def test_empty_message():
    evaluation, indicators = MessageScamDetector.analyze("")
    assert evaluation.score == 0
    assert evaluation.level == "LOW"
    assert len(indicators) == 0

    evaluation, indicators = MessageScamDetector.analyze("   \n\t  ")
    assert evaluation.score == 0
    assert evaluation.level == "LOW"


def test_otp_phishing_message():
    msg = "Dear user, please share your OTP to prevent account suspension immediately."
    evaluation, indicators = MessageScamDetector.analyze(msg)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [ind.rule_id for ind in indicators]
    assert "MSG_CREDENTIAL_REQUEST" in rule_ids


def test_lottery_advance_fee():
    msg = "Congratulations! You have won $1,000,000 in lucky draw. Pay processing fee of $200 to receive your prize."
    evaluation, indicators = MessageScamDetector.analyze(msg)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"


def test_electricity_threat():
    msg = "Urgent: Your electricity power will be disconnected tonight. Call officer immediately to avoid legal action."
    evaluation, indicators = MessageScamDetector.analyze(msg)
    assert evaluation.score >= 50
    assert evaluation.level in ("HIGH", "CRITICAL")


def test_legitimate_transaction():
    msg = "Your account ending in 1234 was debited by $12.50 at Supermarket on 12-Nov-2026. Balance: $500.00."
    evaluation, indicators = MessageScamDetector.analyze(msg)
    assert evaluation.score < 25
    assert evaluation.level == "LOW"


def test_very_long_input():
    long_msg = "Hello team, this is regular update. " * 300 + " Share OTP immediately or account blocked."
    evaluation, indicators = MessageScamDetector.analyze(long_msg)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"

