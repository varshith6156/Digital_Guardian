"""Tests for Fake Job & Internship Scam Detector."""

import pytest
from modules.job_scam_detector import JobScamDetector


def test_empty_job_text():
    evaluation, indicators = JobScamDetector.analyze("")
    assert evaluation.score == 0
    assert evaluation.level == "LOW"
    assert len(indicators) == 0


def test_registration_and_deposit_fee():
    text = "Congratulations! You are directly selected for the role. Please pay refundable security deposit of Rs 2,500 for company laptop."
    evaluation, indicators = JobScamDetector.analyze(text)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "JOB_TRAINING_EQUIPMENT_DEPOSIT" in rule_ids or "JOB_REGISTRATION_FEE" in rule_ids


def test_free_email_google_impersonator():
    text = "Google Recruitment Team has approved your profile. Send resume to hr-google-recruiter@gmail.com for appointment letter."
    evaluation, indicators = JobScamDetector.analyze(text)
    assert evaluation.score >= 50
    assert evaluation.level in ("HIGH", "CRITICAL")
    rule_ids = [i.rule_id for i in indicators]
    assert "JOB_SUSPICIOUS_RECRUITER_CONTACT" in rule_ids


def test_telegram_task_scam():
    text = "Work from home! Like youtube videos and earn $500 daily. Message on Telegram @WorkOfficial to join."
    evaluation, indicators = JobScamDetector.analyze(text)
    assert evaluation.score >= 50
    assert evaluation.level in ("HIGH", "CRITICAL")


def test_legitimate_job_offer():
    text = (
        "Dear Alex, Following up on your on-site interviews, we are pleased to offer you the position "
        "of Senior Backend Engineer at Acme Software Inc. Your benefits and equity package are detailed "
        "in the official portal at careers.acmesoftware.com."
    )
    evaluation, indicators = JobScamDetector.analyze(text)
    assert evaluation.score < 25
    assert evaluation.level == "LOW"

