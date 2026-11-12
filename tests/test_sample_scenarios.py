"""Verification test suite for all 24 illustrative test scenarios in data/sample_scenarios.json."""

import json
from pathlib import Path
import pytest

from modules.message_detector import MessageScamDetector
from modules.url_analyzer import SuspiciousUrlAnalyzer
from modules.job_scam_detector import JobScamDetector
from modules.payment_fraud_detector import PaymentFraudDetector


@pytest.fixture
def scenarios():
    path = Path(__file__).resolve().parent.parent / "data" / "sample_scenarios.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_scenario_counts(scenarios):
    assert len(scenarios["message_detector"]) >= 6
    assert len(scenarios["url_analyzer"]) >= 6
    assert len(scenarios["job_detector"]) >= 6
    assert len(scenarios["payment_detector"]) >= 6
    total = sum(len(v) for v in scenarios.values())
    assert total >= 24


def test_message_detector_scenarios(scenarios):
    for item in scenarios["message_detector"]:
        eval_res, indicators = MessageScamDetector.analyze(item["content"])
        assert 0 <= eval_res.score <= 100
        # If expected is CRITICAL, risk level must be CRITICAL
        if item["risk_expected"] == "CRITICAL":
            assert eval_res.level == "CRITICAL", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"
        elif item["risk_expected"] == "LOW":
            assert eval_res.level == "LOW", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"


def test_url_analyzer_scenarios(scenarios):
    for item in scenarios["url_analyzer"]:
        eval_res, parsed, indicators = SuspiciousUrlAnalyzer.analyze(item["content"])
        assert 0 <= eval_res.score <= 100
        if item["risk_expected"] == "CRITICAL":
            assert eval_res.level == "CRITICAL", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"
        elif item["risk_expected"] == "LOW":
            assert eval_res.level == "LOW", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"


def test_job_detector_scenarios(scenarios):
    for item in scenarios["job_detector"]:
        eval_res, indicators = JobScamDetector.analyze(item["content"])
        assert 0 <= eval_res.score <= 100
        if item["risk_expected"] == "CRITICAL":
            assert eval_res.level == "CRITICAL", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"
        elif item["risk_expected"] == "LOW":
            assert eval_res.level == "LOW", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"


def test_payment_detector_scenarios(scenarios):
    for item in scenarios["payment_detector"]:
        eval_res, indicators = PaymentFraudDetector.analyze(item["content"])
        assert 0 <= eval_res.score <= 100
        if item["risk_expected"] == "CRITICAL":
            assert eval_res.level == "CRITICAL", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"
        elif item["risk_expected"] == "LOW":
            assert eval_res.level == "LOW", f"Failed for {item['id']}: got {eval_res.level} ({eval_res.score})"

