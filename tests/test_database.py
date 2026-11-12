"""Tests for Database and Privacy Manager."""

import pytest
from pathlib import Path
from database.db_manager import DatabaseManager


@pytest.fixture
def test_db(tmp_path):
    test_db_path = tmp_path / "test_dg.db"
    manager = DatabaseManager(db_path=test_db_path)
    return manager


def test_db_initialization(test_db):
    assert test_db.db_path.exists()
    stats = test_db.get_summary_stats()
    assert stats["total_analyses"] == 0


def test_credential_sanitization():
    raw_text = "My secret OTP is 482910 and card is 4532 1234 5678 9012 with password: SuperSecret!"
    sanitized = DatabaseManager.sanitize_summary(raw_text)
    assert "482910" not in sanitized
    assert "SuperSecret!" not in sanitized
    assert "[REDACTED" in sanitized


def test_save_and_retrieve_analysis(test_db):
    aid = test_db.save_analysis(
        analysis_type="Message Scanner",
        risk_score=85,
        risk_level="CRITICAL",
        raw_text_for_summary="Suspicious test message with OTP 123456",
        indicators_count=2,
    )
    assert aid is not None

    records = test_db.get_recent_history(limit=10)
    assert len(records) == 1
    assert records[0]["analysis_id"] == aid
    assert records[0]["risk_score"] == 85
    assert records[0]["risk_level"] == "CRITICAL"
    assert "123456" not in records[0]["summary"]


def test_summary_stats_aggregation(test_db):
    test_db.save_analysis("Message Scanner", 20, "LOW", "Text 1")
    test_db.save_analysis("Message Scanner", 40, "MEDIUM", "Text 2")
    test_db.save_analysis("URL Analyzer", 80, "CRITICAL", "Text 3")

    stats = test_db.get_summary_stats()
    assert stats["total_analyses"] == 3
    assert stats["counts_by_level"]["LOW"] == 1
    assert stats["counts_by_level"]["MEDIUM"] == 1
    assert stats["counts_by_level"]["CRITICAL"] == 1
    assert stats["counts_by_type"]["Message Scanner"] == 2
    assert stats["counts_by_type"]["URL Analyzer"] == 1


def test_delete_record(test_db):
    aid = test_db.save_analysis("Job Scam Detector", 60, "HIGH", "Job test")
    assert test_db.delete_record(aid) is True
    assert len(test_db.get_recent_history()) == 0


def test_clear_history(test_db):
    test_db.save_analysis("Payment Fraud Detector", 90, "CRITICAL", "Pay test 1")
    test_db.save_analysis("Payment Fraud Detector", 90, "CRITICAL", "Pay test 2")
    assert len(test_db.get_recent_history()) == 2

    assert test_db.clear_history() is True
    assert len(test_db.get_recent_history()) == 0
    stats = test_db.get_summary_stats()
    assert stats["total_analyses"] == 0

