"""Tests for Suspicious URL Analyzer."""

import pytest
from modules.url_analyzer import SuspiciousUrlAnalyzer


def test_empty_url():
    evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze("")
    assert evaluation.score == 0
    assert evaluation.level == "LOW"
    assert len(indicators) == 0


def test_ip_address_host():
    url = "http://192.168.1.105:8080/secure/banking/login"
    evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze(url)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "URL_IP_HOST" in rule_ids
    assert parsed.is_ip_address is True


def test_typosquatting_and_suspicious_tld():
    url = "https://secure-login.paypa1-account-verification.xyz/signin"
    evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze(url)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "URL_TYPOSQUATTING" in rule_ids or "URL_BRAND_SPOOFING" in rule_ids


def test_at_symbol_redirect():
    url = "https://www.paypal.com@phishing-server.top/verify"
    evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze(url)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "URL_AT_SYMBOL_REDIRECT" in rule_ids


def test_shortener():
    url = "https://bit.ly/3xY9qzM"
    evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze(url)
    assert parsed.is_shortener is True
    assert evaluation.level in ("MEDIUM", "HIGH")


def test_legitimate_url():
    url = "https://www.github.com/features/actions"
    evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze(url)
    assert evaluation.score < 25
    assert evaluation.level == "LOW"


def test_malformed_url_resilience():
    # Never raise uncaught exception on malformed URL
    bad_urls = [
        "http://[::1]:9999999",
        "https://///invalid///",
        "ftp://host:port/abc",
        "very-long-url-" * 50 + ".com",
    ]
    for b in bad_urls:
        evaluation, parsed, indicators = SuspiciousUrlAnalyzer.analyze(b)
        assert 0 <= evaluation.score <= 100

