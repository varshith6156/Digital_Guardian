"""Tests for Payment Fraud Detector."""

import pytest
from modules.payment_fraud_detector import PaymentFraudDetector


def test_empty_payment_text():
    evaluation, indicators = PaymentFraudDetector.analyze("")
    assert evaluation.score == 0
    assert evaluation.level == "LOW"
    assert len(indicators) == 0


def test_upi_collect_request_trap():
    text = "I have sent you a collect request of Rs 5000. Please accept collect request in PhonePe to receive money immediately."
    evaluation, indicators = PaymentFraudDetector.analyze(text)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "PAY_UPI_COLLECT_PRESSURE" in rule_ids


def test_qr_code_receive_scam():
    text = "To get your cashback, scan this QR code and enter your UPI PIN to receive money in your account."
    evaluation, indicators = PaymentFraudDetector.analyze(text)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "PAY_QR_CODE_RECEIVE_SCAM" in rule_ids or "PAY_RECEIVE_PIN_REQUEST" in rule_ids


def test_anydesk_remote_support():
    text = "Calling from PhonePe customer care. Install AnyDesk on your mobile phone to reverse your failed payment."
    evaluation, indicators = PaymentFraudDetector.analyze(text)
    assert evaluation.score >= 75
    assert evaluation.level == "CRITICAL"
    rule_ids = [i.rule_id for i in indicators]
    assert "PAY_REMOTE_ACCESS_APP" in rule_ids


def test_fake_overpayment():
    text = "I transferred $350 by mistake to your number on OLX. Please refund immediately via UPI."
    evaluation, indicators = PaymentFraudDetector.analyze(text)
    assert evaluation.score >= 50
    assert evaluation.level in ("HIGH", "CRITICAL")


def test_legitimate_receipt():
    text = "Payment received: $45.00 from Jane Doe for invoice #INV-1092. Account credited."
    evaluation, indicators = PaymentFraudDetector.analyze(text)
    assert evaluation.score < 25
    assert evaluation.level == "LOW"

