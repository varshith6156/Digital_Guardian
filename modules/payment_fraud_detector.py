"""Payment Fraud Detector for Digital Guardian AI.

Analyzes financial transactions, UPI instructions, refund requests, and
banking communications for fraudulent patterns including collect-request scams,
QR code deception, remote-access app installation, and fake support impersonation.
"""

from __future__ import annotations
import re
from typing import List, Tuple
from core.risk_engine import DetectedIndicator, RiskEngine, RiskEvaluation


class PaymentFraudDetector:
    """Detects fraud signatures in payment-related instructions and messages."""

    MODULE_NAME = "Payment Fraud Detector"

    RULES = [
        (
            "PAY_UPI_COLLECT_PRESSURE",
            "UPI Collect Request Deception",
            "UPI Manipulation",
            "CRITICAL",
            55,
            "Instructs victim to accept/approve a UPI collect request to 'receive' money. Approving a collect request TRANSFERS money out of your account.",
            [
                r"\b(?:accept|approve|click on|open)\b[^\n.]{0,35}\b(?:collect request|request from|payment request)\b[^\n.]{0,35}\b(?:to receive|for cashback|to get money|to credit)\b",
                r"\b(?:sent you a collect request of|approve request in (?:gpay|phonepe|paytm|bhim))\b",
            ],
        ),
        (
            "PAY_QR_CODE_RECEIVE_SCAM",
            "QR Code Scan to Receive Funds Deception",
            "UPI Manipulation",
            "CRITICAL",
            55,
            "Claims you must scan a QR code and enter a PIN to receive funds. Scanning a QR code is strictly for making payments, never receiving them.",
            [
                r"\b(?:scan (?:this )?qr code|scan qr)\b[^\n.]{0,40}\b(?:to receive|to get|for receiving|for refund|to credit (?:money|cashback|amount))\b",
                r"\b(?:scan qr and enter pin|scan qr code to accept payment)\b",
            ],
        ),
        (
            "PAY_RECEIVE_PIN_REQUEST",
            "PIN or MPIN Required to 'Receive' Money",
            "Credential Harvesting",
            "CRITICAL",
            55,
            "Directs the user to enter their UPI PIN, MPIN, or ATM PIN to receive money or refunds. PINs are never required to receive money.",
            [
                r"\b(?:enter (?:your )?(?:upi|atm|m)?pin)\b[^\n.]{0,35}\b(?:to receive|to credit|for refund|to accept payment|to unlock cashback)\b",
                r"\b(?:enter pin to receive money|pin is required to transfer money to your account)\b",
            ],
        ),
        (
            "PAY_REMOTE_ACCESS_APP",
            "Remote Access Software Solicitation",
            "Device Takeover",
            "CRITICAL",
            55,
            "Instructs victim to install remote desktop control software (AnyDesk, TeamViewer, RustDesk, QuickSupport) under guise of technical assistance.",
            [
                r"\b(?:install|download)\b[^\n.]{0,30}\b(?:anydesk|teamviewer|rustdesk|quicksupport|ultraviewer|zoho assist)\b",
                r"\b(?:share 9-digit code|give remote access|grant screen share)\b[^\n.]{0,30}\b(?:for refund|to verify bank|to executive)\b",
            ],
        ),
        (
            "PAY_FAKE_REFUND_OVERPAYMENT",
            "Accidental Overpayment / Fake Refund Trap",
            "Social Engineering",
            "HIGH",
            38,
            "Claims to have accidentally overpaid or transferred excess funds and demands an immediate refund or reverse transfer.",
            [
                r"\b(?:transferred by mistake|sent by error|overpaid|accidentally sent|transferred excess)\b",
                r"\b(?:refund|send back|return immediately)\b[^\n.]{0,35}\b(?:via upi|to my number|excess amount)\b",
                r"\b(?:refund initiated|refund pending)\b[^\n.]{0,30}\b(?:call customer care|click link to process refund)\b",
            ],
        ),
        (
            "PAY_SUPPORT_IMPERSONATION",
            "Payment Gateway / Customer Support Impersonation",
            "Brand Impersonation",
            "HIGH",
            35,
            "Impersonates official payment gateways, banking support, or fraud departments (PhonePe, Paytm, Google Pay, Razorpay, PayPal).",
            [
                r"\b(?:phonepe|gpay|google pay|paytm|razorpay|paypal|bhim upi)\b[^\n.]{0,30}\b(?:helpdesk|customer support|fraud department|nodal officer|support executive)\b",
                r"\b(?:calling from|message from)\s+(?:bank fraud department|payment gateway support)\b",
            ],
        ),
        (
            "PAY_ADVANCE_ESCROW_CUSTOMS",
            "Advance Delivery / Escrow / Holding Fee",
            "Advance Fee Scam",
            "HIGH",
            35,
            "Requires seller or buyer to deposit advance holding funds, insurance fees, or customs clearance before release.",
            [
                r"\b(?:customs clearance charge|courier insurance fee|holding deposit|escrow charge)\b[^\n.]{0,35}\b(?:must be paid|is required|before delivery)\b",
                r"\b(?:army officer|military personnel)\b[^\n.]{0,40}\b(?:buying on olx|buying item|advance payment link)\b",
            ],
        ),
        (
            "PAY_URGENCY_THREAT",
            "Account Blocking Urgency",
            "Psychological Pressure",
            "MEDIUM",
            24,
            "Creates immediate time panic threatening freezing of wallet balance, penalty fines, or bank lien.",
            [
                r"\b(?:wallet will be blocked|account frozen|penalty fine of|lien placed on account)\b[^\n.]{0,30}\b(?:within \d+|if not paid|immediately)\b",
                r"\b(?:last warning|clear pending due within)\s+\d+\s*(?:minutes?|hours?)\b",
            ],
        ),
    ]

    @classmethod
    def analyze(cls, text: str) -> Tuple[RiskEvaluation, List[DetectedIndicator]]:
        """Scans payment messages and transaction claims for deceptive patterns."""
        if not text or not text.strip():
            empty_eval = RiskEngine.evaluate([])
            return empty_eval, []

        indicators: List[DetectedIndicator] = []

        for rule_id, title, category, severity, weight, description, patterns in cls.RULES:
            matched_for_rule = False
            for pat in patterns:
                for match in re.finditer(pat, text, flags=re.IGNORECASE):
                    matched_str = match.group(0).strip()
                    span = (match.start(), match.end())
                    indicators.append(
                        DetectedIndicator(
                            rule_id=rule_id,
                            title=title,
                            category=category,
                            severity=severity,
                            weight=weight,
                            description=description,
                            matched_text=matched_str,
                            span=span,
                        )
                    )
                    matched_for_rule = True
                    break
                if matched_for_rule:
                    break

        evaluation = RiskEngine.evaluate(indicators)
        return evaluation, evaluation.indicators
