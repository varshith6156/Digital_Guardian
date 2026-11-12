"""Message Scam Detector for Digital Guardian AI.

Analyzes SMS, WhatsApp, email, and social media communications for
deceptive social engineering, credential harvesting, extortion, urgency,
and impersonation tactics.
"""

from __future__ import annotations
import re
from typing import List, Tuple
from core.risk_engine import DetectedIndicator, RiskEngine, RiskEvaluation


class MessageScamDetector:
    """Detects fraud indicators in text communications."""

    MODULE_NAME = "Message Scanner"

    # Pattern definitions: (rule_id, title, category, severity, weight, description, regex_list)
    RULES = [
        (
            "MSG_CREDENTIAL_REQUEST",
            "Credential or OTP Request",
            "Credential Harvesting",
            "CRITICAL",
            55,
            "Solicits sensitive secrets such as OTP, PIN, password, or CVV. Legitimate organizations never request these.",
            [
                r"\b(?:share|send|enter|verify|provide|give)\b[^\n.]{0,30}\b(?:otp|one[- ]time[- ]password|pin|mpin|cvv|password|passcode)\b",
                r"\b(?:otp|one[- ]time[- ]password|pin|cvv)\b[^\n.]{0,25}\b(?:is required|must be shared|to confirm|to cancel)\b",
                r"\b(?:enter your|share your)\b[^\n.]{0,25}\b(?:netbanking|internet banking|credit card details|atm pin)\b",
            ],
        ),
        (
            "MSG_ADVANCE_FEE",
            "Advance Fee / Payment Solicitation",
            "Financial Solicitation",
            "CRITICAL",
            50,
            "Demands an advance fee, processing charge, or clearance tax to release funds, prizes, or parcels.",
            [
                r"\b(?:pay|transfer|deposit|send)\b[^\n.]{0,35}\b(?:fee|advance|processing charge|clearance|tax|refundable deposit|charge)\b[^\n.]{0,25}\b(?:to receive|to claim|to unlock|to release|in advance)\b",
                r"\b(?:processing fee|registration fee|courier charge|customs fee)\b[^\n.]{0,30}\b(?:of\s+(?:\$|₹|rs|usd|inr|\d+)|is required)\b",
            ],
        ),
        (
            "MSG_ACCOUNT_SUSPENSION",
            "Account Suspension or Threat",
            "Extortion & Intimidation",
            "HIGH",
            38,
            "Threatens imminent account closure, disconnection, or legal consequences to provoke panic.",
            [
                r"\b(?:account|service|sim card|electricity|connection)\b[^\n.]{0,30}\b(?:will be suspended|has been blocked|will be disconnected|deactivated|terminated)\b",
                r"\b(?:electricity power will be cut|power disconnected tonight|sim will be blocked)\b",
                r"\b(?:legal action|police case|arrest warrant|court notice|cbi inquiry|fir registered)\b[^\n.]{0,30}\b(?:against you|unless|immediately)\b",
            ],
        ),
        (
            "MSG_KYC_VERIFICATION",
            "Urgent KYC / Document Threat",
            "Social Engineering",
            "HIGH",
            35,
            "Urges immediate KYC (Know Your Customer) or Aadhaar/PAN re-verification to prevent account suspension.",
            [
                r"\b(?:kyc|pan card|aadhaar|id document)\b[^\n.]{0,30}\b(?:is pending|expired|suspended|not updated|re-verify|mandatory)\b",
                r"\b(?:update|complete|verify)\s+your\s+(?:kyc|pan|aadhaar)\b[^\n.]{0,30}\b(?:immediately|within \d+|or account)\b",
            ],
        ),
        (
            "MSG_LOTTERY_REWARD",
            "Unexpected Lottery or Prize Claim",
            "Deceptive Bait",
            "HIGH",
            35,
            "Promises unexpected windfalls, lotteries, cash awards, or luxury gifts to entice the recipient.",
            [
                r"\b(?:congratulations|congrats)\b[^\n.]{0,30}\b(?:won|selected for|winner of)\b[^\n.]{0,30}\b(?:\$|₹|rs|usd|inr|\d+(?:,\d+)*|lottery|lucky draw|iphone|mercedes|kbc)\b",
                r"\b(?:you have won|cash prize of|lucky winner of)\b[^\n.]{0,35}\b(?:\$|₹|rs|lakh|crore|jackpot)\b",
            ],
        ),
        (
            "MSG_IMPERSONATION",
            "Brand or Authority Impersonation",
            "Impersonation",
            "HIGH",
            32,
            "Impersonates well-known financial institutions, couriers, or government agencies.",
            [
                r"\b(?:dear customer|user)\b[^\n.]{0,35}\b(?:sbi|hdfc|icici|axis bank|state bank|wells fargo|chase bank|bank of america|paytm|phonepe|gpay)\b",
                r"\b(?:fedex|dhl|india post|usps|blue dart|ups)\b[^\n.]{0,40}\b(?:parcel|package|shipment|delivery failed|customs)\b",
                r"\b(?:income tax department|internal revenue service|irs|customs department|rbi|cyber police)\b",
            ],
        ),
        (
            "MSG_URGENCY_LANGUAGE",
            "Artificial Urgency and Pressure",
            "Psychological Manipulation",
            "MEDIUM",
            22,
            "Imposes a tight deadline (e.g. 15 minutes, 24 hours) to impair logical scrutiny and cause hasty action.",
            [
                r"\b(?:within\s+\d+\s*(?:mins?|minutes?|hours?|hrs?)|immediately|urgently|at once|act now|last chance|final warning|today only)\b",
                r"\b(?:expires in|valid only for next)\s+\d+\s*(?:minutes?|hours?)\b",
            ],
        ),
        (
            "MSG_SUSPICIOUS_LINK",
            "Embedded Suspicious Link / Shortener",
            "Malicious Infrastructure",
            "HIGH",
            32,
            "Contains a shortened link or untrusted domain structure designed to mask the final destination.",
            [
                r"https?://(?:bit\.ly|tinyurl\.com|is\.gd|t\.co|rb\.gy|cutt\.ly|ow\.ly|shorturl\.at)/\S+",
                r"https?://\S+\.(?:xyz|top|buzz|club|work|icu|vip|cfd|fit|link)(?:/\S*)?",
                r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/\S*)?",
            ],
        ),
        (
            "MSG_SENSITIVE_INFO_REQUEST",
            "Identity Document Solicitation",
            "Data Harvesting",
            "MEDIUM",
            24,
            "Requests sensitive identity papers like Aadhaar, SSN, passport copies, or bank statements.",
            [
                r"\b(?:send|whatsapp|submit|upload)\b[^\n.]{0,25}\b(?:aadhaar|ssn|social security|passport|bank statement|id card photo)\b",
                r"\b(?:photo of your|copy of your)\s+(?:debit card|cheque|pan card|aadhaar)\b",
            ],
        ),
    ]

    @classmethod
    def analyze(cls, text: str) -> Tuple[RiskEvaluation, List[DetectedIndicator]]:
        """Scans message text against all indicators and computes the risk evaluation."""
        if not text or not text.strip():
            empty_eval = RiskEngine.evaluate([])
            return empty_eval, []

        indicators: List[DetectedIndicator] = []
        text_lower = text.lower()

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
                    # Only one match per pattern to keep evidence clear
                    break
                if matched_for_rule:
                    break

        evaluation = RiskEngine.evaluate(indicators)
        return evaluation, evaluation.indicators

