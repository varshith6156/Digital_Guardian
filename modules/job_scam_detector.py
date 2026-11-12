"""Fake Job and Internship Scam Detector for Digital Guardian AI.

Evaluates recruitment correspondence, employment offers, and job listings
for classic fraud markers such as registration fees, guaranteed hiring without
interviews, Telegram-only recruiters, free webmail impersonation, and
unrealistic compensation claims.
"""

from __future__ import annotations
import re
from typing import List, Tuple
from core.risk_engine import DetectedIndicator, RiskEngine, RiskEvaluation


class JobScamDetector:
    """Detects fraud and deception patterns in job and internship offers."""

    MODULE_NAME = "Job Scam Detector"

    RULES = [
        (
            "JOB_REGISTRATION_FEE",
            "Mandatory Registration or Application Fee",
            "Financial Extortion",
            "CRITICAL",
            55,
            "Requires job seekers to pay an upfront registration, application, or processing fee. Legitimate employers never charge candidates to apply.",
            [
                r"\b(?:registration|application|exam|interview|form|seat)\s+fee\b[^\n.]{0,35}\b(?:of\s+(?:\$|₹|rs|usd|inr|\d+)|is required|must pay|to be deposited)\b",
                r"\b(?:pay|deposit|transfer)\b[^\n.]{0,35}\b(?:registration fee|application fee|processing fee|seat booking)\b",
                r"\b(?:nominal|refundable|one-time)\s+(?:fee|deposit|charge)\s+of\b",
            ],
        ),
        (
            "JOB_TRAINING_EQUIPMENT_DEPOSIT",
            "Training / Laptop / Equipment Deposit",
            "Advance Fee Scam",
            "CRITICAL",
            55,
            "Asks candidate to deposit money for laptops, tools, software licenses, or training with a promise of refund later.",
            [
                r"\b(?:refundable\s+)?(?:security\s+deposit|caution\s+deposit|training\s+deposit)\b",
                r"\b(?:laptop|equipment|training|onboarding|software license)\s+(?:fee|deposit|security deposit|cost)\b",
                r"\b(?:pay|deposit)\b[^\n.]{0,60}\b(?:for (?:your )?(?:company\s+)?(?:training|laptop|id card|uniform|work material))\b",
                r"\b(?:refundable security deposit|training charges)\b",
            ],
        ),
        (
            "JOB_GUARANTEED_NO_INTERVIEW",
            "Direct Selection Without Interview",
            "Unrealistic Hiring Process",
            "HIGH",
            38,
            "Claims candidate is directly hired or offers 100% selection guarantee without technical screening or formal interview.",
            [
                r"\b(?:directly selected|selected without interview|direct hiring without|no interview required|100% selection guaranteed|direct appointment letter)\b",
                r"\b(?:selected based on your resume|congratulations! you are appointed)\b[^\n.]{0,35}\b(?:without (?:any )?interview|no test required)\b",
            ],
        ),
        (
            "JOB_UNREALISTIC_COMPENSATION",
            "Absurd or Unrealistic Salary Promises",
            "Deceptive Bait",
            "HIGH",
            35,
            "Offers extraordinarily high income for trivial micro-tasks (e.g. typing, watching YouTube videos, review posting).",
            [
                r"\b(?:earn|daily salary|income|payout)\b[^\n.]{0,30}(?:\$\s*\d{2,}|\d{2,}\s*usd|₹\s*\d{3,}|\d{3,}\s*(?:rs|inr))\b[^\n.]{0,30}\b(?:daily|per day|hourly|for \d+ (?:hours?|mins?))\b",
                r"\b(?:like youtube videos|subscribe channels|simple typing|copy paste|data entry)\b[^\n.]{0,40}\b(?:earn (?:(?:\$|₹|rs|inr)\s*)?\d+|daily payment)\b",
            ],
        ),
        (
            "JOB_SUSPICIOUS_RECRUITER_CONTACT",
            "Free Webmail Impersonating Enterprise",
            "Channel Impersonation",
            "HIGH",
            35,
            "Claims to represent a major enterprise or multinational brand but uses a free public email provider (@gmail, @yahoo, etc.).",
            [
                r"\b(?:google|microsoft|amazon|apple|tcs|infosys|wipro|meta|netflix|accenture|deloitte)\b[^\n]{0,60}\b[a-zA-Z0-9_.+-]+@(?:gmail|yahoo|hotmail|outlook|rediffmail)\.com\b",
                r"\b(?:official hr|recruitment team|careers team)\b[^\n]{0,40}\b[a-zA-Z0-9_.+-]+@(?:gmail|yahoo|hotmail)\.com\b",
            ],
        ),
        (
            "JOB_MESSAGING_ONLY_RECRUITMENT",
            "Telegram / WhatsApp Only Recruiter",
            "Untraceable Channel",
            "MEDIUM",
            25,
            "Directs candidate to communicate exclusively over Telegram or WhatsApp rather than corporate email or ATS portals.",
            [
                r"\b(?:contact|reach|message|dm|ping)\b[^\n.]{0,25}\b(?:on telegram|via telegram|telegram @\w+|whatsapp number|whatsapp only)\b",
                r"\b(?:telegram channel|telegram username|t\.me/\w+)\b[^\n.]{0,35}\b(?:for details|to apply|for interview)\b",
            ],
        ),
        (
            "JOB_URGENCY_DEADLINE",
            "High-Pressure Acceptance Window",
            "Psychological Coercion",
            "MEDIUM",
            20,
            "Pressures candidate to accept the offer within hours or claims the seat will be forfeited immediately.",
            [
                r"\b(?:offer valid only for|must accept within|seat will be cancelled in|respond within)\s+\d+\s*(?:hours?|hrs?|minutes?|today)\b",
                r"\b(?:last date to confirm is today|limited seats left|offer expires shortly)\b",
            ],
        ),
        (
            "JOB_SENSITIVE_CREDENTIALS",
            "Premature Banking or Credential Request",
            "Data Harvesting",
            "HIGH",
            35,
            "Requests bank account numbers, OTP, or credit card info during the application or initial offer stage.",
            [
                r"\b(?:share|send|provide)\b[^\n.]{0,30}\b(?:bank account details|netbanking|atm pin|cancelled cheque photo|card details)\b[^\n.]{0,30}\b(?:for salary credit|before joining|for offer letter)\b",
            ],
        ),
        (
            "JOB_GENERIC_UNPROFESSIONAL",
            "Unprofessional Grammar and Salutations",
            "Informal Presentation",
            "LOW",
            10,
            "Uses generic salutations (e.g. 'Dear Job Seeker') without naming the candidate or specific role requirements.",
            [
                r"\b(?:dear job seeker|dear candidate|hello dear|dear applicant)\b",
                r"\b(?:urgent hiring for freshers|guaranteed work from home job for all)\b",
            ],
        ),
    ]

    @classmethod
    def analyze(cls, text: str) -> Tuple[RiskEvaluation, List[DetectedIndicator]]:
        """Scans job postings and recruitment messages for scam signatures."""
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
