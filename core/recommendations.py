"""Recommendation Engine for Digital Guardian AI.

Generates structured, actionable, and context-aware safety recommendations
tailored to the analysis type, detected fraud vectors, and risk severity.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any
from core.risk_engine import DetectedIndicator


@dataclass
class SafetyRecommendation:
    """Actionable advice item for the user."""
    action_type: str  # DO, DO_NOT, VERIFY, REPORT
    title: str
    detail: str
    priority: int  # 1 (Highest) to 4 (Lowest)


class RecommendationEngine:
    """Generates tailored recommendations based on risk results and detector rules."""

    @classmethod
    def get_recommendations(
        cls,
        module_type: str,
        risk_level: str,
        indicators: List[DetectedIndicator],
    ) -> List[SafetyRecommendation]:
        """Returns prioritized safety actions based on module type and detected indicators."""
        recs: List[SafetyRecommendation] = []
        rule_ids = set(ind.rule_id for ind in indicators)

        # Baseline actions based on risk level
        if risk_level == "CRITICAL":
            recs.append(
                SafetyRecommendation(
                    action_type="DO_NOT",
                    title="Do Not Interact or Send Money",
                    detail="Cease all communication immediately. Do not click links, send money, scan QR codes, or share any OTP or PIN.",
                    priority=1,
                )
            )
            recs.append(
                SafetyRecommendation(
                    action_type="DO",
                    title="Block and Report the Sender",
                    detail="Block the contact number/email on your device and mark it as spam or phishing. File a report on cybercrime portals.",
                    priority=2,
                )
            )
        elif risk_level == "HIGH":
            recs.append(
                SafetyRecommendation(
                    action_type="DO_NOT",
                    title="Pause Before Taking Action",
                    detail="Do not act under artificial urgency or pressure. Scammers rely on panic to prevent rational thinking.",
                    priority=1,
                )
            )
            recs.append(
                SafetyRecommendation(
                    action_type="VERIFY",
                    title="Verify Through Official Channels",
                    detail="Look up the official contact number or website directly from an independent search engine or official billing statement.",
                    priority=2,
                )
            )
        elif risk_level == "MEDIUM":
            recs.append(
                SafetyRecommendation(
                    action_type="VERIFY",
                    title="Independent Verification Recommended",
                    detail="The communication shows ambiguous patterns. Confirm with the organization via official helplines before acting.",
                    priority=2,
                )
            )
        else:
            recs.append(
                SafetyRecommendation(
                    action_type="DO",
                    title="Standard Cyber Hygiene",
                    detail="No immediate threat flags were found. Maintain general vigilance and never share passwords or banking PINs.",
                    priority=3,
                )
            )

        # Module-specific and indicator-specific targeted advice
        if module_type == "message":
            if any("CREDENTIAL" in r or "OTP" in r or "PIN" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="DO_NOT",
                        title="Never Share One-Time Passwords (OTPs)",
                        detail="Banks, telecom operators, and government bodies will never ask for your OTP, MPIN, or password over call or text.",
                        priority=1,
                    )
                )
            if any("IMPERSONATION" in r or "BANK" in r or "GOV" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="VERIFY",
                        title="Check Official Customer Support",
                        detail="Call the phone number printed on the back of your debit card or visit the official bank portal directly.",
                        priority=2,
                    )
                )
            if any("LINK" in r or "URL" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="DO_NOT",
                        title="Do Not Tap Unverified Shortened Links",
                        detail="Shortened links often conceal phishing sites or malware downloaders. Paste the URL into the URL Analyzer module first.",
                        priority=2,
                    )
                )

        elif module_type == "url":
            recs.append(
                SafetyRecommendation(
                    action_type="DO_NOT",
                    title="Never Enter Passwords on Unverified Sites",
                    detail="Check the domain name spelling character by character in the browser address bar before submitting credentials.",
                    priority=1,
                )
            )
            if any("IP_HOST" in r or "MISLEADING" in r or "LOOKALIKE" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="VERIFY",
                        title="Inspect the Exact Domain Name",
                        detail="Legitimate institutions use their primary registered domains, never raw IP addresses or misspelled lookalike names.",
                        priority=1,
                    )
                )
            if any("HTTP" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="DO_NOT",
                        title="Insecure Connection",
                        detail="This site lacks HTTPS encryption. Any information submitted can be intercepted by third parties on the same network.",
                        priority=2,
                    )
                )

        elif module_type == "job":
            if any("FEE" in r or "DEPOSIT" in r or "PAYMENT" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="DO_NOT",
                        title="Never Pay for a Job Offer or Internship",
                        detail="Legitimate employers never require candidates to pay application fees, laptop security deposits, or training charges.",
                        priority=1,
                    )
                )
            if any("FREE_EMAIL" in r or "MESSAGING" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="VERIFY",
                        title="Verify Corporate Domain Email",
                        detail="Official corporate recruiters write from company email domains (e.g., name@google.com), not free Gmail or Telegram handles.",
                        priority=2,
                    )
                )
            recs.append(
                SafetyRecommendation(
                    action_type="VERIFY",
                    title="Cross-check the Official Career Portal",
                    detail="Search for the specific job requisition ID on the company's official 'Careers' page to confirm the vacancy is genuine.",
                    priority=2,
                )
            )

        elif module_type == "payment":
            if any("COLLECT" in r or "RECEIVE_PIN" in r or "QR" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="DO_NOT",
                        title="UPI PIN is ONLY for Sending Money",
                        detail="You NEVER need to enter your UPI PIN or scan a QR code to RECEIVE money. Entering your PIN transfers money OUT.",
                        priority=1,
                    )
                )
            if any("REMOTE_ACCESS" in r for r in rule_ids):
                recs.append(
                    SafetyRecommendation(
                        action_type="DO_NOT",
                        title="Never Install Remote Desktop Apps",
                        detail="Never install AnyDesk, TeamViewer, QuickSupport, or RustDesk at the instruction of someone claiming to represent support or a bank.",
                        priority=1,
                    )
                )
            recs.append(
                SafetyRecommendation(
                    action_type="REPORT",
                    title="Report Payment Fraud Promptly",
                    detail="If you made a payment in error, immediately call your bank's 24/7 fraud helpline and report within the Golden Hour window.",
                    priority=2,
                )
            )

        # Deduplicate recommendations by title and sort by priority
        seen_titles = set()
        deduped = []
        for r in recs:
            if r.title not in seen_titles:
                seen_titles.add(r.title)
                deduped.append(r)

        deduped.sort(key=lambda x: x.priority)
        return deduped

