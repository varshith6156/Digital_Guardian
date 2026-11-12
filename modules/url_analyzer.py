"""Suspicious URL Analyzer for Digital Guardian AI.

Deconstructs URLs into structural components and inspects them for
phishing indicators, homograph/lookalike patterns, IP-based hosting,
shorteners, misleading prefixes, and insecure protocols without EVER
connecting to or loading the target host.
"""

from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional
from core.risk_engine import DetectedIndicator, RiskEngine, RiskEvaluation


KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly",
    "ow.ly", "shorturl.at", "goo.gl", "buff.ly", "adf.ly", "tiny.cc",
    "rebrand.ly", "bl.ink", "hyperurl.co"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "work", "icu", "vip", "cfd", "fit",
    "link", "loan", "stream", "gq", "ml", "cf", "ga", "tk", "cc", "monster",
    "country", "click", "rest", "surf"
}

POPULAR_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe", "binance", "coinbase"
]

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "banking", "update", "wallet", "kyc", "refund", "suspended",
    "confirm", "authenticate", "unlock", "recover", "claim"
]


@dataclass
class ParsedUrlComponents:
    """Breakdown of URL components for explainable inspection."""
    raw_url: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    domain_labels: List[str]
    is_https: bool
    is_ip_address: bool
    is_shortener: bool
    character_count: int


class SuspiciousUrlAnalyzer:
    """Analyzes URL strings statically for deception and risk markers."""

    MODULE_NAME = "URL Analyzer"

    @classmethod
    def parse_url(cls, raw_url: str) -> ParsedUrlComponents:
        """Safely parses a URL string without making network requests."""
        cleaned = raw_url.strip()
        # If user pasted without protocol, normalize for parsing
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = "http://" + cleaned

        parsed = urlparse(cleaned)
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError:
            port = None
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        is_https = parsed.scheme.lower() == "https"

        # Check if host is an IPv4 or IPv6 address
        is_ip = bool(
            re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)
            or re.match(r"^\[?[0-9a-fA-F:]+\]?$", host)
        )

        domain_labels = host.split(".") if host else []
        is_shortener = host in KNOWN_SHORTENERS

        return ParsedUrlComponents(
            raw_url=raw_url,
            scheme=parsed.scheme.lower(),
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            domain_labels=domain_labels,
            is_https=is_https,
            is_ip_address=is_ip,
            is_shortener=is_shortener,
            character_count=len(raw_url),
        )

    @classmethod
    def analyze(cls, raw_url: str) -> Tuple[RiskEvaluation, ParsedUrlComponents, List[DetectedIndicator]]:
        """Conducts static structural analysis on the provided URL."""
        if not raw_url or not raw_url.strip():
            empty_eval = RiskEngine.evaluate([])
            parsed_empty = cls.parse_url("http://empty-input")
            return empty_eval, parsed_empty, []

        parsed = cls.parse_url(raw_url)
        indicators: List[DetectedIndicator] = []
        host = parsed.host
        full_url_lower = raw_url.lower()

        # 1. IP-address based host (CRITICAL)
        if parsed.is_ip_address:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_IP_HOST",
                    title="Direct IP Address Host",
                    category="Host Identification",
                    severity="CRITICAL",
                    weight=55,
                    description=(
                        "The URL routes directly to an IP address rather than a registered domain name. "
                        "Legitimate consumer and corporate services almost never use raw IPs in web links."
                    ),
                    matched_text=host,
                )
            )

        # 2. Insecure HTTP Protocol (MEDIUM - not encrypted, though HTTPS alone doesn't mean safe)
        if not parsed.is_https:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_HTTP_INSECURE",
                    title="Insecure HTTP Connection",
                    category="Transport Security",
                    severity="MEDIUM",
                    weight=20,
                    description=(
                        "The URL uses unencrypted plain HTTP instead of HTTPS. Traffic can be eavesdropped, "
                        "and modern legitimate services always mandate HTTPS."
                    ),
                    matched_text=parsed.scheme + "://",
                )
            )

        # 3. Known URL Shortener (MEDIUM / HIGH)
        if parsed.is_shortener:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_SHORTENER",
                    title="Known URL Shortener Service",
                    category="Destination Concealment",
                    severity="MEDIUM",
                    weight=22,
                    description=(
                        f"The domain '{host}' is a link redirection/shortening service. "
                        "Scammers frequently use shorteners to mask malicious landing pages."
                    ),
                    matched_text=host,
                )
            )

        # 4. Unusual / Risky TLDs
        tld = parsed.domain_labels[-1] if len(parsed.domain_labels) > 1 else ""
        if tld in SUSPICIOUS_TLDS:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_SUSPICIOUS_TLD",
                    title=f"High-Risk Top-Level Domain (.{tld})",
                    category="Domain Reputation",
                    severity="MEDIUM",
                    weight=22,
                    description=(
                        f"The top-level domain '.{tld}' has a statistically high correlation with disposable "
                        "phishing campaigns and malware hosting."
                    ),
                    matched_text=f".{tld}",
                )
            )

        # 5. Lookalike / Typosquatting / Homograph patterns
        # Non-ASCII or Punycode IDN (xn--)
        if "xn--" in host or any(ord(c) > 127 for c in raw_url):
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_HOMOGRAPH_IDN",
                    title="Internationalized Domain / Punycode (Homograph)",
                    category="Visual Spoofing",
                    severity="CRITICAL",
                    weight=55,
                    description=(
                        "The domain contains non-ASCII or Punycode (xn--) characters. "
                        "This technique substitutes visual lookalike letters (e.g. Cyrillic 'а' for Latin 'a') to spoof trusted brands."
                    ),
                    matched_text=host,
                )
            )

        # Typosquatting brand matching
        for brand in POPULAR_BRANDS:
            # Check if brand appears in host but is not the exact registered domain
            if brand in host:
                parts = host.split(".")
                # If host is not brand.com, brand.org, etc. (e.g. paypa1-update.com or paypal.verify-account.com)
                exact_domain = f"{brand}." in host or f".{brand}." in host
                if not (len(parts) >= 2 and parts[-2] == brand):
                    indicators.append(
                        DetectedIndicator(
                            rule_id="URL_BRAND_SPOOFING",
                            title=f"Brand Name Concealment ({brand.capitalize()})",
                            category="Brand Impersonation",
                            severity="HIGH",
                            weight=40,
                            description=(
                                f"The trusted brand name '{brand}' appears inside a secondary subdomain or hyphenated string, "
                                f"while the actual root domain is '{'.'.join(parts[-2:]) if len(parts) >= 2 else host}'."
                            ),
                            matched_text=brand,
                        )
                    )
                    break

        # Typosquatting numeric replacements: g00gle, micros0ft, paypa1, etc.
        typo_patterns = [
            (r"\bg0{1,2}gle\b", "g00gle spoofing Google"),
            (r"\bmicr[o0]s[o0]ft\b", "micros0ft spoofing Microsoft"),
            (r"\bpaypa[l1i]\b", "paypa1 spoofing PayPal"),
            (r"\bamaz[o0]n\b", "amaz0n spoofing Amazon"),
            (r"\bnetf[l1i]x\b", "netfl1x spoofing Netflix"),
        ]
        for pat, desc in typo_patterns:
            m = re.search(pat, host)
            if m:
                indicators.append(
                    DetectedIndicator(
                        rule_id="URL_TYPOSQUATTING",
                        title="Typosquatting Character Substitution",
                        category="Visual Spoofing",
                        severity="CRITICAL",
                        weight=50,
                        description=f"Domain replaces letters with lookalike numbers: {desc}.",
                        matched_text=m.group(0),
                    )
                )
                break

        # 6. Embedded '@' symbol (userinfo trick to obscure true host)
        if "@" in raw_url:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_AT_SYMBOL_REDIRECT",
                    title="Embedded '@' Authority Spoofing",
                    category="Syntax Manipulation",
                    severity="CRITICAL",
                    weight=55,
                    description=(
                        "The URL contains an '@' character. In URI specifications, text before '@' is treated "
                        "as userinfo credentials, and browsers redirect to the host AFTER the '@'."
                    ),
                    matched_text="@",
                )
            )

        # 7. Excessive subdomains (deep subdomain chain)
        if len(parsed.domain_labels) > 4:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_DEEP_SUBDOMAINS",
                    title="Excessive Subdomain Depth",
                    category="Domain Structure",
                    severity="HIGH",
                    weight=30,
                    description=(
                        f"The hostname contains {len(parsed.domain_labels)} domain segments. "
                        "Phishers construct long subdomain prefixes to mimic legitimate corporate structures."
                    ),
                    matched_text=host,
                )
            )

        # 8. Suspicious keywords in path/query combined with external domain
        found_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in parsed.path.lower() or kw in parsed.query.lower()]
        if len(found_keywords) >= 2:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_SUSPICIOUS_PATH_KEYWORDS",
                    title="Multiple Sensitive Workflow Keywords",
                    category="Path Inspection",
                    severity="HIGH",
                    weight=32,
                    description=(
                        f"The URL path or query contains sensitive actions: {', '.join(found_keywords[:3])}. "
                        "Phishing kits often use these endpoints to steal authentication credentials."
                    ),
                    matched_text=", ".join(found_keywords[:2]),
                )
            )

        # 9. Non-standard ports (e.g. :8080, :8888, :2082 on sensitive workflows)
        if parsed.port and parsed.port not in (80, 443):
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_NON_STANDARD_PORT",
                    title=f"Non-Standard Port (:{parsed.port})",
                    category="Network Configuration",
                    severity="MEDIUM",
                    weight=18,
                    description=(
                        f"The URL specifies a custom port ':{parsed.port}'. Legitimate public websites "
                        "operate on standard web ports (80 or 443)."
                    ),
                    matched_text=f":{parsed.port}",
                )
            )

        # 10. Excessive length (> 100 characters)
        if parsed.character_count > 110:
            indicators.append(
                DetectedIndicator(
                    rule_id="URL_EXCESSIVE_LENGTH",
                    title="Excessively Long URL",
                    category="Structural Anomaly",
                    severity="LOW",
                    weight=10,
                    description=(
                        f"The URL is abnormally long ({parsed.character_count} chars). Scammers generate long URLs "
                        "to push malicious domain names out of visible address bar bounds on mobile devices."
                    ),
                    matched_text=raw_url[:40] + "...",
                )
            )

        evaluation = RiskEngine.evaluate(indicators)
        return evaluation, parsed, evaluation.indicators
