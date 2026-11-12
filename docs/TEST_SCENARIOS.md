# Digital Guardian AI — Illustrative Test Scenarios Guide

This document details the **24 illustrative synthetic scenarios** embedded in `data/sample_scenarios.json` across all four fraud detection modules.

> **Disclaimer:** These scenarios use fictional entity names, phone numbers, and domains to safely demonstrate detection capabilities. They are illustrative test cases, not records of actual live incidents.

---

## 1. Message Scam Detector Scenarios

| Scenario ID | Title | Expected Risk | Core Indicators Flagged |
|---|---|---|---|
| `msg_crit_1` | Bank KYC Suspension Threat with Suspicious Link | **CRITICAL** (80–95) | Credential/Password Request, Urgent Account Block Threat, Suspicious Shortened Link, Impersonation |
| `msg_crit_2` | Lottery Jackpot Demanding Advance Fee | **CRITICAL** (80–95) | Advance Fee Solicitation, Unexpected Lottery/Prize Claim |
| `msg_high_1` | Imminent Electricity Disconnection Threat | **HIGH** (50–65) | Power Disconnection Threat, Police/Legal Action Threat, Extreme Urgency |
| `msg_high_2` | Courier Customs Parcel Notification | **HIGH** (50–65) | Impersonation of Logistics Brand (FedEx), Customs Fee Solicitation, `.xyz` Malicious Link |
| `msg_med_1` | Ambiguous Security Notice | **MEDIUM** (25–35) | Unrecognized Login Alert without links or credential harvesting |
| `msg_low_1` | Legitimate Bank Transaction Alert | **LOW** (0–10) | Standard debited balance alert with no links, passwords, or threats |

---

## 2. Suspicious URL Analyzer Scenarios

| Scenario ID | Title | Expected Risk | Core Indicators Flagged |
|---|---|---|---|
| `url_crit_1` | Direct IP Address with Sensitive Path | **CRITICAL** (80–95) | Direct IP Host, Non-standard Port (`:8080`), Insecure HTTP, Sensitive Keywords (`/login/verify`) |
| `url_crit_2` | Typosquatting and Brand Spoofing (`.xyz`) | **CRITICAL** (80–95) | Typosquatting (`paypa1`), Brand Impersonation, Disposable `.xyz` TLD |
| `url_crit_3` | Authority Spoofing with `@` Symbol | **CRITICAL** (85–100) | Embedded `@` Userinfo Redirection Trick, Suspicious TLD (`.top`) |
| `url_high_1` | Excessive Subdomains Mimicking Bank | **HIGH** (50–65) | Excessive Subdomain Depth (>4 levels), Misleading Domain Prefix, Disposable `.club` TLD |
| `url_med_1` | Known URL Shortener Redirection | **MEDIUM** (25–35) | Known Link Redirection/Shortener (`bit.ly`) concealing final destination |
| `url_low_1` | Legitimate Corporate HTTPS Portal | **LOW** (0–10) | Valid HTTPS protocol, reputable registered domain (`github.com`), standard web paths |

---

## 3. Fake Job & Internship Scam Detector Scenarios

| Scenario ID | Title | Expected Risk | Core Indicators Flagged |
|---|---|---|---|
| `job_crit_1` | Direct Hiring Demanding Laptop Deposit | **CRITICAL** (80–95) | Laptop Security Deposit Fee, Direct Selection Without Interview, Free Webmail Impersonation (`@gmail.com`) |
| `job_crit_2` | Data Entry Video Liking with Registration Fee | **CRITICAL** (80–95) | Registration Fee Demand, Absurd Compensation Promise ($500/day for video likes) |
| `job_high_1` | MNC Impersonator Requesting Credentials | **HIGH** (50–65) | Premature Banking/PIN Request, Brand Impersonation (Microsoft) |
| `job_med_1` | Telegram-Exclusive High-Paying Recruitment | **MEDIUM** (30–45) | Telegram-Only Recruiter Contact, High Urgency |
| `job_med_2` | High-Pressure 2-Hour Offer Acceptance Window | **MEDIUM** (25–35) | Artificial Time Window Panic (2 hours) |
| `job_low_1` | Legitimate Enterprise Engineering Offer | **LOW** (0–10) | References formal interview rounds, standard corporate career portal, professional tone |

---

## 4. Payment Fraud Detector Scenarios

| Scenario ID | Title | Expected Risk | Core Indicators Flagged |
|---|---|---|---|
| `pay_crit_1` | UPI Collect Request to 'Receive' Money | **CRITICAL** (85–100) | UPI Collect Request Deception, PIN Required to Receive Funds Trap |
| `pay_crit_2` | QR Code Scan to Receive Refund | **CRITICAL** (80–95) | QR Code Scan to Receive Funds Myth, PIN Required to Claim Refund |
| `pay_crit_3` | Remote Access App Request for Refund | **CRITICAL** (80–95) | Remote Desktop App Solicitation (`AnyDesk`), Impersonation of Google Pay Support |
| `pay_high_1` | Accidental Overpayment Claim Scam | **HIGH** (50–65) | Fake Overpayment / Reverse Transfer Social Engineering |
| `pay_high_2` | Wallet Frozen Urgency Threat | **HIGH** (50–65) | Wallet Freezing Threat, Immediate Penalty Fine Urgency |
| `pay_low_1` | Legitimate Merchant Payment Receipt | **LOW** (0–10) | Standard point-of-sale receipt with transaction ID and no solicitations |

