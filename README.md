# 🛡️ Digital Guardian AI

**Digital Guardian AI** is an intelligent, explainable, 100% local digital fraud detection application built with Python and Streamlit. It helps students, job seekers, and everyday internet users identify suspicious messages, deceptive URLs, fake job and internship offers, and payment fraud attempts before taking irreversible actions.

Unlike black-box AI tools, Digital Guardian AI delivers **transparent mathematical score breakdowns** (0–100 risk index), **inline highlighted evidence**, and **prioritized safety checklists**.

---

## 🌟 Key Capabilities

### 💬 1. Message Scam Detector
- **Urgent & Intimidating Language:** Detects account suspension threats, police action claims, and electricity cutoffs.
- **Credential Harvesting:** Flags demands for OTPs, PINs, passwords, and banking secrets.
- **Advance Fee Solicitations:** Identifies processing fee demands, lottery claims, and customs charges.
- **Brand Impersonation:** Recognizes impersonation of banks (SBI, HDFC, Chase), logistics (FedEx, DHL), and tax agencies.

### 🔗 2. Suspicious URL Analyzer
- **100% Passive & Safe:** Analyzes URLs structurally as strings without ever contacting or visiting the server.
- **Deception Markers:** Detects raw IP hosts (`http://192.168.1.100`), known shorteners (`bit.ly`, `tinyurl`), and suspicious TLDs (`.xyz`, `.top`, `.buzz`).
- **Brand Spoofing & Lookalikes:** Catches typosquatting (`paypa1`), embedded `@` redirects, and deep subdomain nesting.
- **Protocol Audit:** Flags unencrypted plain HTTP while clarifying that HTTPS alone does not guarantee legitimacy.

### 💼 3. Fake Job & Internship Scam Detector
- **Fee Extortion:** Flags upfront application fees, exam fees, and laptop security deposits.
- **Unrealistic Hiring:** Detects "direct selection without interview" and absurd daily compensation claims ($500/day for video likes).
- **Recruiter Channels:** Catches multinational brand impersonators using free public webmail (`@gmail.com`) and Telegram-only recruiters.

### 💳 4. Payment Fraud Detector
- **UPI Collect Traps:** Detects deceptive instructions asking users to accept collect requests to "receive" money.
- **QR Code & PIN Scams:** Educates and flags instructions requiring users to scan QR codes or enter UPI PINs to receive refunds.
- **Remote Desktop Infiltration:** Identifies requests to install remote access tools (`AnyDesk`, `TeamViewer`, `QuickSupport`).
- **Fake Overpayments:** Recognizes accidental overpayment refund claims common on classifieds.

### 🔒 5. Privacy & Local Storage
- **100% Local Execution:** No cloud APIs, no remote AI model downloads, no telemetry.
- **Credential Sanitization:** SQLite history automatically strips OTPs, credit cards, and passwords.
- **User Control:** Clear entire audit history or delete individual records at any time.

---

## 🏗️ Architecture

```
Digital_Guardian_AI/
├── app.py                      # Main Streamlit application and page router
├── requirements.txt            # Project dependencies
├── README.md                   # System documentation
├── .gitignore                  # Git ignore rules
│
├── core/                       # Central logic engines
│   ├── risk_engine.py          # 0-100 bounded risk scoring & transparent tiers
│   ├── evidence_engine.py      # Non-overlapping text span highlighter & extractor
│   └── recommendations.py      # Tailored safety checklist generator
│
├── modules/                    # Specialized fraud detection modules
│   ├── message_detector.py     # SMS, WhatsApp, & email scanner
│   ├── url_analyzer.py         # Static structural link inspector
│   ├── job_scam_detector.py    # Recruitment & internship scam detector
│   └── payment_fraud_detector.py # UPI, QR code, & banking fraud detector
│
├── database/
│   └── db_manager.py           # SQLite manager with credential redacting
│
├── components/                 # Reusable Streamlit UI components
│   ├── sidebar.py              # Navigation and status badge
│   ├── result_card.py          # Risk index card, severity breakdown, & meter
│   ├── evidence_view.py        # Highlighted text card & recommendations
│   └── charts.py               # Plotly distribution and module charts
│
├── data/
│   ├── sample_scenarios.json   # 24 illustrative test scenarios
│   └── digital_guardian.db     # Local SQLite audit log (auto-created)
│
├── tests/                      # Automated test suite
│   ├── test_risk_engine.py
│   ├── test_message_detector.py
│   ├── test_url_analyzer.py
│   ├── test_job_detector.py
│   ├── test_payment_detector.py
│   ├── test_evidence_engine.py
│   └── test_database.py
│
└── docs/
    └── TEST_SCENARIOS.md       # Comprehensive scenarios reference
```

---

## 📊 Risk Scoring Methodology

Scores are computed transparently from detected indicators and mapped to four distinct tiers:

| Score Range | Risk Level | Color | Operational Guidance |
|---|---|---|---|
| **0 – 24** | **LOW** | 🟢 Green | Minimal or no indicators detected. Maintain standard vigilance. |
| **25 – 49** | **MEDIUM** | 🟡 Amber | Ambiguous patterns detected. Independent verification recommended. |
| **50 – 74** | **HIGH** | 🟠 Orange | Strong fraud indicators. Do not proceed without direct confirmation. |
| **75 – 100** | **CRITICAL** | 🔴 Red | Severe deception flags (credentials, advance fees, UPI collect trap). Cease contact. |

---

## 💻 Installation & Setup (Windows)

### Prerequisites
- Python 3.12 or higher (Python 3.14 verified)
- Windows PowerShell or Command Prompt

### Step 1: Open the Project Directory
```powershell
cd "c:\Users\VARSHITH GOUD\OneDrive\Desktop\Digital_Guardian_AI"
```

### Step 2: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 3: Run the Automated Test Suite
```powershell
python -m pytest -v
```

### Step 4: Launch Digital Guardian AI
```powershell
python -m streamlit run app.py
```

The application will start and open automatically in your browser at:
👉 **`http://localhost:8501`**

---

## 🧪 Testing Edge Cases

The automated test suite verifies:
1. **Mathematical Invariant:** Scores are strictly bounded between 0 and 100 under all conditions.
2. **Text Fidelity:** Highlighted phrases match actual user input without fabrication or hallucination.
3. **Resilience:** Resilient against empty strings, massive inputs (10,000+ characters), and malformed URLs.
4. **Privacy:** Verifies that OTPs, credit cards, and passwords are fully redacted before SQLite insertion.

To run tests with full details:
```powershell
python -m pytest tests/ -v
```

---

## ⚖️ Limitations & Decision Support Disclaimer

Digital Guardian AI is an assistive decision-support tool, not an absolute guarantee of safety or fraud.
- Advanced social engineering tactics evolve rapidly; absence of detected flags does not guarantee safety.
- HTTPS encryption confirms transport security, not the trustworthiness of the website owner.
- Users should never rely solely on automated scoring for irreversible financial transactions or legal disputes. Always cross-verify with official organizations.

