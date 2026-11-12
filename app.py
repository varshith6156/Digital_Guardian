"""Digital Guardian AI — Main Application Entrypoint (Full-Screen Executive Edition).

An intelligent, explainable, 100% local digital fraud detection application
that helps students, job seekers, and internet users identify suspicious messages,
phishing URLs, fake job offers, and payment fraud attempts.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
import pandas as pd

from database.db_manager import DatabaseManager
from core.risk_engine import RiskEngine
from core.evidence_engine import EvidenceEngine
from core.recommendations import RecommendationEngine
from modules.message_detector import MessageScamDetector
from modules.url_analyzer import SuspiciousUrlAnalyzer
from modules.job_scam_detector import JobScamDetector
from modules.payment_fraud_detector import PaymentFraudDetector

from components.result_card import render_risk_result_card
from components.evidence_view import render_evidence_section, render_recommendations_section
from components.charts import (
    build_risk_distribution_chart,
    build_module_breakdown_chart,
    build_risk_gauge,
)


# Full-Screen Page Configuration (Sidebar hidden)
st.set_page_config(
    page_title="Digital Guardian AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Professional Executive CSS (No bright cyan/blue)
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Hide default sidebar and its toggle to achieve true full-screen experience */
    [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], section[data-testid="stSidebar"] {
        display: none !important;
    }

    /* Full-screen app background */
    .stApp {
        background-color: #0A0E17 !important;
        color: #E2E8F0 !important;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    /* Headings */
    h1, h2, h3, h4, h5, h6 {
        color: #FFFFFF !important;
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
    }

    /* Professional Executive Action Buttons */
    .stButton>button {
        background: #172033 !important;
        color: #F8FAFC !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        border: 1px solid #27354E !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.4rem !important;
        transition: all 0.2s ease-in-out !important;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25) !important;
    }
    .stButton>button:hover {
        background: #202D45 !important;
        border-color: #3B4E73 !important;
        color: #FFFFFF !important;
        transform: translateY(-1px) !important;
    }
    .stButton>button:active {
        transform: translateY(0px) !important;
    }

    /* Text areas and Input Fields */
    .stTextArea textarea, .stTextInput input {
        background: #0E1422 !important;
        color: #F8FAFC !important;
        border: 1px solid #212C3F !important;
        border-radius: 8px !important;
        font-size: 0.92rem !important;
        padding: 12px 14px !important;
    }
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #4A5D7E !important;
        box-shadow: 0 0 0 2px rgba(74, 93, 126, 0.3) !important;
    }

    /* Selectboxes */
    .stSelectbox div[data-baseweb="select"] {
        background: #0E1422 !important;
        border: 1px solid #212C3F !important;
        border-radius: 8px !important;
        color: #F8FAFC !important;
    }

    /* Tables & Dataframes */
    .stDataFrame {
        border: 1px solid #212C3F !important;
        border-radius: 8px !important;
        overflow: hidden !important;
        background: #0E1422 !important;
    }

    /* Main container padding */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1250px !important;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# Load Sample Scenarios Data
@st.cache_data
def load_sample_scenarios() -> Dict[str, List[Dict[str, Any]]]:
    scenarios_path = Path(__file__).resolve().parent / "data" / "sample_scenarios.json"
    if scenarios_path.exists():
        with open(scenarios_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


# Database Manager instance
@st.cache_resource
def get_db_manager() -> DatabaseManager:
    return DatabaseManager()


db = get_db_manager()
sample_scenarios = load_sample_scenarios()

# Manage current view in session state
if "active_view" not in st.session_state:
    st.session_state["active_view"] = "HOME"


# Helper function to switch views
def navigate_to(view_name: str):
    st.session_state["active_view"] = view_name
    st.rerun()


# Top Navigation Header for Sub-pages
def render_top_navbar(current_view: str):
    col_back, col_nav = st.columns([1.5, 4.5])
    with col_back:
        if st.button("← Back to Main Menu", key="btn_back_home", use_container_width=True):
            navigate_to("HOME")

    with col_nav:
        sub_cols = st.columns(6)
        pages = [
            ("📊 Dashboard", "DASHBOARD"),
            ("💬 Message", "MESSAGE"),
            ("🔗 URL", "URL"),
            ("💼 Job Scam", "JOB"),
            ("💳 Payment", "PAYMENT"),
            ("📜 History", "HISTORY"),
        ]
        for c, (label, target) in zip(sub_cols, pages):
            with c:
                if target != current_view:
                    if st.button(label, key=f"top_nav_{target}", use_container_width=True):
                        navigate_to(target)

    st.markdown("<hr style='border:0; border-top:1px solid #1E2738; margin: 14px 0 24px 0;'>", unsafe_allow_html=True)


# ==========================================
# FULL-SCREEN HOME / MAIN MENU
# ==========================================
def render_home_menu():
    # Project Title
    st.markdown(
        """
        <div style="text-align: center; padding: 25px 10px 30px 10px;">
            <div style="display: inline-block; background: #131A29; border: 1px solid #233047; padding: 6px 14px; border-radius: 20px; font-size: 0.76rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">
                Decision-Support Cybersecurity Shield
            </div>
            <h1 style="font-size: 3rem; font-weight: 800; color: #FFFFFF; margin: 0; letter-spacing: -0.5px;">
                Digital Guardian AI
            </h1>
            <p style="font-size: 1.1rem; color: #8C9BB4; margin: 8px auto 0 auto; max-width: 650px; line-height: 1.5;">
                Intelligent local digital fraud detection and explainable risk analysis. Select an option below to enter:
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 7 Full-Screen Options
    options = [
        ("📊 Dashboard", "DASHBOARD", "Overview of global scan metrics, risk severity distribution, and recent audit activity."),
        ("💬 Message Scanner", "MESSAGE", "Analyze SMS, WhatsApp, and email messages for urgent credential theft and impersonation."),
        ("🔗 URL Analyzer", "URL", "Inspect links for typosquatting, deceptive subdomains, and IP-based hosts safely."),
        ("💼 Job Scam Detector", "JOB", "Identify fake job offers, upfront training/laptop deposits, and Telegram recruiters."),
        ("💳 Payment Fraud Detector", "PAYMENT", "Detect UPI collect-request traps, QR code scams, and remote desktop software."),
        ("📜 Analysis History", "HISTORY", "Review and manage stored audit logs with automatic credential privacy redaction."),
        ("ℹ️ About", "ABOUT", "Review system architecture, explainability methodology, and decision-support guidance."),
    ]

    # Render as structured, full-screen executive selection cards
    col1, col2 = st.columns(2)

    for i, (title, target_view, desc) in enumerate(options):
        target_col = col1 if i % 2 == 0 else col2
        with target_col:
            st.markdown(
                f"""
                <div style="background: #111726; 
                            border: 1px solid #1E2738; 
                            border-radius: 8px; 
                            padding: 22px 24px; 
                            margin-bottom: 8px;
                            min-height: 125px;">
                    <div style="font-size: 1.22rem; font-weight: 700; color: #FFFFFF; margin-bottom: 6px;">
                        {title}
                    </div>
                    <div style="color: #8C9BB4; font-size: 0.88rem; line-height: 1.45;">
                        {desc}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button(f"Enter {title.split()[1]} →", key=f"btn_enter_{target_view}", use_container_width=True):
                navigate_to(target_view)
            st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)


# ==========================================
# OPTION 1: DASHBOARD
# ==========================================
def render_dashboard_page():
    render_top_navbar("DASHBOARD")

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 1.8rem;">📊 Intelligence Dashboard</h2>
            <p style="color: #8C9BB4; font-size: 0.95rem; margin: 4px 0 0 0;">
                Aggregated local analysis metrics, risk tier distribution, and audit history.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    stats = db.get_summary_stats()
    total = stats["total_analyses"]
    counts_by_level = stats["counts_by_level"]

    # Top KPI Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    kpis = [
        ("Total Scans", total, "#FFFFFF"),
        ("Low Risk", counts_by_level.get("LOW", 0), "#10B981"),
        ("Medium Risk", counts_by_level.get("MEDIUM", 0), "#F59E0B"),
        ("High Warnings", counts_by_level.get("HIGH", 0), "#F97316"),
        ("Critical Threats", counts_by_level.get("CRITICAL", 0), "#EF4444"),
    ]
    for col, (label, val, color) in zip([m1, m2, m3, m4, m5], kpis):
        with col:
            st.markdown(
                f"""
                <div style="background: #111726; border: 1px solid #1E2738; border-radius: 8px; padding: 14px 18px; text-align: center;">
                    <div style="color: #8C9BB4; font-size: 0.74rem; font-weight: 600; text-transform: uppercase;">{label}</div>
                    <div style="font-size: 1.85rem; font-weight: 800; color: {color}; margin-top: 3px;">{val:,}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Charts Row
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(build_risk_distribution_chart(counts_by_level), use_container_width=True)
    with c2:
        st.plotly_chart(build_module_breakdown_chart(stats["counts_by_type"]), use_container_width=True)

    # Recent Audit Log Table
    st.markdown("<h4 style='margin: 18px 0 10px 0;'>Recent Audit Records</h4>", unsafe_allow_html=True)
    recent = db.get_recent_history(limit=10)
    if recent:
        df = pd.DataFrame(recent)
        df = df[["analysis_id", "analysis_type", "risk_score", "risk_level", "summary", "created_at"]]
        df.columns = ["Audit ID", "Module", "Score", "Risk Level", "Sanitized Summary", "Timestamp"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No analyses recorded yet.")


# ==========================================
# OPTION 2: MESSAGE SCANNER
# ==========================================
def render_message_scanner_page():
    render_top_navbar("MESSAGE")

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 1.8rem;">💬 Message Scam Detector</h2>
            <p style="color: #8C9BB4; font-size: 0.95rem; margin: 4px 0 0 0;">
                Paste suspicious SMS, WhatsApp, email, or social media messages to analyze deceptive indicators.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    scenarios = sample_scenarios.get("message_detector", [])
    scenario_titles = ["-- Select an Illustrative Test Scenario (Optional) --"] + [
        f"[{s['risk_expected']}] {s['title']}" for s in scenarios
    ]

    selected_idx = st.selectbox("Quick Test Scenarios", options=range(len(scenario_titles)), format_func=lambda x: scenario_titles[x])

    default_text = ""
    if selected_idx > 0:
        default_text = scenarios[selected_idx - 1]["content"]

    user_input = st.text_area(
        "Message Content",
        value=default_text,
        height=140,
        placeholder="Paste message content here...",
    )

    if st.button("Run Message Analysis", key="btn_run_msg"):
        if not user_input.strip():
            st.warning("Please enter a message to analyze.")
        else:
            with st.spinner("Analyzing message patterns..."):
                eval_res, indicators = MessageScamDetector.analyze(user_input)
                recs = RecommendationEngine.get_recommendations("message", eval_res.level, indicators)

                db.save_analysis(
                    analysis_type="Message Scanner",
                    risk_score=eval_res.score,
                    risk_level=eval_res.level,
                    raw_text_for_summary=user_input,
                    indicators_count=len(indicators),
                )

                st.session_state["msg_result"] = {
                    "text": user_input,
                    "eval": eval_res,
                    "indicators": indicators,
                    "recs": recs,
                }

    if "msg_result" in st.session_state:
        res = st.session_state["msg_result"]
        render_risk_result_card(res["eval"], "Message Scam")

        col1, col2 = st.columns([1.6, 1])
        with col1:
            render_evidence_section(res["text"], res["indicators"])
        with col2:
            st.plotly_chart(build_risk_gauge(res["eval"].score, res["eval"].level, res["eval"].color), use_container_width=True)
            render_recommendations_section(res["recs"])


# ==========================================
# OPTION 3: URL ANALYZER
# ==========================================
def render_url_analyzer_page():
    render_top_navbar("URL")

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 1.8rem;">🔗 Suspicious URL Analyzer</h2>
            <p style="color: #8C9BB4; font-size: 0.95rem; margin: 4px 0 0 0;">
                Deconstruct link architecture for lookalikes, raw IP hosts, shorteners, and deceptive paths without connecting to the URL.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    scenarios = sample_scenarios.get("url_analyzer", [])
    scenario_titles = ["-- Select an Illustrative URL (Optional) --"] + [
        f"[{s['risk_expected']}] {s['title']}" for s in scenarios
    ]

    selected_idx = st.selectbox("Quick Test Scenarios", options=range(len(scenario_titles)), format_func=lambda x: scenario_titles[x])

    default_url = ""
    if selected_idx > 0:
        default_url = scenarios[selected_idx - 1]["content"]

    user_url = st.text_input(
        "Website URL",
        value=default_url,
        placeholder="https://example.com/login or http://192.168.1.100/...",
    )

    st.caption("🔒 Safety: URLs are analyzed purely as text strings and will never be contacted or queried over the network.")

    if st.button("Run URL Analysis", key="btn_run_url"):
        if not user_url.strip():
            st.warning("Please provide a URL to analyze.")
        else:
            with st.spinner("Deconstructing URL structure..."):
                eval_res, parsed, indicators = SuspiciousUrlAnalyzer.analyze(user_url)
                recs = RecommendationEngine.get_recommendations("url", eval_res.level, indicators)

                db.save_analysis(
                    analysis_type="URL Analyzer",
                    risk_score=eval_res.score,
                    risk_level=eval_res.level,
                    raw_text_for_summary=user_url,
                    indicators_count=len(indicators),
                )

                st.session_state["url_result"] = {
                    "url": user_url,
                    "eval": eval_res,
                    "parsed": parsed,
                    "indicators": indicators,
                    "recs": recs,
                }

    if "url_result" in st.session_state:
        res = st.session_state["url_result"]
        parsed = res["parsed"]
        render_risk_result_card(res["eval"], "URL Security")

        # Structural architecture components
        st.markdown("<h4 style='margin: 10px 0;'>Parsed URL Architecture</h4>", unsafe_allow_html=True)
        u1, u2, u3, u4 = st.columns(4)
        arch_items = [
            ("Scheme", parsed.scheme, "#10B981" if parsed.is_https else "#F59E0B"),
            ("Host", parsed.host or "None", "#FFFFFF"),
            ("Port", str(parsed.port or "Default"), "#CBD5E1"),
            ("Path Depth", f"{len([p for p in parsed.path.split('/') if p])} segments", "#CBD5E1"),
        ]
        for col, (title, val, val_col) in zip([u1, u2, u3, u4], arch_items):
            with col:
                st.markdown(
                    f"""
                    <div style="background: #111726; border: 1px solid #1E2738; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px;">
                        <div style="color: #64748B; font-size: 0.72rem; text-transform: uppercase;">{title}</div>
                        <div style="color: {val_col}; font-family: monospace; font-size: 0.85rem; font-weight: 600; margin-top: 2px;">{val}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        col1, col2 = st.columns([1.6, 1])
        with col1:
            render_evidence_section(res["url"], res["indicators"])
        with col2:
            st.plotly_chart(build_risk_gauge(res["eval"].score, res["eval"].level, res["eval"].color), use_container_width=True)
            render_recommendations_section(res["recs"])


# ==========================================
# OPTION 4: JOB SCAM DETECTOR
# ==========================================
def render_job_detector_page():
    render_top_navbar("JOB")

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 1.8rem;">💼 Fake Job & Internship Scam Detector</h2>
            <p style="color: #8C9BB4; font-size: 0.95rem; margin: 4px 0 0 0;">
                Audit employment offers and recruiter messages for registration fees, training deposits, and direct hiring without interviews.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    scenarios = sample_scenarios.get("job_detector", [])
    scenario_titles = ["-- Select an Illustrative Job Offer (Optional) --"] + [
        f"[{s['risk_expected']}] {s['title']}" for s in scenarios
    ]

    selected_idx = st.selectbox("Quick Test Scenarios", options=range(len(scenario_titles)), format_func=lambda x: scenario_titles[x])

    default_text = ""
    if selected_idx > 0:
        default_text = scenarios[selected_idx - 1]["content"]

    user_input = st.text_area(
        "Job Offer Content",
        value=default_text,
        height=140,
        placeholder="Paste job offer or recruiter message...",
    )

    if st.button("Run Job Offer Analysis", key="btn_run_job"):
        if not user_input.strip():
            st.warning("Please paste job text to analyze.")
        else:
            with st.spinner("Auditing recruitment patterns..."):
                eval_res, indicators = JobScamDetector.analyze(user_input)
                recs = RecommendationEngine.get_recommendations("job", eval_res.level, indicators)

                db.save_analysis(
                    analysis_type="Job Scam Detector",
                    risk_score=eval_res.score,
                    risk_level=eval_res.level,
                    raw_text_for_summary=user_input,
                    indicators_count=len(indicators),
                )

                st.session_state["job_result"] = {
                    "text": user_input,
                    "eval": eval_res,
                    "indicators": indicators,
                    "recs": recs,
                }

    if "job_result" in st.session_state:
        res = st.session_state["job_result"]
        render_risk_result_card(res["eval"], "Job Offer")

        col1, col2 = st.columns([1.6, 1])
        with col1:
            render_evidence_section(res["text"], res["indicators"])
        with col2:
            st.plotly_chart(build_risk_gauge(res["eval"].score, res["eval"].level, res["eval"].color), use_container_width=True)
            render_recommendations_section(res["recs"])


# ==========================================
# OPTION 5: PAYMENT FRAUD DETECTOR
# ==========================================
def render_payment_detector_page():
    render_top_navbar("PAYMENT")

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 1.8rem;">💳 Payment Fraud Detector</h2>
            <p style="color: #8C9BB4; font-size: 0.95rem; margin: 4px 0 0 0;">
                Inspect payment instructions, refund promises, and buyer claims for UPI collect deception, QR code traps, and remote access apps.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    scenarios = sample_scenarios.get("payment_detector", [])
    scenario_titles = ["-- Select an Illustrative Payment Claim (Optional) --"] + [
        f"[{s['risk_expected']}] {s['title']}" for s in scenarios
    ]

    selected_idx = st.selectbox("Quick Test Scenarios", options=range(len(scenario_titles)), format_func=lambda x: scenario_titles[x])

    default_text = ""
    if selected_idx > 0:
        default_text = scenarios[selected_idx - 1]["content"]

    user_input = st.text_area(
        "Payment Instruction Content",
        value=default_text,
        height=140,
        placeholder="Paste buyer instructions or refund claim...",
    )

    if st.button("Run Payment Analysis", key="btn_run_pay"):
        if not user_input.strip():
            st.warning("Please provide payment instructions to analyze.")
        else:
            with st.spinner("Auditing payment flow safety..."):
                eval_res, indicators = PaymentFraudDetector.analyze(user_input)
                recs = RecommendationEngine.get_recommendations("payment", eval_res.level, indicators)

                db.save_analysis(
                    analysis_type="Payment Fraud Detector",
                    risk_score=eval_res.score,
                    risk_level=eval_res.level,
                    raw_text_for_summary=user_input,
                    indicators_count=len(indicators),
                )

                st.session_state["pay_result"] = {
                    "text": user_input,
                    "eval": eval_res,
                    "indicators": indicators,
                    "recs": recs,
                }

    if "pay_result" in st.session_state:
        res = st.session_state["pay_result"]
        render_risk_result_card(res["eval"], "Payment Flow")

        col1, col2 = st.columns([1.6, 1])
        with col1:
            render_evidence_section(res["text"], res["indicators"])
        with col2:
            st.plotly_chart(build_risk_gauge(res["eval"].score, res["eval"].level, res["eval"].color), use_container_width=True)
            render_recommendations_section(res["recs"])


# ==========================================
# OPTION 6: ANALYSIS HISTORY
# ==========================================
def render_history_page():
    render_top_navbar("HISTORY")

    st.markdown(
        """
        <div style="margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 1.8rem;">📜 Analysis History</h2>
            <p style="color: #8C9BB4; font-size: 0.95rem; margin: 4px 0 0 0;">
                Audit records stored locally in SQLite. Sensitive credentials, OTPs, and card numbers are automatically redacted from summaries.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    records = db.get_recent_history(limit=100)

    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("Clear All History", key="btn_clear_hist_exec", use_container_width=True):
            if db.clear_history():
                st.success("History cleared.")
                st.rerun()

    if not records:
        st.info("No recorded analyses.")
        return

    df = pd.DataFrame(records)

    with col1:
        types = ["All Modules"] + list(df["analysis_type"].unique())
        chosen_type = st.selectbox("Filter by Module", options=types)

    if chosen_type != "All Modules":
        df = df[df["analysis_type"] == chosen_type]

    st.markdown(f"**Records Found: {len(df)}**")

    display_df = df[["analysis_id", "analysis_type", "risk_score", "risk_level", "summary", "created_at"]]
    display_df.columns = ["Audit ID", "Module", "Score", "Risk Level", "Sanitized Summary", "Timestamp"]
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("##### Delete Single Record")
    d1, d2 = st.columns([3, 1])
    with d1:
        target_id = st.selectbox("Select Record ID", options=df["analysis_id"].tolist())
    with d2:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("Delete Record", key="btn_del_single_exec", use_container_width=True):
            if db.delete_record(target_id):
                st.success(f"Record {target_id} deleted.")
                st.rerun()


# ==========================================
# OPTION 7: ABOUT
# ==========================================
def render_about_page():
    render_top_navbar("ABOUT")

    st.markdown(
        """
        <div style="background: #111726; border: 1px solid #1E2738; border-radius: 8px; padding: 24px 28px; margin-bottom: 24px;">
            <h2 style="color: #FFFFFF; margin: 0 0 10px 0;">About Digital Guardian AI</h2>
            <p style="color: #CBD5E1; line-height: 1.6; font-size: 0.95rem;">
                Digital Guardian AI is an <b>explainable, local decision support tool</b> designed to help users identify digital fraud,
                deceptive links, fake recruitment letters, and transaction manipulation.
            </p>
            <p style="color: #8C9BB4; line-height: 1.5; font-size: 0.88rem; margin: 0;">
                Calculations are fully transparent (0–100 risk index) with highlighted text evidence showing the exact rules matched and prioritized safety actions.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            """
            <div style="background: #0E1422; border: 1px solid #1E2738; border-radius: 8px; padding: 18px 22px; min-height: 180px;">
                <h4 style="color: #FFFFFF; margin-top: 0;">Local Security & Privacy</h4>
                <ul style="color: #8C9BB4; font-size: 0.86rem; line-height: 1.6; padding-left: 20px;">
                    <li>Zero cloud API requests or external AI services.</li>
                    <li>Automatic credential redaction before local storage.</li>
                    <li>Passive URL structural analysis without visiting target servers.</li>
                    <li>Full history control with clear and single-entry delete tools.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            """
            <div style="background: #0E1422; border: 1px solid #1E2738; border-radius: 8px; padding: 18px 22px; min-height: 180px;">
                <h4 style="color: #FFFFFF; margin-top: 0;">Decision-Support Disclaimer</h4>
                <p style="color: #8C9BB4; font-size: 0.86rem; line-height: 1.6;">
                    Digital Guardian AI is an <b>assistive advisory tool</b>, not a legal or definitive guarantee that a message, URL, or company is safe or fraudulent.
                </p>
                <p style="color: #64748B; font-size: 0.82rem; line-height: 1.5; margin: 0;">
                    Always verify independently with official organizations before transferring funds or disclosing sensitive information.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ==========================================
# MAIN APP ROUTER
# ==========================================
def main():
    active_view = st.session_state.get("active_view", "HOME")

    if active_view == "HOME":
        render_home_menu()
    elif active_view == "DASHBOARD":
        render_dashboard_page()
    elif active_view == "MESSAGE":
        render_message_scanner_page()
    elif active_view == "URL":
        render_url_analyzer_page()
    elif active_view == "JOB":
        render_job_detector_page()
    elif active_view == "PAYMENT":
        render_payment_detector_page()
    elif active_view == "HISTORY":
        render_history_page()
    elif active_view == "ABOUT":
        render_about_page()


if __name__ == "__main__":
    main()
