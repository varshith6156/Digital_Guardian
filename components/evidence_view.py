"""Evidence view and recommendations renderer for Digital Guardian AI (Executive Theme)."""

import streamlit as st
import html
from typing import List
from core.risk_engine import DetectedIndicator
from core.evidence_engine import EvidenceEngine
from core.recommendations import SafetyRecommendation


def render_evidence_section(original_text: str, indicators: List[DetectedIndicator]):
    """Renders both the inline text highlight console and the structured evidence item cards."""
    st.markdown(
        """
        <div style="font-size: 1.1rem; font-weight: 700; color: #FFFFFF; margin: 18px 0 10px 0;">
            🔍 Evidence & Content Inspection
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not original_text or not original_text.strip():
        st.info("No content provided to display evidence.")
        return

    if not indicators:
        st.markdown(
            """
            <div style="background: #0E1624; border: 1px solid #1E2E40; border-radius: 6px; padding: 16px 20px; color: #8C9BB4;">
                <div style="color: #10B981; font-weight: 600; font-size: 0.95rem; margin-bottom: 4px;">
                    ✅ No Suspicious Indicators Flagged
                </div>
                No manipulative or deceptive patterns were matched in this input. The communication appears standard.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Render highlighted text card
    highlighted_html = EvidenceEngine.render_highlighted_html(original_text, indicators)

    st.markdown(
        f"""
        <div style="background: #0B0E17; border: 1px solid #1E2738; border-radius: 8px; overflow: hidden; margin-bottom: 18px;">
            <div style="background: #0F1523; border-bottom: 1px solid #1E2738; padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; font-family: monospace; font-size: 0.75rem; color: #64748B;">
                <span>ANALYZED_INPUT_STREAM</span>
                <span style="color: #94A3B8;">{len(indicators)} flagged indicator(s)</span>
            </div>
            <div style="padding: 16px 20px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.88rem; line-height: 1.7; color: #E2E8F0; white-space: pre-wrap; word-break: break-word;">
                {highlighted_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Detailed indicators breakdown
    st.markdown(
        f"""
        <div style="font-size: 0.8rem; font-weight: 700; color: #8C9BB4; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 8px;">
            Flagged Rules ({len(indicators)})
        </div>
        """,
        unsafe_allow_html=True,
    )

    severity_colors = {
        "CRITICAL": "#EF4444",
        "HIGH": "#F97316",
        "MEDIUM": "#F59E0B",
        "LOW": "#64748B",
    }

    for idx, ind in enumerate(indicators, 1):
        color = severity_colors.get(ind.severity, "#64748B")
        matched_str = html.escape(ind.matched_text) if ind.matched_text else "Pattern match"

        st.markdown(
            f"""
            <div style="background: #111726; border: 1px solid #1E2738; border-left: 4px solid {color}; border-radius: 6px; padding: 12px 16px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; flex-wrap: wrap; gap: 8px;">
                    <div style="color: #FFFFFF; font-weight: 600; font-size: 0.92rem;">
                        {idx}. {ind.title}
                    </div>
                    <span style="background: #0B0F19; color: {color}; border: 1px solid #1E2738; border-radius: 4px; padding: 2px 8px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase;">
                        {ind.severity} (+{ind.weight or 0} pts)
                    </span>
                </div>
                <div style="color: #94A3B8; font-size: 0.84rem; margin-bottom: 6px; line-height: 1.4;">
                    {ind.description}
                </div>
                <div style="background: #0B0F19; border: 1px solid #1A2333; border-radius: 4px; padding: 5px 10px; font-family: monospace; font-size: 0.78rem; color: #CBD5E1; display: inline-block;">
                    Matched: <span style="color: #FFFFFF; font-weight: 600;">"{matched_str}"</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_recommendations_section(recommendations: List[SafetyRecommendation]):
    """Renders the actionable safety and verification checklist."""
    st.markdown(
        """
        <div style="font-size: 1.1rem; font-weight: 700; color: #FFFFFF; margin: 18px 0 10px 0;">
            🛡️ Recommended Safety Actions
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not recommendations:
        st.info("No special safety actions required. Continue practicing standard digital hygiene.")
        return

    badge_meta = {
        "DO_NOT": ("⛔ DO NOT", "#EF4444", "#1E1218"),
        "DO": ("✅ RECOMMENDED", "#10B981", "#0D1E19"),
        "VERIFY": ("🔍 VERIFY", "#E2E8F0", "#161D2B"),
        "REPORT": ("📢 REPORT", "#F59E0B", "#221C12"),
    }

    for rec in recommendations:
        badge_text, col, bg_col = badge_meta.get(
            rec.action_type, ("ℹ️ NOTE", "#94A3B8", "#121824")
        )

        st.markdown(
            f"""
            <div style="background: #111726; border: 1px solid #1E2738; border-radius: 6px; padding: 14px 16px; margin-bottom: 10px; display: flex; gap: 14px; align-items: flex-start;">
                <div style="background: {bg_col}; border: 1px solid #2A364B; color: {col}; border-radius: 4px; padding: 4px 8px; font-size: 0.7rem; font-weight: 700; white-space: nowrap; margin-top: 2px;">
                    {badge_text}
                </div>
                <div>
                    <div style="color: #FFFFFF; font-weight: 600; font-size: 0.92rem; margin-bottom: 2px;">
                        {rec.title}
                    </div>
                    <div style="color: #94A3B8; font-size: 0.84rem; line-height: 1.45;">
                        {rec.detail}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
