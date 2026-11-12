"""Risk Result Card Component for Digital Guardian AI (Executive Professional Theme)."""

import streamlit as st
from core.risk_engine import RiskEvaluation


def render_risk_result_card(eval_res: RiskEvaluation, module_name: str):
    """Renders a clean, executive risk assessment card without bright blue styling."""
    score = eval_res.score
    level = eval_res.level
    color = eval_res.color

    crit_count = len(eval_res.indicators_by_severity.get("CRITICAL", []))
    high_count = len(eval_res.indicators_by_severity.get("HIGH", []))
    med_count = len(eval_res.indicators_by_severity.get("MEDIUM", []))
    low_count = len(eval_res.indicators_by_severity.get("LOW", []))

    st.markdown(
        f"""
        <div style="background: #111726; 
                    border: 1px solid #1E2738; 
                    border-left: 5px solid {color}; 
                    border-radius: 8px; 
                    padding: 22px 24px; 
                    margin-bottom: 22px; 
                    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);">
            
            <!-- Header Row -->
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px; margin-bottom: 18px;">
                <div>
                    <div style="font-size: 0.74rem; text-transform: uppercase; letter-spacing: 1px; color: #8C9BB4; font-weight: 600;">
                        {module_name} Assessment Report
                    </div>
                    <div style="margin: 4px 0 0 0; font-size: 1.6rem; font-weight: 700; color: #FFFFFF;">
                        Risk Evaluation: <span style="color: {color};">{level}</span>
                    </div>
                </div>

                <!-- Score Indicator -->
                <div style="background: #0B0F19; border: 1px solid #1E2738; border-radius: 8px; padding: 10px 20px; text-align: center;">
                    <div style="font-size: 2.1rem; font-weight: 800; color: {color}; line-height: 1;">
                        {score}<span style="font-size: 1rem; font-weight: 500; color: #64748B;">/100</span>
                    </div>
                    <div style="font-size: 0.68rem; color: #8C9BB4; text-transform: uppercase; font-weight: 600; letter-spacing: 0.8px; margin-top: 3px;">
                        Risk Index
                    </div>
                </div>
            </div>

            <!-- Risk Tier Meter -->
            <div style="margin-bottom: 18px;">
                <div style="display: flex; justify-content: space-between; font-size: 0.72rem; font-weight: 500; color: #64748B; margin-bottom: 5px;">
                    <span>LOW (0–24)</span>
                    <span>MEDIUM (25–49)</span>
                    <span>HIGH (50–74)</span>
                    <span>CRITICAL (75–100)</span>
                </div>
                <div style="width: 100%; height: 7px; background: #0B0F19; border-radius: 4px; overflow: hidden; border: 1px solid #1E2738;">
                    <div style="width: {max(3, score)}%; height: 100%; background: linear-gradient(90deg, #10B981 0%, #F59E0B 40%, #F97316 70%, #EF4444 100%); border-radius: 4px;"></div>
                </div>
            </div>

            <!-- Verdict & Explanation -->
            <div style="background: #0D121F; border: 1px solid #1A2333; border-radius: 6px; padding: 14px 18px; margin-bottom: 18px;">
                <div style="color: #F1F5F9; font-size: 0.94rem; font-weight: 600; margin-bottom: 4px;">
                    {eval_res.summary_verdict}
                </div>
                <div style="color: #94A3B8; font-size: 0.86rem; line-height: 1.5;">
                    {eval_res.explanation}
                </div>
            </div>

            <!-- Severity Counters Grid -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px;">
                <div style="background: #0D121F; border: 1px solid #1E2738; border-radius: 6px; padding: 10px; text-align: center;">
                    <div style="color: #EF4444; font-size: 1.25rem; font-weight: 700;">{crit_count}</div>
                    <div style="color: #8C9BB4; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;">Critical Flags</div>
                </div>
                <div style="background: #0D121F; border: 1px solid #1E2738; border-radius: 6px; padding: 10px; text-align: center;">
                    <div style="color: #F97316; font-size: 1.25rem; font-weight: 700;">{high_count}</div>
                    <div style="color: #8C9BB4; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;">High Flags</div>
                </div>
                <div style="background: #0D121F; border: 1px solid #1E2738; border-radius: 6px; padding: 10px; text-align: center;">
                    <div style="color: #F59E0B; font-size: 1.25rem; font-weight: 700;">{med_count}</div>
                    <div style="color: #8C9BB4; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;">Medium Flags</div>
                </div>
                <div style="background: #0D121F; border: 1px solid #1E2738; border-radius: 6px; padding: 10px; text-align: center;">
                    <div style="color: #10B981; font-size: 1.25rem; font-weight: 700;">{low_count}</div>
                    <div style="color: #8C9BB4; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;">Low / Normal</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
