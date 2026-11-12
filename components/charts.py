"""Plotly charts and visualizations for Digital Guardian AI (Executive Theme)."""

from typing import Dict, Any
import plotly.graph_objects as go


CHART_THEME = {
    "paper_bgcolor": "rgba(0,0,0,0)",
    "plot_bgcolor": "rgba(0,0,0,0)",
    "font": {"color": "#8C9BB4", "family": "Inter, -apple-system, sans-serif"},
    "margin": {"l": 15, "r": 15, "t": 35, "b": 15},
}


def build_risk_distribution_chart(counts_by_level: Dict[str, int]) -> go.Figure:
    """Builds a polished donut chart of analysis results by risk tier."""
    labels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    values = [counts_by_level.get(l, 0) for l in labels]
    colors = ["#10B981", "#F59E0B", "#F97316", "#EF4444"]

    total = sum(values)

    if total == 0:
        labels = ["No Data Yet"]
        values = [1]
        colors = ["#1E2738"]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.68,
                marker=dict(colors=colors, line=dict(color="#0B0E14", width=2)),
                textinfo="percent" if total > 0 and labels != ["No Data Yet"] else "none",
                hoverinfo="label+value+percent",
                textfont=dict(color="#FFFFFF", size=11),
            )
        ]
    )

    if total > 0 and labels != ["No Data Yet"]:
        fig.add_annotation(
            text=f"<b>{total}</b><br><span style='font-size:10px;color:#64748B;'>AUDITS</span>",
            x=0.5,
            y=0.5,
            showarrow=False,
            font=dict(size=17, color="#FFFFFF"),
        )

    fig.update_layout(
        title=dict(text="Risk Severity Distribution", font=dict(size=13, color="#FFFFFF")),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
            font=dict(size=11, color="#8C9BB4"),
        ),
        height=260,
        **CHART_THEME,
    )
    return fig


def build_module_breakdown_chart(counts_by_type: Dict[str, int]) -> go.Figure:
    """Builds a horizontal bar chart showing detections per module."""
    modules = [
        "Message Scanner",
        "URL Analyzer",
        "Job Scam Detector",
        "Payment Fraud Detector",
    ]
    display_names = ["Messages", "URLs", "Jobs/Offers", "Payments"]
    values = [counts_by_type.get(m, 0) for m in modules]

    fig = go.Figure(
        data=[
            go.Bar(
                x=values,
                y=display_names,
                orientation="h",
                marker=dict(
                    color=["#475569", "#64748B", "#4B5563", "#374151"],
                    line=dict(color="#1E2738", width=1),
                ),
                text=values,
                textposition="auto",
                textfont=dict(color="#FFFFFF", size=11),
            )
        ]
    )

    fig.update_layout(
        title=dict(text="Audits by Detection Category", font=dict(size=13, color="#FFFFFF")),
        xaxis=dict(gridcolor="#1E2738", zeroline=False, tickfont=dict(color="#64748B")),
        yaxis=dict(tickfont=dict(color="#E2E8F0")),
        height=260,
        **CHART_THEME,
    )
    return fig


def build_risk_gauge(score: int, level: str, color: str) -> go.Figure:
    """Builds a circular gauge for instant visual feedback of risk index."""
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            title={"text": f"<b>{level}</b>", "font": {"size": 15, "color": color}},
            number={"font": {"size": 32, "color": "#FFFFFF"}, "suffix": "/100"},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#374151"},
                "bar": {"color": color, "thickness": 0.3},
                "bgcolor": "#0D121F",
                "borderwidth": 1,
                "bordercolor": "#1E2738",
                "steps": [
                    {"range": [0, 24], "color": "rgba(16, 185, 129, 0.08)"},
                    {"range": [25, 49], "color": "rgba(245, 158, 11, 0.08)"},
                    {"range": [50, 74], "color": "rgba(249, 115, 22, 0.08)"},
                    {"range": [75, 100], "color": "rgba(239, 68, 68, 0.08)"},
                ],
            },
        )
    )

    fig.update_layout(
        height=200,
        margin={"l": 15, "r": 15, "t": 15, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#8C9BB4"},
    )
    return fig
