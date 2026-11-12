"""Evidence Highlighting and Extraction Engine for Digital Guardian AI.

Safely highlights detected suspicious phrases in user-provided content,
resolving overlapping or nested matches, escaping HTML safely, and providing
clear rule citations without ever fabricating or altering the source text.
"""

from __future__ import annotations
import html
import re
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
from core.risk_engine import DetectedIndicator


@dataclass
class EvidenceItem:
    """Structured evidence item for display and reporting."""
    rule_id: str
    title: str
    category: str
    severity: str
    matched_text: str
    description: str
    start: int
    end: int


class EvidenceEngine:
    """Handles text span alignment, interval merging, and safe HTML markup."""

    @classmethod
    def extract_evidence(
        cls, original_text: str, indicators: List[DetectedIndicator]
    ) -> List[EvidenceItem]:
        """Aligns indicators to actual text offsets and produces sorted EvidenceItems."""
        if not original_text or not indicators:
            return []

        evidence: List[EvidenceItem] = []
        text_lower = original_text.lower()

        for ind in indicators:
            matched = ind.matched_text.strip()
            if not matched:
                continue

            # If valid span already provided and matches
            s, e = ind.span
            if 0 <= s < e <= len(original_text) and original_text[s:e].lower() == matched.lower():
                evidence.append(
                    EvidenceItem(
                        rule_id=ind.rule_id,
                        title=ind.title,
                        category=ind.category,
                        severity=ind.severity,
                        matched_text=original_text[s:e],
                        description=ind.description,
                        start=s,
                        end=e,
                    )
                )
                continue

            # Otherwise find all occurrences in the text
            # Escape regex special characters in the matched snippet
            pattern = re.escape(matched)
            for m in re.finditer(pattern, original_text, flags=re.IGNORECASE):
                start_idx = m.start()
                end_idx = m.end()
                evidence.append(
                    EvidenceItem(
                        rule_id=ind.rule_id,
                        title=ind.title,
                        category=ind.category,
                        severity=ind.severity,
                        matched_text=original_text[start_idx:end_idx],
                        description=ind.description,
                        start=start_idx,
                        end=end_idx,
                    )
                )
                # Tag the primary occurrence to avoid clutter
                break

        # Sort primarily by start offset
        evidence.sort(key=lambda x: (x.start, -(x.end - x.start)))
        return evidence

    @classmethod
    def render_highlighted_html(
        cls, original_text: str, indicators: List[DetectedIndicator]
    ) -> str:
        """Renders original text with colored highlight spans without breaking HTML or nesting."""
        if not original_text:
            return "<div class='empty-text-notice'>No content submitted for analysis.</div>"

        evidence = cls.extract_evidence(original_text, indicators)
        if not evidence:
            escaped = html.escape(original_text).replace("\n", "<br>")
            return f"<div class='safe-text-preview'>{escaped}</div>"

        # Severity ranking for color precedence
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        severity_colors = {
            "CRITICAL": "#EF4444",
            "HIGH": "#F97316",
            "MEDIUM": "#F59E0B",
            "LOW": "#3B82F6",
        }

        # Build boundary points for interval partitioning
        points = set([0, len(original_text)])
        for ev in evidence:
            points.add(max(0, min(len(original_text), ev.start)))
            points.add(max(0, min(len(original_text), ev.end)))

        sorted_points = sorted(list(points))
        slices_html: List[str] = []

        for i in range(len(sorted_points) - 1):
            p1 = sorted_points[i]
            p2 = sorted_points[i + 1]
            if p1 >= p2:
                continue

            slice_text = original_text[p1:p2]
            slice_escaped = html.escape(slice_text).replace("\n", "<br>")

            # Check which evidence items cover this slice
            matching_ev = [ev for ev in evidence if ev.start <= p1 and p2 <= ev.end]

            if matching_ev:
                # Pick highest severity among overlapping indicators
                top_ev = max(matching_ev, key=lambda ev: severity_rank.get(ev.severity, 0))
                color = severity_colors.get(top_ev.severity, "#EF4444")
                rules_summary = "; ".join(set(ev.title for ev in matching_ev))
                title_attr = html.escape(f"[{top_ev.severity}] {rules_summary}: {top_ev.description}")

                # Styled inline badge highlight
                slice_html = (
                    f'<mark class="dg-highlight dg-{top_ev.severity.lower()}" '
                    f'style="background: {color}2A; color: #FFFFFF; border-bottom: 2px solid {color}; '
                    f'padding: 2px 4px; border-radius: 4px; font-weight: 500;" '
                    f'title="{title_attr}">{slice_escaped}</mark>'
                )
                slices_html.append(slice_html)
            else:
                slices_html.append(slice_escaped)

        return "".join(slices_html)
