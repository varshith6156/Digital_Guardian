"""Database and Privacy Manager for Digital Guardian AI.

Maintains local SQLite history with strict privacy controls:
- Strips sensitive credentials, OTPs, and personal numbers from stored summaries
- Never saves full raw input messages by default
- Supports full history clearing and individual record deletion
- Graceful error handling for database access
"""

from __future__ import annotations
import sqlite3
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


DB_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DB_DIR / "digital_guardian.db"


class DatabaseManager:
    """Manages SQLite persistent storage for audit logs and dashboard statistics."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._ensure_dir()
        self.init_db()

    def _ensure_dir(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> bool:
        """Initializes tables with proper schema and indexes."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS analysis_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id TEXT UNIQUE NOT NULL,
                        analysis_type TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        indicators_count INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_analysis_type 
                    ON analysis_history(analysis_type)
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_created_at 
                    ON analysis_history(created_at)
                    """
                )
                conn.commit()
            return True
        except Exception:
            return False

    @staticmethod
    def sanitize_summary(text: str, max_length: int = 140) -> str:
        """Sanitizes content to strip credentials, OTPs, PINs, card numbers, and tokens."""
        if not text:
            return "Empty input analyzed."

        sanitized = text.strip()
        # Redact 4 to 8 digit codes (potential OTPs, PINs, 2FA codes)
        sanitized = re.sub(r"\b\d{4,8}\b", "[REDACTED-NUM]", sanitized)
        # Redact credit/debit card numbers
        sanitized = re.sub(r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED-CARD]", sanitized)
        # Redact password mentions
        sanitized = re.sub(
            r"(?i)(password|passcode|secret|pin|cvv)\s*[:=]\s*\S+",
            r"\1: [REDACTED]",
            sanitized,
        )
        # Redact email addresses
        sanitized = re.sub(
            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "[REDACTED-EMAIL]",
            sanitized,
        )
        # Collapse whitespace
        sanitized = " ".join(sanitized.split())
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length].rstrip() + "..."
        return sanitized

    def save_analysis(
        self,
        analysis_type: str,
        risk_score: int,
        risk_level: str,
        raw_text_for_summary: str,
        indicators_count: int = 0,
        custom_id: Optional[str] = None,
    ) -> Optional[str]:
        """Saves an anonymized analysis entry. Returns the analysis_id on success."""
        analysis_id = custom_id or f"DGAI-{uuid.uuid4().hex[:10].upper()}"
        summary = self.sanitize_summary(raw_text_for_summary)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO analysis_history (
                        analysis_id, analysis_type, risk_score, risk_level, 
                        summary, indicators_count, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        analysis_id,
                        analysis_type,
                        int(risk_score),
                        str(risk_level).upper(),
                        summary,
                        int(indicators_count),
                        timestamp,
                    ),
                )
                conn.commit()
            return analysis_id
        except Exception:
            return None

    def get_recent_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetches the latest analyses up to the given limit."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT analysis_id, analysis_type, risk_score, risk_level, 
                           summary, indicators_count, created_at
                    FROM analysis_history
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception:
            return []

    def get_summary_stats(self) -> Dict[str, Any]:
        """Calculates dashboard metrics from actual recorded database analyses."""
        stats = {
            "total_analyses": 0,
            "counts_by_level": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "counts_by_type": {},
            "average_risk_score": 0.0,
        }
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Total and average
                cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM analysis_history")
                row = cursor.fetchone()
                if row and row[0]:
                    stats["total_analyses"] = row[0]
                    stats["average_risk_score"] = round(float(row[1] or 0), 1)

                # Counts by risk level
                cursor.execute(
                    """
                    SELECT risk_level, COUNT(*) 
                    FROM analysis_history 
                    GROUP BY risk_level
                    """
                )
                for level, count in cursor.fetchall():
                    if level in stats["counts_by_level"]:
                        stats["counts_by_level"][level] = count

                # Counts by module type
                cursor.execute(
                    """
                    SELECT analysis_type, COUNT(*) 
                    FROM analysis_history 
                    GROUP BY analysis_type
                    """
                )
                for atype, count in cursor.fetchall():
                    stats["counts_by_type"][atype] = count

            return stats
        except Exception:
            return stats

    def delete_record(self, analysis_id: str) -> bool:
        """Deletes a single analysis record by its ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM analysis_history WHERE analysis_id = ?",
                    (analysis_id,),
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception:
            return False

    def clear_history(self) -> bool:
        """Clears all analysis history completely."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM analysis_history")
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='analysis_history'")
                conn.commit()
            return True
        except Exception:
            return False

