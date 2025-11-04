"""
Storage Module for LLM Analysis Reports

Handles database operations for the reports table in rag.db
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportStorage:
    """
    Manages storage of LLM-generated threat analysis reports
    """

    def __init__(self, db_path: str):
        """
        Initialize report storage

        Args:
            db_path: Path to SQLite database (rag.db)
        """
        self.db_path = Path(db_path)
        self.conn = None

        # Ensure database exists
        if not self.db_path.exists():
            logger.warning(f"Database not found at {db_path}, will create it")

        self._init_database()

    def _init_database(self):
        """Create reports table if it doesn't exist"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        # Create reports table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                hosts TEXT,
                agents TEXT,
                alerts_count INTEGER NOT NULL,
                mitre_list TEXT,
                summary TEXT,
                risk_score INTEGER,
                details JSON,
                iocs JSON,
                suggested_actions JSON,
                faiss_context TEXT
            )
        """)

        # Create index for faster queries
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_created
            ON reports(created_at DESC)
        """)

        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_reports_window
            ON reports(window_start, window_end)
        """)

        self.conn.commit()
        logger.info("Reports table initialized")

    def save_report(
        self,
        window_start: datetime,
        window_end: datetime,
        alerts_count: int,
        llm_output: Dict[str, Any],
        hosts: List[str],
        agents: List[str],
        risk_score: int,
        faiss_context: List[Dict[str, Any]]
    ) -> int:
        """
        Save an LLM-generated report to database

        Args:
            window_start: Analysis window start time
            window_end: Analysis window end time
            alerts_count: Number of alerts analyzed
            llm_output: Parsed JSON output from LLM
            hosts: List of affected hosts
            agents: List of affected agents
            risk_score: Calculated risk score (0-100)
            faiss_context: Retrieved knowledge items from FAISS

        Returns:
            Report ID (auto-incremented primary key)
        """
        # Format timestamps
        window_start_str = window_start.isoformat()
        window_end_str = window_end.isoformat()

        # Extract fields from LLM output
        summary = llm_output.get('summary', '')
        mitre_list = json.dumps(llm_output.get('mitre_list', []))
        iocs = json.dumps(llm_output.get('iocs', []))
        suggested_actions = json.dumps(llm_output.get('suggested_actions', []))
        details = json.dumps(llm_output.get('details', llm_output))

        # Format hosts and agents
        hosts_str = ', '.join(hosts) if hosts else None
        agents_str = ', '.join(agents) if agents else None

        # Format FAISS context
        faiss_context_str = json.dumps([
            {
                'entity_type': item.get('entity_type'),
                'name': item.get('name'),
                'score': item.get('score', 0),
                'mitre_id': item.get('metadata', {}).get('mitre_id')
            }
            for item in faiss_context
        ])

        # Insert report
        cursor = self.conn.execute("""
            INSERT INTO reports (
                window_start, window_end, hosts, agents, alerts_count,
                mitre_list, summary, risk_score, details, iocs,
                suggested_actions, faiss_context
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            window_start_str,
            window_end_str,
            hosts_str,
            agents_str,
            alerts_count,
            mitre_list,
            summary,
            risk_score,
            details,
            iocs,
            suggested_actions,
            faiss_context_str
        ))

        self.conn.commit()
        report_id = cursor.lastrowid

        logger.info(
            f"Saved report {report_id} for window {window_start_str} to {window_end_str} "
            f"({alerts_count} alerts, risk score: {risk_score})"
        )

        return report_id

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a single report by ID

        Args:
            report_id: Report ID

        Returns:
            Report dict or None if not found
        """
        cursor = self.conn.execute(
            "SELECT * FROM reports WHERE id = ?",
            (report_id,)
        )
        row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_dict(row)

    def get_recent_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent reports

        Args:
            limit: Maximum number of reports to return

        Returns:
            List of report dicts
        """
        cursor = self.conn.execute(
            "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )

        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def get_reports_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get reports within a date range

        Args:
            start_date: Start of range
            end_date: End of range

        Returns:
            List of report dicts
        """
        cursor = self.conn.execute("""
            SELECT * FROM reports
            WHERE created_at >= ? AND created_at <= ?
            ORDER BY created_at DESC
        """, (start_date.isoformat(), end_date.isoformat()))

        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def get_high_risk_reports(self, min_score: int = 70) -> List[Dict[str, Any]]:
        """
        Get reports with risk score above threshold

        Args:
            min_score: Minimum risk score

        Returns:
            List of report dicts
        """
        cursor = self.conn.execute("""
            SELECT * FROM reports
            WHERE risk_score >= ?
            ORDER BY risk_score DESC, created_at DESC
        """, (min_score,))

        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert SQLite row to dictionary with JSON parsing"""
        report = dict(row)

        # Parse JSON fields
        for field in ['mitre_list', 'details', 'iocs', 'suggested_actions', 'faiss_context']:
            if report.get(field):
                try:
                    report[field] = json.loads(report[field])
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse JSON for field {field}")
                    report[field] = []

        return report

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about stored reports

        Returns:
            Dict with statistics
        """
        cursor = self.conn.execute("""
            SELECT
                COUNT(*) as total_reports,
                AVG(risk_score) as avg_risk_score,
                MAX(risk_score) as max_risk_score,
                SUM(alerts_count) as total_alerts_analyzed,
                MIN(created_at) as first_report,
                MAX(created_at) as last_report
            FROM reports
        """)

        row = cursor.fetchone()

        return {
            'total_reports': row['total_reports'],
            'avg_risk_score': round(row['avg_risk_score'], 2) if row['avg_risk_score'] else 0,
            'max_risk_score': row['max_risk_score'] or 0,
            'total_alerts_analyzed': row['total_alerts_analyzed'] or 0,
            'first_report': row['first_report'],
            'last_report': row['last_report']
        }

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
