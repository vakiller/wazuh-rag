"""
Storage Module for LLM Analysis Reports

Handles database operations for the reports table (SQLite or PostgreSQL)
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class ReportStorage:
    """
    Manages storage of LLM-generated threat analysis reports
    """

    def __init__(self, db_path: str = None):
        """
        Initialize report storage

        Auto-detects PostgreSQL if DB_HOST env var is set, otherwise uses SQLite.

        Args:
            db_path: Path to SQLite database (only used if not using PostgreSQL)
        """
        self.conn = None
        self.use_postgres = bool(os.getenv('DB_HOST'))

        if self.use_postgres:
            # Use PostgreSQL
            import psycopg2
            import psycopg2.extras

            self.conn = psycopg2.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                port=os.getenv('DB_PORT', '5432'),
                database=os.getenv('DB_NAME', 'wazuh_rag'),
                user=os.getenv('DB_USER', 'wazuh_user'),
                password=os.getenv('DB_PASSWORD', '')
            )
            self.conn.autocommit = False
            logger.info(f"Connected to PostgreSQL database for reports: {os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}")
        else:
            # Use SQLite
            if db_path is None:
                db_path = "./rag.db"

            self.db_path = Path(db_path)

            if not self.db_path.exists():
                logger.warning(f"Database not found at {db_path}, will create it")

            self._init_sqlite()

    def _init_sqlite(self):
        """Initialize SQLite database"""
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
                severity TEXT,
                risk_score INTEGER,
                details JSON,
                iocs JSON,
                suggested_actions JSON,
                faiss_context TEXT
            )
        """)

        # Add severity column to existing tables (Phase 4 enhancement)
        try:
            self.conn.execute("ALTER TABLE reports ADD COLUMN severity TEXT")
            logger.info("Added severity column to reports table")
        except sqlite3.OperationalError:
            # Column already exists
            pass

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
        logger.info("Reports table initialized (SQLite)")
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
                severity TEXT,
                risk_score INTEGER,
                details JSON,
                iocs JSON,
                suggested_actions JSON,
                faiss_context TEXT
            )
        """)

        # Add severity column to existing tables (Phase 4 enhancement)
        try:
            self.conn.execute("ALTER TABLE reports ADD COLUMN severity TEXT")
            logger.info("Added severity column to reports table")
        except sqlite3.OperationalError:
            # Column already exists
            pass

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

        # Extract fields from LLM output (handles multiple response formats)
        extracted = self._extract_fields_from_llm_output(llm_output)

        # Ensure summary is a string
        summary = str(extracted.get('summary', '')) if extracted.get('summary') else ''

        # Extract severity (Phase 4)
        severity = extracted.get('severity', 'Medium')
        # Validate severity is one of the allowed values
        if severity not in ['Low', 'Medium', 'High', 'Critical']:
            logger.warning(f"Invalid severity value '{severity}', defaulting to 'Medium'")
            severity = 'Medium'

        # Convert to JSON strings for database storage - ensure they're always strings
        try:
            mitre_list_data = extracted.get('mitre_list', [])
            # Ensure it's serializable
            if mitre_list_data is None:
                mitre_list = "[]"
            else:
                mitre_list = json.dumps(mitre_list_data, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error serializing mitre_list: {e}, type: {type(extracted.get('mitre_list'))}, value: {extracted.get('mitre_list')}")
            mitre_list = "[]"

        try:
            iocs_data = extracted.get('iocs', {})
            if iocs_data is None:
                iocs = "{}"
            else:
                iocs = json.dumps(iocs_data, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error serializing iocs: {e}, type: {type(extracted.get('iocs'))}, value: {extracted.get('iocs')}")
            iocs = "{}"

        try:
            actions_data = extracted.get('suggested_actions', [])
            if actions_data is None:
                suggested_actions = "[]"
            else:
                suggested_actions = json.dumps(actions_data, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error serializing suggested_actions: {e}, type: {type(extracted.get('suggested_actions'))}, value: {extracted.get('suggested_actions')}")
            suggested_actions = "[]"

        try:
            # Custom JSON encoder to handle datetime objects
            def json_serial(obj):
                """JSON serializer for objects not serializable by default json code"""
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Type {type(obj)} not serializable")

            details = json.dumps(llm_output, ensure_ascii=False, default=json_serial)  # Store full LLM response
        except Exception as e:
            logger.error(f"Error serializing details (full LLM output): {e}")
            details = "{}"

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

        # Ensure all string parameters are actually strings (not None, lists, dicts, etc.)
        # SQLite only accepts: NULL, INTEGER, REAL, TEXT, BLOB
        mitre_list = str(mitre_list) if mitre_list is not None else "[]"
        summary = str(summary) if summary is not None else ""
        severity = str(severity) if severity is not None else "Medium"
        iocs = str(iocs) if iocs is not None else "{}"
        suggested_actions = str(suggested_actions) if suggested_actions is not None else "[]"
        details = str(details) if details is not None else "{}"
        faiss_context_str = str(faiss_context_str) if faiss_context_str is not None else "[]"

        # Build params tuple (Phase 4 includes severity)
        params = (
            window_start_str,
            window_end_str,
            hosts_str,
            agents_str,
            alerts_count,
            mitre_list,
            summary,
            severity,
            risk_score,
            details,
            iocs,
            suggested_actions,
            faiss_context_str
        )

        logger.debug(f"Parameter types: {[type(p).__name__ for p in params]}")
        logger.debug(f"Severity: {severity}, Risk Score: {risk_score}")

        # Insert report (different syntax for SQLite vs PostgreSQL)
        if self.use_postgres:
            import psycopg2.extras
            import psycopg2.extensions

            # Register adapter for dicts only (NOT lists, as they conflict with PostgreSQL arrays)
            psycopg2.extensions.register_adapter(dict, psycopg2.extras.Json)

            # For PostgreSQL: use actual Python lists for array columns
            hosts_array = hosts if hosts else []
            agents_array = agents if agents else []

            # Helper to parse JSON strings and wrap in psycopg2.extras.Json for JSONB columns
            def to_jsonb(val):
                if isinstance(val, str):
                    try:
                        parsed = json.loads(val)
                        return psycopg2.extras.Json(parsed)
                    except:
                        return psycopg2.extras.Json(val)
                return psycopg2.extras.Json(val)

            # PostgreSQL uses %s placeholders and RETURNING for ID
            with self.conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO reports (
                        window_start, window_end, hosts, agents, alerts_count,
                        mitre_list, summary, severity, risk_score, details, iocs,
                        suggested_actions, faiss_context
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    window_start,
                    window_end,
                    hosts_array,
                    agents_array,
                    alerts_count,
                    to_jsonb(mitre_list),
                    summary,
                    severity,
                    risk_score,
                    to_jsonb(details),
                    to_jsonb(iocs),
                    to_jsonb(suggested_actions),
                    to_jsonb(faiss_context_str)
                ))
                report_id = cursor.fetchone()[0]

            self.conn.commit()
        else:
            # SQLite uses ? placeholders
            cursor = self.conn.execute("""
                INSERT INTO reports (
                    window_start, window_end, hosts, agents, alerts_count,
                    mitre_list, summary, severity, risk_score, details, iocs,
                    suggested_actions, faiss_context
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, params)

            self.conn.commit()
            report_id = cursor.lastrowid

        logger.info(
            f"Saved report {report_id} for window {window_start_str} to {window_end_str} "
            f"({alerts_count} alerts, severity: {severity}, risk score: {risk_score})"
        )

        return report_id

    def _extract_fields_from_llm_output(self, llm_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract fields from LLM output in the expected Phase 4 format

        Args:
            llm_output: Raw LLM output dictionary

        Returns:
            Dict with extracted fields for Phase 4
        """
        # Phase 4 expected format:
        # {
        #   "summary": "...",
        #   "severity": "Low|Medium|High|Critical",
        #   "timeline": [{timestamp, host, tactic, technique, description}],
        #   "mitre_list": [{technique_id, technique_name, tactic}],
        #   "iocs": {ips: [], users: [], hashes: [], domains: [], file_paths: [], registry_keys: [], processes: [], commands: []},
        #   "suggested_actions": {containment: [], eradication: [], recovery: []},
        #   "business_impact": {affected_systems, operational_risk, data_integrity_risk, domain_wide_risk},
        #   "evidence_map": [{finding, alert_ids, timestamps, hosts, knowledge_refs}],
        #   "detection_recommendations": [{type, description}],
        #   ...
        # }

        result = {
            'summary': llm_output.get('summary', llm_output.get('tldr', '')),
            'severity': llm_output.get('severity', 'Medium'),
            'mitre_list': llm_output.get('mitre_list', []),
            'iocs': llm_output.get('iocs', {}),
            'suggested_actions': llm_output.get('suggested_actions', {}),
            'timeline': llm_output.get('timeline', []),
            'business_impact': llm_output.get('business_impact', {}),
            'evidence_map': llm_output.get('evidence_map', []),
            'detection_recommendations': llm_output.get('detection_recommendations', [])
        }

        # Ensure iocs has the Phase 4 structure
        if not isinstance(result['iocs'], dict):
            result['iocs'] = {}

        # Ensure all required IOC fields exist (Phase 4 expanded)
        ioc_template = {
            'ips': [],
            'users': [],
            'hashes': [],
            'domains': [],
            'file_paths': [],
            'registry_keys': [],
            'processes': [],
            'commands': []
        }
        for key, default_value in ioc_template.items():
            if key not in result['iocs']:
                result['iocs'][key] = default_value

        # Ensure suggested_actions has Phase 4 structure (object with 3 phases)
        if not isinstance(result['suggested_actions'], dict):
            result['suggested_actions'] = {'containment': [], 'eradication': [], 'recovery': []}
        else:
            for phase in ['containment', 'eradication', 'recovery']:
                if phase not in result['suggested_actions']:
                    result['suggested_actions'][phase] = []

        # Ensure business_impact has proper structure
        if not isinstance(result['business_impact'], dict):
            result['business_impact'] = {}
        impact_template = {
            'affected_systems': [],
            'operational_risk': '',
            'data_integrity_risk': '',
            'domain_wide_risk': ''
        }
        for key, default_value in impact_template.items():
            if key not in result['business_impact']:
                result['business_impact'][key] = default_value

        return result

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
