"""
SQLite-based output handler for storing normalized alerts in a relational database.
"""

import sqlite3
from typing import Dict, Any, Optional
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class SQLiteOutputHandler:
    """
    Store normalized alerts in SQLite database.

    Suitable for:
    - Moderate data volumes (millions of alerts)
    - SQL-based querying and reporting
    - Local development and analysis
    - Environments without external database infrastructure

    Features:
    - Automatic schema creation
    - Indexed columns for common queries
    - UPSERT support (INSERT OR REPLACE)
    - Transaction batching for performance
    """

    def __init__(self, db_path: str = "./wazuh_alerts.db", batch_size: int = 100):
        """
        Initialize the SQLite handler.

        Args:
            db_path: Path to SQLite database file
            batch_size: Number of inserts to batch before committing
        """
        self.db_path = Path(db_path)
        self.batch_size = batch_size
        self.conn: Optional[sqlite3.Connection] = None
        self.pending_count = 0
        self._init_db()
        logger.info(f"SQLite output handler initialized: {self.db_path}")

    def _init_db(self):
        """Initialize database connection and create schema."""
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)

        # Create alerts table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                document_id TEXT UNIQUE NOT NULL,
                index_name TEXT,
                agent_id TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                rule_id TEXT,
                rule_description TEXT,
                rule_level INTEGER,
                rule_groups TEXT,  -- JSON array
                mitre_techniques TEXT,  -- JSON array
                mitre_tactics TEXT,  -- JSON array
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                file_path TEXT,
                file_hash TEXT,
                process_name TEXT,
                process_id INTEGER,
                command_line TEXT,
                username TEXT,
                win_eventid INTEGER,
                full_log TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for common queries
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_agent_id ON alerts(agent_id)",
            "CREATE INDEX IF NOT EXISTS idx_rule_level ON alerts(rule_level)",
            "CREATE INDEX IF NOT EXISTS idx_rule_id ON alerts(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_source_ip ON alerts(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_dest_ip ON alerts(dest_ip)",
            "CREATE INDEX IF NOT EXISTS idx_document_id ON alerts(document_id)",
        ]

        for index_sql in indexes:
            self.conn.execute(index_sql)

        self.conn.commit()
        logger.info("Database schema initialized")

    def handle(self, normalized_alert: Dict[str, Any]):
        """
        Insert normalized alert into database.

        Uses INSERT OR REPLACE to handle duplicate document_ids gracefully.

        Args:
            normalized_alert: Normalized alert dictionary
        """
        try:
            # Convert arrays to JSON strings
            alert_copy = normalized_alert.copy()
            alert_copy['rule_groups'] = json.dumps(alert_copy.get('rule_groups', []))
            alert_copy['mitre_techniques'] = json.dumps(alert_copy.get('mitre_techniques', []))
            alert_copy['mitre_tactics'] = json.dumps(alert_copy.get('mitre_tactics', []))

            self.conn.execute("""
                INSERT OR REPLACE INTO alerts (
                    timestamp, document_id, index_name, agent_id, agent_name, agent_ip,
                    rule_id, rule_description, rule_level, rule_groups,
                    mitre_techniques, mitre_tactics,
                    source_ip, dest_ip, source_port, dest_port, protocol,
                    file_path, file_hash, process_name, process_id, command_line,
                    username, win_eventid, full_log
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                alert_copy.get('timestamp'),
                alert_copy.get('document_id'),
                alert_copy.get('index_name'),
                alert_copy.get('agent_id'),
                alert_copy.get('agent_name'),
                alert_copy.get('agent_ip'),
                alert_copy.get('rule_id'),
                alert_copy.get('rule_description'),
                alert_copy.get('rule_level'),
                alert_copy.get('rule_groups'),
                alert_copy.get('mitre_techniques'),
                alert_copy.get('mitre_tactics'),
                alert_copy.get('source_ip'),
                alert_copy.get('dest_ip'),
                alert_copy.get('source_port'),
                alert_copy.get('dest_port'),
                alert_copy.get('protocol'),
                alert_copy.get('file_path'),
                alert_copy.get('file_hash'),
                alert_copy.get('process_name'),
                alert_copy.get('process_id'),
                alert_copy.get('command_line'),
                alert_copy.get('username'),
                alert_copy.get('win_eventid'),
                alert_copy.get('full_log'),
            ))

            self.pending_count += 1

            # Commit in batches for performance
            if self.pending_count >= self.batch_size:
                self.conn.commit()
                logger.debug(f"Committed batch of {self.pending_count} alerts")
                self.pending_count = 0

        except Exception as e:
            logger.error(f"Failed to insert alert into database: {e}")
            self.conn.rollback()
            self.pending_count = 0

    def flush(self):
        """Commit any pending transactions."""
        if self.pending_count > 0:
            try:
                self.conn.commit()
                logger.debug(f"Flushed {self.pending_count} pending alerts")
                self.pending_count = 0
            except Exception as e:
                logger.error(f"Failed to flush pending alerts: {e}")
                self.conn.rollback()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dictionary with database statistics
        """
        try:
            cursor = self.conn.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor = self.conn.execute("""
                SELECT
                    COUNT(DISTINCT agent_id) as unique_agents,
                    COUNT(DISTINCT rule_id) as unique_rules,
                    MIN(timestamp) as earliest_alert,
                    MAX(timestamp) as latest_alert
                FROM alerts
            """)
            row = cursor.fetchone()

            # Get database file size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

            return {
                'db_path': str(self.db_path),
                'db_size_bytes': db_size,
                'db_size_mb': round(db_size / (1024 * 1024), 2),
                'total_alerts': total_alerts,
                'unique_agents': row[0] if row else 0,
                'unique_rules': row[1] if row else 0,
                'earliest_alert': row[2] if row else None,
                'latest_alert': row[3] if row else None,
                'pending_count': self.pending_count,
            }
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {'error': str(e)}

    def close(self):
        """Close database connection."""
        if self.conn:
            self.flush()
            self.conn.close()
            logger.info("Database connection closed")
            self.conn = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
