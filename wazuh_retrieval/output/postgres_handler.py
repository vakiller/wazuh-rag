"""
PostgreSQL-based output handler for storing normalized alerts in a relational database.
"""

import psycopg2
import psycopg2.extras
from typing import Dict, Any, Optional
import json
import logging
import os

logger = logging.getLogger(__name__)


class PostgreSQLOutputHandler:
    """
    Store normalized alerts in PostgreSQL database.

    Suitable for:
    - High data volumes (millions to billions of alerts)
    - SQL-based querying and reporting
    - Production deployments with external database access
    - Docker/containerized environments

    Features:
    - Connection pooling ready
    - Batch inserts for performance
    - UPSERT support (ON CONFLICT)
    - JSON/JSONB support for arrays
    - Array support for PostgreSQL
    """

    def __init__(
        self,
        host: str = None,
        port: int = 5432,
        database: str = "wazuh_rag",
        user: str = None,
        password: str = None,
        batch_size: int = 100
    ):
        """
        Initialize the PostgreSQL handler.

        Args:
            host: PostgreSQL host
            port: PostgreSQL port
            database: Database name
            user: Database user
            password: Database password
            batch_size: Number of inserts to batch before committing
        """
        # Load from environment if not provided
        self.host = host or os.getenv('DB_HOST', 'localhost')
        self.port = port or int(os.getenv('DB_PORT', '5432'))
        self.database = database or os.getenv('DB_NAME', 'wazuh_rag')
        self.user = user or os.getenv('DB_USER', 'wazuh_user')
        self.password = password or os.getenv('DB_PASSWORD', 'wazuh_password')
        self.batch_size = batch_size

        self.conn: Optional[psycopg2.extensions.connection] = None
        self.pending_alerts = []
        self._init_db()
        logger.info(
            f"PostgreSQL output handler initialized: {self.host}:{self.port}/{self.database}")

    def _init_db(self):
        """Initialize database connection."""
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                connect_timeout=10
            )
            # Set autocommit to False for batch processing
            self.conn.autocommit = False
            logger.info("PostgreSQL connection established")

            # Verify alerts table exists
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_schema = 'public'
                        AND table_name = 'alerts'
                    )
                """)
                table_exists = cur.fetchone()[0]
                if not table_exists:
                    logger.warning(
                        "Alerts table does not exist. Please run init-db.sql first")
                else:
                    logger.info("Alerts table verified")

        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise

    def handle(self, normalized_alert: Dict[str, Any]):
        """
        Buffer normalized alert for batch insert.

        Args:
            normalized_alert: Normalized alert dictionary
        """
        try:
            # Add to pending batch
            self.pending_alerts.append(normalized_alert)

            # Insert batch if we've reached batch size
            if len(self.pending_alerts) >= self.batch_size:
                self._insert_batch()

        except Exception as e:
            logger.error(f"Failed to buffer alert: {e}")

    def _insert_batch(self):
        """Insert pending alerts as a batch."""
        if not self.pending_alerts:
            return

        try:
            with self.conn.cursor() as cur:
                # Use execute_values for efficient batch insert
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO alerts (
                        timestamp, document_id, index_name, agent_id, agent_name, agent_ip,
                        rule_id, rule_description, rule_level, rule_groups,
                        mitre_techniques, mitre_tactics,
                        source_ip, dest_ip, source_port, dest_port, protocol,
                        file_path, file_hash, process_name, process_id, command_line,
                        user_name, win_eventid, full_log
                    ) VALUES %s
                    ON CONFLICT (document_id) DO UPDATE SET
                        timestamp = EXCLUDED.timestamp,
                        rule_level = EXCLUDED.rule_level,
                        full_log = EXCLUDED.full_log
                    """,
                    [
                        (
                            alert.get('timestamp'),
                            alert.get('document_id'),
                            alert.get('index_name'),
                            alert.get('agent_id'),
                            alert.get('agent_name'),
                            alert.get('agent_ip'),
                            alert.get('rule_id'),
                            alert.get('rule_description'),
                            alert.get('rule_level'),
                            alert.get('rule_groups', []),  # PostgreSQL array
                            alert.get('mitre_techniques', []),
                            alert.get('mitre_tactics', []),
                            alert.get('source_ip'),
                            alert.get('dest_ip'),
                            alert.get('source_port'),
                            alert.get('dest_port'),
                            alert.get('protocol'),
                            alert.get('file_path'),
                            alert.get('file_hash'),
                            alert.get('process_name'),
                            alert.get('process_id'),
                            alert.get('command_line'),
                            alert.get('username'),  # Map to user_name
                            alert.get('win_eventid'),
                            alert.get('full_log'),
                        )
                        for alert in self.pending_alerts
                    ]
                )

            self.conn.commit()
            logger.debug(
                f"Inserted batch of {len(self.pending_alerts)} alerts")
            self.pending_alerts = []

        except Exception as e:
            logger.error(f"Failed to insert batch: {e}")
            self.conn.rollback()
            self.pending_alerts = []

    def flush(self):
        """Insert any pending alerts."""
        if self.pending_alerts:
            try:
                self._insert_batch()
                logger.debug(
                    f"Flushed {len(self.pending_alerts)} pending alerts")
            except Exception as e:
                logger.error(f"Failed to flush pending alerts: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dictionary with database statistics
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM alerts")
                total_alerts = cur.fetchone()[0]

                cur.execute("""
                    SELECT
                        COUNT(DISTINCT agent_id) as unique_agents,
                        COUNT(DISTINCT rule_id) as unique_rules,
                        MIN(timestamp) as earliest_alert,
                        MAX(timestamp) as latest_alert
                    FROM alerts
                """)
                row = cur.fetchone()

                # Get database size
                cur.execute("""
                    SELECT pg_database_size(current_database())
                """)
                db_size = cur.fetchone()[0]

                return {
                    'db_host': self.host,
                    'db_name': self.database,
                    'db_size_bytes': db_size,
                    'db_size_mb': round(db_size / (1024 * 1024), 2),
                    'total_alerts': total_alerts,
                    'unique_agents': row[0] if row else 0,
                    'unique_rules': row[1] if row else 0,
                    'earliest_alert': row[2].isoformat() if row and row[2] else None,
                    'latest_alert': row[3].isoformat() if row and row[3] else None,
                    'pending_count': len(self.pending_alerts),
                }
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {'error': str(e)}

    def close(self):
        """Close database connection."""
        if self.conn:
            self.flush()
            self.conn.close()
            logger.info("PostgreSQL connection closed")
            self.conn = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
