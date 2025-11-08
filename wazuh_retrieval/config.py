"""
Configuration management for Wazuh Indexer connection and collection settings.
"""

from dataclasses import dataclass
from typing import Optional
import os


@dataclass
class IndexerConfig:
    """Configuration for Wazuh Indexer connection and collection behavior"""

    # Connection settings
    host: str
    port: int = 9200
    username: str = "admin"
    password: str = "SecretPassword"
    use_ssl: bool = True
    verify_certs: bool = True
    ca_certs_path: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3

    # Index patterns
    alerts_index_pattern: str = "wazuh-alerts-*"
    archives_index_pattern: str = "wazuh-archives-*"
    monitoring_index_pattern: str = "wazuh-monitoring-*"

    # Collection settings
    batch_size: int = 1000
    poll_interval_seconds: int = 300  # 5 minutes for near-real-time
    lookback_minutes: int = 7  # Lookback window with 2-minute overlap buffer
    min_alert_level: int = 0  # Minimum alert level to collect (0 = all)

    # Output settings
    output_dir: str = "./collected_alerts"
    sqlite_db_path: str = "./wazuh_alerts.db"
    state_file: str = ".wazuh_collector_state.json"

    @classmethod
    def from_env(cls):
        """
        Load configuration from environment variables.

        Environment variables:
            WAZUH_INDEXER_HOST: Indexer hostname or IP
            WAZUH_INDEXER_PORT: Indexer port (default: 9200)
            WAZUH_INDEXER_USER: Username for authentication
            WAZUH_INDEXER_PASSWORD: Password for authentication
            WAZUH_INDEXER_SSL: Use SSL (true/false, default: true)
            WAZUH_INDEXER_VERIFY_CERTS: Verify SSL certificates (true/false, default: true)
            WAZUH_INDEXER_CA_CERTS: Path to CA certificates file
            WAZUH_POLL_INTERVAL: Polling interval in seconds (default: 300)
            WAZUH_BATCH_SIZE: Number of documents per batch (default: 1000)
            WAZUH_MIN_ALERT_LEVEL: Minimum alert level (default: 0)
        """
        return cls(
            host=os.getenv("WAZUH_INDEXER_HOST", "localhost"),
            port=int(os.getenv("WAZUH_INDEXER_PORT", "9200")),
            username=os.getenv("WAZUH_INDEXER_USER", "admin"),
            password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
            use_ssl=os.getenv("WAZUH_INDEXER_SSL", "true").lower() == "true",
            verify_certs=os.getenv(
                "WAZUH_INDEXER_VERIFY_CERTS", "true").lower() == "true",
            ca_certs_path=os.getenv("WAZUH_INDEXER_CA_CERTS"),
            poll_interval_seconds=int(os.getenv("WAZUH_POLL_INTERVAL", "300")),
            batch_size=int(os.getenv("WAZUH_BATCH_SIZE", "1000")),
            min_alert_level=int(os.getenv("WAZUH_MIN_ALERT_LEVEL", "0")),
            output_dir=os.getenv("WAZUH_OUTPUT_DIR", "./collected_alerts"),
            sqlite_db_path=os.getenv("WAZUH_SQLITE_DB", "./wazuh_alerts.db"),
            state_file=os.getenv("WAZUH_STATE_FILE",
                                 ".wazuh_collector_state.json"),
        )

    def validate(self) -> bool:
        """
        Validate configuration settings.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If any required setting is invalid
        """
        if not self.host:
            raise ValueError("WAZUH_INDEXER_HOST must be set")

        if not self.password:
            raise ValueError("WAZUH_INDEXER_PASSWORD must be set")

        if self.port < 1 or self.port > 65535:
            raise ValueError(f"Invalid port: {self.port}")

        if self.batch_size < 1 or self.batch_size > 10000:
            raise ValueError(
                f"batch_size must be between 1 and 10000, got: {self.batch_size}")

        if self.poll_interval_seconds < 10:
            raise ValueError(
                f"poll_interval_seconds must be at least 10 seconds, got: {self.poll_interval_seconds}")

        if self.min_alert_level < 0 or self.min_alert_level > 15:
            raise ValueError(
                f"min_alert_level must be between 0 and 15, got: {self.min_alert_level}")

        return True
