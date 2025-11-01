"""
Kafka-based output handler for publishing normalized alerts to message queues.

Note: This handler requires kafka-python package to be installed.
Install with: pip install kafka-python
"""

import json
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

try:
    from kafka import KafkaProducer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    logger.warning("kafka-python not installed. KafkaOutputHandler will not be available.")


class KafkaOutputHandler:
    """
    Publish normalized alerts to Kafka topic.

    Suitable for:
    - Production, high-volume environments
    - Distributed processing pipelines
    - Real-time streaming analytics
    - Decoupled microservices architecture

    Features:
    - Automatic serialization
    - Configurable compression
    - Delivery acknowledgments
    - Partitioning by document_id for ordering
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str = "wazuh.alerts.normalized",
        compression_type: str = "gzip",
        acks: str = "all",
        retries: int = 3
    ):
        """
        Initialize the Kafka handler.

        Args:
            bootstrap_servers: Kafka broker addresses (e.g., "localhost:9092")
            topic: Topic name to publish to
            compression_type: Compression algorithm (gzip, snappy, lz4, or none)
            acks: Acknowledgment mode (0, 1, or 'all')
            retries: Number of retries for failed sends

        Raises:
            ImportError: If kafka-python is not installed
        """
        if not KAFKA_AVAILABLE:
            raise ImportError(
                "kafka-python package is required for KafkaOutputHandler. "
                "Install with: pip install kafka-python"
            )

        self.topic = topic
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
            compression_type=compression_type,
            acks=acks,
            retries=retries,
            max_in_flight_requests_per_connection=5,
            request_timeout_ms=30000,
        )
        self.success_count = 0
        self.error_count = 0
        logger.info(f"Kafka producer initialized for topic: {topic}")

    def handle(self, normalized_alert: Dict[str, Any]):
        """
        Publish normalized alert to Kafka.

        Args:
            normalized_alert: Normalized alert dictionary
        """
        try:
            # Use document_id as key for partitioning (ensures ordering per document)
            key = normalized_alert.get('document_id', '').encode('utf-8')

            future = self.producer.send(
                self.topic,
                key=key,
                value=normalized_alert
            )

            # Add callback for delivery confirmation (async)
            future.add_callback(self._on_success)
            future.add_errback(self._on_error)

        except Exception as e:
            logger.error(f"Failed to publish alert to Kafka: {e}")
            self.error_count += 1

    def _on_success(self, record_metadata):
        """Callback for successful delivery."""
        self.success_count += 1
        logger.debug(
            f"Alert published to {record_metadata.topic} "
            f"partition {record_metadata.partition} "
            f"offset {record_metadata.offset}"
        )

    def _on_error(self, exc):
        """Callback for delivery failure."""
        self.error_count += 1
        logger.error(f"Failed to publish alert: {exc}")

    def flush(self):
        """Flush pending messages (blocking)."""
        try:
            self.producer.flush()
            logger.info(f"Flushed all pending messages to Kafka")
        except Exception as e:
            logger.error(f"Failed to flush Kafka producer: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get producer statistics.

        Returns:
            Dictionary with producer statistics
        """
        return {
            'topic': self.topic,
            'success_count': self.success_count,
            'error_count': self.error_count,
            'success_rate': (
                self.success_count / (self.success_count + self.error_count)
                if (self.success_count + self.error_count) > 0
                else 0.0
            ),
        }

    def close(self):
        """Close producer and cleanup resources."""
        try:
            self.flush()
            self.producer.close(timeout=10)
            logger.info("Kafka producer closed")
        except Exception as e:
            logger.error(f"Error closing Kafka producer: {e}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
