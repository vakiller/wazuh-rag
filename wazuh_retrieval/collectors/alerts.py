"""
Alert collector for retrieving security alerts from wazuh-alerts-* indices.
"""

from typing import Dict, Any, List, Optional, Iterator
from datetime import datetime, timedelta
from .base import BaseCollector
import logging

logger = logging.getLogger(__name__)


class AlertCollector(BaseCollector):
    """
    Collector for wazuh-alerts-* indices.

    Collects security alerts with support for:
    - Time-range filtering
    - Alert level filtering
    - Near-real-time collection with state tracking
    - Historical backfill
    """

    def get_index_pattern(self) -> str:
        """Return the index pattern for alerts."""
        return self.config.alerts_index_pattern

    def build_query(
        self,
        start_time: str,
        end_time: str,
        search_after: Optional[List] = None,
        min_level: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Build query for alerts in time range.

        Args:
            start_time: ISO8601 timestamp
            end_time: ISO8601 timestamp
            search_after: Pagination token
            min_level: Minimum alert level (0-15, default from config)

        Returns:
            Query body dictionary
        """
        if min_level is None:
            min_level = self.config.min_alert_level

        # Build bool query with time range
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time,
                                "format": "strict_date_optional_time"
                            }
                        }
                    }
                ]
            }
        }

        # Filter by alert level if specified
        if min_level > 0:
            query["bool"]["must"].append({
                "range": {
                    "rule.level": {
                        "gte": min_level
                    }
                }
            })

        body = {
            "query": query,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"_id": {"order": "asc"}}  # Tie-breaker for consistent pagination
            ],
            "size": self.config.batch_size,
            "_source": True  # Return all fields
        }

        if search_after:
            body["search_after"] = search_after

        return body

    def collect_recent(
        self,
        lookback_minutes: Optional[int] = None,
        min_level: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Collect recent alerts (near-real-time).

        Uses state tracker to resume from last processed timestamp,
        preventing duplicate processing.

        Args:
            lookback_minutes: How far back to look (default: from config)
            min_level: Minimum alert level (default: from config)

        Yields:
            Raw alert documents
        """
        if lookback_minutes is None:
            lookback_minutes = self.config.lookback_minutes

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=lookback_minutes)

        # Check state tracker for last processed timestamp
        last_processed = self.state_tracker.get_last_timestamp('alerts')
        if last_processed:
            # Remove timezone info from last_processed for comparison
            last_processed_naive = last_processed.replace(tzinfo=None)
            # Resume from last checkpoint, but don't go back further than lookback window
            start_time = max(start_time, last_processed_naive)
            logger.info(f"Resuming from last checkpoint: {start_time.isoformat()}")

        start_str = start_time.isoformat() + "Z"
        end_str = end_time.isoformat() + "Z"

        logger.info(f"Collecting recent alerts from {start_str} to {end_str}")

        doc_count = 0
        for doc in self.collect_batch(start_str, end_str, min_level=min_level):
            yield doc
            doc_count += 1

        # Update state tracker with end time
        self.state_tracker.update_last_timestamp('alerts', end_time)
        logger.info(f"Collected {doc_count} recent alerts, updated checkpoint to {end_str}")

    def collect_historical(
        self,
        start_date: datetime,
        end_date: datetime,
        min_level: Optional[int] = None
    ) -> Iterator[Dict[str, Any]]:
        """
        Collect historical alerts in date range.

        Use this for backfilling historical data. Does not update
        the state tracker checkpoint.

        Args:
            start_date: Start of historical range
            end_date: End of historical range
            min_level: Minimum alert level (default: from config)

        Yields:
            Raw alert documents
        """
        start_str = start_date.isoformat() + "Z"
        end_str = end_date.isoformat() + "Z"

        logger.info(f"Collecting historical alerts from {start_str} to {end_str}")

        doc_count = 0
        for doc in self.collect_batch(start_str, end_str, min_level=min_level):
            yield doc
            doc_count += 1

        logger.info(f"Collected {doc_count} historical alerts")

    def get_alert_count(
        self,
        start_time: str,
        end_time: str,
        min_level: Optional[int] = None
    ) -> int:
        """
        Get count of alerts in time range without retrieving documents.

        Useful for estimating data volume before collection.

        Args:
            start_time: ISO8601 timestamp
            end_time: ISO8601 timestamp
            min_level: Minimum alert level

        Returns:
            Number of matching alerts
        """
        query = self.build_query(start_time, end_time, min_level=min_level)
        # Remove pagination fields for count query
        query.pop('sort', None)
        query.pop('size', None)

        try:
            count = self.client.count(
                index=self.get_index_pattern(),
                body={"query": query["query"]}
            )
            return count
        except Exception as e:
            logger.error(f"Failed to count alerts: {e}")
            return 0
