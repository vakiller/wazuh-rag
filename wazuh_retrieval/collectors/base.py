"""
Base collector class with common functionality for paginated data collection.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Iterator, Optional
import logging

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """
    Abstract base class for data collectors.

    Provides common functionality for paginated collection using search_after API,
    error handling, and state tracking integration.
    """

    def __init__(self, client, config, state_tracker):
        """
        Initialize the collector.

        Args:
            client: WazuhIndexerClient instance
            config: IndexerConfig instance
            state_tracker: StateTracker instance
        """
        self.client = client
        self.config = config
        self.state_tracker = state_tracker

    @abstractmethod
    def get_index_pattern(self) -> str:
        """
        Return the index pattern for this collector.

        Returns:
            Index pattern string (e.g., 'wazuh-alerts-*')
        """
        pass

    @abstractmethod
    def build_query(
        self,
        start_time: str,
        end_time: str,
        search_after: Optional[List] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Build query for time range.

        Args:
            start_time: ISO8601 timestamp for range start
            end_time: ISO8601 timestamp for range end
            search_after: Pagination token from previous page
            **kwargs: Additional query parameters

        Returns:
            Query body dictionary (OpenSearch DSL)
        """
        pass

    def collect_batch(
        self,
        start_time: str,
        end_time: str,
        **query_kwargs
    ) -> Iterator[Dict[str, Any]]:
        """
        Collect documents in batches using search_after pagination.

        This method handles pagination automatically using the search_after API,
        which is more efficient and consistent than offset-based pagination for
        large result sets.

        Args:
            start_time: ISO8601 timestamp for range start
            end_time: ISO8601 timestamp for range end
            **query_kwargs: Additional parameters passed to build_query()

        Yields:
            Raw documents from the index (including _source, _id, _index, etc.)
        """
        search_after = None
        total_collected = 0
        page_count = 0

        logger.info(
            f"Starting batch collection for {self.get_index_pattern()} "
            f"from {start_time} to {end_time}"
        )

        while True:
            page_count += 1
            query = self.build_query(start_time, end_time, search_after, **query_kwargs)

            try:
                response = self.client.search(
                    index=self.get_index_pattern(),
                    body=query
                )
            except Exception as e:
                logger.error(f"Query failed on page {page_count}: {e}")
                break

            hits = response.get('hits', {}).get('hits', [])

            if not hits:
                logger.info(
                    f"Collection complete. Total: {total_collected} documents "
                    f"across {page_count} pages"
                )
                break

            for hit in hits:
                yield hit
                total_collected += 1

            # Update search_after for next page
            last_hit = hits[-1]
            search_after = last_hit.get('sort')

            if not search_after:
                logger.warning("No sort values in response, stopping pagination")
                break

            logger.debug(
                f"Page {page_count}: collected {len(hits)} documents, "
                f"total: {total_collected}"
            )

            # Safety check to prevent infinite loops
            if page_count > 100000:  # 100k pages * 1000 docs = 100M docs max
                logger.error(
                    f"Reached maximum page limit ({page_count}), stopping collection"
                )
                break

        logger.info(f"Batch collection finished: {total_collected} documents collected")
