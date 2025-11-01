"""
OpenSearch client wrapper for Wazuh Indexer connection management.
"""

from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import ConnectionError, TransportError
from typing import Dict, Any, Optional, List
import logging
from .config import IndexerConfig
from .exceptions import IndexerConnectionError, IndexerQueryError

logger = logging.getLogger(__name__)


class WazuhIndexerClient:
    """
    Wrapper around OpenSearch client with connection management and error handling.

    Provides a high-level interface for connecting to and querying the Wazuh Indexer
    with automatic retry logic and connection pooling.
    """

    def __init__(self, config: IndexerConfig):
        """
        Initialize the Wazuh Indexer client.

        Args:
            config: IndexerConfig instance with connection parameters
        """
        self.config = config
        self._client: Optional[OpenSearch] = None

    def connect(self) -> OpenSearch:
        """
        Establish connection to Wazuh Indexer.

        Returns:
            OpenSearch client instance

        Raises:
            IndexerConnectionError: If connection fails
        """
        if self._client is not None:
            return self._client

        try:
            client_params = {
                'hosts': [{'host': self.config.host, 'port': self.config.port}],
                'http_auth': (self.config.username, self.config.password),
                'use_ssl': self.config.use_ssl,
                'verify_certs': self.config.verify_certs,
                'connection_class': RequestsHttpConnection,
                'timeout': self.config.timeout,
                'max_retries': self.config.max_retries,
                'retry_on_timeout': True,
            }

            if self.config.ca_certs_path:
                client_params['ca_certs'] = self.config.ca_certs_path

            self._client = OpenSearch(**client_params)

            # Test connection
            info = self._client.info()
            logger.info(f"Connected to Wazuh Indexer: {info['version']['number']}")
            logger.info(f"Cluster name: {info.get('cluster_name', 'unknown')}")

            return self._client

        except ConnectionError as e:
            raise IndexerConnectionError(f"Failed to connect to indexer at {self.config.host}:{self.config.port}: {str(e)}")
        except Exception as e:
            raise IndexerConnectionError(f"Unexpected connection error: {str(e)}")

    def search(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute search query with error handling.

        Args:
            index: Index pattern to search
            body: Query body (Elasticsearch/OpenSearch DSL)

        Returns:
            Search response dictionary

        Raises:
            IndexerQueryError: If query execution fails
        """
        client = self.connect()

        try:
            response = client.search(index=index, body=body)
            return response
        except TransportError as e:
            raise IndexerQueryError(
                f"Query failed on index '{index}': {e.error}, status: {e.status_code}"
            )
        except Exception as e:
            raise IndexerQueryError(f"Unexpected query error on index '{index}': {str(e)}")

    def get_indices(self, pattern: str) -> List[Dict[str, Any]]:
        """
        Get list of indices matching pattern.

        Args:
            pattern: Index pattern (e.g., 'wazuh-alerts-*')

        Returns:
            List of index metadata dictionaries

        Raises:
            IndexerQueryError: If operation fails
        """
        client = self.connect()

        try:
            indices = client.cat.indices(index=pattern, format='json')
            return indices
        except Exception as e:
            raise IndexerQueryError(f"Failed to get indices for pattern '{pattern}': {str(e)}")

    def count(self, index: str, body: Optional[Dict[str, Any]] = None) -> int:
        """
        Get count of documents matching query.

        Args:
            index: Index pattern to search
            body: Optional query body (if None, counts all documents)

        Returns:
            Document count

        Raises:
            IndexerQueryError: If count operation fails
        """
        client = self.connect()

        try:
            response = client.count(index=index, body=body)
            return response.get('count', 0)
        except Exception as e:
            raise IndexerQueryError(f"Failed to count documents in index '{index}': {str(e)}")

    def get_cluster_health(self) -> Dict[str, Any]:
        """
        Get cluster health status.

        Returns:
            Cluster health information

        Raises:
            IndexerQueryError: If operation fails
        """
        client = self.connect()

        try:
            health = client.cluster.health()
            return health
        except Exception as e:
            raise IndexerQueryError(f"Failed to get cluster health: {str(e)}")

    def close(self):
        """Close client connection and cleanup resources."""
        if self._client:
            try:
                self._client.close()
                logger.info("Closed connection to Wazuh Indexer")
            except Exception as e:
                logger.warning(f"Error closing client connection: {e}")
            finally:
                self._client = None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
