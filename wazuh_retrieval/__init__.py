"""
Wazuh Retrieval Module
----------------------
Data collection and normalization module for Wazuh Indexer (OpenSearch/Elasticsearch).

This module provides:
- Connection management to Wazuh Indexer
- Alert and event collection with pagination
- Schema transformation and normalization
- State tracking for resumable collection
- Multiple output handlers (file, SQLite, Kafka)
- Scheduled collection for near-real-time monitoring
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .client import WazuhIndexerClient
from .config import IndexerConfig
from .exceptions import (
    WazuhRetrievalError,
    IndexerConnectionError,
    IndexerQueryError,
    TransformationError,
    StateTrackingError,
)

__all__ = [
    "WazuhIndexerClient",
    "IndexerConfig",
    "WazuhRetrievalError",
    "IndexerConnectionError",
    "IndexerQueryError",
    "TransformationError",
    "StateTrackingError",
]
