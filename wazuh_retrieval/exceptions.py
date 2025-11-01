"""
Custom exception classes for the Wazuh retrieval module.
"""


class WazuhRetrievalError(Exception):
    """Base exception for all Wazuh retrieval module errors"""
    pass


class IndexerConnectionError(WazuhRetrievalError):
    """Raised when connection to the Wazuh Indexer fails"""
    pass


class IndexerQueryError(WazuhRetrievalError):
    """Raised when a query to the Wazuh Indexer fails"""
    pass


class TransformationError(WazuhRetrievalError):
    """Raised when document transformation fails"""
    pass


class StateTrackingError(WazuhRetrievalError):
    """Raised when state tracking operations fail"""
    pass


class ConfigurationError(WazuhRetrievalError):
    """Raised when configuration is invalid or missing"""
    pass
