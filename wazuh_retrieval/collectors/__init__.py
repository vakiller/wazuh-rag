"""
Data collectors for retrieving documents from Wazuh Indexer indices.
"""

from .base import BaseCollector
from .alerts import AlertCollector

__all__ = ["BaseCollector", "AlertCollector"]
