"""
Schema definitions and transformation logic for normalizing Wazuh documents.
"""

from .transformer import AlertTransformer
from .mappings import ALERT_FIELD_MAPPINGS, NORMALIZED_SCHEMA

__all__ = ["AlertTransformer", "ALERT_FIELD_MAPPINGS", "NORMALIZED_SCHEMA"]
