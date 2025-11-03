"""
Knowledge Ingestion Module for RAG-based Threat Analysis System

This module connects to OpenCTI to collect cybersecurity knowledge
(MITRE ATT&CK techniques, malware, indicators, etc.) and stores them
as vector embeddings in FAISS for retrieval in the RAG pipeline.

Phase 2: Knowledge Base Construction
"""

__version__ = "2.0.0"
__author__ = "Security Team"

from .opencti_client import OpenCTIClient
from .normalize import KnowledgeNormalizer
from .embedder import EmbeddingModel
from .storage import KnowledgeStorage

__all__ = [
    "OpenCTIClient",
    "KnowledgeNormalizer",
    "EmbeddingModel",
    "KnowledgeStorage",
]
