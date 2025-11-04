"""
LLM Analysis Module - Phase 3

Automated threat analysis using LLM with RAG-based context retrieval.

This module combines:
- Alert data from Phase 1 (Wazuh)
- Threat intelligence from Phase 2 (OpenCTI + FAISS)
- Local LLM analysis (Ollama via LangChain)

Main entry point: ThreatAnalyzer
"""

__version__ = "3.0.0"
__author__ = "Security Team"

from .analyze_window import ThreatAnalyzer
from .llm_client import LLMClient
from .storage import ReportStorage
from .retrieval import AlertRetriever, KnowledgeRetriever

__all__ = [
    "ThreatAnalyzer",
    "LLMClient",
    "ReportStorage",
    "AlertRetriever",
    "KnowledgeRetriever",
]
