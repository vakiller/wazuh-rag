"""
Retrieval Module

Queries alerts from database and retrieves relevant knowledge from FAISS
"""

import logging
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Optional
from pathlib import Path
import sys

# Add parent directory to path to import Phase 2 modules
sys.path.insert(0, str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)


class AlertRetriever:
    """
    Retrieves alerts from rag.db within a time window
    """

    def __init__(self, db_path: str):
        """
        Initialize alert retriever

        Args:
            db_path: Path to rag.db
        """
        self.db_path = Path(db_path)
        self.conn = None

        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        logger.info(f"Connected to database: {db_path}")

    def get_alerts_in_window(
        self,
        window_minutes: int = 30,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get alerts from the last N minutes

        Args:
            window_minutes: Number of minutes to look back
            end_time: End of window (defaults to now)

        Returns:
            List of alert dicts
        """
        if end_time is None:
            end_time = datetime.utcnow()

        start_time = end_time - timedelta(minutes=window_minutes)

        logger.info(
            f"Querying alerts from {start_time.isoformat()} "
            f"to {end_time.isoformat()}"
        )

        # Query alerts table
        cursor = self.conn.execute("""
            SELECT *
            FROM alerts
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
        """, (start_time.isoformat(), end_time.isoformat()))

        alerts = [dict(row) for row in cursor.fetchall()]

        logger.info(f"Retrieved {len(alerts)} alerts from database")

        return alerts

    def extract_mitre_techniques(self, alerts: List[Dict[str, Any]]) -> Set[str]:
        """
        Extract unique MITRE technique IDs from alerts

        Args:
            alerts: List of alert dicts

        Returns:
            Set of MITRE technique IDs (e.g., {'T1078', 'T1059'})
        """
        techniques = set()

        for alert in alerts:
            mitre_field = alert.get('mitre_techniques', '[]')

            if mitre_field and mitre_field != '[]':
                try:
                    mitre_list = json.loads(mitre_field) if isinstance(mitre_field, str) else mitre_field
                    techniques.update(mitre_list)
                except (json.JSONDecodeError, TypeError):
                    logger.warning(f"Failed to parse MITRE techniques from alert {alert.get('alert_id')}")

        logger.info(f"Extracted {len(techniques)} unique MITRE techniques: {techniques}")

        return techniques

    def extract_hosts_and_agents(self, alerts: List[Dict[str, Any]]) -> tuple[List[str], List[str]]:
        """
        Extract unique hosts and agent IDs from alerts

        Args:
            alerts: List of alert dicts

        Returns:
            Tuple of (unique_hosts, unique_agents)
        """
        hosts = set()
        agents = set()

        for alert in alerts:
            if alert.get('agent_ip'):
                hosts.add(alert['agent_ip'])
            if alert.get('agent_name'):
                hosts.add(alert['agent_name'])
            if alert.get('agent_id'):
                agents.add(alert['agent_id'])

        return list(hosts), list(agents)

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class KnowledgeRetriever:
    """
    Retrieves relevant knowledge from FAISS index and knowledge database
    """

    def __init__(
        self,
        faiss_index_path: str,
        metadata_db_path: str,
        embedding_model_name: str,
        device: str = "cpu"
    ):
        """
        Initialize knowledge retriever

        Args:
            faiss_index_path: Path to FAISS index file
            metadata_db_path: Path to knowledge.db
            embedding_model_name: Name of embedding model (must match Phase 2)
            device: Device for embedding model (cpu/cuda)
        """
        self.faiss_index_path = Path(faiss_index_path)
        self.metadata_db_path = Path(metadata_db_path)
        self.embedding_model_name = embedding_model_name
        self.device = device

        self.storage = None
        self.embedder = None

        logger.info("Initializing knowledge retriever")
        self._init_components()

    def _init_components(self):
        """Initialize FAISS storage and embedding model"""
        try:
            from knowledge_ingest import KnowledgeStorage, EmbeddingModel
        except ImportError:
            raise ImportError(
                "Phase 2 knowledge_ingest module not found. "
                "Ensure Phase 2 is properly installed."
            )

        # Initialize embedding model
        self.embedder = EmbeddingModel(
            model_name=self.embedding_model_name,
            device=self.device,
            normalize=True
        )

        # Initialize storage
        self.storage = KnowledgeStorage(
            faiss_index_path=str(self.faiss_index_path),
            metadata_db_path=str(self.metadata_db_path),
            embedding_dim=self.embedder.get_dimension(),
            index_type="IndexFlatIP"
        )

        logger.info(
            f"Knowledge retriever initialized "
            f"({self.storage.faiss_index.ntotal} vectors in index)"
        )

    def retrieve_by_mitre_id(self, mitre_ids: Set[str]) -> List[Dict[str, Any]]:
        """
        Retrieve knowledge items by exact MITRE ID match

        Args:
            mitre_ids: Set of MITRE technique IDs

        Returns:
            List of matching knowledge items
        """
        if not mitre_ids:
            return []

        results = []

        for mitre_id in mitre_ids:
            # Query knowledge database for exact match
            cursor = self.storage.db_conn.execute("""
                SELECT * FROM knowledge
                WHERE entity_type = 'attack-pattern'
                AND json_extract(metadata, '$.mitre_id') = ?
            """, (mitre_id,))

            for row in cursor.fetchall():
                item = dict(row)
                # Parse JSON metadata
                if item.get('metadata'):
                    try:
                        item['metadata'] = json.loads(item['metadata'])
                    except json.JSONDecodeError:
                        item['metadata'] = {}

                results.append(item)

        logger.info(f"Retrieved {len(results)} knowledge items by MITRE ID")

        return results

    def retrieve_by_semantic_search(
        self,
        query_text: str,
        top_k: int = 5,
        score_threshold: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Retrieve knowledge items by semantic similarity

        Args:
            query_text: Query text to search for
            top_k: Number of results to return
            score_threshold: Minimum similarity score

        Returns:
            List of knowledge items with similarity scores
        """
        if not query_text:
            return []

        # Generate query embedding
        query_embedding = self.embedder.embed(query_text)

        # Search FAISS
        results = self.storage.search(
            query_embedding=query_embedding,
            top_k=top_k
        )

        # Filter by score threshold
        filtered = [r for r in results if r.get('score', 0) >= score_threshold]

        logger.info(
            f"Semantic search returned {len(filtered)}/{len(results)} items "
            f"above threshold {score_threshold}"
        )

        return filtered

    def retrieve_context(
        self,
        alerts: List[Dict[str, Any]],
        top_k: int = 5,
        score_threshold: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant knowledge context for alerts

        Combines:
        1. Exact MITRE ID matches
        2. Semantic search based on alert summaries

        Args:
            alerts: List of alert dicts
            top_k: Number of semantic search results
            score_threshold: Minimum similarity score

        Returns:
            Combined list of knowledge items (deduplicated)
        """
        all_results = []
        seen_ids = set()

        # 1. Get MITRE technique exact matches
        retriever = AlertRetriever(str(self.metadata_db_path).replace('knowledge.db', 'rag.db'))
        mitre_ids = retriever.extract_mitre_techniques(alerts)

        mitre_matches = self.retrieve_by_mitre_id(mitre_ids)
        for item in mitre_matches:
            item_id = item.get('opencti_id') or item.get('id')
            if item_id not in seen_ids:
                all_results.append(item)
                seen_ids.add(item_id)

        # 2. Semantic search on combined alert context
        # Build query from alert descriptions
        query_parts = []
        for alert in alerts[:10]:  # Limit to first 10 alerts for query
            rule_desc = alert.get('rule_description', '')
            if rule_desc:
                query_parts.append(rule_desc)

        if query_parts:
            query_text = ' '.join(query_parts)
            semantic_results = self.retrieve_by_semantic_search(
                query_text,
                top_k=top_k,
                score_threshold=score_threshold
            )

            for item in semantic_results:
                item_id = item.get('opencti_id') or item.get('id')
                if item_id not in seen_ids:
                    all_results.append(item)
                    seen_ids.add(item_id)

        logger.info(
            f"Retrieved {len(all_results)} total knowledge items "
            f"({len(mitre_matches)} exact + {len(all_results) - len(mitre_matches)} semantic)"
        )

        return all_results

    def close(self):
        """Close storage connection"""
        if self.storage:
            self.storage.close()
