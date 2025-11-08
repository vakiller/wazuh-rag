"""
Knowledge Storage Layer - PostgreSQL Version

Manages FAISS vector index and PostgreSQL metadata storage.
Provides unified interface for adding, searching, and managing knowledge.
"""

import logging
import psycopg2
import psycopg2.extras
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import numpy as np
import os

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for storage errors"""
    pass


class KnowledgeStoragePostgres:
    """
    Manages FAISS index and PostgreSQL metadata database

    Architecture:
    - FAISS index: Stores embedding vectors for fast similarity search
    - PostgreSQL database: Stores entity metadata indexed by vector ID

    The vector ID in FAISS corresponds to the vector_id in PostgreSQL.
    """

    def __init__(
        self,
        faiss_index_path: str,
        embedding_dim: int,
        index_type: str = "IndexFlatIP",
        db_host: str = None,
        db_port: int = 5432,
        db_name: str = None,
        db_user: str = None,
        db_password: str = None
    ):
        """
        Initialize storage

        Args:
            faiss_index_path: Path to FAISS index file
            embedding_dim: Dimension of embedding vectors
            index_type: FAISS index type (IndexFlatIP, IndexFlatL2, etc.)
            db_host: PostgreSQL host
            db_port: PostgreSQL port
            db_name: Database name
            db_user: Database user
            db_password: Database password
        """
        self.faiss_index_path = Path(faiss_index_path)
        self.embedding_dim = embedding_dim
        self.index_type = index_type

        # Database connection parameters
        self.db_host = db_host or os.getenv('DB_HOST', 'localhost')
        self.db_port = db_port or int(os.getenv('DB_PORT', '5432'))
        self.db_name = db_name or os.getenv('DB_NAME', 'wazuh_rag')
        self.db_user = db_user or os.getenv('DB_USER', 'wazuh_user')
        self.db_password = db_password or os.getenv('DB_PASSWORD', 'wazuh_password')

        self.faiss_index = None
        self.db_conn = None

        # Ensure parent directories exist
        self.faiss_index_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Initializing storage (FAISS: {faiss_index_path}, "
            f"PostgreSQL: {self.db_host}/{self.db_name}, dim: {embedding_dim})"
        )

        self._init_faiss()
        self._init_postgres()

    def _init_faiss(self):
        """Initialize or load FAISS index"""
        try:
            import faiss
        except ImportError:
            raise StorageError(
                "faiss not installed. "
                "Install with: pip install faiss-cpu (or faiss-gpu)"
            )

        # Load existing index if present
        if self.faiss_index_path.exists():
            try:
                self.faiss_index = faiss.read_index(str(self.faiss_index_path))
                logger.info(
                    f"Loaded existing FAISS index with {self.faiss_index.ntotal} vectors"
                )
                return
            except Exception as e:
                logger.warning(f"Failed to load existing index: {e}. Creating new one.")

        # Create new index
        if self.index_type == "IndexFlatIP":
            # Inner product (for cosine similarity with normalized vectors)
            self.faiss_index = faiss.IndexFlatIP(self.embedding_dim)
        elif self.index_type == "IndexFlatL2":
            # L2 distance (Euclidean)
            self.faiss_index = faiss.IndexFlatL2(self.embedding_dim)
        else:
            raise StorageError(f"Unsupported index type: {self.index_type}")

        logger.info(f"Created new FAISS {self.index_type} index (dim: {self.embedding_dim})")

    def _init_postgres(self):
        """Initialize PostgreSQL metadata database connection"""
        try:
            self.db_conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password,
                connect_timeout=10
            )
            self.db_conn.autocommit = False
            logger.info("Connected to PostgreSQL metadata database")

            # Verify knowledge table exists
            with self.db_conn.cursor() as cur:
                cur.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables
                        WHERE table_schema = 'public'
                        AND table_name = 'knowledge'
                    )
                """)
                table_exists = cur.fetchone()[0]
                if not table_exists:
                    logger.warning("Knowledge table does not exist. Please run init-db.sql first")
                else:
                    logger.info("Knowledge table verified")

        except Exception as e:
            raise StorageError(f"Failed to connect to PostgreSQL: {e}")

    def add(
        self,
        embeddings: np.ndarray,
        entities: List[Dict[str, Any]]
    ) -> List[int]:
        """
        Add entities and their embeddings to storage

        Args:
            embeddings: numpy array of shape (n, embedding_dim)
            entities: List of normalized entity dicts

        Returns:
            List of vector IDs assigned

        Raises:
            StorageError: If addition fails
        """
        if len(embeddings) != len(entities):
            raise StorageError(
                f"Mismatch: {len(embeddings)} embeddings but {len(entities)} entities"
            )

        if len(embeddings) == 0:
            return []

        try:
            # Get starting vector ID
            start_id = self.faiss_index.ntotal

            # Add to FAISS
            self.faiss_index.add(embeddings.astype(np.float32))

            # Add to PostgreSQL
            vector_ids = []
            indexed_at = datetime.utcnow()

            with self.db_conn.cursor() as cur:
                for i, entity in enumerate(entities):
                    vector_id = start_id + i
                    vector_ids.append(vector_id)

                    # Serialize metadata
                    metadata_json = json.dumps(entity.get('metadata', {}))

                    # Handle datetime objects
                    created_at = entity.get('created_at')
                    updated_at = entity.get('updated_at')
                    if isinstance(created_at, str):
                        created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    if isinstance(updated_at, str):
                        updated_at = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))

                    # Insert or update (handle duplicates)
                    cur.execute("""
                        INSERT INTO knowledge (
                            vector_id, opencti_id, standard_id, entity_type,
                            name, content, metadata, created_at, updated_at,
                            confidence, indexed_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (opencti_id) DO UPDATE SET
                            vector_id = EXCLUDED.vector_id,
                            standard_id = EXCLUDED.standard_id,
                            name = EXCLUDED.name,
                            content = EXCLUDED.content,
                            metadata = EXCLUDED.metadata,
                            updated_at = EXCLUDED.updated_at,
                            confidence = EXCLUDED.confidence,
                            indexed_at = EXCLUDED.indexed_at
                    """, (
                        vector_id,
                        entity['id'],
                        entity.get('standard_id'),
                        entity['entity_type'],
                        entity['name'],
                        entity['content'],
                        metadata_json,
                        created_at,
                        updated_at,
                        entity.get('confidence', 0),
                        indexed_at
                    ))

            self.db_conn.commit()

            logger.info(f"Added {len(entities)} entities (vector IDs: {start_id}-{start_id + len(entities) - 1})")

            return vector_ids

        except Exception as e:
            self.db_conn.rollback()
            raise StorageError(f"Failed to add entities: {e}")

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 10,
        entity_type_filter: Optional[str] = None,
        score_threshold: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar entities

        Args:
            query_embedding: Query vector of shape (embedding_dim,)
            top_k: Number of results to return
            entity_type_filter: Optional filter by entity type
            score_threshold: Optional minimum similarity score

        Returns:
            List of result dicts with 'score', 'vector_id', and entity fields

        Raises:
            StorageError: If search fails
        """
        if self.faiss_index.ntotal == 0:
            logger.warning("FAISS index is empty")
            return []

        try:
            # Reshape query to (1, embedding_dim)
            query = query_embedding.reshape(1, -1).astype(np.float32)

            # Search with more results if filtering (we'll filter afterward)
            search_k = top_k * 5 if entity_type_filter else top_k

            distances, indices = self.faiss_index.search(query, search_k)
            distances = distances[0]
            indices = indices[0]

            # Filter out invalid indices (-1)
            valid_mask = indices >= 0
            valid_indices = indices[valid_mask]
            valid_distances = distances[valid_mask]

            if len(valid_indices) == 0:
                return []

            # Fetch metadata from PostgreSQL
            results = []
            with self.db_conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                for vector_id, score in zip(valid_indices, valid_distances):
                    # Apply score threshold
                    if score_threshold is not None and score < score_threshold:
                        continue

                    cur.execute("""
                        SELECT * FROM knowledge WHERE vector_id = %s
                    """, (int(vector_id),))

                    row = cur.fetchone()
                    if row:
                        # Apply entity type filter
                        if entity_type_filter and row['entity_type'] != entity_type_filter:
                            continue

                        # Parse metadata JSON
                        metadata = json.loads(row['metadata']) if row['metadata'] else {}

                        result = {
                            'score': float(score),
                            'vector_id': int(vector_id),
                            'opencti_id': row['opencti_id'],
                            'standard_id': row['standard_id'],
                            'entity_type': row['entity_type'],
                            'name': row['name'],
                            'content': row['content'],
                            'metadata': metadata,
                            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                            'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None,
                            'confidence': row['confidence']
                        }
                        results.append(result)

                        # Stop if we have enough results
                        if len(results) >= top_k:
                            break

            return results

        except Exception as e:
            raise StorageError(f"Search failed: {e}")

    def get_by_mitre_id(self, mitre_id: str) -> Optional[Dict[str, Any]]:
        """Get knowledge entry by MITRE technique ID"""
        try:
            with self.db_conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("""
                    SELECT * FROM knowledge
                    WHERE entity_type = 'attack-pattern'
                    AND metadata->>'mitre_id' = %s
                    LIMIT 1
                """, (mitre_id,))

                row = cur.fetchone()
                if row:
                    metadata = json.loads(row['metadata']) if row['metadata'] else {}
                    return {
                        'vector_id': row['vector_id'],
                        'opencti_id': row['opencti_id'],
                        'entity_type': row['entity_type'],
                        'name': row['name'],
                        'content': row['content'],
                        'metadata': metadata
                    }
            return None

        except Exception as e:
            logger.error(f"Failed to get entry by MITRE ID: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        try:
            with self.db_conn.cursor() as cur:
                # Total vectors
                cur.execute("SELECT COUNT(*) FROM knowledge")
                total_vectors = cur.fetchone()[0]

                # Entity type counts
                cur.execute("""
                    SELECT entity_type, COUNT(*) as count
                    FROM knowledge
                    GROUP BY entity_type
                    ORDER BY count DESC
                """)
                entity_counts = {row[0]: row[1] for row in cur.fetchall()}

            return {
                'faiss_index_path': str(self.faiss_index_path),
                'db_host': self.db_host,
                'db_name': self.db_name,
                'total_vectors': total_vectors,
                'faiss_ntotal': self.faiss_index.ntotal,
                'embedding_dim': self.embedding_dim,
                'index_type': self.index_type,
                'entity_counts': entity_counts
            }

        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {'error': str(e)}

    def save_index(self):
        """Save FAISS index to disk"""
        try:
            import faiss
            faiss.write_index(self.faiss_index, str(self.faiss_index_path))
            logger.info(f"Saved FAISS index to {self.faiss_index_path}")
        except Exception as e:
            logger.error(f"Failed to save FAISS index: {e}")
            raise StorageError(f"Failed to save index: {e}")

    def save(self):
        """Save FAISS index to disk (alias for save_index for compatibility)"""
        self.save_index()

    def close(self):
        """Close database connection and save index"""
        if self.db_conn:
            self.db_conn.close()
            logger.info("PostgreSQL connection closed")
            self.db_conn = None

        if self.faiss_index:
            self.save_index()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
