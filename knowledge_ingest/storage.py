"""
Knowledge Storage Layer

Manages FAISS vector index and SQLite metadata storage.
Provides unified interface for adding, searching, and managing knowledge.
"""

import logging
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for storage errors"""
    pass


class KnowledgeStorage:
    """
    Manages FAISS index and SQLite metadata database

    Architecture:
    - FAISS index: Stores embedding vectors for fast similarity search
    - SQLite database: Stores entity metadata indexed by vector ID

    The vector ID in FAISS corresponds to the row ID in SQLite.
    """

    def __init__(
        self,
        faiss_index_path: str,
        metadata_db_path: str,
        embedding_dim: int,
        index_type: str = "IndexFlatIP"
    ):
        """
        Initialize storage

        Args:
            faiss_index_path: Path to FAISS index file
            metadata_db_path: Path to SQLite database file
            embedding_dim: Dimension of embedding vectors
            index_type: FAISS index type (IndexFlatIP, IndexFlatL2, etc.)
        """
        self.faiss_index_path = Path(faiss_index_path)
        self.metadata_db_path = Path(metadata_db_path)
        self.embedding_dim = embedding_dim
        self.index_type = index_type

        self.faiss_index = None
        self.db_conn = None

        # Ensure parent directories exist
        self.faiss_index_path.parent.mkdir(parents=True, exist_ok=True)
        self.metadata_db_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Initializing storage (FAISS: {faiss_index_path}, "
            f"SQLite: {metadata_db_path}, dim: {embedding_dim})"
        )

        self._init_faiss()
        self._init_sqlite()

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

    def _init_sqlite(self):
        """Initialize SQLite metadata database"""
        self.db_conn = sqlite3.connect(str(self.metadata_db_path))
        self.db_conn.row_factory = sqlite3.Row

        # Create schema
        self.db_conn.execute("""
            CREATE TABLE IF NOT EXISTS knowledge (
                vector_id INTEGER PRIMARY KEY,
                opencti_id TEXT NOT NULL,
                standard_id TEXT,
                entity_type TEXT NOT NULL,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata TEXT,
                created_at TEXT,
                updated_at TEXT,
                confidence INTEGER,
                indexed_at TEXT NOT NULL,
                UNIQUE(opencti_id)
            )
        """)

        # Create indices for common queries
        self.db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_type ON knowledge(entity_type)"
        )
        self.db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_opencti_id ON knowledge(opencti_id)"
        )
        self.db_conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_updated_at ON knowledge(updated_at)"
        )

        self.db_conn.commit()
        logger.info("Initialized SQLite metadata database")

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

            # Add to SQLite
            vector_ids = []
            indexed_at = datetime.utcnow().isoformat() + "Z"

            for i, entity in enumerate(entities):
                vector_id = start_id + i
                vector_ids.append(vector_id)

                # Serialize metadata
                metadata_json = json.dumps(entity.get('metadata', {}))

                # Handle datetime objects
                created_at = entity.get('created_at')
                updated_at = entity.get('updated_at')
                if isinstance(created_at, datetime):
                    created_at = created_at.isoformat() + "Z"
                if isinstance(updated_at, datetime):
                    updated_at = updated_at.isoformat() + "Z"

                # Insert or replace (handle duplicates)
                self.db_conn.execute("""
                    INSERT OR REPLACE INTO knowledge (
                        vector_id, opencti_id, standard_id, entity_type,
                        name, content, metadata, created_at, updated_at,
                        confidence, indexed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        entity_type_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar entities

        Args:
            query_embedding: Query vector of shape (embedding_dim,)
            top_k: Number of results to return
            entity_type_filter: Optional filter by entity type

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

            # Search FAISS (get more than top_k in case we need to filter)
            search_k = top_k * 10 if entity_type_filter else top_k
            search_k = min(search_k, self.faiss_index.ntotal)

            scores, vector_ids = self.faiss_index.search(query, search_k)

            # Flatten results
            scores = scores[0]
            vector_ids = vector_ids[0]

            # Fetch metadata from SQLite
            results = []
            for score, vector_id in zip(scores, vector_ids):
                if vector_id == -1:  # FAISS returns -1 for empty slots
                    continue

                # Fetch entity
                cursor = self.db_conn.execute(
                    "SELECT * FROM knowledge WHERE vector_id = ?",
                    (int(vector_id),)
                )
                row = cursor.fetchone()

                if not row:
                    logger.warning(f"Vector ID {vector_id} not found in metadata DB")
                    continue

                # Apply entity type filter
                if entity_type_filter and row['entity_type'] != entity_type_filter:
                    continue

                # Build result
                result = {
                    'score': float(score),
                    'vector_id': int(vector_id),
                    'opencti_id': row['opencti_id'],
                    'standard_id': row['standard_id'],
                    'entity_type': row['entity_type'],
                    'name': row['name'],
                    'content': row['content'],
                    'metadata': json.loads(row['metadata']) if row['metadata'] else {},
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at'],
                    'confidence': row['confidence'],
                }

                results.append(result)

                # Stop if we have enough results
                if len(results) >= top_k:
                    break

            logger.debug(f"Search returned {len(results)} results")

            return results

        except Exception as e:
            raise StorageError(f"Search failed: {e}")

    def get_by_id(self, opencti_id: str) -> Optional[Dict[str, Any]]:
        """
        Get entity by OpenCTI ID

        Args:
            opencti_id: OpenCTI entity ID

        Returns:
            Entity dict or None if not found
        """
        cursor = self.db_conn.execute(
            "SELECT * FROM knowledge WHERE opencti_id = ?",
            (opencti_id,)
        )
        row = cursor.fetchone()

        if not row:
            return None

        return {
            'vector_id': row['vector_id'],
            'opencti_id': row['opencti_id'],
            'standard_id': row['standard_id'],
            'entity_type': row['entity_type'],
            'name': row['name'],
            'content': row['content'],
            'metadata': json.loads(row['metadata']) if row['metadata'] else {},
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
            'confidence': row['confidence'],
        }

    def count(self, entity_type: Optional[str] = None) -> int:
        """
        Count entities in storage

        Args:
            entity_type: Optional filter by entity type

        Returns:
            Total count
        """
        if entity_type:
            cursor = self.db_conn.execute(
                "SELECT COUNT(*) FROM knowledge WHERE entity_type = ?",
                (entity_type,)
            )
        else:
            cursor = self.db_conn.execute("SELECT COUNT(*) FROM knowledge")

        return cursor.fetchone()[0]

    def get_entity_types(self) -> Dict[str, int]:
        """
        Get count of entities by type

        Returns:
            Dict mapping entity_type to count
        """
        cursor = self.db_conn.execute("""
            SELECT entity_type, COUNT(*) as count
            FROM knowledge
            GROUP BY entity_type
            ORDER BY count DESC
        """)

        return {row['entity_type']: row['count'] for row in cursor}

    def delete_by_type(self, entity_type: str) -> int:
        """
        Delete all entities of a specific type

        Note: This requires rebuilding FAISS index.

        Args:
            entity_type: Entity type to delete

        Returns:
            Number of entities deleted
        """
        cursor = self.db_conn.execute(
            "SELECT COUNT(*) FROM knowledge WHERE entity_type = ?",
            (entity_type,)
        )
        count = cursor.fetchone()[0]

        if count == 0:
            return 0

        # Delete from SQLite
        self.db_conn.execute(
            "DELETE FROM knowledge WHERE entity_type = ?",
            (entity_type,)
        )
        self.db_conn.commit()

        logger.warning(
            f"Deleted {count} {entity_type} entities. "
            "FAISS index needs rebuilding for full effect."
        )

        return count

    def save(self):
        """Save FAISS index to disk"""
        try:
            import faiss
            faiss.write_index(self.faiss_index, str(self.faiss_index_path))
            logger.info(f"Saved FAISS index to {self.faiss_index_path}")
        except Exception as e:
            raise StorageError(f"Failed to save FAISS index: {e}")

    def close(self):
        """Close database connection and save index"""
        if self.db_conn:
            self.db_conn.close()
            logger.info("Closed SQLite connection")

        self.save()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics

        Returns:
            Dict with statistics
        """
        return {
            'total_vectors': self.faiss_index.ntotal,
            'embedding_dim': self.embedding_dim,
            'index_type': self.index_type,
            'entity_counts': self.get_entity_types(),
            'faiss_index_path': str(self.faiss_index_path),
            'metadata_db_path': str(self.metadata_db_path),
        }

    def __repr__(self) -> str:
        return (
            f"KnowledgeStorage(vectors={self.faiss_index.ntotal}, "
            f"dim={self.embedding_dim}, "
            f"index={self.index_type})"
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
