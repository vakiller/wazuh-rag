"""
Embedding Model Wrapper

Provides text-to-vector embedding using sentence-transformers.
Supports both CPU and GPU inference.
"""

import logging
from typing import List, Union
import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingModelError(Exception):
    """Base exception for embedding model errors"""
    pass


class EmbeddingModel:
    """
    Wrapper for sentence-transformers embedding model

    Converts text to dense vector representations suitable for semantic search.
    """

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        device: str = "cpu",
        normalize: bool = True
    ):
        """
        Initialize embedding model

        Args:
            model_name: HuggingFace model name or path
            device: 'cpu' or 'cuda'
            normalize: Whether to L2-normalize embeddings (for cosine similarity)
        """
        self.model_name = model_name
        self.device = device
        self.normalize = normalize
        self.model = None
        self.embedding_dim = None

        logger.info(f"Initializing embedding model: {model_name} on {device}")
        self._load_model()

    def _load_model(self):
        """Load sentence-transformers model"""
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise EmbeddingModelError(
                "sentence-transformers not installed. "
                "Install with: pip install sentence-transformers"
            )

        try:
            self.model = SentenceTransformer(self.model_name, device=self.device)
            self.embedding_dim = self.model.get_sentence_embedding_dimension()
            logger.info(
                f"Loaded model {self.model_name} "
                f"(dimension: {self.embedding_dim}, device: {self.device})"
            )
        except Exception as e:
            raise EmbeddingModelError(f"Failed to load model {self.model_name}: {e}")

    def embed(
        self,
        texts: Union[str, List[str]],
        batch_size: int = 32,
        show_progress: bool = False
    ) -> np.ndarray:
        """
        Generate embeddings for text(s)

        Args:
            texts: Single text string or list of texts
            batch_size: Batch size for encoding
            show_progress: Show progress bar for large batches

        Returns:
            numpy array of shape (n_texts, embedding_dim)

        Raises:
            EmbeddingModelError: If encoding fails
        """
        if not self.model:
            raise EmbeddingModelError("Model not loaded")

        # Convert single string to list
        is_single = isinstance(texts, str)
        if is_single:
            texts = [texts]

        if not texts:
            return np.array([])

        try:
            embeddings = self.model.encode(
                texts,
                batch_size=batch_size,
                show_progress_bar=show_progress,
                normalize_embeddings=self.normalize,
                convert_to_numpy=True
            )

            logger.debug(
                f"Generated {len(embeddings)} embeddings "
                f"(shape: {embeddings.shape})"
            )

            return embeddings

        except Exception as e:
            raise EmbeddingModelError(f"Encoding failed: {e}")

    def embed_batch(
        self,
        texts: List[str],
        batch_size: int = 32,
        show_progress: bool = True
    ) -> np.ndarray:
        """
        Generate embeddings for a batch of texts

        Convenience method with progress bar enabled by default.

        Args:
            texts: List of text strings
            batch_size: Batch size for encoding
            show_progress: Show progress bar

        Returns:
            numpy array of shape (n_texts, embedding_dim)
        """
        return self.embed(texts, batch_size=batch_size, show_progress=show_progress)

    def get_dimension(self) -> int:
        """
        Get embedding dimension

        Returns:
            Embedding vector dimension
        """
        if not self.embedding_dim:
            raise EmbeddingModelError("Model not loaded")
        return self.embedding_dim

    def similarity(
        self,
        text1: Union[str, np.ndarray],
        text2: Union[str, np.ndarray]
    ) -> float:
        """
        Calculate similarity between two texts or embeddings

        If normalize=True, this is cosine similarity.
        Otherwise, it's inner product.

        Args:
            text1: Text string or embedding vector
            text2: Text string or embedding vector

        Returns:
            Similarity score (0-1 for normalized, unbounded otherwise)
        """
        # Get embeddings if inputs are strings
        if isinstance(text1, str):
            embedding1 = self.embed(text1)[0]
        else:
            embedding1 = text1

        if isinstance(text2, str):
            embedding2 = self.embed(text2)[0]
        else:
            embedding2 = text2

        # Inner product (equals cosine similarity for normalized vectors)
        similarity = np.dot(embedding1, embedding2)

        return float(similarity)

    def batch_similarity(
        self,
        query: Union[str, np.ndarray],
        candidates: Union[List[str], np.ndarray]
    ) -> np.ndarray:
        """
        Calculate similarity between query and multiple candidates

        Args:
            query: Query text or embedding
            candidates: List of candidate texts or embeddings array

        Returns:
            Array of similarity scores
        """
        # Get query embedding
        if isinstance(query, str):
            query_embedding = self.embed(query)[0]
        else:
            query_embedding = query

        # Get candidate embeddings
        if isinstance(candidates, list) and len(candidates) > 0 and isinstance(candidates[0], str):
            candidate_embeddings = self.embed(candidates)
        else:
            candidate_embeddings = candidates

        # Compute inner products
        similarities = np.dot(candidate_embeddings, query_embedding)

        return similarities

    def __repr__(self) -> str:
        return (
            f"EmbeddingModel(model={self.model_name}, "
            f"device={self.device}, "
            f"dim={self.embedding_dim}, "
            f"normalize={self.normalize})"
        )


class EmbeddingCache:
    """
    Simple in-memory cache for embeddings to avoid re-encoding

    Useful for repeated queries during development/testing.
    """

    def __init__(self, max_size: int = 10000):
        """
        Initialize cache

        Args:
            max_size: Maximum number of cached embeddings (LRU eviction)
        """
        self.max_size = max_size
        self.cache: dict[str, np.ndarray] = {}
        self.access_order: List[str] = []

    def get(self, text: str) -> Union[np.ndarray, None]:
        """Get cached embedding if exists"""
        if text in self.cache:
            # Update access order (move to end)
            self.access_order.remove(text)
            self.access_order.append(text)
            return self.cache[text]
        return None

    def put(self, text: str, embedding: np.ndarray):
        """Cache embedding"""
        # If at capacity, evict least recently used
        if len(self.cache) >= self.max_size and text not in self.cache:
            lru_key = self.access_order.pop(0)
            del self.cache[lru_key]

        # Add/update cache
        if text in self.cache:
            self.access_order.remove(text)
        self.cache[text] = embedding
        self.access_order.append(text)

    def clear(self):
        """Clear all cached embeddings"""
        self.cache.clear()
        self.access_order.clear()

    def size(self) -> int:
        """Get current cache size"""
        return len(self.cache)
