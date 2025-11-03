#!/usr/bin/env python3
"""
Check Knowledge Storage Statistics

Shows the current state of FAISS index and SQLite metadata database.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from knowledge_ingest import KnowledgeStorage, EmbeddingModel


def main():
    print("=" * 60)
    print("Knowledge Storage Statistics")
    print("=" * 60)

    # Initialize embedding model (just to get dimension)
    print("\nInitializing embedding model...")
    embedder = EmbeddingModel(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        device="cpu",
        normalize=True
    )

    # Load storage
    print("Loading storage...")
    storage = KnowledgeStorage(
        faiss_index_path="./data/faiss_index/knowledge.index",
        metadata_db_path="./data/faiss_index/knowledge.db",
        embedding_dim=embedder.get_dimension(),
        index_type="IndexFlatIP"
    )

    # Get statistics
    stats = storage.get_stats()

    print("\n" + "=" * 60)
    print("STORAGE STATISTICS")
    print("=" * 60)

    print(f"\nTotal vectors in FAISS index: {stats['total_vectors']}")
    print(f"Embedding dimension: {stats['embedding_dim']}")
    print(f"Index type: {stats['index_type']}")
    print(f"\nFAISS index file: {stats['faiss_index_path']}")
    print(f"SQLite database: {stats['metadata_db_path']}")

    print("\n" + "-" * 60)
    print("ENTITY COUNTS BY TYPE")
    print("-" * 60)

    entity_counts = stats['entity_counts']
    if entity_counts:
        for entity_type, count in entity_counts.items():
            print(f"  {entity_type:25s} {count:,}")
        print(f"\n  {'TOTAL':25s} {sum(entity_counts.values()):,}")
    else:
        print("  No entities found - database is empty")

    # Get total from SQLite
    total_db = storage.count()
    print(f"\nTotal records in SQLite: {total_db:,}")

    if total_db > 0:
        print("\n" + "-" * 60)
        print("SAMPLE ENTITIES (First 5)")
        print("-" * 60)

        # Query first 5 entities from SQLite
        cursor = storage.db_conn.execute("""
            SELECT vector_id, entity_type, name, confidence
            FROM knowledge
            ORDER BY vector_id
            LIMIT 5
        """)

        for row in cursor:
            print(f"\nVector ID: {row[0]}")
            print(f"  Type: {row[1]}")
            print(f"  Name: {row[2]}")
            print(f"  Confidence: {row[3]}")

    print("\n" + "=" * 60)
    print("STATUS")
    print("=" * 60)

    if total_db == 0:
        print("\n⚠️  Knowledge base is EMPTY")
        print("\nTo populate the knowledge base, run:")
        print("  1. Set your OpenCTI API token:")
        print("     export OPENCTI_TOKEN='your-token-here'")
        print("\n  2. Test connection:")
        print("     python3 sync_opencti.py --test-connection")
        print("\n  3. Sync entities:")
        print("     python3 sync_opencti.py --entity-type attack-pattern --max-items 50")
    else:
        print(f"\n✅ Knowledge base contains {total_db:,} entities")
        print(f"✅ FAISS index contains {stats['total_vectors']:,} vectors")

    print("\n" + "=" * 60)

    storage.close()


if __name__ == '__main__':
    main()
