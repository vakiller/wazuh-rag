#!/usr/bin/env python3
"""
OpenCTI Knowledge Synchronization Script

Main entry point for syncing threat intelligence from OpenCTI to local FAISS index.

Usage:
    python sync_opencti.py --full          # Full sync (all entities)
    python sync_opencti.py --incremental   # Incremental sync (new/updated only)
    python sync_opencti.py --entity-type attack-pattern  # Sync specific type
    python sync_opencti.py --stats         # Show storage statistics
"""

import argparse
import logging
import sys
import os
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from knowledge_ingest import (
    OpenCTIClient,
    KnowledgeNormalizer,
    EmbeddingModel,
    KnowledgeStorage
)
from knowledge_ingest.opencti_client import OpenCTIClientError
from knowledge_ingest.embedder import EmbeddingModelError
from knowledge_ingest.storage import StorageError


# Configure logging
def setup_logging(log_level: str, log_file: Optional[str] = None, console: bool = True):
    """Setup logging configuration"""
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(level)

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def load_config(config_path: str = "knowledge_ingest/config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file"""
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)

    # Override API token from environment if set
    if 'OPENCTI_TOKEN' in os.environ:
        config['opencti']['api_token'] = os.environ['OPENCTI_TOKEN']

    return config


def load_sync_state(state_file: str) -> Dict[str, Any]:
    """Load sync state from file"""
    state_path = Path(state_file)

    if not state_path.exists():
        return {}

    try:
        with open(state_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to load sync state: {e}")
        return {}


def save_sync_state(state_file: str, state: Dict[str, Any]):
    """Save sync state to file"""
    state_path = Path(state_file)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to save sync state: {e}")


def sync_entity_type(
    client: OpenCTIClient,
    normalizer: KnowledgeNormalizer,
    embedder: EmbeddingModel,
    storage: KnowledgeStorage,
    entity_type: str,
    batch_size: int = 100,
    max_items: int = -1,
    modified_after: Optional[datetime] = None
) -> int:
    """
    Sync entities of a specific type

    Args:
        client: OpenCTI client
        normalizer: Knowledge normalizer
        embedder: Embedding model
        storage: Storage manager
        entity_type: Type of entity to sync
        batch_size: Batch size for processing
        max_items: Maximum items to sync (-1 for unlimited)
        modified_after: Only sync items modified after this datetime

    Returns:
        Number of entities synced
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting sync for entity type: {entity_type}")

    count = 0
    batch_entities = []
    batch_texts = []

    try:
        # Fetch entities from OpenCTI
        for entity in client.fetch_entities(
            entity_type,
            batch_size=batch_size,
            max_items=max_items,
            modified_after=modified_after
        ):
            # Normalize entity
            try:
                normalized = normalizer.normalize(entity)
                batch_entities.append(normalized)
                batch_texts.append(normalized['content'])
            except Exception as e:
                logger.error(f"Failed to normalize entity {entity.get('id')}: {e}")
                continue

            # Process batch when full
            if len(batch_entities) >= batch_size:
                # Generate embeddings
                embeddings = embedder.embed_batch(batch_texts, show_progress=False)

                # Store
                storage.add(embeddings, batch_entities)

                count += len(batch_entities)
                logger.info(f"Processed {count} {entity_type} entities")

                # Clear batch
                batch_entities = []
                batch_texts = []

        # Process remaining entities
        if batch_entities:
            embeddings = embedder.embed_batch(batch_texts, show_progress=False)
            storage.add(embeddings, batch_entities)
            count += len(batch_entities)

        logger.info(f"Completed sync for {entity_type}: {count} entities")
        return count

    except Exception as e:
        logger.error(f"Sync failed for {entity_type}: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Sync threat intelligence from OpenCTI to local FAISS index"
    )

    parser.add_argument(
        '--config',
        default='knowledge_ingest/config.yaml',
        help='Path to configuration file'
    )

    parser.add_argument(
        '--full',
        action='store_true',
        help='Perform full sync (all entities)'
    )

    parser.add_argument(
        '--incremental',
        action='store_true',
        help='Perform incremental sync (only new/updated entities)'
    )

    parser.add_argument(
        '--entity-type',
        choices=['attack-pattern', 'malware', 'course-of-action',
                 'intrusion-set', 'indicator', 'report'],
        help='Sync only specific entity type'
    )

    parser.add_argument(
        '--max-items',
        type=int,
        default=-1,
        help='Maximum number of items to sync per type (-1 for unlimited)'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show storage statistics and exit'
    )

    parser.add_argument(
        '--test-connection',
        action='store_true',
        help='Test OpenCTI connection and exit'
    )

    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return 1

    # Setup logging
    setup_logging(
        args.log_level,
        config.get('logging', {}).get('file'),
        config.get('logging', {}).get('console', True)
    )

    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("OpenCTI Knowledge Sync Starting")
    logger.info("=" * 60)

    # Initialize components
    try:
        # OpenCTI client
        opencti_config = config['opencti']
        client = OpenCTIClient(
            url=opencti_config['url'],
            api_token=opencti_config['api_token'],
            verify_ssl=opencti_config.get('verify_ssl', True)
        )

        # Test connection if requested
        if args.test_connection:
            logger.info("Testing OpenCTI connection...")
            about = client.test_connection()
            logger.info(f"✓ Connected to OpenCTI version {about.get('version')}")
            return 0

        # Embedding model
        embedding_config = config['embedding']
        embedder = EmbeddingModel(
            model_name=embedding_config['model_name'],
            device=embedding_config.get('device', 'cpu'),
            normalize=embedding_config.get('normalize', True)
        )

        # Storage
        storage_config = config['storage']
        storage = KnowledgeStorage(
            faiss_index_path=storage_config['faiss_index_path'],
            metadata_db_path=storage_config['metadata_db_path'],
            embedding_dim=embedder.get_dimension(),
            index_type=storage_config.get('index_type', 'IndexFlatIP')
        )

        # Show stats if requested
        if args.stats:
            stats = storage.get_stats()
            logger.info("Storage Statistics:")
            logger.info(f"  Total vectors: {stats['total_vectors']}")
            logger.info(f"  Embedding dimension: {stats['embedding_dim']}")
            logger.info(f"  Index type: {stats['index_type']}")
            logger.info("  Entity counts:")
            for entity_type, count in stats['entity_counts'].items():
                logger.info(f"    {entity_type}: {count}")
            return 0

        # Normalizer
        normalizer = KnowledgeNormalizer()

        # Load sync state
        sync_config = config.get('sync', {})
        state_file = sync_config.get('state_file', './data/faiss_index/.opencti_sync_state.json')
        state = load_sync_state(state_file)

        # Determine entity types to sync
        if args.entity_type:
            entity_types = [args.entity_type]
        else:
            entity_types = opencti_config.get('entity_types', [
                'attack-pattern', 'malware', 'course-of-action',
                'intrusion-set', 'indicator', 'report'
            ])

        # Determine sync mode
        modified_after = None
        if args.incremental and not args.full:
            # Get last sync timestamp for incremental sync
            last_sync = state.get('last_sync_timestamp')
            if last_sync:
                modified_after = datetime.fromisoformat(last_sync.rstrip('Z'))
                logger.info(f"Incremental sync from: {modified_after}")
            else:
                logger.warning("No previous sync found, performing full sync")

        # Sync each entity type
        total_synced = 0
        sync_start = datetime.utcnow()

        for entity_type in entity_types:
            try:
                count = sync_entity_type(
                    client=client,
                    normalizer=normalizer,
                    embedder=embedder,
                    storage=storage,
                    entity_type=entity_type,
                    batch_size=opencti_config.get('batch_size', 100),
                    max_items=args.max_items if args.max_items > 0 else opencti_config.get('max_items_per_type', -1),
                    modified_after=modified_after
                )
                total_synced += count

                # Update state
                state[f'last_sync_{entity_type}'] = sync_start.isoformat() + 'Z'

            except Exception as e:
                logger.error(f"Failed to sync {entity_type}: {e}")
                continue

        # Save storage
        storage.save()

        # Update and save state
        state['last_sync_timestamp'] = sync_start.isoformat() + 'Z'
        state['last_sync_count'] = total_synced
        save_sync_state(state_file, state)

        # Final stats
        logger.info("=" * 60)
        logger.info("Sync Complete")
        logger.info(f"Total entities synced: {total_synced}")
        logger.info(f"Storage: {storage}")
        logger.info("=" * 60)

        return 0

    except OpenCTIClientError as e:
        logger.error(f"OpenCTI client error: {e}")
        return 1
    except EmbeddingModelError as e:
        logger.error(f"Embedding model error: {e}")
        return 1
    except StorageError as e:
        logger.error(f"Storage error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
