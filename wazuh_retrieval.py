#!/usr/bin/env python3
"""
Wazuh Alert Collector - Main Application Entry Point

This application collects security alerts from Wazuh Indexer,
transforms them to a normalized schema, and outputs them to
various storage backends for further analysis and reporting.

Usage:
    python main.py [--config CONFIG_FILE] [--log-level LEVEL]

Environment variables are used for configuration (see .env.example).
"""

import argparse
import sys
import logging
from pathlib import Path

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, environment variables must be set manually
    pass

from wazuh_retrieval.config import IndexerConfig
from wazuh_retrieval.client import WazuhIndexerClient
from wazuh_retrieval.tracking.state import StateTracker
from wazuh_retrieval.output.sqlite_handler import SQLiteOutputHandler
from wazuh_retrieval.output.postgres_handler import PostgreSQLOutputHandler
from wazuh_retrieval.output.file_handler import JSONLinesOutputHandler
from wazuh_retrieval.scheduler import WazuhCollectorScheduler
from wazuh_retrieval.utils import setup_logging
from wazuh_retrieval.exceptions import ConfigurationError
import os

logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Wazuh Alert Collector - Collect and normalize security alerts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with SQLite output (default)
  python main.py

  # Run with file output
  python main.py --output file

  # Run with debug logging
  python main.py --log-level DEBUG

  # Run historical backfill (not implemented in this example)
  # python main.py --mode backfill --start 2025-01-01 --end 2025-01-15

Environment Variables:
  See .env.example for all configuration options
        """
    )

    parser.add_argument(
        '--output',
        choices=['sqlite', 'postgres', 'file'],
        default=None,
        help='Output handler type (default: auto-detect from env)'
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    parser.add_argument(
        '--log-file',
        type=str,
        help='Optional log file path'
    )

    parser.add_argument(
        '--no-immediate-run',
        action='store_true',
        help='Do not run collection immediately on start'
    )

    return parser.parse_args()


def create_output_handler(args, config):
    """
    Create appropriate output handler based on arguments or environment.

    Args:
        args: Parsed command-line arguments
        config: IndexerConfig instance

    Returns:
        Output handler instance
    """
    # Auto-detect from environment if not specified
    output_type = args.output
    if output_type is None:
        # Check if DB_HOST is set (indicates PostgreSQL)
        if os.getenv('DB_HOST'):
            output_type = 'postgres'
        else:
            output_type = 'sqlite'

    if output_type == 'postgres':
        logger.info(f"Using PostgreSQL output handler: {os.getenv('DB_HOST', 'localhost')}/{os.getenv('DB_NAME', 'wazuh_rag')}")
        return PostgreSQLOutputHandler()
    elif output_type == 'sqlite':
        logger.info(f"Using SQLite output handler: {config.sqlite_db_path}")
        return SQLiteOutputHandler(config.sqlite_db_path)
    elif output_type == 'file':
        logger.info(f"Using JSONL file output handler: {config.output_dir}")
        return JSONLinesOutputHandler(config.output_dir)
    else:
        raise ConfigurationError(f"Unknown output handler: {output_type}")


def main():
    """Main application entry point."""
    args = parse_arguments()

    # Setup logging
    setup_logging(log_level=args.log_level, log_file=args.log_file)

    logger.info("="*60)
    logger.info("Wazuh Alert Collector Starting")
    logger.info("="*60)

    output_handler = None
    try:
        # Load configuration from environment
        logger.info("Loading configuration from environment variables...")
        config = IndexerConfig.from_env()
        config.validate()
        logger.info("Configuration loaded successfully")

        # Initialize components
        logger.info("Initializing components...")

        client = WazuhIndexerClient(config)
        logger.info(f"  Client: connecting to {config.host}:{config.port}")

        state_tracker = StateTracker(config.state_file)
        logger.info(f"  State tracker: {config.state_file}")

        output_handler = create_output_handler(args, config)
        logger.info(f"  Output handler: {args.output}")

        # Create scheduler
        scheduler = WazuhCollectorScheduler(
            config=config,
            client=client,
            state_tracker=state_tracker,
            output_handler=output_handler
        )

        logger.info("All components initialized successfully")
        logger.info("="*60)

        # Start collection
        run_immediately = not args.no_immediate_run
        scheduler.start(run_immediately=run_immediately)

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Please check your environment variables (see .env.example)")
        sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

    finally:
        # Clean up resources
        if output_handler and hasattr(output_handler, 'close'):
            try:
                output_handler.close()
                logger.info("Output handler closed successfully")
            except Exception as e:
                logger.error(f"Error closing output handler: {e}")


if __name__ == "__main__":
    main()
