"""
Scheduler for periodic collection of Wazuh alerts.
"""

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
from typing import Callable, Optional
import logging
import signal
import sys

from .collectors.alerts import AlertCollector
from .schema.transformer import AlertTransformer

logger = logging.getLogger(__name__)


class WazuhCollectorScheduler:
    """
    Scheduler for periodic collection and processing of Wazuh alerts.

    Features:
    - Configurable polling intervals
    - Automatic error handling and retry
    - Graceful shutdown on signals
    - Pluggable output handlers
    - Statistics tracking
    """

    def __init__(self, config, client, state_tracker, output_handler):
        """
        Initialize the scheduler.

        Args:
            config: IndexerConfig instance
            client: WazuhIndexerClient instance
            state_tracker: StateTracker instance
            output_handler: Output handler instance (file, SQLite, Kafka, etc.)
        """
        self.config = config
        self.client = client
        self.state_tracker = state_tracker
        self.output_handler = output_handler
        self.scheduler = BlockingScheduler()
        self.transformer = AlertTransformer()

        # Initialize collectors
        self.alert_collector = AlertCollector(client, config, state_tracker)

        # Statistics
        self.stats = {
            'total_collected': 0,
            'total_transformed': 0,
            'total_output': 0,
            'errors': 0,
            'last_run': None,
            'last_run_duration': None,
        }

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)

    def collect_and_process_alerts(self):
        """
        Job function: collect recent alerts and process them.

        This is the main work function called by the scheduler.
        """
        start_time = datetime.utcnow()
        logger.info("="*60)
        logger.info("Starting alert collection job")
        logger.info("="*60)

        try:
            collected_count = 0
            transformed_count = 0
            output_count = 0
            error_count = 0

            # Collect recent alerts
            logger.info("Collecting recent alerts...")
            for raw_alert in self.alert_collector.collect_recent(
                lookback_minutes=self.config.lookback_minutes,
                min_level=self.config.min_alert_level
            ):
                collected_count += 1

                try:
                    # Transform to normalized schema
                    normalized = self.transformer.transform(raw_alert)
                    transformed_count += 1

                    # Send to output handler
                    self.output_handler.handle(normalized)
                    output_count += 1

                except Exception as e:
                    error_count += 1
                    doc_id = raw_alert.get('_id', 'unknown')
                    logger.error(f"Failed to process alert {doc_id}: {e}")

                # Log progress every 1000 alerts
                if collected_count % 1000 == 0:
                    logger.info(f"Progress: {collected_count} collected, {transformed_count} transformed")

            # Flush any pending writes
            if hasattr(self.output_handler, 'flush'):
                self.output_handler.flush()

            # Update statistics
            self.stats['total_collected'] += collected_count
            self.stats['total_transformed'] += transformed_count
            self.stats['total_output'] += output_count
            self.stats['errors'] += error_count
            self.stats['last_run'] = start_time.isoformat()

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            self.stats['last_run_duration'] = duration

            logger.info("="*60)
            logger.info("Alert collection job completed")
            logger.info(f"  Collected: {collected_count}")
            logger.info(f"  Transformed: {transformed_count}")
            logger.info(f"  Output: {output_count}")
            logger.info(f"  Errors: {error_count}")
            logger.info(f"  Duration: {duration:.2f} seconds")
            logger.info("="*60)

        except Exception as e:
            logger.error(f"Alert collection job failed with error: {e}", exc_info=True)
            self.stats['errors'] += 1

    def start(self, run_immediately: bool = True):
        """
        Start the scheduler.

        Args:
            run_immediately: If True, run collection immediately before starting scheduler
        """
        logger.info(f"Starting Wazuh alert collection scheduler")
        logger.info(f"  Index pattern: {self.config.alerts_index_pattern}")
        logger.info(f"  Poll interval: {self.config.poll_interval_seconds} seconds")
        logger.info(f"  Lookback window: {self.config.lookback_minutes} minutes")
        logger.info(f"  Min alert level: {self.config.min_alert_level}")
        logger.info(f"  Batch size: {self.config.batch_size}")

        # Schedule the collection job
        self.scheduler.add_job(
            self.collect_and_process_alerts,
            trigger=IntervalTrigger(seconds=self.config.poll_interval_seconds),
            id='alert_collection',
            name='Collect and process Wazuh alerts',
            max_instances=1,  # Prevent overlapping runs
            coalesce=True,  # Merge missed runs into one
            misfire_grace_time=60,  # Allow 60s grace period for delayed starts
        )

        logger.info("Scheduler configured successfully")

        # Run immediately on start if requested
        if run_immediately:
            logger.info("Running initial collection...")
            self.collect_and_process_alerts()

        # Start scheduler (blocking)
        logger.info("Starting scheduler loop...")
        try:
            self.scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            logger.info("Scheduler stopped by user")
            self.stop()

    def stop(self):
        """Stop the scheduler and cleanup resources."""
        logger.info("Stopping scheduler...")

        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)

        # Flush any pending writes
        if hasattr(self.output_handler, 'flush'):
            self.output_handler.flush()

        # Close connections
        if hasattr(self.output_handler, 'close'):
            self.output_handler.close()

        self.client.close()

        logger.info("Scheduler stopped successfully")
        logger.info(f"Final statistics: {self.stats}")

    def get_stats(self) -> dict:
        """
        Get scheduler statistics.

        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()

        # Add output handler stats if available
        if hasattr(self.output_handler, 'get_stats'):
            stats['output_handler'] = self.output_handler.get_stats()

        # Add state tracker stats
        stats['state_tracker'] = self.state_tracker.get_stats()

        return stats
