"""
State tracking for collection checkpointing and resume functionality.
"""

from typing import Optional, Dict, Any
from datetime import datetime
import json
import logging
from pathlib import Path
from ..exceptions import StateTrackingError

logger = logging.getLogger(__name__)


class StateTracker:
    """
    Tracks collection state to prevent duplicate processing and enable resume.

    State is persisted to a JSON file on disk for durability across restarts.
    Each collector maintains its own timestamp and checkpoint data.
    """

    def __init__(self, state_file: str = ".wazuh_collector_state.json"):
        """
        Initialize the state tracker.

        Args:
            state_file: Path to state file (relative or absolute)
        """
        self.state_file = Path(state_file)
        self.state: Dict[str, Any] = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """
        Load state from disk.

        Returns:
            State dictionary, or empty dict if file doesn't exist
        """
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    logger.info(f"Loaded state from {self.state_file}")
                    return state
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse state file: {e}")
                logger.warning("Starting with empty state")
                return {}
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
                return {}

        logger.info("No existing state file, starting fresh")
        return {}

    def _save_state(self):
        """
        Persist state to disk.

        Raises:
            StateTrackingError: If save operation fails
        """
        try:
            # Ensure directory exists
            self.state_file.parent.mkdir(parents=True, exist_ok=True)

            # Write to temporary file first (atomic write)
            temp_file = self.state_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(self.state, f, indent=2, default=str)

            # Atomic rename
            temp_file.replace(self.state_file)

            logger.debug(f"State saved to {self.state_file}")
        except Exception as e:
            raise StateTrackingError(f"Failed to save state: {e}")

    def get_last_timestamp(self, collector_name: str) -> Optional[datetime]:
        """
        Get last processed timestamp for a collector.

        Args:
            collector_name: Name of the collector (e.g., 'alerts')

        Returns:
            Last processed timestamp as datetime, or None if not set
        """
        timestamp_str = self.state.get(f"{collector_name}_last_timestamp")
        if timestamp_str:
            try:
                # Handle both with and without timezone
                timestamp_str = timestamp_str.replace('Z', '+00:00')
                return datetime.fromisoformat(timestamp_str)
            except (ValueError, AttributeError) as e:
                logger.warning(f"Invalid timestamp in state for {collector_name}: {e}")
        return None

    def update_last_timestamp(self, collector_name: str, timestamp: datetime):
        """
        Update last processed timestamp for a collector.

        Args:
            collector_name: Name of the collector (e.g., 'alerts')
            timestamp: Last processed timestamp
        """
        self.state[f"{collector_name}_last_timestamp"] = timestamp.isoformat() + "Z"
        self.state[f"{collector_name}_last_update"] = datetime.utcnow().isoformat() + "Z"
        self._save_state()
        logger.debug(f"Updated checkpoint for {collector_name}: {timestamp.isoformat()}")

    def get_checkpoint(self, collector_name: str, checkpoint_name: str) -> Any:
        """
        Get arbitrary checkpoint data.

        Useful for storing custom state like:
        - Last processed document ID
        - Backfill progress markers
        - Error counts

        Args:
            collector_name: Name of the collector
            checkpoint_name: Name of the checkpoint

        Returns:
            Checkpoint value, or None if not set
        """
        return self.state.get(f"{collector_name}_{checkpoint_name}")

    def set_checkpoint(self, collector_name: str, checkpoint_name: str, value: Any):
        """
        Set arbitrary checkpoint data.

        Args:
            collector_name: Name of the collector
            checkpoint_name: Name of the checkpoint
            value: Value to store (must be JSON-serializable)
        """
        self.state[f"{collector_name}_{checkpoint_name}"] = value
        self._save_state()
        logger.debug(f"Set checkpoint {collector_name}.{checkpoint_name} = {value}")

    def clear_checkpoint(self, collector_name: str, checkpoint_name: Optional[str] = None):
        """
        Clear checkpoint(s) for a collector.

        Args:
            collector_name: Name of the collector
            checkpoint_name: Specific checkpoint to clear, or None to clear all
        """
        if checkpoint_name:
            key = f"{collector_name}_{checkpoint_name}"
            if key in self.state:
                del self.state[key]
                logger.info(f"Cleared checkpoint {key}")
        else:
            # Clear all checkpoints for this collector
            prefix = f"{collector_name}_"
            keys_to_delete = [k for k in self.state.keys() if k.startswith(prefix)]
            for key in keys_to_delete:
                del self.state[key]
            logger.info(f"Cleared all checkpoints for {collector_name}")

        self._save_state()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about tracked state.

        Returns:
            Dictionary with state statistics
        """
        collectors = set()
        for key in self.state.keys():
            if '_' in key:
                collector = key.split('_')[0]
                collectors.add(collector)

        stats = {
            'total_keys': len(self.state),
            'collectors': list(collectors),
            'state_file': str(self.state_file),
            'state_file_exists': self.state_file.exists(),
        }

        # Add last update times for each collector
        for collector in collectors:
            last_update = self.state.get(f"{collector}_last_update")
            if last_update:
                stats[f"{collector}_last_update"] = last_update

        return stats
