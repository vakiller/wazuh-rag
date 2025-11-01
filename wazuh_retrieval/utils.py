"""
Utility functions for the Wazuh retrieval module.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def parse_time_range(time_str: str) -> datetime:
    """
    Parse relative time strings to datetime objects.

    Args:
        time_str: Time string (e.g., 'now', 'now-5m', 'now-1h', 'now-1d')

    Returns:
        datetime object

    Examples:
        parse_time_range('now') -> current UTC time
        parse_time_range('now-5m') -> 5 minutes ago
        parse_time_range('now-1h') -> 1 hour ago
        parse_time_range('now-7d') -> 7 days ago
    """
    now = datetime.utcnow()

    if time_str == 'now':
        return now

    if time_str.startswith('now-'):
        delta_str = time_str[4:]  # Remove 'now-'

        # Parse number and unit
        if delta_str.endswith('m'):
            minutes = int(delta_str[:-1])
            return now - timedelta(minutes=minutes)
        elif delta_str.endswith('h'):
            hours = int(delta_str[:-1])
            return now - timedelta(hours=hours)
        elif delta_str.endswith('d'):
            days = int(delta_str[:-1])
            return now - timedelta(days=days)
        else:
            raise ValueError(f"Invalid time unit in: {time_str}")

    # Try parsing as ISO format
    try:
        return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError(f"Cannot parse time string: {time_str}")


def format_bytes(size_bytes: int) -> str:
    """
    Format bytes to human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., '1.5 MB', '500 KB')
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def get_active_indices(client, pattern: str, days_back: int = 7) -> List[str]:
    """
    Get list of active indices matching pattern within time window.

    Optimizes queries by targeting specific indices instead of wildcard.
    Wazuh typically creates daily indices (wazuh-alerts-4.x-YYYY.MM.DD).

    Args:
        client: WazuhIndexerClient instance
        pattern: Index pattern (e.g., 'wazuh-alerts-*')
        days_back: How many days back to include

    Returns:
        List of index names
    """
    try:
        # Get all indices matching pattern
        indices = client.get_indices(pattern)

        cutoff_date = datetime.utcnow() - timedelta(days=days_back)
        active = []

        for idx in indices:
            index_name = idx['index']

            # Try to parse date from index name
            try:
                # Assumes format: wazuh-alerts-4.x-YYYY.MM.DD
                parts = index_name.split('-')
                if len(parts) >= 3:
                    date_part = parts[-1]  # Last part should be date
                    index_date = datetime.strptime(date_part, '%Y.%m.%d')

                    if index_date >= cutoff_date:
                        active.append(index_name)
                else:
                    # Can't parse date, include it to be safe
                    active.append(index_name)
            except (ValueError, IndexError):
                # Can't parse date, include it to be safe
                active.append(index_name)

        logger.info(f"Found {len(active)} active indices for pattern {pattern}")
        return sorted(active)

    except Exception as e:
        logger.error(f"Failed to get active indices: {e}")
        # Return pattern as fallback
        return [pattern]


def chunk_time_range(
    start_date: datetime,
    end_date: datetime,
    chunk_days: int = 1
) -> List[tuple]:
    """
    Split a time range into smaller chunks.

    Useful for processing large historical ranges in manageable pieces.

    Args:
        start_date: Start of range
        end_date: End of range
        chunk_days: Size of each chunk in days

    Returns:
        List of (chunk_start, chunk_end) tuples

    Example:
        chunk_time_range(
            datetime(2025, 1, 1),
            datetime(2025, 1, 3),
            chunk_days=1
        )
        # Returns: [
        #   (2025-01-01, 2025-01-02),
        #   (2025-01-02, 2025-01-03)
        # ]
    """
    chunks = []
    current = start_date

    while current < end_date:
        chunk_end = min(current + timedelta(days=chunk_days), end_date)
        chunks.append((current, chunk_end))
        current = chunk_end

    return chunks


def validate_alert(alert: Dict[str, Any]) -> bool:
    """
    Validate that a normalized alert has required fields.

    Args:
        alert: Normalized alert dictionary

    Returns:
        True if valid, False otherwise
    """
    required_fields = ['timestamp', 'document_id', 'agent_id', 'rule_id', 'rule_level']

    for field in required_fields:
        if field not in alert or alert[field] is None:
            logger.warning(f"Alert missing required field '{field}': {alert.get('document_id', 'unknown')}")
            return False

    return True


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize string for safe storage/transmission.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not value:
        return ""

    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length] + "...[truncated]"

    # Remove null bytes
    value = value.replace('\x00', '')

    return value


def setup_logging(log_level: str = "INFO", log_file: str = None):
    """
    Setup logging configuration for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional log file path
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    logger.info(f"Logging configured: level={log_level}, file={log_file or 'none'}")
