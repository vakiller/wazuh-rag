"""
File-based output handler that writes normalized alerts to JSONL files.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class JSONLinesOutputHandler:
    """
    Write normalized alerts to JSONL (JSON Lines) files.

    Suitable for:
    - Development and testing
    - Batch processing pipelines
    - Small to medium scale deployments
    - File-based integration with other tools

    Features:
    - Daily file rotation
    - Append-only writes
    - Automatic directory creation
    """

    def __init__(self, output_dir: str = "./collected_alerts"):
        """
        Initialize the file handler.

        Args:
            output_dir: Directory to write output files (created if doesn't exist)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.current_file: Optional[Path] = None
        self.current_date: Optional[datetime.date] = None
        logger.info(f"JSONLines output handler initialized: {self.output_dir}")

    def _get_output_file(self) -> Path:
        """
        Get output file for current date (daily rotation).

        Returns:
            Path to current output file
        """
        today = datetime.utcnow().date()

        if today != self.current_date:
            self.current_date = today
            self.current_file = self.output_dir / f"alerts_{today.isoformat()}.jsonl"
            logger.info(f"Rotated to new output file: {self.current_file}")

        return self.current_file

    def handle(self, normalized_alert: Dict[str, Any]):
        """
        Write normalized alert to JSONL file.

        Args:
            normalized_alert: Normalized alert dictionary
        """
        output_file = self._get_output_file()

        try:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(normalized_alert, default=str, ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"Failed to write alert to file {output_file}: {e}")

    def get_file_stats(self) -> Dict[str, Any]:
        """
        Get statistics about output files.

        Returns:
            Dictionary with file statistics
        """
        files = list(self.output_dir.glob("alerts_*.jsonl"))

        stats = {
            'output_dir': str(self.output_dir),
            'total_files': len(files),
            'current_file': str(self.current_file) if self.current_file else None,
            'files': []
        }

        for file_path in sorted(files):
            try:
                file_stats = file_path.stat()
                # Count lines (approximation of alerts)
                with open(file_path, 'r') as f:
                    line_count = sum(1 for _ in f)

                stats['files'].append({
                    'name': file_path.name,
                    'size_bytes': file_stats.st_size,
                    'alert_count': line_count,
                    'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                })
            except Exception as e:
                logger.warning(f"Failed to get stats for {file_path}: {e}")

        return stats
