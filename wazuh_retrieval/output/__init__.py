"""
Output handlers for writing normalized alerts to various storage backends.
"""

from .file_handler import JSONLinesOutputHandler
from .sqlite_handler import SQLiteOutputHandler

__all__ = ["JSONLinesOutputHandler", "SQLiteOutputHandler"]
