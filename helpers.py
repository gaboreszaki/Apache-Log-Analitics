"""Helper utilities for the Apache Log Analyzer."""

import os
import gzip
import datetime
from typing import List, Optional


class Fore:
    """ANSI color escape sequences for terminal output."""
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"


class Style:
    """ANSI style escape sequences for terminal output."""
    BRIGHT = "\033[1m"
    RESET_ALL = "\033[0m"


# Common file extensions considered as downloads
DOWNLOAD_EXTENSIONS = frozenset({
    '.zip', '.pdf', '.exe', '.dmg', '.tar', '.gz',
    '.tgz', '.rar', '.7z', '.iso', '.msi',
})

# Sensitive paths that indicate probing or attack attempts
SENSITIVE_PATHS = (
    '.env', 'xmlrpc.php', 'wp-admin', 'cgi-bin',
    '.git', 'shell', 'backup', 'config', 'sql',
)

# HTTP status codes indicating suspicious activity
SUSPICIOUS_STATUS_CODES = ('403', '401', '400')

# Error log severity levels considered critical
CRITICAL_LEVELS = ('error', 'crit', 'alert', 'emerg')

# Threat score weights
THREAT_SCORE_STATUS = 1
THREAT_SCORE_SENSITIVE_PATH = 2
THREAT_SCORE_CRITICAL_ERROR = 5

# Session timeout threshold in seconds (30 minutes)
SESSION_TIMEOUT_SECONDS = 1800

# Default session duration for single-hit visitors (seconds)
DEFAULT_SINGLE_HIT_DURATION = 30.0

# Timestamp formats used in Apache logs
TIMESTAMP_FORMATS = (
    '%d/%b/%Y:%H:%M:%S',
    '%a %b %d %H:%M:%S.%f %Y',
    '%a %b %d %H:%M:%S %Y',
    '%b %d %H:%M:%S %Y',
)


def enable_windows_ansi() -> None:
    """Enable ANSI escape sequence support on Windows terminals."""
    import sys
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.GetStdHandle(ctypes.wintypes.DWORD(-11))
        kernel32.SetConsoleMode(handle, ctypes.wintypes.DWORD(7))


def parse_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    """
    Parse various Apache timestamp formats.

    :param ts_str: Raw timestamp string from a log file.
    :return: Parsed datetime object, or None if no format matched.
    """
    ts_clean = ts_str.strip('[]')
    if ' ' in ts_clean and '/' in ts_clean:
        ts_clean = ts_clean.split(' ')[0]

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.datetime.strptime(ts_clean, fmt)
        except (ValueError, TypeError):
            continue
    return None


def is_download(request: str) -> bool:
    """
    Check whether an HTTP request targets a downloadable file.

    :param request: HTTP request line (e.g. "GET /file.zip HTTP/1.1").
    :return: True if the request is for a download resource.
    """
    try:
        path = request.split(' ')[1] if ' ' in request else request
        ext = os.path.splitext(path.split('?')[0])[1].lower()
        return ext in DOWNLOAD_EXTENSIONS or '/download' in path.lower()
    except IndexError:
        return False


def extract_path(request: str) -> str:
    """
    Extract the URL path from an HTTP request line.

    :param request: HTTP request line (e.g. "GET /page HTTP/1.1").
    :return: The path component of the request.
    """
    try:
        return request.split(' ')[1] if ' ' in request else request
    except IndexError:
        return request


def estimate_session_time(timestamps: List[datetime.datetime]) -> float:
    """
    Estimate total browsing time in seconds from a list of request timestamps.

    A gap exceeding SESSION_TIMEOUT_SECONDS starts a new session.

    :param timestamps: List of datetime objects for a single visitor.
    :return: Estimated time spent in seconds.
    """
    if not timestamps:
        return 0.0
    timestamps.sort()
    if len(timestamps) < 2:
        return DEFAULT_SINGLE_HIT_DURATION

    total_time = 0.0
    start = timestamps[0]
    last = timestamps[0]
    for ts in timestamps[1:]:
        gap = (ts - last).total_seconds()
        if gap > SESSION_TIMEOUT_SECONDS:
            total_time += (last - start).total_seconds() + DEFAULT_SINGLE_HIT_DURATION
            start = ts
        last = ts
    total_time += (last - start).total_seconds() + DEFAULT_SINGLE_HIT_DURATION
    return total_time


def format_bandwidth(size_bytes: int) -> str:
    """
    Format a byte count into a human-readable string.

    :param size_bytes: Size in bytes.
    :return: Formatted string (e.g. "1.5 MB").
    """
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def open_log_file(file_path: str):
    """
    Open a plain-text or gzip-compressed log file for reading.

    :param file_path: Path to the log file.
    :return: A file-like object opened for text reading.
    """
    if file_path.endswith('.gz'):
        return gzip.open(file_path, 'rt', errors='ignore')
    if file_path.endswith('.bz2'):
        import bz2
        return bz2.open(file_path, 'rt', errors='ignore')
    return open(file_path, 'r', errors='ignore')


def is_sensitive_request(request: str) -> bool:
    """
    Check whether a request targets a known sensitive path.

    :param request: HTTP request line.
    :return: True if the request matches a sensitive pattern.
    """
    lower = request.lower()
    return any(pattern in lower for pattern in SENSITIVE_PATHS)
