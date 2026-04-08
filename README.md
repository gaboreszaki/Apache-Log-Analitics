# Apache Web Server Log Analyzer

A lightweight, zero-dependency CLI tool for parsing and analyzing Apache HTTP Server logs (access and error). It produces structured, color-coded reports covering web traffic, downloads, errors, and security threats.

## Features

- **Time-Period Analysis**
  - Summary views for **Total**, **Current Month**, and **Last Month**.
  - Flexible filtering via CLI flags.
- **Multi-Log Support** — automatically detects and processes `access.log` and `error.log` files, including compressed `.gz` and `.bz2` archives.
- **VHost Awareness** — supports the standard Combined Log Format as well as `other_vhosts_access.log` with `vhost:port` prefixes.
- **Traffic Statistics**
  - Total requests and unique visitor counts.
  - Bandwidth usage (auto-scaled B / KB / MB / GB).
  - Average visitor session duration.
  - HTTP status code distribution (2xx, 3xx, 4xx, 5xx).
- **Download Tracking**
  - Identifies downloads by common file extensions (`.zip`, `.pdf`, `.exe`, `.dmg`, etc.) and `/download` URL patterns.
  - Separates successful downloads (**DL OK**) from failed attempts (**DL Err**).
- **Error Analysis**
  - Total error count and distribution by severity level (`error`, `crit`, `alert`, `emerg`).
  - Top unique error messages.
- **Threat Detection (Bad Actors)**
  - Scores IPs generating `403`/`401`/`400` responses.
  - Scores IPs targeting sensitive paths (`.env`, `xmlrpc.php`, `wp-admin`, `cgi-bin`, `.git`, etc.).
  - Flags IPs triggering critical errors or ModSecurity rules.
  - Provides ready-to-use `sudo ufw` ban commands.
- **Terminal Visualization** — uses standard ANSI escape codes for clean, color-coded table output (works on Linux, macOS, and Windows 10+).

## Requirements

- **Python 3.7+** (uses `dataclasses`; no third-party dependencies)
- **Apache HTTP Server Logs** — standard `access.log` and `error.log` files (plain text or `.gz`/`.bz2` compressed)

## Project Structure

```
├── main.py              # CLI entry point and LogAnalyzer class
├── helpers.py           # Utility functions, constants, and ANSI helpers
├── tests/
│   ├── test_main.py     # Unit tests for helpers and LogAnalyzer
│   └── mock_logs/       # Sample log files used by tests
│       ├── access.log
│       └── error.log
├── apache log files/    # Example Apache log directory (sample data)
├── README.md
└── LICENSE
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/gaboreszaki/Apache-Log-Analitics
   cd Apache-Log-Analitics
   ```

2. **No additional installation required** — the tool uses only the Python standard library.

## Quick Start

Run with default settings (shows **Current Month** summary and **Bad Actors**):
```bash
python main.py "/path/to/your/apache/logs"
```

Show a full detailed report:
```bash
python main.py "/path/to/your/apache/logs" -f
```

Show CLI help:
```bash
python main.py -h
```

On Linux, reading system logs typically requires elevated privileges:
```bash
sudo python3 main.py /var/log/apache2
```

On Windows:
```powershell
python main.py "C:\path\to\your\apache\logs"
```

## Usage

```
python main.py [path_to_logs] [flags]
```

If no path is provided, the tool looks for a local `apache log files` directory, then falls back to `/var/log/apache2` or `/var/logs/apache2`.

### Options

| Flag | Long Flag        | Description                                                  |
|------|------------------|--------------------------------------------------------------|
| `-f` | `--full`         | Display a detailed monthly breakdown report per domain.      |
| `-t` | `--total`        | Show the **Total** period summary.                           |
| `-c` | `--current`      | Show the **Current Month** summary.                          |
| `-l` | `--last`         | Show the **Last Month** summary.                             |
| `-b` | `--bad-actors`   | Explicitly show bad actors for the selected periods.         |
| `-h` | `--help`         | Show the help message and exit.                              |

> **Default behaviour:** When no period flags are provided, the tool shows the current month summary with bad actors.

### Examples

**Show current month summary (default):**
```bash
python main.py "./logs/"
```

**Show total summary without bad actors:**
```bash
python main.py "./logs/" -t
```

**Show total and last month summary with bad actors:**
```bash
python main.py "./logs/" -t -l -b
```

**Generate a detailed report for all periods:**
```bash
python main.py "./logs/" -f -t -c -l
```

## Helpers Module

The `helpers.py` module contains reusable utility functions and constants extracted from the main analyzer:

| Function / Constant            | Description                                                        |
|--------------------------------|--------------------------------------------------------------------|
| `parse_timestamp(ts_str)`      | Parse various Apache timestamp formats into `datetime` objects.    |
| `is_download(request)`         | Check if an HTTP request targets a downloadable file.              |
| `extract_path(request)`        | Extract the URL path from an HTTP request line.                    |
| `estimate_session_time(ts)`    | Estimate browsing session duration from a list of timestamps.      |
| `format_bandwidth(bytes)`      | Format byte counts into human-readable strings (KB/MB/GB).        |
| `open_log_file(path)`          | Open plain-text, `.gz`, or `.bz2` log files transparently.        |
| `is_sensitive_request(req)`    | Check if a request targets a known sensitive path.                 |
| `enable_windows_ansi()`        | Enable ANSI escape sequence support on Windows terminals.          |
| `DOWNLOAD_EXTENSIONS`          | Frozenset of file extensions considered as downloads.              |
| `SENSITIVE_PATHS`              | Tuple of path patterns indicating probing or attacks.              |
| `THREAT_SCORE_*`               | Named constants for threat scoring weights.                        |
| `SESSION_TIMEOUT_SECONDS`      | Session gap threshold (default: 1800s / 30 min).                   |

## Threat Scoring Logic

The analyzer calculates a **Threat Score** for each IP address:

| Trigger                                                    | Points |
|------------------------------------------------------------|--------|
| `403` (Forbidden), `401` (Unauthorized), or `400` (Bad Request) | **+1** |
| Request targeting sensitive paths (`.env`, `wp-admin`, etc.)     | **+2** |
| Critical error (`crit`/`alert`/`emerg`) or ModSecurity trigger   | **+5** |

The top 5 bad actors per period are displayed with their threat score and a ready-to-use UFW ban command.

## Running Tests

```bash
python -m unittest discover -s tests -v
```

All tests use mock log files in `tests/mock_logs/` and require no external dependencies.

## Output Preview

The tool produces structured tables with ANSI colors:

- **Cyan** — domain headers and table borders
- **Green** — totals and successful metrics
- **Yellow** — download errors and warnings
- **Red** — error counts, critical issues, and high threat scores
- **White** — IP addresses in the bad actors table

## Privacy & Data Handling

- This tool does **not** collect, store, transmit, or persist any data.
- No cookies, analytics, telemetry, or external services are used.
- All processing happens locally on the log files you provide.
- Log files are read in a streaming fashion; no databases or caches are created.

## GDPR Compliance

This application follows **Privacy by Design** principles:

- **Data Processing** — the tool processes Apache log files which may contain personal data (IP addresses).
- **Local Execution** — all processing occurs on the user's local machine. No data is transmitted externally.
- **No Persistence** — analysis results are held in volatile memory (RAM) and discarded when the process exits.
- **User Responsibility** — as the operator, you are the **Data Controller** for any logs you analyze. Ensure you have a legal basis for processing and handle output in accordance with GDPR requirements.
- **Data Integrity** — the tool never modifies the original log files.

## License

See [LICENSE](LICENSE) for details.
