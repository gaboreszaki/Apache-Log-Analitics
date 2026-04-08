# Apache Web Server Log Analyzer

A powerful CLI-based tool designed to parse and analyze Apache HTTP Server logs (access and error logs). It provides a structured, colorized report of web traffic, downloads, errors, and security threats.

## Features

- **Time-Period Analysis**: 
  - Summary views for **Total**, **Current Month**, and **Last Month**.
  - Flexible filtering using CLI arguments.
- **Multi-Log Support**: Automatically detects and processes `access.log` and `error.log` files, including compressed `.gz` archives.
- **VHost Awareness**: Supports standard Apache log formats and "other_vhosts_access.log" with vhost:port prefixes.
- **Traffic Statistics**: 
  - Total requests and unique visitor counts.
  - Data transfer (MB) and average visitor stay duration.
  - HTTP status code distribution (2xx, 3xx, 4xx, 5xx).
  - Top 5 requested paths and referrers.
- **Download Tracking**: 
  - Identifies downloads based on common file extensions (`.zip`, `.pdf`, `.exe`, etc.).
  - Separates successful downloads (`DL OK`) from failed attempts (`DL Err`).
- **Error Analysis**: 
  - Total error count and distribution by severity level (error, crit, alert, etc.).
  - Top 5 unique error messages.
- **Threat Detection (Bad Actors)**: 
  - Identifies potentially malicious IPs based on 403/401/400 errors.
  - Scores IPs targeting sensitive files (e.g., `.env`, `xmlrpc.php`, `wp-admin`, `cgi-bin`, `.git`).
  - Flags IPs triggering critical ModSecurity or Apache errors.
  - Provides `sudo ufw` ban commands for identified bad actors.
- **Terminal Visualization**: Uses standard ANSI escape codes for a clean, color-coded table output.

## Requirements

- **Python 3.6+**
- **Apache HTTP Server Logs**: Standard `access.log` and `error.log` (including compressed `.gz` archives).

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/gaboreszaki/Apache-Log-Analitics
   cd Apache-Log-Analitics
   ```

### Quick Start

- Run with default settings (shows **Current Month** summary and **Bad Actors**):
  ```bash
  python main.py "/path/to/your/apache/logs"
  ```
- Show a full detailed report for the current month:
  ```bash
  python main.py "/path/to/your/apache/logs" -f
  ```
- Show CLI help:
  ```bash
  python main.py -h
  ```
- On Windows, you can also use:
  ```powershell
  python main.py "C:\path\to\your\apache\logs"
  ```

## Usage

Run the script by providing the path to a directory containing Apache logs or a specific log file. If no arguments are provided, it defaults to the **Current Month** summary and includes the **Top Bad Actors**.

```bash
python main.py [path_to_logs] [flags]
```

### Options

| Flag | Long Flag | Description |
|------|-----------|-------------|
| `-f` | `--full` | Displays a detailed report with full statistics for each domain. |
| `-t` | `--total` | Show **Total** period summary. |
| `-c` | `--current` | Show **Current Month** summary. |
| `-l` | `--last` | Show **Last Month** summary. |
| `-b` | `--bad-actors` | Explicitly show bad actors for the selected periods. |
| `-h` | `--help` | Show the help message and exit. |

*Note: If no period flags (`-t`, `-c`, `-l`) are provided, the tool defaults to the current month.*

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

## Threat Scoring Logic

The analyzer calculates a "Threat Score" for IP addresses to help identify bad actors:
- **+1 Point**: For each 403 (Forbidden), 401 (Unauthorized), or 400 (Bad Request).
- **+2 Points**: For requests targeting sensitive paths like `.env`, `wp-admin`, `cgi-bin`, or `.git`.
- **+5 Points**: For IPs generating critical system errors (crit, alert, emerg) or triggering ModSecurity rules.

## Output Preview

The tool produces structured tables with colors:
- **Cyan**: Domain headers and table structures.
- **Green**: Successful requests and access statistics.
- **Yellow**: Status codes (3xx) and visitor stay warnings.
- **Red**: Error statistics, failed downloads, and high-threat scores.

## Privacy & Data Handling

- This CLI tool does not collect, store, transmit, or persist any data.
- No cookies, analytics, telemetry, or external services are used.
- All processing happens locally on the log files you provide.
- The tool reads log files in a streaming manner and does not create databases or cache user data.

## GDPR Compliance

This application is designed with **Privacy by Design** principles to assist users in staying GDPR compliant when analyzing web server logs.

- **Data Processing**: The tool processes Apache log files, which may contain **Personal Data** such as IP addresses.
- **Local Execution**: All processing occurs strictly on the user's local machine. No data is ever transmitted to external servers, APIs, or third-party services.
- **No Persistence**: The application does not store, save, or cache any personal data extracted from the logs. All analysis results are stored in volatile memory (RAM) and are cleared once the process terminates.
- **User Responsibility**: As the operator of the tool, you are the **Data Controller** for any logs you analyze. You should ensure that you have a legal basis for processing the log data and that you handle the output (e.g., terminal screens or redirected output files) in accordance with GDPR requirements.
- **Security**: The tool does not modify the original log files, ensuring data integrity is maintained.

---
*Note: If no path is provided, the script attempts to look for logs in common Linux locations like `/var/log/apache2/`.*
