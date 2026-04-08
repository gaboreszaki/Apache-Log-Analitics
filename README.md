# Apache Web Server Log Analyzer

A powerful CLI-based tool designed to parse and analyze Apache HTTP Server logs (access and error logs). It provides a structured, colorized report of web traffic, downloads, errors, and security threats.

## Features

- **Multi-Log Support**: Automatically detects and processes `access.log` and `error.log` files, including compressed `.gz` archives.
- **VHost Awareness**: Supports standard Apache log formats and "other_vhosts_access.log" with vhost:port prefixes.
- **Traffic Statistics**: 
  - Total requests and unique visitor counts.
  - Data transfer (MB) and average visitor stay duration.
  - HTTP status code distribution (2xx, 3xx, 4xx, 5xx).
  - Top 5 requested paths and referrers.
- **Download Tracking**: 
  - Identifies downloads based on common file extensions (`.zip`, `.pdf`, `.exe`, etc.).
  - Separates successful downloads (2xx) from failed attempts (4xx/5xx).
- **Error Analysis**: 
  - Total error count and distribution by severity level (error, crit, alert, etc.).
  - Top 5 unique error messages.
- **Threat Detection (Bad Actors)**: 
  - Identifies potentially malicious IPs based on 403/401/400 errors.
  - Scores IPs targeting sensitive files (e.g., `.env`, `xmlrpc.php`, `.git`).
  - Flags IPs triggering critical ModSecurity or Apache errors.
- **Terminal Visualization**: Uses `colorama` for a clean, color-coded table output.

## Requirements

- **Python 3.6+**
- **Apache HTTP Server Logs**: Standard `access.log` and `error.log` (including compressed `.gz` archives).
- **Dependencies**: `colorama` (for terminal visualization).

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd CLI-Appache-log-analitics
   ```

2. **Install dependencies**:
   This tool requires `colorama` for colorized terminal output.
   ```bash
   pip install colorama
   ```

## Usage

Run the script by providing the path to a directory containing Apache logs or a specific log file.

```bash
python main.py [path_to_logs] [flags]
```

### Options

| Flag | Long Flag | Description |
|------|-----------|-------------|
| `-s` | `--summary` | (Default) Displays a compact summary table of all domains. |
| `-f` | `--full` | Displays a detailed report with full statistics for each domain. |
| `-h` | `--help` | Show the help message and exit. |

### Examples

**Analyze logs in a specific directory (default summary):**
```bash
python main.py "./logs/"
```

**Generate a detailed report:**
```bash
python main.py "./logs/" -f
```

**Analyze a single file:**
```bash
python main.py "/var/log/apache2/access.log"
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

---
*Note: If no path is provided, the script attempts to look for logs in common Linux locations like `/var/log/apache2/`.*
