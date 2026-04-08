"""
Apache Web Server Log Analyzer

A CLI tool for parsing and analyzing Apache HTTP Server access and error logs.
Provides traffic statistics, download tracking, error analysis, and threat detection.
"""

import re
import os
import argparse
import datetime
import sys
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

from helpers import (
    Fore, Style,
    SUSPICIOUS_STATUS_CODES, CRITICAL_LEVELS,
    THREAT_SCORE_STATUS, THREAT_SCORE_SENSITIVE_PATH, THREAT_SCORE_CRITICAL_ERROR,
    enable_windows_ansi, parse_timestamp, is_download, extract_path,
    estimate_session_time, format_bandwidth, open_log_file, is_sensitive_request,
)

# Enable ANSI colors on Windows
enable_windows_ansi()

# Regex to parse Apache Access Logs (Combined Log Format with optional vhost)
ACCESS_LOG_REGEX = re.compile(
    r'^(?:(?P<vhost>[^:\s]+):?(?P<port>\d+)?\s+)?'
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^]]+)]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Regex to parse Apache Error Logs
ERROR_LOG_REGEX = re.compile(
    r'^\[(?P<timestamp>[^]]+)]\s+'
    r'\[(?P<level>[^]]+)]\s+'
    r'(?:\[pid\s+(?P<pid>\d+)]\s+)?'
    r'(?:\[client\s+(?P<ip>[^: ]+):?(?P<port>\d+)?]\s+)?'
    r'(?P<message>.*)'
)

# Regex to extract hostname from error log messages
HOSTNAME_REGEX = re.compile(r'\[hostname "([^"]+)"]')

# Month abbreviations for report display
MONTH_NAMES = {
    1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun',
    7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec',
}

PERIODS = ('total', 'last_month', 'current_month')


@dataclass
class AccessStats:
    """Container for access log statistics per vhost and period."""
    requests: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    status_codes: Counter = field(default_factory=Counter)
    downloads: int = 0
    ips: Dict[str, Dict[str, Any]] = field(
        default_factory=lambda: defaultdict(
            lambda: {'count': 0, 'timestamps': [], 'ua': set()}
        )
    )
    paths: Counter = field(default_factory=Counter)
    referrers: Counter = field(default_factory=Counter)
    total_size: int = 0
    download_success_paths: Counter = field(default_factory=Counter)
    download_error_paths: Counter = field(default_factory=Counter)
    vhost_requests: Counter = field(default_factory=Counter)


@dataclass
class ErrorStats:
    """Container for error log statistics per vhost and period."""
    errors: int = 0
    levels: Counter = field(default_factory=Counter)
    messages: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)


class LogAnalyzer:
    """
    Parses and analyzes Apache access and error logs.

    Supports filtering by time periods (total, last month, current month)
    and identifies potentially malicious IP addresses.
    """

    def __init__(self, log_path: str, now: Optional[datetime.datetime] = None):
        """
        Initialize the analyzer.

        :param log_path: Path to a file or directory containing Apache logs.
        :param now: Reference date for period calculations (defaults to now).
        """
        self.log_path = log_path
        self.now = now or datetime.datetime.now()
        self.current_month = (self.now.year, self.now.month)

        first_of_current = self.now.replace(day=1)
        last_day_prev = first_of_current - datetime.timedelta(days=1)
        self.last_month = (last_day_prev.year, last_day_prev.month)

        # Period-level data: period -> vhost -> Stats
        self.access_data: Dict[str, Dict[str, AccessStats]] = {
            p: defaultdict(AccessStats) for p in PERIODS
        }
        self.error_data: Dict[str, Dict[str, ErrorStats]] = {
            p: defaultdict(ErrorStats) for p in PERIODS
        }
        self.bad_actors: Dict[str, Counter] = {p: Counter() for p in PERIODS}

        # Monthly granular data: (year, month) -> vhost -> Stats
        self.monthly_access: Dict[tuple, Dict[str, AccessStats]] = defaultdict(
            lambda: defaultdict(AccessStats)
        )
        self.monthly_errors: Dict[tuple, Dict[str, ErrorStats]] = defaultdict(
            lambda: defaultdict(ErrorStats)
        )
        self.monthly_bad_actors: Dict[tuple, Dict[str, Counter]] = defaultdict(
            lambda: defaultdict(Counter)
        )

    # ------------------------------------------------------------------
    # Helpers delegated to helpers module (kept as methods for backward compat)
    # ------------------------------------------------------------------

    @staticmethod
    def parse_timestamp(ts_str: str) -> Optional[datetime.datetime]:
        """Parse an Apache timestamp string. Delegates to helpers."""
        return parse_timestamp(ts_str)

    @staticmethod
    def is_download(request: str) -> bool:
        """Check if a request is a file download. Delegates to helpers."""
        return is_download(request)

    @staticmethod
    def estimate_time(timestamps: List[datetime.datetime]) -> float:
        """Estimate session time from timestamps. Delegates to helpers."""
        return estimate_session_time(timestamps)

    # ------------------------------------------------------------------
    # File discovery and dispatch
    # ------------------------------------------------------------------

    def process_files(self) -> None:
        """Walk the log path and process all identified Apache log files."""
        if not os.path.exists(self.log_path):
            print(f"Error: Path {self.log_path} does not exist.", file=sys.stderr)
            return

        files: List[str] = []
        if os.path.isfile(self.log_path):
            files.append(self.log_path)
        else:
            try:
                for name in os.listdir(self.log_path):
                    full = os.path.join(self.log_path, name)
                    if os.path.isfile(full):
                        files.append(full)
            except PermissionError:
                print(
                    f"Error: Permission denied when accessing {self.log_path}",
                    file=sys.stderr,
                )
                return

        for file_path in files:
            basename = os.path.basename(file_path).lower()
            if 'access' in basename:
                self.process_access_log(file_path)
            elif 'error' in basename:
                self.process_error_log(file_path)

    # ------------------------------------------------------------------
    # Access log processing
    # ------------------------------------------------------------------

    def process_access_log(self, file_path: str) -> None:
        """Process an entire access log file line by line."""
        try:
            with open_log_file(file_path) as fh:
                for line in fh:
                    self.process_access_log_line(line)
        except Exception as exc:
            print(f"Error processing access log {file_path}: {exc}", file=sys.stderr)

    def process_access_log_line(self, line: str) -> None:
        """Parse a single access log line and update all statistics."""
        match = ACCESS_LOG_REGEX.match(line)
        if not match:
            return

        data = match.groupdict()
        vhost = data.get('vhost') or 'default'
        ip = data['ip']
        timestamp = parse_timestamp(data['timestamp'])
        request = data['request']
        status = data['status']

        try:
            raw_size = data['size']
            size = int(raw_size) if raw_size and raw_size != '-' else 0
        except (ValueError, TypeError):
            size = 0

        path = extract_path(request)
        is_dl = is_download(request)
        is_sensitive = is_sensitive_request(request)

        # Determine relevant aggregate periods
        relevant_periods = ['total']
        if timestamp:
            month_key = (timestamp.year, timestamp.month)
            if month_key == self.current_month:
                relevant_periods.append('current_month')
            elif month_key == self.last_month:
                relevant_periods.append('last_month')

        # Compute threat score for this line
        threat_score = 0
        if status in SUSPICIOUS_STATUS_CODES and ip:
            threat_score += THREAT_SCORE_STATUS
        if is_sensitive:
            threat_score += THREAT_SCORE_SENSITIVE_PATH

        # Update period-level stats
        for period in relevant_periods:
            self._update_access_stats(
                self.access_data[period][vhost],
                ip, timestamp, status, size, path, data['referrer'],
                data['user_agent'], is_dl,
            )
            if threat_score:
                self.bad_actors[period][ip] += threat_score

        # Update monthly granular stats
        if timestamp:
            month_key = (timestamp.year, timestamp.month)
            self._update_access_stats(
                self.monthly_access[month_key][vhost],
                ip, timestamp, status, size, path, data['referrer'],
                data['user_agent'], is_dl,
            )
            if threat_score:
                self.monthly_bad_actors[month_key][vhost][ip] += threat_score

    @staticmethod
    def _update_access_stats(
        stats: AccessStats,
        ip: str,
        timestamp: Optional[datetime.datetime],
        status: str,
        size: int,
        path: str,
        referrer: str,
        user_agent: str,
        is_dl: bool,
    ) -> None:
        """Apply a single parsed access log entry to an AccessStats object."""
        stats.requests += 1
        stats.unique_ips.add(ip)
        stats.status_codes[status] += 1
        stats.total_size += size
        stats.paths[path] += 1
        stats.referrers[referrer] += 1

        ip_info = stats.ips[ip]
        ip_info['count'] += 1
        if timestamp:
            ip_info['timestamps'].append(timestamp)
        ip_info['ua'].add(user_agent)

        if is_dl:
            stats.downloads += 1
            path_only = path.split('?')[0]
            if status.startswith('2'):
                stats.download_success_paths[path_only] += 1
            elif status.startswith('4') or status.startswith('5'):
                stats.download_error_paths[path_only] += 1

    # ------------------------------------------------------------------
    # Error log processing
    # ------------------------------------------------------------------

    def process_error_log(self, file_path: str) -> None:
        """Process an entire error log file line by line."""
        try:
            with open_log_file(file_path) as fh:
                for line in fh:
                    self.process_error_log_line(line)
        except Exception as exc:
            print(f"Error processing error log {file_path}: {exc}", file=sys.stderr)

    def process_error_log_line(self, line: str) -> None:
        """Parse a single error log line and update all statistics."""
        match = ERROR_LOG_REGEX.match(line)
        if not match:
            return

        data = match.groupdict()
        vhost = 'default'
        hostname_match = HOSTNAME_REGEX.search(data['message'])
        if hostname_match:
            vhost = hostname_match.group(1)

        timestamp = parse_timestamp(data['timestamp'])
        month_key = (timestamp.year, timestamp.month) if timestamp else None

        relevant_periods = ['total']
        if month_key:
            if month_key == self.current_month:
                relevant_periods.append('current_month')
            elif month_key == self.last_month:
                relevant_periods.append('last_month')

        ip = data.get('ip')
        level = data['level']
        message = data['message']

        # Compute threat score
        threat_score = 0
        if ip and (level in CRITICAL_LEVELS or 'ModSecurity' in message):
            threat_score = THREAT_SCORE_CRITICAL_ERROR

        for period in relevant_periods:
            self._update_error_stats(self.error_data[period][vhost], level, message, ip)
            if threat_score and ip:
                self.bad_actors[period][ip] += threat_score

        if timestamp:
            mk = (timestamp.year, timestamp.month)
            self._update_error_stats(self.monthly_errors[mk][vhost], level, message, ip)
            if threat_score and ip:
                self.monthly_bad_actors[mk][vhost][ip] += threat_score

    @staticmethod
    def _update_error_stats(
        stats: ErrorStats, level: str, message: str, ip: Optional[str]
    ) -> None:
        """Apply a single parsed error log entry to an ErrorStats object."""
        stats.errors += 1
        stats.levels[level] += 1
        truncated = message.split('] ')[-1] if ']' in message else message
        stats.messages[truncated[:100]] += 1
        if ip:
            stats.ips[ip] += 1

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def get_summary(
        self,
        period_filter: Optional[List[str]] = None,
        show_bad_actors: bool = True,
    ) -> str:
        """Generate a compact tabular summary for the specified periods."""
        output: List[str] = []

        all_domains: Set[str] = set()
        for period in PERIODS:
            all_domains.update(self.access_data[period].keys())
            all_domains.update(self.error_data[period].keys())

        domains = sorted(all_domains)
        if not domains:
            return Fore.YELLOW + "No log data found." + Fore.RESET

        domain_width = max(min(max(len(d) for d in domains), 50), 15)
        periods_to_show = period_filter if period_filter else list(PERIODS)

        for period in periods_to_show:
            if period not in PERIODS:
                continue

            label = period.replace('_', ' ').upper()
            output.append(
                f"\n{Fore.CYAN}{Style.BRIGHT}[ {label} SUMMARY ]{Style.RESET_ALL}"
            )

            header = (
                f"| {'Domain':<{domain_width}} | {'Visitors':<10} | {'Requests':<10} "
                f"| {'DL OK':<7} | {'DL Err':<7} | {'Avg Time':<10} | {'Errors':<10} |"
            )
            border = "-" * len(header)

            output.append(Fore.CYAN + border + Fore.RESET)
            output.append(Fore.CYAN + header + Fore.RESET)
            output.append(Fore.CYAN + border + Fore.RESET)

            has_data = False
            for domain in domains:
                acc = self.access_data[period].get(domain, AccessStats())
                err = self.error_data[period].get(domain, ErrorStats())
                if not acc.requests and not err.errors:
                    continue

                has_data = True
                visitors = len(acc.unique_ips)
                dl_ok = sum(acc.download_success_paths.values())
                dl_err = sum(acc.download_error_paths.values())
                errors = err.errors

                all_times = [
                    estimate_session_time(ip_data['timestamps'])
                    for ip_data in acc.ips.values()
                    if ip_data.get('timestamps')
                ]
                avg_time = sum(all_times) / len(all_times) if all_times else 0.0
                avg_time_str = f"{avg_time / 60:.2f}m"

                d_display = domain[:domain_width]
                err_color = Fore.RED if errors > 0 else ""
                dl_err_color = Fore.YELLOW if dl_err > 0 else ""
                reset_c = Fore.CYAN
                line = (
                    f"| {d_display:<{domain_width}} | {visitors:<10} | {acc.requests:<10} "
                    f"| {dl_ok:<7} | {dl_err_color}{dl_err:<7}"
                    f"{reset_c if dl_err > 0 else ''} | {avg_time_str:<10} "
                    f"| {err_color}{errors:<10}{reset_c if errors > 0 else ''} |"
                )
                output.append(Fore.CYAN + line + Fore.RESET)

            if not has_data:
                remaining = len(header) - 4
                output.append(
                    Fore.CYAN + f"| {'No data for this period':<{remaining}} |" + Fore.RESET
                )

            output.append(Fore.CYAN + border + Fore.RESET)

            if show_bad_actors and self.bad_actors[period]:
                output.append(
                    f"\n{Fore.YELLOW}| {'Top Bad Actors (IP) - ' + label:<30} "
                    f"| {'Threat Score':<12} | {'UFW Permanent Ban Command':<48} |{Fore.RESET}"
                )
                bad_border = "-" * 100
                output.append(Fore.YELLOW + bad_border + Fore.RESET)
                for ip, score in self.bad_actors[period].most_common(5):
                    ban_cmd = f"sudo ufw insert 1 deny from {ip}"
                    output.append(
                        f"{Fore.YELLOW}| {Fore.WHITE}{ip:<30} {Fore.YELLOW}"
                        f"| {Fore.RED}{score:<12} {Fore.YELLOW}"
                        f"| {Fore.CYAN}{ban_cmd:<48} {Fore.YELLOW}|{Fore.RESET}"
                    )
                output.append(Fore.YELLOW + bad_border + Fore.RESET)
                output.append(
                    f"{Fore.YELLOW}Note: Don't forget to reload the firewall to apply "
                    f"changes: {Fore.CYAN}sudo ufw reload{Fore.RESET}"
                )

        return "\n".join(output)

    def get_full_report(self, period_filter: Optional[List[str]] = None) -> str:
        """Generate a detailed monthly breakdown report per domain with totals."""
        output: List[str] = []

        all_domains: Set[str] = set()
        all_months: Set[tuple] = set()
        for mk in self.monthly_access:
            all_months.add(mk)
            all_domains.update(self.monthly_access[mk].keys())
        for mk in self.monthly_errors:
            all_months.add(mk)
            all_domains.update(self.monthly_errors[mk].keys())

        domains = sorted(all_domains)
        months = sorted(all_months)

        if not domains:
            return Fore.YELLOW + "No log data found." + Fore.RESET

        # Filter months by period if specified
        if period_filter:
            allowed: Set[tuple] = set()
            for p in period_filter:
                if p == 'total':
                    allowed = set(months)
                    break
                elif p == 'current_month':
                    allowed.add(self.current_month)
                elif p == 'last_month':
                    allowed.add(self.last_month)
            if allowed:
                months = sorted(m for m in months if m in allowed)

        # Grand totals
        grand = {
            'visitors': set(), 'requests': 0,
            'dl_ok': 0, 'dl_fail': 0, 'errors': 0, 'criticals': 0,
            'warnings': 0, 'infos': 0, 'bad_actors': set(), 'attacks': 0,
            'total_size': 0, 'avg_times': [],
            'status_2xx': 0, 'status_3xx': 0, 'status_4xx': 0, 'status_5xx': 0,
        }

        for domain in domains:
            output.append(
                f"\n{Fore.CYAN}{Style.BRIGHT}[ {domain.upper()} ]{Style.RESET_ALL}"
            )

            header = (
                f"| {'Month':<10} | {'Visitors':>8} | {'Requests':>8} "
                f"| {'2xx':>5} | {'3xx':>5} | {'4xx':>5} | {'5xx':>5} "
                f"| {'Avg Time':>8} | {'Bandwidth':>10} | {'DL OK':>6} | {'DL Fail':>7} "
                f"| {'Errors':>6} | {'Criticals':>9} | {'Warnings':>8} | {'Info':>5} "
                f"| {'Bad IPs':>7} | {'Attacks':>7} |"
            )
            border = "-" * len(header)

            output.append(Fore.CYAN + border + Fore.RESET)
            output.append(Fore.CYAN + header + Fore.RESET)
            output.append(Fore.CYAN + border + Fore.RESET)

            domain_has_data = False
            dt = {
                'visitors': set(), 'requests': 0,
                '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0,
                'times': [], 'size': 0,
                'dl_ok': 0, 'dl_fail': 0,
                'errors': 0, 'criticals': 0, 'warnings': 0, 'infos': 0,
                'bad_ips': set(), 'attacks': 0,
            }

            for mk in months:
                acc = self.monthly_access.get(mk, {}).get(domain, AccessStats())
                err = self.monthly_errors.get(mk, {}).get(domain, ErrorStats())
                ba = self.monthly_bad_actors.get(mk, {}).get(domain, Counter())

                if not acc.requests and not err.errors:
                    continue
                domain_has_data = True

                row = self._compute_report_row(acc, err, ba)
                month_label = f"{MONTH_NAMES[mk[1]]} {mk[0]}"
                output.append(
                    Fore.CYAN + self._format_report_row(month_label, row) + Fore.RESET
                )

                # Accumulate domain totals
                dt['visitors'].update(acc.unique_ips)
                dt['requests'] += row['requests']
                dt['2xx'] += row['s2xx']; dt['3xx'] += row['s3xx']
                dt['4xx'] += row['s4xx']; dt['5xx'] += row['s5xx']
                dt['times'].extend(row['all_times'])
                dt['size'] += row['bw']
                dt['dl_ok'] += row['dl_ok']; dt['dl_fail'] += row['dl_fail']
                dt['errors'] += row['errors']; dt['criticals'] += row['criticals']
                dt['warnings'] += row['warnings']; dt['infos'] += row['infos']
                dt['bad_ips'].update(ba.keys()); dt['attacks'] += row['attacks']

                # Accumulate grand totals
                grand['visitors'].update(acc.unique_ips)
                grand['requests'] += row['requests']
                grand['dl_ok'] += row['dl_ok']; grand['dl_fail'] += row['dl_fail']
                grand['errors'] += row['errors']; grand['criticals'] += row['criticals']
                grand['warnings'] += row['warnings']; grand['infos'] += row['infos']
                grand['bad_actors'].update(ba.keys()); grand['attacks'] += row['attacks']
                grand['total_size'] += row['bw']
                grand['avg_times'].extend(row['all_times'])
                grand['status_2xx'] += row['s2xx']; grand['status_3xx'] += row['s3xx']
                grand['status_4xx'] += row['s4xx']; grand['status_5xx'] += row['s5xx']

            if not domain_has_data:
                remaining = len(header) - 4
                output.append(
                    Fore.CYAN + f"| {'No data':<{remaining}} |" + Fore.RESET
                )
            else:
                output.append(Fore.CYAN + border + Fore.RESET)
                total_row = self._build_total_row(dt)
                output.append(
                    Fore.GREEN + self._format_report_row('TOTAL', total_row) + Fore.RESET
                )

            output.append(Fore.CYAN + border + Fore.RESET)

        # Grand Totals Table
        output.append(
            f"\n{Fore.GREEN}{Style.BRIGHT}"
            f"[ GRAND TOTALS — ALL DOMAINS, ALL PERIODS ]{Style.RESET_ALL}"
        )
        output.extend(self._format_grand_totals(grand))

        return "\n".join(output)

    # ------------------------------------------------------------------
    # Report helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_report_row(
        acc: AccessStats, err: ErrorStats, ba: Counter
    ) -> Dict[str, Any]:
        """Compute a single row of metrics from access/error/bad-actor data."""
        s2xx = sum(v for k, v in acc.status_codes.items() if k.startswith('2'))
        s3xx = sum(v for k, v in acc.status_codes.items() if k.startswith('3'))
        s4xx = sum(v for k, v in acc.status_codes.items() if k.startswith('4'))
        s5xx = sum(v for k, v in acc.status_codes.items() if k.startswith('5'))

        all_times = [
            estimate_session_time(ip_data['timestamps'])
            for ip_data in acc.ips.values()
            if ip_data.get('timestamps')
        ]
        avg_time = sum(all_times) / len(all_times) if all_times else 0.0

        return {
            'visitors': len(acc.unique_ips),
            'requests': acc.requests,
            's2xx': s2xx, 's3xx': s3xx, 's4xx': s4xx, 's5xx': s5xx,
            'avg_time': avg_time,
            'bw': acc.total_size,
            'dl_ok': sum(acc.download_success_paths.values()),
            'dl_fail': sum(acc.download_error_paths.values()),
            'errors': err.errors,
            'criticals': (
                err.levels.get('crit', 0)
                + err.levels.get('alert', 0)
                + err.levels.get('emerg', 0)
            ),
            'warnings': err.levels.get('warn', 0),
            'infos': err.levels.get('info', 0) + err.levels.get('notice', 0),
            'bad_ips': len(ba),
            'attacks': sum(ba.values()),
            'all_times': all_times,
        }

    @staticmethod
    def _build_total_row(dt: Dict[str, Any]) -> Dict[str, Any]:
        """Build a total-row dict from accumulated domain totals."""
        avg = sum(dt['times']) / len(dt['times']) if dt['times'] else 0.0
        return {
            'visitors': len(dt['visitors']),
            'requests': dt['requests'],
            's2xx': dt['2xx'], 's3xx': dt['3xx'],
            's4xx': dt['4xx'], 's5xx': dt['5xx'],
            'avg_time': avg,
            'bw': dt['size'],
            'dl_ok': dt['dl_ok'], 'dl_fail': dt['dl_fail'],
            'errors': dt['errors'], 'criticals': dt['criticals'],
            'warnings': dt['warnings'], 'infos': dt['infos'],
            'bad_ips': len(dt['bad_ips']), 'attacks': dt['attacks'],
            'all_times': dt['times'],
        }

    @staticmethod
    def _format_report_row(label: str, row: Dict[str, Any]) -> str:
        """Format a single report table row."""
        avg_str = f"{row['avg_time'] / 60:.1f}m"
        bw_str = format_bandwidth(row['bw'])

        err_color = Fore.RED if row['errors'] > 0 else ''
        crit_color = Fore.RED if row['criticals'] > 0 else ''
        dl_f_color = Fore.YELLOW if row['dl_fail'] > 0 else ''
        ba_color = Fore.RED if row['bad_ips'] > 0 else ''
        reset = Fore.CYAN

        return (
            f"| {label:<10} | {row['visitors']:>8} | {row['requests']:>8} "
            f"| {row['s2xx']:>5} | {row['s3xx']:>5} | {row['s4xx']:>5} | {row['s5xx']:>5} "
            f"| {avg_str:>8} | {bw_str:>10} "
            f"| {row['dl_ok']:>6} | {dl_f_color}{row['dl_fail']:>7}{reset if row['dl_fail'] > 0 else ''} "
            f"| {err_color}{row['errors']:>6}{reset if row['errors'] > 0 else ''} "
            f"| {crit_color}{row['criticals']:>9}{reset if row['criticals'] > 0 else ''} "
            f"| {row['warnings']:>8} | {row['infos']:>5} "
            f"| {ba_color}{row['bad_ips']:>7}{reset if row['bad_ips'] > 0 else ''} "
            f"| {row['attacks']:>7} |"
        )

    @staticmethod
    def _format_grand_totals(grand: Dict[str, Any]) -> List[str]:
        """Format the grand totals table."""
        lines: List[str] = []
        avg_times = grand['avg_times']
        avg = sum(avg_times) / len(avg_times) if avg_times else 0.0

        rows = [
            ('Unique Visitors', str(len(grand['visitors']))),
            ('Total Requests', str(grand['requests'])),
            ('Successful (2xx)', str(grand['status_2xx'])),
            ('Redirects (3xx)', str(grand['status_3xx'])),
            ('Client Errors (4xx)', str(grand['status_4xx'])),
            ('Server Errors (5xx)', str(grand['status_5xx'])),
            ('Avg Session Time', f"{avg / 60:.1f} min"),
            ('Total Bandwidth', format_bandwidth(grand['total_size'])),
            ('Downloads OK', str(grand['dl_ok'])),
            ('Downloads Failed', str(grand['dl_fail'])),
            ('Error Log Entries', str(grand['errors'])),
            ('Critical/Alert/Emerg', str(grand['criticals'])),
            ('Warnings', str(grand['warnings'])),
            ('Info/Notice', str(grand['infos'])),
            ('Bad Actor IPs', str(len(grand['bad_actors']))),
            ('Total Attack Score', str(grand['attacks'])),
        ]

        t_header = f"| {'Metric':<25} | {'Value':>15} |"
        t_border = "-" * len(t_header)
        lines.append(Fore.GREEN + t_border + Fore.RESET)
        lines.append(Fore.GREEN + t_header + Fore.RESET)
        lines.append(Fore.GREEN + t_border + Fore.RESET)
        for label, val in rows:
            lines.append(Fore.GREEN + f"| {label:<25} | {val:>15} |" + Fore.RESET)
        lines.append(Fore.GREEN + t_border + Fore.RESET)
        return lines


def main() -> None:
    """CLI entry point for the Apache Log Analyzer."""
    parser = argparse.ArgumentParser(description="Apache Web Server Log Analyzer")
    parser.add_argument(
        "path", nargs="?", default="apache log files",
        help="Path to log directory or file",
    )
    parser.add_argument(
        "-f", "--full", action="store_true",
        help="Display detailed report instead of summary",
    )
    parser.add_argument("-t", "--total", action="store_true", help="Show total summary")
    parser.add_argument(
        "-c", "--current", action="store_true", help="Show current month summary",
    )
    parser.add_argument(
        "-l", "--last", action="store_true", help="Show last month summary",
    )
    parser.add_argument(
        "-b", "--bad-actors", action="store_true",
        help="Show bad actors for selected periods",
    )

    args = parser.parse_args()

    log_path = args.path
    if log_path == "apache log files" and not os.path.exists(log_path):
        for candidate in ("/var/log/apache2", "/var/logs/apache2"):
            if os.path.exists(candidate):
                log_path = candidate
                break

    if not os.path.exists(log_path):
        print(
            f"Error: Log directory or file not found at: {log_path}", file=sys.stderr
        )
        sys.exit(1)

    analyzer = LogAnalyzer(log_path)
    analyzer.process_files()

    period_filter: List[str] = []
    if args.total:
        period_filter.append('total')
    if args.current:
        period_filter.append('current_month')
    if args.last:
        period_filter.append('last_month')

    # Default: show current month with bad actors when no flags given
    if not any([args.total, args.current, args.last, args.bad_actors]):
        period_filter = ['current_month']
        show_bad_actors = True
    else:
        if not period_filter and args.bad_actors:
            period_filter = ['current_month']
        show_bad_actors = args.bad_actors

    if args.full:
        full_period = period_filter if any([args.total, args.current, args.last]) else None
        print(analyzer.get_full_report(period_filter=full_period))
    else:
        print(analyzer.get_summary(period_filter=period_filter, show_bad_actors=show_bad_actors))


if __name__ == "__main__":
    main()
