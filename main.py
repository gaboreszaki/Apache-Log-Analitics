import re
import os
import gzip
import argparse
import datetime
import sys
import subprocess
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any, Set, cast
from dataclasses import dataclass, field

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

if sys.platform == "win32":
    # Initialize Windows terminal to support ANSI escape sequences
    subprocess.run("", shell=True)

# Regex to parse Apache Access Logs (Combined Log Format with optional vhost)
ACCESS_LOG_REGEX = re.compile(
    r'^(?:(?P<vhost>[^:\s]+):?(?P<port>\d+)?\s+)?(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^]]+)]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Regex to parse Apache Error Logs
ERROR_LOG_REGEX = re.compile(
    r'^\[(?P<timestamp>[^]]+)]\s+\[(?P<level>[^]]+)]\s+(?:\[pid\s+(?P<pid>\d+)]\s+)?(?:\[client\s+(?P<ip>[^: ]+):?(?P<port>\d+)?]\s+)?(?P<message>.*)'
)

# Common file extensions for downloads to track
DOWNLOAD_EXTENSIONS = {'.zip', '.pdf', '.exe', '.dmg', '.tar', '.gz', '.tgz', '.rar', '.7z', '.iso', '.msi'}

@dataclass
class AccessStats:
    """Container for access log statistics per vhost and period."""
    requests: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    status_codes: Counter = field(default_factory=Counter)
    downloads: int = 0
    # Detailed IP mapping: count, timestamps, and user agents
    ips: Dict[str, Dict[str, Any]] = field(default_factory=lambda: defaultdict(lambda: {'count': 0, 'timestamps': [], 'ua': set()}))
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
    Main class for processing Apache access and error logs.
    Supports filtering by periods (total, last month, current month)
    and identifying potentially malicious actors.
    """
    def __init__(self, log_path: str, now: Optional[datetime.datetime] = None):
        """
        Initialize the analyzer with a path to logs and a reference date.
        
        :param log_path: Path to a file or directory containing Apache logs.
        :param now: Optional reference date (useful for testing or re-analyzing past logs).
        """
        self.log_path = log_path
        
        self.now = now or datetime.datetime.now()
        self.current_month = (self.now.year, self.now.month)
        
        # Calculate the previous month period for filtering
        first_of_current = self.now.replace(day=1)
        last_day_of_last_month = first_of_current - datetime.timedelta(days=1)
        self.last_month = (last_day_of_last_month.year, last_day_of_last_month.month)

        self.periods = ['total', 'last_month', 'current_month']
        
        # Data storage structures: period -> vhost -> Stats
        self.access_data: Dict[str, Dict[str, AccessStats]] = {
            p: defaultdict(AccessStats) for p in self.periods
        }
        
        self.error_data: Dict[str, Dict[str, ErrorStats]] = {
            p: defaultdict(ErrorStats) for p in self.periods
        }
        
        # IP -> Threat Score
        self.bad_actors: Dict[str, Counter] = {p: Counter() for p in self.periods}

        # Monthly granular data: (year, month) -> vhost -> Stats
        self.monthly_access: Dict[tuple, Dict[str, AccessStats]] = defaultdict(lambda: defaultdict(AccessStats))
        self.monthly_errors: Dict[tuple, Dict[str, ErrorStats]] = defaultdict(lambda: defaultdict(ErrorStats))
        self.monthly_bad_actors: Dict[tuple, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))

    def parse_timestamp(self, ts_str: str) -> Optional[datetime.datetime]:
        """
        Attempts to parse various Apache timestamp formats.
        
        :param ts_str: Raw timestamp string from log file.
        :return: datetime object if successful, None otherwise.
        """
        ts_clean = ts_str.strip('[]')
        if ' ' in ts_clean and '/' in ts_clean:
             ts_clean = ts_clean.split(' ')[0]

        formats = [
            '%d/%b/%Y:%H:%M:%S',
            '%a %b %d %H:%M:%S.%f %Y',
            '%a %b %d %H:%M:%S %Y',
            '%b %d %H:%M:%S %Y',
        ]
        
        for fmt in formats:
            try:
                return datetime.datetime.strptime(ts_clean, fmt)
            except (ValueError, TypeError):
                continue
        return None

    def is_download(self, request: str) -> bool:
        """
        Heuristic to check if a request refers to a file download.
        
        :param request: HTTP request line (e.g. "GET /file.zip HTTP/1.1").
        """
        try:
            path = request.split(' ')[1] if ' ' in request else request
            ext = os.path.splitext(path.split('?')[0])[1].lower()
            return ext in DOWNLOAD_EXTENSIONS or '/download' in path.lower()
        except IndexError:
            return False

    def process_files(self) -> None:
        """Walks through the log path and processes all identified Apache log files."""
        if not os.path.exists(self.log_path):
            print(f"Error: Path {self.log_path} does not exist.", file=sys.stderr)
            return

        files = []
        if os.path.isfile(self.log_path):
            files.append(self.log_path)
        else:
            try:
                for f in os.listdir(self.log_path):
                    f_path = os.path.join(self.log_path, f)
                    if os.path.isfile(f_path):
                        files.append(f_path)
            except PermissionError:
                print(f"Error: Permission denied when accessing {self.log_path}", file=sys.stderr)
                return

        for file_path in files:
            name = os.path.basename(file_path).lower()
            # Basic file type identification by filename
            if 'access' in name:
                self.process_access_log(file_path)
            elif 'error' in name:
                self.process_error_log(file_path)

    def open_log(self, file_path: str):
        """Helper to open plain text or compressed log files."""
        if file_path.endswith('.gz'):
            return gzip.open(file_path, 'rt', errors='ignore')
        elif file_path.endswith('.bz2'):
            import bz2
            return bz2.open(file_path, 'rt', errors='ignore')
        return open(file_path, 'r', errors='ignore')

    def process_access_log(self, file_path: str) -> None:
        """Processes an entire access log file line by line."""
        try:
            with self.open_log(file_path) as f:
                for line in f:
                    self.process_access_log_line(line)
        except Exception as e:
            print(f"Error processing access log {file_path}: {e}", file=sys.stderr)

    def process_access_log_line(self, line: str) -> None:
        """Parses a single access log line and updates statistics."""
        match = ACCESS_LOG_REGEX.match(line)
        if match:
            data = match.groupdict()
            vhost = data.get('vhost') or 'default'
            ip = data['ip']
            timestamp = self.parse_timestamp(data['timestamp'])
            request = data['request']
            status = data['status']
            try:
                size_val = data['size']
                size = int(size_val) if (size_val and size_val != '-') else 0
            except (ValueError, TypeError):
                size = 0

            # Determine which time periods this entry belongs to
            relevant_periods = ['total']
            if timestamp:
                if (timestamp.year, timestamp.month) == self.current_month:
                    relevant_periods.append('current_month')
                elif (timestamp.year, timestamp.month) == self.last_month:
                    relevant_periods.append('last_month')

            for p in relevant_periods:
                stats = self.access_data[p][vhost]
                stats.requests += 1
                stats.unique_ips.add(ip)
                stats.status_codes[status] += 1
                stats.total_size += size
                
                try:
                    path = request.split(' ')[1] if ' ' in request else request
                except IndexError:
                    path = request
                stats.paths[path] += 1
                stats.referrers[data['referrer']] += 1
                
                ip_stats = stats.ips[ip]
                ip_stats['count'] += 1
                if timestamp:
                    ip_stats['timestamps'].append(timestamp)
                ip_stats['ua'].add(data['user_agent'])

                if self.is_download(request):
                    stats.downloads += 1
                    try:
                        path_only = path.split('?')[0]
                        if status.startswith('2'):
                            stats.download_success_paths[path_only] += 1
                        elif status.startswith('4') or status.startswith('5'):
                            stats.download_error_paths[path_only] += 1
                    except Exception:
                        pass

                # Bad actor scoring logic:
                # 403 Forbidden or 401 Unauthorized are signs of probing
                if status in ('403', '401') or (status == '400' and ip):
                    self.bad_actors[p][ip] += 1
                # Accessing sensitive files or directories increases score significantly
                if any(x in request.lower() for x in ('.env', 'xmlrpc.php', 'wp-admin', 'cgi-bin', '.git', 'shell', 'backup', 'config', 'sql')):
                    self.bad_actors[p][ip] += 2

            # Monthly granular tracking
            if timestamp:
                month_key = (timestamp.year, timestamp.month)
                ms = self.monthly_access[month_key][vhost]
                ms.requests += 1
                ms.unique_ips.add(ip)
                ms.status_codes[status] += 1
                ms.total_size += size
                try:
                    path_m = request.split(' ')[1] if ' ' in request else request
                except IndexError:
                    path_m = request
                ms.paths[path_m] += 1
                ms.referrers[data['referrer']] += 1
                ip_stats_m = ms.ips[ip]
                ip_stats_m['count'] += 1
                ip_stats_m['timestamps'].append(timestamp)
                ip_stats_m['ua'].add(data['user_agent'])
                if self.is_download(request):
                    ms.downloads += 1
                    try:
                        path_only_m = path_m.split('?')[0]
                        if status.startswith('2'):
                            ms.download_success_paths[path_only_m] += 1
                        elif status.startswith('4') or status.startswith('5'):
                            ms.download_error_paths[path_only_m] += 1
                    except Exception:
                        pass
                if status in ('403', '401') or (status == '400' and ip):
                    self.monthly_bad_actors[month_key][vhost][ip] += 1
                if any(x in request.lower() for x in ('.env', 'xmlrpc.php', 'wp-admin', 'cgi-bin', '.git', 'shell', 'backup', 'config', 'sql')):
                    self.monthly_bad_actors[month_key][vhost][ip] += 2

    def process_error_log(self, file_path: str) -> None:
        """Processes an entire error log file line by line."""
        try:
            with self.open_log(file_path) as f:
                for line in f:
                    self.process_error_log_line(line)
        except Exception as e:
            print(f"Error processing error log {file_path}: {e}", file=sys.stderr)

    def process_error_log_line(self, line: str) -> None:
        """Parses a single error log line and updates statistics."""
        match = ERROR_LOG_REGEX.match(line)
        if match:
            data = match.groupdict()
            vhost = 'default'
            # Try to extract hostname if present in the message
            if '[hostname "' in data['message']:
                vh_match = re.search(r'\[hostname "([^"]+)"]', data['message'])
                if vh_match:
                    vhost = vh_match.group(1)
            
            timestamp = self.parse_timestamp(data['timestamp'])
            period_key = (timestamp.year, timestamp.month) if timestamp else None

            relevant_periods = ['total']
            if period_key:
                if period_key == self.current_month:
                    relevant_periods.append('current_month')
                elif period_key == self.last_month:
                    relevant_periods.append('last_month')

            for p in relevant_periods:
                stats = self.error_data[p][vhost]
                stats.errors += 1
                stats.levels[data['level']] += 1
                
                # Truncate long error messages for cleaner reporting
                msg = data['message'].split('] ')[-1] if ']' in data['message'] else data['message']
                stats.messages[msg[:100]] += 1
                
                if data.get('ip'):
                    ip = data['ip']
                    stats.ips[ip] += 1
                    # High-level errors from a specific IP are highly suspicious
                    if data['level'] in ('error', 'crit', 'alert', 'emerg') or 'ModSecurity' in data['message']:
                        self.bad_actors[p][ip] += 5

            # Monthly granular error tracking
            if timestamp:
                month_key = (timestamp.year, timestamp.month)
                me = self.monthly_errors[month_key][vhost]
                me.errors += 1
                me.levels[data['level']] += 1
                msg = data['message'].split('] ')[-1] if ']' in data['message'] else data['message']
                me.messages[msg[:100]] += 1
                if data.get('ip'):
                    ip = data['ip']
                    me.ips[ip] += 1
                    if data['level'] in ('error', 'crit', 'alert', 'emerg') or 'ModSecurity' in data['message']:
                        self.monthly_bad_actors[month_key][vhost][ip] += 5

    def estimate_time(self, timestamps: List[datetime.datetime]) -> float:
        """
        Estimates total time spent by a visitor in seconds.
        A gap of more than 30 minutes between requests starts a new 'session'.
        """
        if not timestamps:
            return 0.0
        timestamps.sort()
        total_time = 0.0
        if len(timestamps) < 2:
            return 30.0 # Single hit assumed to be 30 seconds
        
        start = timestamps[0]
        last = timestamps[0]
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - last).total_seconds()
            if gap > 1800: # 30 min gap
                total_time += (last - start).total_seconds() + 30.0
                start = timestamps[i]
            last = timestamps[i]
        total_time += (last - start).total_seconds() + 30.0
        return total_time

    def get_summary(self, period_filter: Optional[List[str]] = None, show_bad_actors: bool = True) -> str:
        """Generates a compact tabular summary of statistics for specified periods."""
        output = []
        
        all_domains = set()
        for p in self.periods:
            all_domains.update(self.access_data[p].keys())
            all_domains.update(self.error_data[p].keys())
        
        domains = sorted(all_domains)
        if not domains:
            return Fore.YELLOW + "No log data found." + Fore.RESET

        domain_width = max(len(d) for d in domains) if domains else 30
        domain_width = max(min(domain_width, 50), 15)

        periods_to_show = period_filter if period_filter else self.periods

        for p in periods_to_show:
            if p not in self.periods:
                continue
                
            p_display = p.replace('_', ' ').upper()
            output.append(f"\n{Fore.CYAN}{Style.BRIGHT}[ {p_display} SUMMARY ]{Style.RESET_ALL}")
            
            header = f"| {'Domain':<{domain_width}} | {'Visitors':<10} | {'Requests':<10} | {'DL OK':<7} | {'DL Err':<7} | {'Avg Time':<10} | {'Errors':<10} |"
            border = "-" * len(header)
            
            output.append(Fore.CYAN + border + Fore.RESET)
            output.append(Fore.CYAN + header + Fore.RESET)
            output.append(Fore.CYAN + border + Fore.RESET)
            
            p_found = False
            for d in domains:
                acc = self.access_data[p].get(d, AccessStats())
                err = self.error_data[p].get(d, ErrorStats())
                
                if not acc.requests and not err.errors:
                    continue
                
                p_found = True
                visitors = len(acc.unique_ips)
                requests = acc.requests
                dl_ok = sum(acc.download_success_paths.values())
                dl_err = sum(acc.download_error_paths.values())
                errors = err.errors
                
                all_times = []
                for ip_data in acc.ips.values():
                    if ip_data.get('timestamps'):
                        all_times.append(self.estimate_time(ip_data['timestamps']))
                avg_time = sum(all_times) / len(all_times) if all_times else 0.0
                avg_time_str = f"{avg_time/60:.2f}m"

                d_display = d[:domain_width]
                err_color = Fore.RED if errors > 0 else ""
                dl_err_color = Fore.YELLOW if dl_err > 0 else ""
                line = f"| {d_display:<{domain_width}} | {visitors:<10} | {requests:<10} | {dl_ok:<7} | {dl_err_color}{dl_err:<7}{Fore.CYAN if dl_err > 0 else ''} | {avg_time_str:<10} | {err_color}{errors:<10}{Fore.CYAN if errors > 0 else ''} |"
                output.append(Fore.CYAN + line + Fore.RESET)
            
            if not p_found:
                remaining = len(header) - 4
                output.append(Fore.CYAN + f"| {'No data for this period':<{remaining}} |" + Fore.RESET)
            
            output.append(Fore.CYAN + border + Fore.RESET)

            if show_bad_actors and self.bad_actors[p]:
                output.append(f"\n{Fore.YELLOW}| {'Top Bad Actors (IP) - ' + p_display:<30} | {'Threat Score':<12} | {'UFW Permanent Ban Command':<48} |{Fore.RESET}")
                bad_border = "-" * 100
                output.append(Fore.YELLOW + bad_border + Fore.RESET)
                for ip, score in self.bad_actors[p].most_common(5):
                    ban_cmd = f"sudo ufw insert 1 deny from {ip}"
                    output.append(f"{Fore.YELLOW}| {Fore.WHITE}{ip:<30} {Fore.YELLOW}| {Fore.RED}{score:<12} {Fore.YELLOW}| {Fore.CYAN}{ban_cmd:<48} {Fore.YELLOW}|{Fore.RESET}")
                output.append(Fore.YELLOW + bad_border + Fore.RESET)
                output.append(f"{Fore.YELLOW}Note: Don't forget to reload the firewall to apply changes: {Fore.CYAN}sudo ufw reload{Fore.RESET}")
                
        return "\n".join(output)

    def get_full_report(self, period_filter: Optional[List[str]] = None) -> str:
        """Generates a detailed monthly breakdown report per domain with totals table."""
        output = []

        # Collect all domains and months
        all_domains = set()
        all_months = set()
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

        # Filter months by period_filter if specified
        if period_filter:
            allowed_months = set()
            for p in period_filter:
                if p == 'total':
                    allowed_months = set(months)
                    break
                elif p == 'current_month':
                    allowed_months.add(self.current_month)
                elif p == 'last_month':
                    allowed_months.add(self.last_month)
            if allowed_months:
                months = sorted(m for m in months if m in allowed_months)

        month_names = {1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun',
                       7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec'}

        # Grand totals accumulators
        grand_totals = {
            'visitors': set(), 'requests': 0, 'interactions': 0,
            'dl_ok': 0, 'dl_fail': 0, 'errors': 0, 'criticals': 0,
            'warnings': 0, 'infos': 0, 'bad_actors': set(), 'attacks': 0,
            'total_size': 0, 'avg_times': [],
            'status_2xx': 0, 'status_3xx': 0, 'status_4xx': 0, 'status_5xx': 0,
        }

        # Per-domain monthly tables
        for domain in domains:
            output.append(f"\n{Fore.CYAN}{Style.BRIGHT}[ {domain.upper()} ]{Style.RESET_ALL}")

            header = (f"| {'Month':<10} | {'Visitors':>8} | {'Requests':>8} | {'2xx':>5} | {'3xx':>5} | {'4xx':>5} | {'5xx':>5} "
                      f"| {'Avg Time':>8} | {'Bandwidth':>10} | {'DL OK':>6} | {'DL Fail':>7} "
                      f"| {'Errors':>6} | {'Criticals':>9} | {'Warnings':>8} | {'Info':>5} "
                      f"| {'Bad IPs':>7} | {'Attacks':>7} |")
            border = "-" * len(header)

            output.append(Fore.CYAN + border + Fore.RESET)
            output.append(Fore.CYAN + header + Fore.RESET)
            output.append(Fore.CYAN + border + Fore.RESET)

            domain_has_data = False
            # Domain totals accumulators
            dt_visitors = set()
            dt_requests = 0
            dt_2xx = 0; dt_3xx = 0; dt_4xx = 0; dt_5xx = 0
            dt_times = []
            dt_size = 0
            dt_dl_ok = 0; dt_dl_fail = 0
            dt_errors = 0; dt_criticals = 0; dt_warnings = 0; dt_infos = 0
            dt_bad_ips = set(); dt_attacks = 0

            for mk in months:
                acc = self.monthly_access.get(mk, {}).get(domain, AccessStats())
                err = self.monthly_errors.get(mk, {}).get(domain, ErrorStats())
                ba = self.monthly_bad_actors.get(mk, {}).get(domain, Counter())

                if not acc.requests and not err.errors:
                    continue
                domain_has_data = True

                visitors = len(acc.unique_ips)
                requests = acc.requests
                s2xx = sum(v for k, v in acc.status_codes.items() if k.startswith('2'))
                s3xx = sum(v for k, v in acc.status_codes.items() if k.startswith('3'))
                s4xx = sum(v for k, v in acc.status_codes.items() if k.startswith('4'))
                s5xx = sum(v for k, v in acc.status_codes.items() if k.startswith('5'))
                interactions = s2xx + s3xx  # successful interactions

                all_times = []
                for ip_data in acc.ips.values():
                    if ip_data.get('timestamps'):
                        all_times.append(self.estimate_time(ip_data['timestamps']))
                avg_time = sum(all_times) / len(all_times) if all_times else 0.0
                avg_time_str = f"{avg_time/60:.1f}m"

                bw = acc.total_size
                if bw >= 1073741824:
                    bw_str = f"{bw/1073741824:.1f} GB"
                elif bw >= 1048576:
                    bw_str = f"{bw/1048576:.1f} MB"
                elif bw >= 1024:
                    bw_str = f"{bw/1024:.1f} KB"
                else:
                    bw_str = f"{bw} B"

                dl_ok = sum(acc.download_success_paths.values())
                dl_fail = sum(acc.download_error_paths.values())
                errors = err.errors
                criticals = err.levels.get('crit', 0) + err.levels.get('alert', 0) + err.levels.get('emerg', 0)
                warnings = err.levels.get('warn', 0)
                infos = err.levels.get('info', 0) + err.levels.get('notice', 0)
                bad_ips = len(ba)
                attacks = sum(ba.values())

                month_label = f"{month_names[mk[1]]} {mk[0]}"

                err_color = Fore.RED if errors > 0 else ''
                crit_color = Fore.RED if criticals > 0 else ''
                dl_f_color = Fore.YELLOW if dl_fail > 0 else ''
                ba_color = Fore.RED if bad_ips > 0 else ''
                reset = Fore.CYAN

                line = (f"| {month_label:<10} | {visitors:>8} | {requests:>8} | {s2xx:>5} | {s3xx:>5} | {s4xx:>5} | {s5xx:>5} "
                        f"| {avg_time_str:>8} | {bw_str:>10} | {dl_ok:>6} | {dl_f_color}{dl_fail:>7}{reset if dl_fail > 0 else ''} "
                        f"| {err_color}{errors:>6}{reset if errors > 0 else ''} | {crit_color}{criticals:>9}{reset if criticals > 0 else ''} | {warnings:>8} | {infos:>5} "
                        f"| {ba_color}{bad_ips:>7}{reset if bad_ips > 0 else ''} | {attacks:>7} |")
                output.append(Fore.CYAN + line + Fore.RESET)

                # Accumulate domain totals
                dt_visitors.update(acc.unique_ips)
                dt_requests += requests
                dt_2xx += s2xx; dt_3xx += s3xx; dt_4xx += s4xx; dt_5xx += s5xx
                dt_times.extend(all_times)
                dt_size += bw
                dt_dl_ok += dl_ok; dt_dl_fail += dl_fail
                dt_errors += errors; dt_criticals += criticals; dt_warnings += warnings; dt_infos += infos
                dt_bad_ips.update(ba.keys()); dt_attacks += attacks

                # Accumulate grand totals
                grand_totals['visitors'].update(acc.unique_ips)
                grand_totals['requests'] += requests
                grand_totals['interactions'] += interactions
                grand_totals['dl_ok'] += dl_ok
                grand_totals['dl_fail'] += dl_fail
                grand_totals['errors'] += errors
                grand_totals['criticals'] += criticals
                grand_totals['warnings'] += warnings
                grand_totals['infos'] += infos
                grand_totals['bad_actors'].update(ba.keys())
                grand_totals['attacks'] += attacks
                grand_totals['total_size'] += bw
                grand_totals['avg_times'].extend(all_times)
                grand_totals['status_2xx'] += s2xx
                grand_totals['status_3xx'] += s3xx
                grand_totals['status_4xx'] += s4xx
                grand_totals['status_5xx'] += s5xx

            if not domain_has_data:
                remaining = len(header) - 4
                output.append(Fore.CYAN + f"| {'No data':<{remaining}} |" + Fore.RESET)
            else:
                # Domain total row
                output.append(Fore.CYAN + border + Fore.RESET)
                dt_avg = sum(dt_times) / len(dt_times) if dt_times else 0.0
                dt_avg_str = f"{dt_avg/60:.1f}m"
                if dt_size >= 1073741824:
                    dt_bw_str = f"{dt_size/1073741824:.1f} GB"
                elif dt_size >= 1048576:
                    dt_bw_str = f"{dt_size/1048576:.1f} MB"
                elif dt_size >= 1024:
                    dt_bw_str = f"{dt_size/1024:.1f} KB"
                else:
                    dt_bw_str = f"{dt_size} B"
                dt_bad_count = len(dt_bad_ips)
                err_color = Fore.RED if dt_errors > 0 else ''
                crit_color = Fore.RED if dt_criticals > 0 else ''
                dl_f_color = Fore.YELLOW if dt_dl_fail > 0 else ''
                ba_color = Fore.RED if dt_bad_count > 0 else ''
                reset = Fore.CYAN
                total_line = (f"| {'TOTAL':<10} | {len(dt_visitors):>8} | {dt_requests:>8} | {dt_2xx:>5} | {dt_3xx:>5} | {dt_4xx:>5} | {dt_5xx:>5} "
                              f"| {dt_avg_str:>8} | {dt_bw_str:>10} | {dt_dl_ok:>6} | {dl_f_color}{dt_dl_fail:>7}{reset if dt_dl_fail > 0 else ''} "
                              f"| {err_color}{dt_errors:>6}{reset if dt_errors > 0 else ''} | {crit_color}{dt_criticals:>9}{reset if dt_criticals > 0 else ''} | {dt_warnings:>8} | {dt_infos:>5} "
                              f"| {ba_color}{dt_bad_count:>7}{reset if dt_bad_count > 0 else ''} | {dt_attacks:>7} |")
                output.append(Fore.GREEN + total_line + Fore.RESET)

            output.append(Fore.CYAN + border + Fore.RESET)

        # Grand Totals Table
        output.append(f"\n{Fore.GREEN}{Style.BRIGHT}[ GRAND TOTALS — ALL DOMAINS, ALL PERIODS ]{Style.RESET_ALL}")

        gt_avg_times = cast(List[float], grand_totals['avg_times'])
        gt_visitors = cast(Set[str], grand_totals['visitors'])
        gt_bad_actors = cast(Set[str], grand_totals['bad_actors'])
        gt_avg = sum(gt_avg_times) / len(gt_avg_times) if gt_avg_times else 0.0
        gt_bw = cast(int, grand_totals['total_size'])
        if gt_bw >= 1073741824:
            gt_bw_str = f"{gt_bw/1073741824:.1f} GB"
        elif gt_bw >= 1048576:
            gt_bw_str = f"{gt_bw/1048576:.1f} MB"
        elif gt_bw >= 1024:
            gt_bw_str = f"{gt_bw/1024:.1f} KB"
        else:
            gt_bw_str = f"{gt_bw} B"

        totals_rows = [
            ('Unique Visitors', str(len(gt_visitors))),
            ('Total Requests', str(grand_totals['requests'])),
            ('Successful (2xx)', str(grand_totals['status_2xx'])),
            ('Redirects (3xx)', str(grand_totals['status_3xx'])),
            ('Client Errors (4xx)', str(grand_totals['status_4xx'])),
            ('Server Errors (5xx)', str(grand_totals['status_5xx'])),
            ('Avg Session Time', f"{gt_avg/60:.1f} min"),
            ('Total Bandwidth', gt_bw_str),
            ('Downloads OK', str(grand_totals['dl_ok'])),
            ('Downloads Failed', str(grand_totals['dl_fail'])),
            ('Error Log Entries', str(grand_totals['errors'])),
            ('Critical/Alert/Emerg', str(grand_totals['criticals'])),
            ('Warnings', str(grand_totals['warnings'])),
            ('Info/Notice', str(grand_totals['infos'])),
            ('Bad Actor IPs', str(len(gt_bad_actors))),
            ('Total Attack Score', str(grand_totals['attacks'])),
        ]

        t_header = f"| {'Metric':<25} | {'Value':>15} |"
        t_border = "-" * len(t_header)
        output.append(Fore.GREEN + t_border + Fore.RESET)
        output.append(Fore.GREEN + t_header + Fore.RESET)
        output.append(Fore.GREEN + t_border + Fore.RESET)
        for label, val in totals_rows:
            output.append(Fore.GREEN + f"| {label:<25} | {val:>15} |" + Fore.RESET)
        output.append(Fore.GREEN + t_border + Fore.RESET)

        return "\n".join(output)


def main():
    """CLI entry point for the Apache Log Analyzer."""
    parser = argparse.ArgumentParser(description="Apache Web Server Log Analyzer")
    parser.add_argument("path", nargs="?", default="apache log files", help="Path to log directory or file")
    parser.add_argument("-f", "--full", action="store_true", help="Display detailed report instead of summary")
    
    # Period filters
    parser.add_argument("-t", "--total", action="store_true", help="Show total summary")
    parser.add_argument("-c", "--current", action="store_true", help="Show current month summary")
    parser.add_argument("-l", "--last", action="store_true", help="Show last month summary")
    parser.add_argument("-b", "--bad-actors", action="store_true", help="Show bad actors for selected periods")
    
    args = parser.parse_args()
    
    log_path = args.path
    # Automatic path detection if default is used and doesn't exist locally
    if log_path == "apache log files" and not os.path.exists(log_path):
        if os.path.exists("/var/log/apache2"):
            log_path = "/var/log/apache2"
        elif os.path.exists("/var/logs/apache2"):
            log_path = "/var/logs/apache2"

    if not os.path.exists(log_path):
        print(f"Error: Log directory or file not found at: {log_path}", file=sys.stderr)
        sys.exit(1)

    analyzer = LogAnalyzer(log_path)
    analyzer.process_files()
    
    period_filter = []
    if args.total:
        period_filter.append('total')
    if args.current:
        period_filter.append('current_month')
    if args.last:
        period_filter.append('last_month')
        
    # Default behavior: show current month and bad actors if no arguments given
    if not any([args.total, args.current, args.last, args.bad_actors]):
        period_filter = ['current_month']
        show_bad_actors = True
    else:
        if not period_filter and args.bad_actors:
             period_filter = ['current_month']
        
        show_bad_actors = args.bad_actors

    if args.full:
        # For full report, show all months unless a specific period filter was explicitly requested
        full_period = period_filter if any([args.total, args.current, args.last]) else None
        print(analyzer.get_full_report(period_filter=full_period))
    else:
        print(analyzer.get_summary(period_filter=period_filter, show_bad_actors=show_bad_actors))

if __name__ == "__main__":
    main()
