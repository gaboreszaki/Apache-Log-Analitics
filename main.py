import re
import os
import gzip
import argparse
import datetime
import sys
import subprocess
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any

# Simple ANSI coloring solution to replace colorama
class Fore:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"

class Style:
    BRIGHT = "\033[1m"
    RESET_ALL = "\033[0m"

# Enable ANSI escape codes on Windows if needed
if sys.platform == "win32":
    subprocess.run("", shell=True)

# Regular expression for parsing "other_vhosts_access.log"
# Format: vhost:port ip - - [timestamp] "request" status size "referrer" "user_agent"
# Standard Apache combined format: ip - - [timestamp] "request" status size "referrer" "user_agent"
ACCESS_LOG_REGEX = re.compile(
    r'^(?:(?P<vhost>[^:\s]+):?(?P<port>\d+)?\s+)?(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^]]+)]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Standard error log regex (simplified)
# Format: [timestamp] [module:level] [pid] [client ip:port] AHxxxxx: message
ERROR_LOG_REGEX = re.compile(
    r'^\[(?P<timestamp>[^]]+)]\s+\[(?P<level>[^]]+)]\s+(?:\[pid\s+(?P<pid>\d+)]\s+)?(?:\[client\s+(?P<ip>[^: ]+):?(?P<port>\d+)?]\s+)?(?P<message>.*)'
)

DOWNLOAD_EXTENSIONS = {'.zip', '.pdf', '.exe', '.dmg', '.tar', '.gz', '.tgz', '.rar', '.7z', '.iso', '.msi'}

class LogAnalyzer:
    def __init__(self, log_path: str):
        """
        Initializes the LogAnalyzer with a path to log files.
        :param log_path: Path to a directory or a single log file.
        """
        self.log_path = log_path
        
        # Determine current and last month
        # Current date from issue: 2026-04-08
        self.now = datetime.datetime(2026, 4, 8)
        self.current_month = (self.now.year, self.now.month)
        
        first_of_current = self.now.replace(day=1)
        last_day_of_last_month = first_of_current - datetime.timedelta(days=1)
        self.last_month = (last_day_of_last_month.year, last_day_of_last_month.month)

        # Periods to track
        self.periods = ['total', 'last_month', 'current_month']
        
        # access_data structure:
        # { period: { vhost: { requests: int, unique_ips: set, status_codes: Counter, ... } } }
        self.access_data: Dict[str, Dict[str, Dict[str, Any]]] = {
            p: defaultdict(lambda: {
                'requests': 0,
                'unique_ips': set(),
                'status_codes': Counter(),
                'downloads': 0,
                'ips': defaultdict(lambda: {'count': 0, 'timestamps': [], 'ua': set()}),
                'paths': Counter(),
                'referrers': Counter(),
                'total_size': 0,
                'download_success_paths': Counter(),
                'download_error_paths': Counter(),
                'vhost_requests': Counter(),
            }) for p in self.periods
        }
        
        self.error_data:Dict[str, Dict[str, Dict[str, Any]]] = {
            p: defaultdict(lambda: {
                'errors': 0,
                'levels': Counter(),
                'messages': Counter(),
                'ips': Counter()
            }) for p in self.periods
        }
        
        self.bad_actors: Dict[str, Counter] = {p: Counter() for p in self.periods}

    def parse_timestamp(self, ts_str: str) -> Optional[datetime.datetime]:
        """Parses Apache timestamp string (access or error log) into a datetime object."""
        # Access log format: 08/Apr/2026:00:02:22 +0000
        # Error log format: Wed Apr 08 00:00:10.123456 2026
        formats = [
            '%d/%b/%Y:%H:%M:%S',
            '%a %b %d %H:%M:%S.%f %Y',
            '%a %b %d %H:%M:%S %Y'
        ]
        
        # Clean up timestamp string
        ts_clean = ts_str.split(' ')[0] if '/' in ts_str else ts_str
        
        for fmt in formats:
            try:
                return datetime.datetime.strptime(ts_clean, fmt)
            except (ValueError, TypeError):
                continue
        return None

    def is_download(self, request: str) -> bool:
        """Determines if a request represents a file download based on extensions or keywords."""
        try:
            path = request.split(' ')[1] if ' ' in request else request
            ext = os.path.splitext(path.split('?')[0])[1].lower()
            return ext in DOWNLOAD_EXTENSIONS or '/download' in path.lower()
        except IndexError:
            return False

    def process_files(self) -> None:
        """Finds and processes log files in the specified log path."""
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
            if 'access' in name:
                self.process_access_log(file_path)
            elif 'error' in name:
                self.process_error_log(file_path)

    def open_log(self, file_path: str):
        """Helper to open plain text, gzipped, or bzip2 log files."""
        if file_path.endswith('.gz'):
            return gzip.open(file_path, 'rt', errors='ignore')
        elif file_path.endswith('.bz2'):
            import bz2
            return bz2.open(file_path, 'rt', errors='ignore')
        return open(file_path, 'r', errors='ignore')

    def process_access_log(self, file_path: str) -> None:
        """Parses an access log file and populates access_data."""
        try:
            with self.open_log(file_path) as f:
                for line in f:
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

                        # Determine periods
                        relevant_periods = ['total']
                        if timestamp:
                            if (timestamp.year, timestamp.month) == self.current_month:
                                relevant_periods.append('current_month')
                            elif (timestamp.year, timestamp.month) == self.last_month:
                                relevant_periods.append('last_month')

                        for p in relevant_periods:
                            stats = self.access_data[p][vhost]
                            stats['requests'] += 1
                            stats['unique_ips'].add(ip)
                            stats['status_codes'][status] += 1
                            stats['total_size'] += size
                            
                            try:
                                path = request.split(' ')[1] if ' ' in request else request
                            except IndexError:
                                path = request
                            stats['paths'][path] += 1
                            stats['referrers'][data['referrer']] += 1
                            
                            ip_stats = stats['ips'][ip]
                            ip_stats['count'] += 1
                            if timestamp:
                                ip_stats['timestamps'].append(timestamp)
                            ip_stats['ua'].add(data['user_agent'])

                            if self.is_download(request):
                                stats['downloads'] += 1
                                # Track downloaded files by success/error based on status code class
                                try:
                                    path_only = path.split('?')[0]
                                    if status.startswith('2'):
                                        stats['download_success_paths'][path_only] += 1
                                    elif status.startswith('4') or status.startswith('5'):
                                        stats['download_error_paths'][path_only] += 1
                                except Exception:
                                    pass

                        # Bad actor identification
                        if status in ('403', '401') or (status == '400' and ip):
                            for p in relevant_periods:
                                self.bad_actors[p][ip] += 1
                        if any(x in request.lower() for x in ('.env', 'xmlrpc.php', 'wp-admin', 'cgi-bin', '.git', 'shell', 'backup', 'config', 'sql')):
                            for p in relevant_periods:
                                self.bad_actors[p][ip] += 2
        except Exception as e:
            print(f"Error processing access log {file_path}: {e}", file=sys.stderr)

    def process_error_log(self, file_path: str) -> None:
        """Parses an error log file and populates error_data."""
        try:
            with self.open_log(file_path) as f:
                for line in f:
                    match = ERROR_LOG_REGEX.match(line)
                    if match:
                        data = match.groupdict()
                        vhost = 'default'
                        if '[hostname "' in data['message']:
                            vh_match = re.search(r'\[hostname "([^"]+)"]', data['message'])
                            if vh_match:
                                vhost = vh_match.group(1)
                        
                        # Try to parse error log timestamp using the unified helper
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
                            stats['errors'] += 1
                            stats['levels'][data['level']] += 1
                            
                            msg = data['message'].split('] ')[-1] if ']' in data['message'] else data['message']
                            stats['messages'][msg[:100]] += 1
                            
                            if data.get('ip'):
                                ip = data['ip']
                                stats['ips'][ip] += 1
                                if data['level'] in ('error', 'crit', 'alert', 'emerg') or 'ModSecurity' in data['message']:
                                    for p in relevant_periods:
                                        self.bad_actors[p][ip] += 5
        except Exception as e:
            print(f"Error processing error log {file_path}: {e}", file=sys.stderr)

    def estimate_time(self, timestamps: List[datetime.datetime]) -> float:
        """Estimates total session time for a list of timestamps."""
        if not timestamps:
            return 0.0
        timestamps.sort()
        total_time = 0.0
        if len(timestamps) < 2:
            return 30.0
        
        start = timestamps[0]
        last = timestamps[0]
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - last).total_seconds()
            if gap > 1800:
                total_time += (last - start).total_seconds() + 30.0
                start = timestamps[i]
            last = timestamps[i]
        total_time += (last - start).total_seconds() + 30.0
        return total_time

    def get_summary(self, period_filter: Optional[List[str]] = None, show_bad_actors: bool = True) -> str:
        """Returns a summary table for the specified periods."""
        output = []
        
        # Collect all domains across all periods
        all_domains = set()
        for p in self.periods:
            all_domains.update(self.access_data[p].keys())
            all_domains.update(self.error_data[p].keys())
        
        domains = sorted(all_domains)
        if not domains:
            return Fore.YELLOW + "No log data found." + Fore.RESET

        # Dynamic width calculation
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
                acc = self.access_data[p].get(d, {})
                err = self.error_data[p].get(d, {})
                
                if not acc and not err:
                    continue
                
                p_found = True
                visitors = len(acc.get('unique_ips', set()))
                requests = acc.get('requests', 0)
                dl_ok = sum(acc.get('download_success_paths', Counter()).values())
                dl_err = sum(acc.get('download_error_paths', Counter()).values())
                errors = err.get('errors', 0)
                
                all_times = []
                if acc and 'ips' in acc:
                    for ip_data in acc['ips'].values():
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
                # Calculate remaining width after "| "
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
                
        return "\n".join(output)

    def get_full_report(self, period_filter: Optional[List[str]] = None) -> str:
        """Returns a detailed report for the specified periods."""
        report = []
        
        periods_to_show = period_filter if period_filter else ['total']
        
        for p in periods_to_show:
            if p not in self.periods:
                continue
                
            p_display = p.replace('_', ' ').upper()
            report.append(f"\n{Fore.YELLOW}{Style.BRIGHT}DETAILED REPORT ({p_display} PERIOD){Style.RESET_ALL}")
            
            domains = sorted(set(self.access_data[p].keys()) | set(self.error_data[p].keys()))
            
            for d in domains:
                report.append(f"\n{Fore.CYAN}{'='*80}{Fore.RESET}")
                report.append(f"{Fore.CYAN} DOMAIN: {Fore.YELLOW}{Style.BRIGHT}{d}{Style.RESET_ALL} ({p_display})")
                report.append(f"{Fore.CYAN}{'='*80}{Fore.RESET}")
                
                acc = self.access_data[p].get(d)
                if acc:
                    report.append(f"\n{Fore.GREEN}[ ACCESS STATISTICS ]{Fore.RESET}")
                    report.append(f"  {Fore.WHITE}Total Requests:         {acc['requests']}{Fore.RESET}")
                    report.append(f"  {Fore.WHITE}Unique Visitors:        {len(acc['unique_ips'])}{Fore.RESET}")
                    report.append(f"  {Fore.WHITE}Data Transferred:       {acc['total_size'] / 1024 / 1024:.2f} MB{Fore.RESET}")
                    report.append(f"  {Fore.WHITE}Downloads Identified:   {acc['downloads']}{Fore.RESET}")
                    
                    all_times = []
                    for ip_data in acc['ips'].values():
                        all_times.append(self.estimate_time(ip_data['timestamps']))
                    avg_time = sum(all_times) / len(all_times) if all_times else 0.0
                    report.append(f"  {Fore.WHITE}Avg Visitor Stay:       {avg_time/60:.2f} minutes{Fore.RESET}")

                    report.append(f"\n{Fore.GREEN}[ STATUS CODE DISTRIBUTION ]{Fore.RESET}")
                    for code, count in sorted(acc['status_codes'].items()):
                        color = Fore.GREEN if code.startswith('2') else (Fore.YELLOW if code.startswith('3') else Fore.RED)
                        report.append(f"  {color}{code}: {count}{Fore.RESET}")

                    report.append(f"\n{Fore.GREEN}[ TOP 5 REQUESTED PATHS ]{Fore.RESET}")
                    path_header = f"  | {'Hits':<7} | {'Path'}"
                    report.append(Fore.GREEN + path_header + Fore.RESET)
                    report.append(Fore.GREEN + "  " + "-" * 50 + Fore.RESET)
                    for path, count in acc['paths'].most_common(5):
                        report.append(f"  | {count:<7} | {path}")

                    report.append(f"\n{Fore.GREEN}[ TOP 5 REFERRERS ]{Fore.RESET}")
                    ref_header = f"  | {'Hits':<7} | {'Referrer'}"
                    report.append(Fore.GREEN + ref_header + Fore.RESET)
                    report.append(Fore.GREEN + "  " + "-" * 50 + Fore.RESET)
                    for ref, count in acc['referrers'].most_common(5):
                        if ref == "-": continue
                        report.append(f"  | {count:<7} | {ref}")

                    # Detailed downloaded files section
                    report.append(f"\n{Fore.GREEN}[ DOWNLOADED FILES ]{Fore.RESET}")
                    if acc['download_success_paths']:
                        report.append(f"  {Fore.CYAN}Successful Downloads:{Fore.RESET}")
                        dl_header = f"    | {'Hits':<7} | {'File Path'}"
                        report.append(Fore.CYAN + dl_header + Fore.RESET)
                        report.append(Fore.CYAN + "    " + "-" * 60 + Fore.RESET)
                        for p_path, c in acc['download_success_paths'].most_common():
                            report.append(f"    | {c:<7} | {p_path}")
                    else:
                        report.append(f"  {Fore.CYAN}Successful: None{Fore.RESET}")

                    if acc['download_error_paths']:
                        report.append(f"\n  {Fore.RED}Error Downloads:{Fore.RESET}")
                        err_dl_header = f"    | {'Hits':<7} | {'File Path'}"
                        report.append(Fore.RED + err_dl_header + Fore.RESET)
                        report.append(Fore.RED + "    " + "-" * 60 + Fore.RESET)
                        for p_path, c in acc['download_error_paths'].most_common():
                            report.append(f"    | {c:<7} | {p_path}")
                    else:
                        report.append(f"  {Fore.RED}Errors: None{Fore.RESET}")

                err = self.error_data[p].get(d)
                if err:
                    report.append(f"\n{Fore.RED}[ ERROR STATISTICS ]{Fore.RESET}")
                    report.append(f"  {Fore.WHITE}Total Errors:           {err['errors']}{Fore.RESET}")
                    report.append(f"\n{Fore.RED}[ ERROR LEVELS ]{Fore.RESET}")
                    for level, count in err['levels'].items():
                        report.append(f"  {Fore.YELLOW}{level:<15}: {Fore.WHITE}{count}{Fore.RESET}")
                    
                    report.append(f"\n{Fore.RED}[ TOP 5 ERROR MESSAGES ]{Fore.RESET}")
                    msg_header = f"  | {'Hits':<7} | {'Message'}"
                    report.append(Fore.RED + msg_header + Fore.RESET)
                    report.append(Fore.RED + "  " + "-" * 50 + Fore.RESET)
                    for msg, count in err['messages'].most_common(5):
                        report.append(f"  | {count:<7} | {msg}")

            if self.bad_actors[p]:
                report.append(f"\n{Fore.RED}{'='*80}{Fore.RESET}")
                report.append(f"{Fore.RED} IDENTIFIED BAD ACTORS - {p_display}{Fore.RESET}")
                report.append(f"{Fore.RED}{'='*80}{Fore.RESET}")
                header = f"| {'IP Address':<20} | {'Score':<10} | {'Target (Most Frequent)'}"
                border = "-" * 80
                report.append(Fore.RED + "| " + header[2:] + Fore.RESET)
                report.append(Fore.RED + border + Fore.RESET)
                for ip, score in self.bad_actors[p].most_common(10):
                    target = "N/A"
                    # Try to find the most frequent path for this IP across all domains in this period
                    max_hits = 0
                    for d in domains:
                        acc_d = self.access_data[p].get(d)
                        if acc_d and ip in acc_d['ips']:
                            # This is a bit expensive, let's just find where they hit most
                            hits = acc_d['ips'][ip]['count']
                            if hits > max_hits:
                                max_hits = hits
                                most_common_path = acc_d['paths'].most_common(1)
                                if most_common_path:
                                    target = f"{d}: {most_common_path[0][0][:40]}"
                    report.append(f"{Fore.RED}| {Fore.WHITE}{ip:<20} {Fore.RED}| {Fore.YELLOW}{score:<10} {Fore.RED}| {Fore.WHITE}{target}{Fore.RESET}")
                report.append(Fore.RED + border + Fore.RESET)

        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Apache Web Server Log Analyzer")
    parser.add_argument("path", nargs="?", default="apache log files", help="Path to log directory or file")
    parser.add_argument("-f", "--full", action="store_true", help="Display detailed report instead of summary")
    
    parser.add_argument("-t", "--total", action="store_true", help="Show total summary")
    parser.add_argument("-c", "--current", action="store_true", help="Show current month summary")
    parser.add_argument("-l", "--last", action="store_true", help="Show last month summary")
    parser.add_argument("-b", "--bad-actors", action="store_true", help="Show bad actors for selected periods")
    
    args = parser.parse_args()
    
    log_path = args.path
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
    
    # Determine which periods to show
    period_filter = []
    if args.total:
        period_filter.append('total')
    if args.current:
        period_filter.append('current_month')
    if args.last:
        period_filter.append('last_month')
        
    # Default behavior: current month + bad actors
    if not any([args.total, args.current, args.last, args.bad_actors]):
        period_filter = ['current_month']
        show_bad_actors = True
    else:
        # If any period is selected but NOT --bad-actors, we only show bad actors if --bad-actors is set
        # But if ONLY --bad-actors is set, which periods to show? 
        # Requirement: "separate ... with an argument... default shows current month and bad actors"
        # If someone calls with just --bad-actors, maybe show for current month?
        # Or if someone calls with --total, only show total summary (no bad actors unless -b is also there)
        if not period_filter and args.bad_actors:
             period_filter = ['current_month']
        
        show_bad_actors = args.bad_actors

    if args.full:
        print(analyzer.get_full_report(period_filter=period_filter))
    else:
        print(analyzer.get_summary(period_filter=period_filter, show_bad_actors=show_bad_actors))

if __name__ == "__main__":
    main()
