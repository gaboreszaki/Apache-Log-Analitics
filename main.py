import re
import os
import gzip
import argparse
import datetime
import sys
import colorama
from colorama import Fore, Back, Style
from collections import defaultdict, Counter

colorama.init(autoreset=True)

# Regular expression for parsing "other_vhosts_access.log"
# Format: vhost:port ip - - [timestamp] "request" status size "referrer" "user_agent"
# Standard Apache combined format: ip - - [timestamp] "request" status size "referrer" "user_agent"
ACCESS_LOG_REGEX = re.compile(
    r'^(?:(?P<vhost>[^:]+):?(?P<port>\d+)?\s+)?(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Standard error log regex (simplified)
# Format: [timestamp] [module:level] [pid] [client ip:port] AHxxxxx: message
ERROR_LOG_REGEX = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+\[pid\s+(?P<pid>\d+)\]\s+(?:\[client\s+(?P<ip>[^:\]]+):?(?P<port>\d+)?\]\s+)?(?P<message>.*)'
)

DOWNLOAD_EXTENSIONS = {'.zip', '.pdf', '.exe', '.dmg', '.tar', '.gz', '.tgz', '.rar', '.7z', '.iso', '.msi'}

class LogAnalyzer:
    def __init__(self, log_path):
        self.log_path = log_path
        self.access_data = defaultdict(lambda: {
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
        })
        self.error_data = defaultdict(lambda: {
            'errors': 0,
            'levels': Counter(),
            'messages': Counter(),
            'ips': Counter()
        })
        self.bad_actors = Counter()

    def parse_timestamp(self, ts_str):
        # Apache access log format: 08/Apr/2026:00:02:22 +0000
        try:
            return datetime.datetime.strptime(ts_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        except (ValueError, IndexError):
            return None

    def is_download(self, request):
        try:
            path = request.split(' ')[1] if ' ' in request else request
            ext = os.path.splitext(path.split('?')[0])[1].lower()
            return ext in DOWNLOAD_EXTENSIONS or '/download' in path.lower()
        except IndexError:
            return False

    def process_files(self):
        if not os.path.exists(self.log_path):
            print(f"Error: Path {self.log_path} does not exist.")
            return

        files = []
        if os.path.isfile(self.log_path):
            files.append(self.log_path)
        else:
            for f in os.listdir(self.log_path):
                f_path = os.path.join(self.log_path, f)
                if os.path.isfile(f_path):
                    files.append(f_path)

        for file_path in files:
            name = os.path.basename(file_path).lower()
            if 'access' in name:
                self.process_access_log(file_path)
            elif 'error' in name:
                self.process_error_log(file_path)

    def open_log(self, file_path):
        if file_path.endswith('.gz'):
            return gzip.open(file_path, 'rt', errors='ignore')
        return open(file_path, 'r', errors='ignore')

    def process_access_log(self, file_path):
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
                        size = int(data['size']) if data['size'] != '-' else 0
                    except ValueError:
                        size = 0

                    stats = self.access_data[vhost]
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
                        self.bad_actors[ip] += 1
                    if any(x in request.lower() for x in ('.env', 'xmlrpc.php', 'wp-admin', 'cgi-bin', '.git', 'shell')):
                        self.bad_actors[ip] += 2

    def process_error_log(self, file_path):
        with self.open_log(file_path) as f:
            for line in f:
                match = ERROR_LOG_REGEX.match(line)
                if match:
                    data = match.groupdict()
                    vhost = 'default'
                    if '[hostname "' in data['message']:
                        vh_match = re.search(r'\[hostname "([^"]+)"\]', data['message'])
                        if vh_match:
                            vhost = vh_match.group(1)

                    stats = self.error_data[vhost]
                    stats['errors'] += 1
                    stats['levels'][data['level']] += 1
                    
                    msg = data['message'].split('] ')[-1] if ']' in data['message'] else data['message']
                    stats['messages'][msg[:100]] += 1
                    
                    if data['ip']:
                        ip = data['ip']
                        stats['ips'][ip] += 1
                        if data['level'] in ('error', 'crit', 'alert', 'emerg') or 'ModSecurity' in data['message']:
                            self.bad_actors[ip] += 5

    def estimate_time(self, timestamps):
        if not timestamps:
            return 0
        timestamps.sort()
        total_time = 0
        if len(timestamps) < 2:
            return 30
        
        start = timestamps[0]
        last = timestamps[0]
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - last).total_seconds()
            if gap > 1800:
                total_time += (last - start).total_seconds() + 30
                start = timestamps[i]
            last = timestamps[i]
        total_time += (last - start).total_seconds() + 30
        return total_time

    def get_summary(self):
        output = []
        header = f"| {'Domain':<30} | {'Visitors':<10} | {'Requests':<10} | {'Downloads':<10} | {'Errors':<10} |"
        border = "-" * len(header)
        
        output.append(Fore.CYAN + border)
        output.append(Fore.CYAN + header)
        output.append(Fore.CYAN + border)
        
        domains = sorted(set(self.access_data.keys()) | set(self.error_data.keys()))
        for d in domains:
            acc = self.access_data.get(d, {})
            err = self.error_data.get(d, {})
            visitors = len(acc.get('unique_ips', []))
            requests = acc.get('requests', 0)
            downloads = acc.get('downloads', 0)
            errors = err.get('errors', 0)
            
            line = f"| {d[:30]:<30} | {visitors:<10} | {requests:<10} | {downloads:<10} | {Fore.RED if errors > 0 else ''}{errors:<10}{Fore.CYAN if errors > 0 else ''} |"
            output.append(Fore.CYAN + line)
        output.append(Fore.CYAN + border)
        
        if self.bad_actors:
            output.append(f"\n{Fore.YELLOW}| {'Top Bad Actors (IP)':<30} | {'Threat Score':<12} |")
            bad_border = "-" * 47
            output.append(Fore.YELLOW + bad_border)
            for ip, score in self.bad_actors.most_common(5):
                output.append(f"{Fore.YELLOW}| {Fore.WHITE}{ip:<30} {Fore.YELLOW}| {Fore.RED}{score:<12} {Fore.YELLOW}|")
            output.append(Fore.YELLOW + bad_border)
                
        return "\n".join(output)

    def get_full_report(self):
        report = []
        domains = sorted(set(self.access_data.keys()) | set(self.error_data.keys()))
        
        for d in domains:
            report.append(f"\n{Fore.CYAN}{'='*80}")
            report.append(f"{Fore.CYAN} DOMAIN: {Fore.YELLOW}{Style.BRIGHT}{d}")
            report.append(f"{Fore.CYAN}{'='*80}")
            
            acc = self.access_data.get(d)
            if acc:
                report.append(f"\n{Fore.GREEN}[ ACCESS STATISTICS ]")
                report.append(f"  {Fore.WHITE}Total Requests:         {acc['requests']}")
                report.append(f"  {Fore.WHITE}Unique Visitors:        {len(acc['unique_ips'])}")
                report.append(f"  {Fore.WHITE}Data Transferred:       {acc['total_size'] / 1024 / 1024:.2f} MB")
                report.append(f"  {Fore.WHITE}Downloads Identified:   {acc['downloads']}")
                
                all_times = []
                for ip_data in acc['ips'].values():
                    all_times.append(self.estimate_time(ip_data['timestamps']))
                avg_time = sum(all_times) / len(all_times) if all_times else 0
                report.append(f"  {Fore.WHITE}Avg Visitor Stay:       {avg_time/60:.2f} minutes")

                report.append(f"\n{Fore.GREEN}[ STATUS CODE DISTRIBUTION ]")
                for code, count in sorted(acc['status_codes'].items()):
                    color = Fore.GREEN if code.startswith('2') else (Fore.YELLOW if code.startswith('3') else Fore.RED)
                    report.append(f"  {color}{code}: {count}")

                report.append(f"\n{Fore.GREEN}[ TOP 5 REQUESTED PATHS ]")
                path_header = f"  | {'Hits':<7} | {'Path'}"
                report.append(Fore.GREEN + path_header)
                report.append(Fore.GREEN + "  " + "-" * 50)
                for path, count in acc['paths'].most_common(5):
                    report.append(f"  | {count:<7} | {path}")

                report.append(f"\n{Fore.GREEN}[ TOP 5 REFERRERS ]")
                ref_header = f"  | {'Hits':<7} | {'Referrer'}"
                report.append(Fore.GREEN + ref_header)
                report.append(Fore.GREEN + "  " + "-" * 50)
                for ref, count in acc['referrers'].most_common(5):
                    if ref == "-": continue
                    report.append(f"  | {count:<7} | {ref}")

                # Detailed downloaded files section
                report.append(f"\n{Fore.GREEN}[ DOWNLOADED FILES ]")
                # Successful downloads (2xx)
                if acc['download_success_paths']:
                    report.append(f"  {Fore.CYAN}Successful Downloads:")
                    dl_header = f"    | {'Hits':<7} | {'File Path'}"
                    report.append(Fore.CYAN + dl_header)
                    report.append(Fore.CYAN + "    " + "-" * 60)
                    for p, c in acc['download_success_paths'].most_common():
                        report.append(f"    | {c:<7} | {p}")
                else:
                    report.append(f"  {Fore.CYAN}Successful: None")

                # Error downloads (4xx/5xx)
                if acc['download_error_paths']:
                    report.append(f"\n  {Fore.RED}Error Downloads:")
                    err_dl_header = f"    | {'Hits':<7} | {'File Path'}"
                    report.append(Fore.RED + err_dl_header)
                    report.append(Fore.RED + "    " + "-" * 60)
                    for p, c in acc['download_error_paths'].most_common():
                        report.append(f"    | {c:<7} | {p}")
                else:
                    report.append(f"  {Fore.RED}Errors: None")

            err = self.error_data.get(d)
            if err:
                report.append(f"\n{Fore.RED}[ ERROR STATISTICS ]")
                report.append(f"  {Fore.WHITE}Total Errors:           {err['errors']}")
                report.append(f"\n{Fore.RED}[ ERROR LEVELS ]")
                for level, count in err['levels'].items():
                    report.append(f"  {Fore.YELLOW}{level:<15}: {Fore.WHITE}{count}")
                
                report.append(f"\n{Fore.RED}[ TOP 5 ERROR MESSAGES ]")
                msg_header = f"  | {'Hits':<7} | {'Message'}"
                report.append(Fore.RED + msg_header)
                report.append(Fore.RED + "  " + "-" * 50)
                for msg, count in err['messages'].most_common(5):
                    report.append(f"  | {count:<7} | {msg}")

        if self.bad_actors:
            report.append(f"\n{Fore.RED}{'='*80}")
            report.append(f"{Fore.RED} IDENTIFIED BAD ACTORS (Threat Detection)")
            report.append(f"{Fore.RED}{'='*80}")
            header = f"| {'IP Address':<20} | {'Score':<10} | {'Primary Activity / Target'}"
            border = "-" * 80
            report.append(Fore.RED + "| " + header[2:])
            report.append(Fore.RED + border)
            for ip, score in self.bad_actors.most_common(10):
                target = "N/A"
                for d in domains:
                    if ip in self.access_data[d]['ips']:
                        target = self.access_data[d]['paths'].most_common(1)[0][0]
                        break
                report.append(f"{Fore.RED}| {Fore.WHITE}{ip:<20} {Fore.RED}| {Fore.YELLOW}{score:<10} {Fore.RED}| {Fore.WHITE}{target}")
            report.append(Fore.RED + border)

        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Apache Web Server Log Analyzer")
    parser.add_argument("path", nargs="?", default="apache log files", help="Path to log directory or file")
    parser.add_argument("-s", "--summary", action="store_true", help="Display compact summary table")
    parser.add_argument("-f", "--full", action="store_true", help="Display detailed report")
    
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
    
    if args.full:
        print(analyzer.get_full_report())
    else:
        # Default to summary
        print(analyzer.get_summary())

if __name__ == "__main__":
    main()
