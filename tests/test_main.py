import unittest
import os
import datetime
from main import LogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.mock_log_path: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mock_logs')
        self.test_now = datetime.datetime(2026, 4, 8)
        self.analyzer = LogAnalyzer(self.mock_log_path, now=self.test_now)

    def test_parse_timestamp_access(self):
        ts_str = "08/Apr/2026:00:02:22 +0000"
        dt = self.analyzer.parse_timestamp(ts_str)
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.day, 8)

    def test_parse_timestamp_error(self):
        ts_str = "Wed Apr 08 00:00:10.123456 2026"
        dt = self.analyzer.parse_timestamp(ts_str)
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.day, 8)

    def test_is_download(self):
        self.assertTrue(self.analyzer.is_download("GET /file.zip HTTP/1.1"))
        self.assertTrue(self.analyzer.is_download("GET /some/path/download/file HTTP/1.1"))
        self.assertFalse(self.analyzer.is_download("GET /index.html HTTP/1.1"))

    def test_estimate_time(self):
        ts1 = datetime.datetime(2026, 4, 8, 10, 0, 0)
        ts2 = datetime.datetime(2026, 4, 8, 10, 5, 0)
        ts3 = datetime.datetime(2026, 4, 8, 10, 10, 0)
        
        self.assertEqual(self.analyzer.estimate_time([ts1]), 30.0)
        
        self.assertEqual(self.analyzer.estimate_time([ts1, ts2]), 330.0)
        
        ts_late = datetime.datetime(2026, 4, 8, 11, 0, 0)
        self.assertEqual(self.analyzer.estimate_time([ts1, ts_late]), 60.0)

    def test_process_mock_logs(self):
        self.analyzer.process_files()
        
        self.assertIn('test1.com', self.analyzer.access_data['total'])
        self.assertIn('test2.com', self.analyzer.access_data['total'])
        
        self.assertEqual(self.analyzer.access_data['total']['test1.com'].requests, 4)
        
        self.assertEqual(self.analyzer.access_data['current_month']['test1.com'].requests, 2)
        
        self.assertEqual(self.analyzer.access_data['current_month']['test1.com'].downloads, 2)
        self.assertEqual(self.analyzer.access_data['current_month']['test1.com'].download_success_paths['/files/manual.pdf'], 1)
        self.assertEqual(self.analyzer.access_data['current_month']['test1.com'].download_error_paths['/files/secret.zip'], 1)
        
        self.assertEqual(self.analyzer.bad_actors['current_month']['5.6.7.8'], 14)

    def test_error_log_domain_detection(self):
        self.analyzer.process_files()
        self.assertIn('test1.com', self.analyzer.error_data['current_month'])
        self.assertEqual(self.analyzer.error_data['current_month']['test1.com'].errors, 1)

    def test_malformed_access_log(self):
        temp_log: str = os.path.join(self.mock_log_path, 'malformed_access.log')
        with open(temp_log, 'w') as f:
            f.write("This is a totally malformed line that should not crash the parser\n")
            f.write('test.com:80 1.1.1.1 - - [08/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "UA"\n')
        
        try:
            self.analyzer.process_access_log(str(temp_log))
            self.assertEqual(self.analyzer.access_data['current_month']['test.com'].requests, 1)
        finally:
            if os.path.exists(temp_log):
                os.remove(temp_log)

    def test_bad_actor_scoring(self):
        self.analyzer.process_access_log_line('test.com:80 1.1.1.1 - - [08/Apr/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 200 100 "-" "UA"')
        self.assertEqual(self.analyzer.bad_actors['current_month']['1.1.1.1'], 2)
        
        self.analyzer.process_access_log_line('test.com:80 1.1.1.1 - - [08/Apr/2026:10:01:00 +0000] "GET /private HTTP/1.1" 403 100 "-" "UA"')
        self.assertEqual(self.analyzer.bad_actors['current_month']['1.1.1.1'], 2 + 1)
        
        self.analyzer.process_error_log_line('[Wed Apr 08 10:05:00 2026] [crit] [pid 1] [client 1.1.1.1:1] Message')
        self.assertEqual(self.analyzer.bad_actors['current_month']['1.1.1.1'], 3 + 5)

    def test_date_periods(self):
        self.analyzer.process_access_log_line('test.com:80 1.1.1.1 - - [08/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "UA"')
        self.assertIn('test.com', self.analyzer.access_data['current_month'])
        self.assertIn('test.com', self.analyzer.access_data['total'])
        self.assertNotIn('test.com', self.analyzer.access_data['last_month'])
        
        self.analyzer.process_access_log_line('test.com:80 2.2.2.2 - - [15/Mar/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "UA"')
        self.assertIn('test.com', self.analyzer.access_data['last_month'])
        self.assertEqual(self.analyzer.access_data['last_month']['test.com'].requests, 1)
        self.assertEqual(self.analyzer.access_data['total']['test.com'].requests, 2)
        
        self.analyzer.process_access_log_line('test.com:80 3.3.3.3 - - [15/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "UA"')
        self.assertEqual(self.analyzer.access_data['total']['test.com'].requests, 3)
        self.assertEqual(self.analyzer.access_data['current_month']['test.com'].requests, 1)
        self.assertEqual(self.analyzer.access_data['last_month']['test.com'].requests, 1)

if __name__ == '__main__':
    unittest.main()
