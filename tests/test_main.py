import unittest
import os
import datetime
from main import LogAnalyzer
from helpers import (
    parse_timestamp, is_download, estimate_session_time,
    format_bandwidth, extract_path, is_sensitive_request,
)


class TestHelpers(unittest.TestCase):
    """Tests for standalone helper functions in helpers.py."""

    def test_parse_timestamp_access_format(self):
        dt = parse_timestamp("08/Apr/2026:00:02:22 +0000")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.day, 8)

    def test_parse_timestamp_error_format(self):
        dt = parse_timestamp("Wed Apr 08 00:00:10.123456 2026")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 4)
        self.assertEqual(dt.day, 8)

    def test_parse_timestamp_invalid(self):
        self.assertIsNone(parse_timestamp("not-a-date"))

    def test_is_download_true(self):
        self.assertTrue(is_download("GET /file.zip HTTP/1.1"))
        self.assertTrue(is_download("GET /some/path/download/file HTTP/1.1"))

    def test_is_download_false(self):
        self.assertFalse(is_download("GET /index.html HTTP/1.1"))

    def test_extract_path(self):
        self.assertEqual(extract_path("GET /page HTTP/1.1"), "/page")
        self.assertEqual(extract_path("/raw-path"), "/raw-path")

    def test_estimate_session_time_single(self):
        ts = datetime.datetime(2026, 4, 8, 10, 0, 0)
        self.assertEqual(estimate_session_time([ts]), 30.0)

    def test_estimate_session_time_multiple(self):
        ts1 = datetime.datetime(2026, 4, 8, 10, 0, 0)
        ts2 = datetime.datetime(2026, 4, 8, 10, 5, 0)
        self.assertEqual(estimate_session_time([ts1, ts2]), 330.0)

    def test_estimate_session_time_gap(self):
        ts1 = datetime.datetime(2026, 4, 8, 10, 0, 0)
        ts2 = datetime.datetime(2026, 4, 8, 11, 0, 0)
        self.assertEqual(estimate_session_time([ts1, ts2]), 60.0)

    def test_estimate_session_time_empty(self):
        self.assertEqual(estimate_session_time([]), 0.0)

    def test_format_bandwidth(self):
        self.assertEqual(format_bandwidth(500), "500 B")
        self.assertEqual(format_bandwidth(2048), "2.0 KB")
        self.assertEqual(format_bandwidth(2 * 1048576), "2.0 MB")
        self.assertEqual(format_bandwidth(3 * 1073741824), "3.0 GB")

    def test_is_sensitive_request(self):
        self.assertTrue(is_sensitive_request("GET /.env HTTP/1.1"))
        self.assertTrue(is_sensitive_request("GET /wp-admin/ HTTP/1.1"))
        self.assertFalse(is_sensitive_request("GET /index.html HTTP/1.1"))


class TestLogAnalyzer(unittest.TestCase):
    """Tests for the LogAnalyzer class."""

    def setUp(self):
        self.mock_log_path: str = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'mock_logs'
        )
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
        self.assertEqual(
            self.analyzer.access_data['current_month']['test1.com']
            .download_success_paths['/files/manual.pdf'], 1,
        )
        self.assertEqual(
            self.analyzer.access_data['current_month']['test1.com']
            .download_error_paths['/files/secret.zip'], 1,
        )

        self.assertEqual(self.analyzer.bad_actors['current_month']['5.6.7.8'], 14)

    def test_error_log_domain_detection(self):
        self.analyzer.process_files()
        self.assertIn('test1.com', self.analyzer.error_data['current_month'])
        self.assertEqual(self.analyzer.error_data['current_month']['test1.com'].errors, 1)

    def test_malformed_access_log(self):
        temp_log: str = os.path.join(self.mock_log_path, 'malformed_access.log')
        with open(temp_log, 'w') as f:
            f.write("This is a totally malformed line that should not crash the parser\n")
            f.write(
                'test.com:80 1.1.1.1 - - [08/Apr/2026:10:00:00 +0000] '
                '"GET / HTTP/1.1" 200 100 "-" "UA"\n'
            )

        try:
            self.analyzer.process_access_log(str(temp_log))
            self.assertEqual(
                self.analyzer.access_data['current_month']['test.com'].requests, 1,
            )
        finally:
            if os.path.exists(temp_log):
                os.remove(temp_log)

    def test_bad_actor_scoring(self):
        self.analyzer.process_access_log_line(
            'test.com:80 1.1.1.1 - - [08/Apr/2026:10:00:00 +0000] '
            '"GET /.env HTTP/1.1" 200 100 "-" "UA"'
        )
        self.assertEqual(self.analyzer.bad_actors['current_month']['1.1.1.1'], 2)

        self.analyzer.process_access_log_line(
            'test.com:80 1.1.1.1 - - [08/Apr/2026:10:01:00 +0000] '
            '"GET /private HTTP/1.1" 403 100 "-" "UA"'
        )
        self.assertEqual(self.analyzer.bad_actors['current_month']['1.1.1.1'], 2 + 1)

        self.analyzer.process_error_log_line(
            '[Wed Apr 08 10:05:00 2026] [crit] [pid 1] [client 1.1.1.1:1] Message'
        )
        self.assertEqual(self.analyzer.bad_actors['current_month']['1.1.1.1'], 3 + 5)

    def test_date_periods(self):
        self.analyzer.process_access_log_line(
            'test.com:80 1.1.1.1 - - [08/Apr/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 100 "-" "UA"'
        )
        self.assertIn('test.com', self.analyzer.access_data['current_month'])
        self.assertIn('test.com', self.analyzer.access_data['total'])
        self.assertNotIn('test.com', self.analyzer.access_data['last_month'])

        self.analyzer.process_access_log_line(
            'test.com:80 2.2.2.2 - - [15/Mar/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 100 "-" "UA"'
        )
        self.assertIn('test.com', self.analyzer.access_data['last_month'])
        self.assertEqual(self.analyzer.access_data['last_month']['test.com'].requests, 1)
        self.assertEqual(self.analyzer.access_data['total']['test.com'].requests, 2)

        self.analyzer.process_access_log_line(
            'test.com:80 3.3.3.3 - - [15/Feb/2026:10:00:00 +0000] '
            '"GET / HTTP/1.1" 200 100 "-" "UA"'
        )
        self.assertEqual(self.analyzer.access_data['total']['test.com'].requests, 3)
        self.assertEqual(self.analyzer.access_data['current_month']['test.com'].requests, 1)
        self.assertEqual(self.analyzer.access_data['last_month']['test.com'].requests, 1)

    def test_summary_no_data(self):
        result = self.analyzer.get_summary()
        self.assertIn("No log data found", result)

    def test_full_report_no_data(self):
        result = self.analyzer.get_full_report()
        self.assertIn("No log data found", result)


if __name__ == '__main__':
    unittest.main()
