"""Unit tests. Run with:  python -m unittest -v"""

import unittest
from datetime import datetime

from log_analyzer import (
    LogParseError,
    analyze,
    is_private_address,
    parse_line,
    render_text,
    to_dict,
)


def failed(ip, second, minute=0, user="admin"):
    return f"2026-11-02 10:{minute:02d}:{second:02d} WARNING Login FAILED for {user} from {ip}"


class ParseLineTests(unittest.TestCase):
    def test_custom_format(self):
        event = parse_line("2026-11-02 10:15:01 WARNING Login FAILED for admin from 203.0.113.45")
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.timestamp, datetime(2026, 11, 2, 10, 15, 1))

    def test_custom_format_is_case_insensitive_and_finds_ip_anywhere(self):
        event = parse_line("2026-11-02 10:15:01 auth failed login user=bob ip=10.0.0.5 retry")
        self.assertEqual(event.ip, "10.0.0.5")
        self.assertEqual(event.username, "bob")

    def test_ssh_failed_password(self):
        line = "Nov  2 10:15:32 web01 sshd[1234]: Failed password for invalid user test from 203.0.113.45 port 52144 ssh2"
        event = parse_line(line, year=2026)
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.username, "test")
        self.assertEqual(event.timestamp, datetime(2026, 11, 2, 10, 15, 32))

    def test_non_failure_lines_are_ignored(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("2026-11-02 10:15:01 INFO Login SUCCESS for alice from 192.168.1.15"))
        self.assertIsNone(parse_line("Nov  2 10:15:32 web01 sshd[1]: Accepted password for a from 10.0.0.1 port 22 ssh2"))
        self.assertIsNone(parse_line("Nov  2 10:15:32 web01 sshd[1]: Failed publickey for a from 10.0.0.1 port 22 ssh2"))
        self.assertIsNone(parse_line("Nov  2 10:15:32 web01 sshd[1]: Invalid user x from 10.0.0.1 port 22"))

    def test_malformed_failure_lines_raise(self):
        with self.assertRaises(LogParseError):
            parse_line("2026-13-45 99:99:99 Login FAILED for x from 10.0.0.1")
        with self.assertRaises(LogParseError):
            parse_line("2026-11-02 10:15:01 Login FAILED for x from not-an-ip")


class DetectionTests(unittest.TestCase):
    def test_five_failures_in_five_minutes_is_bruteforce(self):
        lines = [failed("203.0.113.5", s) for s in (0, 10, 20, 30, 40)]
        result = analyze(lines)
        stats = result.ip_stats[0]
        self.assertTrue(stats.is_bruteforce)
        self.assertEqual((stats.risk, stats.decision), ("HIGH", "BLOCK"))
        self.assertEqual(stats.bruteforce_bursts, 1)

    def test_four_failures_is_not_bruteforce(self):
        result = analyze([failed("203.0.113.5", s) for s in (0, 10, 20, 30)])
        self.assertFalse(result.ip_stats[0].is_bruteforce)
        self.assertEqual(result.ip_stats[0].risk, "MEDIUM")

    def test_slow_attempts_outside_window_are_not_bruteforce(self):
        lines = [failed("203.0.113.5", 0, minute=m) for m in (0, 10, 20, 30, 40, 50)]
        stats = analyze(lines).ip_stats[0]
        self.assertFalse(stats.is_bruteforce)
        self.assertEqual(stats.peak_in_window, 1)

    def test_window_and_threshold_are_configurable(self):
        lines = [failed("203.0.113.5", 0, minute=m) for m in (0, 4, 8)]
        self.assertFalse(analyze(lines).ip_stats[0].is_bruteforce)
        tuned = analyze(lines, threshold=3, window_minutes=10)
        self.assertTrue(tuned.ip_stats[0].is_bruteforce)

    def test_two_separate_bursts_are_counted_separately(self):
        first = [failed("203.0.113.5", s) for s in (0, 5, 10, 15, 20)]
        second = [failed("203.0.113.5", s, minute=30) for s in (0, 5, 10, 15, 20)]
        self.assertEqual(analyze(first + second).ip_stats[0].bruteforce_bursts, 2)

    def test_out_of_order_logs_are_sorted(self):
        lines = [failed("203.0.113.5", s) for s in (40, 0, 30, 10, 20)]
        self.assertTrue(analyze(lines).ip_stats[0].is_bruteforce)

    def test_ips_are_tracked_independently(self):
        lines = [failed("203.0.113.5", 0), failed("203.0.113.6", 1), failed("203.0.113.5", 2)]
        by_ip = {s.ip: s.failures for s in analyze(lines).ip_stats}
        self.assertEqual(by_ip, {"203.0.113.5": 2, "203.0.113.6": 1})

    def test_total_failures_alone_can_reach_high(self):
        lines = [failed("203.0.113.5", 0, minute=m) for m in range(0, 50, 5)]  # 10 slow failures
        stats = analyze(lines).ip_stats[0]
        self.assertFalse(stats.is_bruteforce)
        self.assertEqual((stats.risk, stats.decision), ("HIGH", "BLOCK"))

    def test_single_failure_is_low(self):
        stats = analyze([failed("203.0.113.5", 0)]).ip_stats[0]
        self.assertEqual((stats.risk, stats.decision), ("LOW", "ALLOW"))


class RobustnessTests(unittest.TestCase):
    def test_empty_log_does_not_crash(self):
        result = analyze([])
        self.assertEqual(result.failed_logins, 0)
        self.assertIn("No failed login events found.", render_text(result))
        self.assertIsNone(to_dict(result)["summary"]["first_event"])

    def test_malformed_lines_are_counted_not_fatal(self):
        lines = ["2026-13-45 99:99:99 Login FAILED for x from 10.0.0.1", failed("203.0.113.5", 0)]
        result = analyze(lines)
        self.assertEqual(result.malformed_lines, 1)
        self.assertEqual(result.failed_logins, 1)

    def test_invalid_settings_are_rejected(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)
        with self.assertRaises(ValueError):
            analyze([], window_minutes=0)
        with self.assertRaises(ValueError):
            analyze([], medium_threshold=10, high_threshold=3)

    def test_private_and_public_addresses(self):
        self.assertTrue(is_private_address("192.168.1.20"))
        self.assertTrue(is_private_address("10.0.0.5"))
        self.assertFalse(is_private_address("8.8.8.8"))
        self.assertFalse(is_private_address("203.0.113.45"))  # documentation range treated as public
        self.assertTrue(is_private_address("::1"))

    def test_username_counts_and_report_contents(self):
        lines = [failed("203.0.113.5", s, user=u) for s, u in enumerate(["root", "root", "admin", "root", "admin"])]
        result = analyze(lines)
        self.assertEqual(result.usernames.most_common(1), [("root", 3)])
        text = render_text(result)
        self.assertIn("203.0.113.5 -> BLOCK", text)
        self.assertIn("T1110", text)


if __name__ == "__main__":
    unittest.main()
