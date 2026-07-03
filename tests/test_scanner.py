import unittest
from unittest.mock import patch

from core.scanner import discover_host, parse_ports, scan_port_details, scan_ports, scan_targets


class ParsePortsTests(unittest.TestCase):
    def test_parse_ports_supports_values_and_ranges(self):
        self.assertEqual(parse_ports("80, 22, 1000-1002"), [22, 80, 1000, 1001, 1002])

    def test_parse_ports_rejects_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-10")


class ScanPortsTests(unittest.TestCase):
    @patch("core.scanner.grab_banner", return_value="SSH-2.0-Test")
    @patch("core.scanner.identify_service", return_value="ssh")
    @patch("core.scanner.scan_port", return_value=True)
    def test_scan_port_details_returns_dataclass(
        self,
        mock_scan_port,
        mock_identify_service,
        mock_grab_banner,
    ):
        result = scan_port_details("127.0.0.1", 22, 1.0)

        self.assertTrue(result.is_open)
        self.assertEqual(result.port, 22)
        self.assertEqual(result.service_name, "ssh")
        self.assertEqual(result.banner, "SSH-2.0-Test")
        mock_scan_port.assert_called_once()
        mock_identify_service.assert_called_once_with(22)
        mock_grab_banner.assert_called_once_with(ip="127.0.0.1", port=22, timeout=1.0)

    @patch("core.scanner.scan_port_details")
    def test_scan_ports_returns_sorted_results(self, mock_scan_port_details):
        mock_scan_port_details.side_effect = [
            type("Result", (), {"port": 443})(),
            type("Result", (), {"port": 22})(),
        ]

        results = scan_ports("127.0.0.1", [443, 22], timeout=1.0, max_workers=2)

        self.assertEqual([item.port for item in results], [22, 443])

    @patch("core.scanner.scan_port", side_effect=[False, True])
    def test_discover_host_returns_true_when_any_probe_succeeds(self, mock_scan_port):
        self.assertTrue(discover_host("127.0.0.1", [22, 80], timeout=1.0))
        self.assertEqual(mock_scan_port.call_count, 2)

    @patch("core.scanner.scan_target")
    def test_scan_targets_creates_report_summary(self, mock_scan_target):
        host_one = type(
            "HostResult",
            (),
            {
                "target": "127.0.0.1",
                "ip": "127.0.0.1",
                "is_alive": True,
                "results": [type("Result", (), {"is_open": True})()],
                "open_port_count": 1,
                "closed_port_count": 0,
                "error": None,
            },
        )()
        host_two = type(
            "HostResult",
            (),
            {
                "target": "example.com",
                "ip": "93.184.216.34",
                "is_alive": False,
                "results": [],
                "open_port_count": 0,
                "closed_port_count": 0,
                "error": None,
            },
        )()
        mock_scan_target.side_effect = [host_one, host_two]

        report = scan_targets(["127.0.0.1", "example.com"], [80], timeout=1.0, max_workers=5)

        self.assertEqual(report.summary.total_hosts_scanned, 2)
        self.assertEqual(report.summary.total_hosts_alive, 1)
        self.assertEqual(report.summary.total_open_ports, 1)
