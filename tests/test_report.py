import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.report import save_report
from models.results import HostScanResult, PortScanResult, ScanReport


class ScanReportTests(unittest.TestCase):
    def test_to_json_contains_expected_fields(self):
        report = ScanReport(
            targets=["example.com"],
            scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_seconds=1.5,
            hosts=[
                HostScanResult(
                    target="example.com",
                    ip="93.184.216.34",
                    is_alive=True,
                    results=[PortScanResult(port=80, is_open=True, service_name="http")],
                )
            ],
        )

        payload = json.loads(report.to_json())

        self.assertEqual(payload["targets"], ["example.com"])
        self.assertEqual(payload["hosts"][0]["results"][0]["service_name"], "http")
        self.assertEqual(payload["summary"]["total_hosts_alive"], 1)
        self.assertEqual(payload["summary"]["total_closed_ports"], 0)

    def test_save_report_writes_both_formats_without_suffix(self):
        report_hosts = [
            HostScanResult(
                target="localhost",
                ip="127.0.0.1",
                is_alive=True,
                results=[PortScanResult(port=22, is_open=True, service_name="ssh")],
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "scan_report"
            saved_files = save_report(
                ["localhost"],
                report_hosts,
                2.0,
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                base_path,
            )

            self.assertEqual(len(saved_files), 2)
            self.assertTrue((Path(temp_dir) / "scan_report.json").exists())
            self.assertTrue((Path(temp_dir) / "scan_report.txt").exists())

    def test_to_text_includes_summary_fields(self):
        report = ScanReport(
            targets=["localhost"],
            scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_seconds=2.0,
            hosts=[
                HostScanResult(
                    target="localhost",
                    ip="127.0.0.1",
                    is_alive=True,
                    results=[PortScanResult(port=22, is_open=True, service_name="ssh")],
                )
            ],
        )

        text_report = report.to_text()

        self.assertIn("Hosts Unresponsive: 0", text_report)
        self.assertIn("Average Open Ports Per Alive Host: 1.00", text_report)
