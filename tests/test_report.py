import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from core.report import save_report
from models.results import PortScanResult, ScanReport


class ScanReportTests(unittest.TestCase):
    def test_to_json_contains_expected_fields(self):
        report = ScanReport(
            target="example.com",
            ip="93.184.216.34",
            scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            results=[PortScanResult(port=80, is_open=True, service_name="http")],
        )

        payload = json.loads(report.to_json())

        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(payload["results"][0]["service_name"], "http")

    def test_save_report_writes_both_formats_without_suffix(self):
        report_results = [PortScanResult(port=22, is_open=True, service_name="ssh")]

        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "scan_report"
            saved_files = save_report("localhost", "127.0.0.1", report_results, base_path)

            self.assertEqual(len(saved_files), 2)
            self.assertTrue((Path(temp_dir) / "scan_report.json").exists())
            self.assertTrue((Path(temp_dir) / "scan_report.txt").exists())
