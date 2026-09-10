import struct
import unittest
from unittest.mock import patch

from core.dns import _build_query, _parse_response, enumerate_dns, reverse_dns


class DnsTests(unittest.TestCase):
    def test_build_query_contains_target_and_record_type(self):
        query = _build_query("example.com", 1234, 1)

        self.assertEqual(struct.unpack("!H", query[:2])[0], 1234)
        self.assertIn(b"\x07example\x03com\x00", query)
        self.assertEqual(query[-4:-2], b"\x00\x01")

    @patch("core.dns.reverse_dns", return_value=["host.example.com"])
    @patch("core.dns.query_dns")
    def test_enumerate_dns_collects_records_and_reverse_dns(
        self,
        mock_query_dns,
        mock_reverse_dns,
    ):
        mock_query_dns.side_effect = lambda target, record_type, timeout: {
            "A": ["93.184.216.34"],
            "AAAA": [],
            "CNAME": ["www.example.com"],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com"],
            "TXT": ["v=example"],
        }[record_type]

        result = enumerate_dns("example.com")

        self.assertEqual(result.records["A"], ["93.184.216.34"])
        self.assertEqual(result.records["CNAME"], ["www.example.com"])
        self.assertEqual(result.reverse_dns["93.184.216.34"], ["host.example.com"])
        self.assertEqual(mock_reverse_dns.call_count, 1)

    @patch("core.dns.socket.gethostbyaddr", side_effect=OSError("not found"))
    def test_reverse_dns_raises_clean_os_error(self, mock_gethostbyaddr):
        with self.assertRaises(OSError):
            reverse_dns("192.0.2.1")

        mock_gethostbyaddr.assert_called_once_with("192.0.2.1")

    def test_parse_response_rejects_short_packet(self):
        with self.assertRaises(ValueError):
            _parse_response(b"short", 1, "A")
