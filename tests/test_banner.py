import unittest
from unittest.mock import patch

from core.banner import _normalize_banner, grab_banner


class GrabBannerTests(unittest.TestCase):
    @patch("core.banner.socket.socket")
    def test_skip_banner_grab_for_tls_port(self, mock_socket):
        banner = grab_banner("127.0.0.1", 443, timeout=1.0)

        self.assertIsNone(banner)
        mock_socket.assert_not_called()

    def test_normalize_banner_flattens_lines(self):
        banner = _normalize_banner("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n")

        self.assertEqual(banner, "HTTP/1.1 200 OK | Server: Apache")
