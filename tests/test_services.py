import unittest

from core.services import identify_service


class IdentifyServiceTests(unittest.TestCase):
    def test_identify_known_service(self):
        self.assertEqual(identify_service(443), "https")

    def test_identify_unknown_service(self):
        self.assertEqual(identify_service(9999), "unknown")
