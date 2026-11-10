
import unittest
from unittest.mock import patch

from url_tls.redirect_analyzer import analyze_redirects


class TestRedirectAnalyzer(unittest.TestCase):

    @patch("url_tls.redirect_analyzer.fetch_response_headers")
    def test_relative_redirect(self, mock_fetch):
        mock_fetch.side_effect = [
            (302, {"location": ["/home"]}),
            (200, {})
        ]

        result = analyze_redirects("https://example.com")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["redirects"]), 1)
        self.assertEqual(
            result["final_url"],
            "https://example.com/home"
        )

    @patch("url_tls.redirect_analyzer.fetch_response_headers")
    def test_redirect_loop(self, mock_fetch):
        mock_fetch.return_value = (
            302,
            {"location": ["https://example.com"]}
        )

        result = analyze_redirects("https://example.com")

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("redirect_loop", indicators)

    @patch("url_tls.redirect_analyzer.fetch_response_headers")
    def test_invalid_redirect_scheme(self, mock_fetch):
        mock_fetch.return_value = (
            302,
            {"location": ["javascript:alert(1)"]}
        )

        result = analyze_redirects("https://example.com")

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(mock_fetch.call_count, 1)

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("invalid_redirect_destination", indicators)

    @patch("url_tls.redirect_analyzer.fetch_response_headers")
    def test_unsafe_redirect_destination(self, mock_fetch):
        mock_fetch.side_effect = [
            (302, {"location": ["http://127.0.0.1"]}),
            PermissionError("Unsafe destination IP rejected")
        ]

        result = analyze_redirects("https://example.com")

        self.assertEqual(result["status"], "blocked")

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("unsafe_redirect_destination", indicators)


    @patch("url_tls.redirect_analyzer.fetch_response_headers")
    def test_malicious_redirect_header(self, mock_fetch):
        mock_fetch.return_value = (
            302,
            {"location": ["https://example.com/\r\nInjected-Header: malicious"]}
        )

        result = analyze_redirects("https://example.com")

        self.assertEqual(result["status"], "blocked")

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("invalid_redirect_destination", indicators)

        finding = next(
            finding for finding in result["findings"]
            if finding["indicator"] == "invalid_redirect_destination"
        )

        self.assertEqual(finding["severity"], "high")
        self.assertEqual(mock_fetch.call_count, 1)

if __name__ == "__main__":
    unittest.main()

