
import unittest
from unittest.mock import patch

from url_tls.analyzer import analyze_url_tls


class TestIntegratedAnalyzer(unittest.TestCase):

    @patch("url_tls.analyzer.analyze_redirects")
    @patch("url_tls.analyzer.analyze_tls")
    @patch("url_tls.analyzer.analyze_domain")
    def test_successful_analysis(
        self, mock_domain, mock_tls, mock_redirect
    ):
        mock_domain.return_value = {
            "status": "completed",
            "destination_safety": "safe",
            "findings": [],
            "limitations": []
        }

        mock_tls.return_value = {
            "status": "completed",
            "findings": [],
            "limitations": []
        }

        mock_redirect.return_value = {
            "status": "completed",
            "findings": [],
            "limitations": []
        }

        result = analyze_url_tls("https://example.com")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["module"], "url_tls")
        self.assertIn("url_analysis", result["details"])
        self.assertIn("domain_analysis", result["details"])
        self.assertIn("tls_analysis", result["details"])
        self.assertIn("redirect_analysis", result["details"])

    @patch("url_tls.analyzer.analyze_domain")
    def test_unsafe_destination_blocked(self, mock_domain):
        mock_domain.return_value = {
            "status": "completed",
            "destination_safety": "blocked",
            "findings": [
                {
                    "indicator": "unsafe_ip_destination",
                    "severity": "high",
                    "evidence": "Private IP rejected.",
                    "source": "domain_analyzer"
                }
            ],
            "limitations": []
        }

        result = analyze_url_tls("http://127.0.0.1")

        self.assertEqual(result["status"], "blocked")
        self.assertIn(
            "unsafe_ip_destination",
            [f["indicator"] for f in result["findings"]]
        )

    @patch("url_tls.analyzer.analyze_domain")
    @patch("url_tls.analyzer.analyze_tls")
    @patch("url_tls.analyzer.analyze_redirects")
    def test_invalid_scheme_stops_analysis(
        self, mock_redirect, mock_tls, mock_domain
    ):
        result = analyze_url_tls("javascript:alert(1)")

        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["details"]["url_analysis"]["valid"])

        mock_domain.assert_not_called()
        mock_tls.assert_not_called()
        mock_redirect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
