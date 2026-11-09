import unittest

from url_tls.url_analyzer import validate_and_analyze_url


class TestURLAnalyzer(unittest.TestCase):

    # Benign URL tests

    def test_wikipedia_url(self):
        result = validate_and_analyze_url(
            "https://www.wikipedia.org"
        )
        self.assertTrue(result["valid"])

    def test_github_url(self):
        result = validate_and_analyze_url(
            "https://github.com"
        )
        self.assertTrue(result["valid"])

    def test_example_url(self):
        result = validate_and_analyze_url(
            "https://example.com"
        )
        self.assertTrue(result["valid"])

    # Suspicious URL tests

    def test_typosquatting_detection(self):
        result = validate_and_analyze_url(
            "https://paypa1.com/login"
        )

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("possible_typosquatting", indicators)

    def test_suspicious_keyword_detection(self):
        result = validate_and_analyze_url(
            "https://example.com/login"
        )

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("suspicious_keywords", indicators)

    def test_private_ip_detection(self):
        result = validate_and_analyze_url(
            "http://192.168.1.10"
        )

        indicators = [
            finding["indicator"]
            for finding in result["findings"]
        ]

        self.assertIn("ip_address_url", indicators)


if __name__ == "__main__":
    unittest.main()