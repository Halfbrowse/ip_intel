from __future__ import annotations

import unittest

from signal_web import compute_favicon_hashes, extract_page_enrichment, parse_ads_txt, parse_assetlinks, parse_security_txt


class SignalWebTests(unittest.TestCase):
    def test_extract_page_enrichment(self) -> None:
        html = """
        <html lang="en">
          <head>
            <meta property="fb:app_id" content="12345">
            <meta name="twitter:site" content="@example">
            <meta name="author" content="Example GmbH">
            <script src="/_next/static/chunk.js"></script>
          </head>
          <body>pub-1234567890123456<link rel="me" href="https://social.example/@team"></body>
        </html>
        """
        parsed = extract_page_enrichment(html, base_url="https://example.com/")
        self.assertEqual(parsed["fb_app_id"], ["12345"])
        self.assertEqual(parsed["twitter_site"], ["@example"])
        self.assertIn("pub-1234567890123456", parsed["adsense_publisher_ids"])
        self.assertIn("https://social.example/@team", parsed["rel_me"])
        self.assertIn("https://example.com/_next/static/chunk.js", parsed["script_assets"])

    def test_parse_ads_txt(self) -> None:
        parsed = parse_ads_txt("google.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0")
        self.assertEqual(parsed["publisher_ids"], ["pub-1234567890123456"])
        self.assertEqual(parsed["records"][0]["seller_domain"], "google.com")

    def test_parse_assetlinks(self) -> None:
        parsed = parse_assetlinks(
            '[{"target":{"namespace":"android_app","package_name":"com.example.app","sha256_cert_fingerprints":["AB:CD"]}}]'
        )
        self.assertEqual(parsed["android_apps"][0]["package_name"], "com.example.app")

    def test_parse_security_txt(self) -> None:
        parsed = parse_security_txt("Contact: mailto:security@example.com\nContact: https://example.com/security")
        self.assertEqual(parsed["contacts"], ["mailto:security@example.com", "https://example.com/security"])

    def test_compute_favicon_hashes(self) -> None:
        hashes = compute_favicon_hashes(b"favicon")
        self.assertIsNotNone(hashes["favicon_md5"])


if __name__ == "__main__":
    unittest.main()
