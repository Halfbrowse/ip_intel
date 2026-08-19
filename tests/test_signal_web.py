from __future__ import annotations

import unittest

import db.intel_db as intel_db
import sources.signal_web as sw
from sources.signal_web import (
    compute_favicon_hashes,
    extract_page_enrichment,
    find_favicon_urls,
    normalize_contact_phone,
    normalize_crypto_address,
    parse_ads_txt,
    parse_assetlinks,
    parse_homepage_html,
    parse_security_txt,
)


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

    def test_find_favicon_urls_ignores_malformed_entries(self) -> None:
        urls = find_favicon_urls(
            "https://example.com/",
            homepage_data={"favicon_links": ["broken", {"href": "/favicon-32.png"}]},
        )
        self.assertIn("https://example.com/favicon-32.png", urls)


BTC_P2PKH = "1AgcmCFT24sRuNMxDLjSpVAR8idLdfsGka"
BTC_P2SH = "3BNdgjjtZyBozY4PLSQ3F7XMHEv4Da7QYq"
BTC_BECH32 = "bc1qdgmn2pa023s70hqpf9x72dutvzqxehkn56aknx"
BTC_BECH32M = "bc1pprt4x8anym0sfc49dda8rwmp05mdm559hpex6qu4n3g35c4zt0cscwrntc"
BCH_CASHADDR = "qp4rwdg84a2xre7uq9y5mefh3dsgqmx76vade29k3q"
LTC_P2PKH = "LUua2QZH6j7VAB47PUik6WEBLvzcmYvEaS"
LTC_P2SH = "MSqUABvs9Q7mZEtfaJFPW1bFKLpEMaY6Ry"
LTC_BECH32 = "ltc1qe7mmpnn67zxgq3y8cr5z2g0ny6fj5tksr3zf9u"
DOGE = "DEpiJTC6KUmiSNYYwvj1NFL21rMdtDwgxB"
TRON = "TKepmFdBAnzP4YRaocPALdrZ3WNeoboqmR"
XRP = "rwgcmUETph1Ru4MxDLjSFVwR35dLdC1Gk2"
SOL = "EGKU7NfVypyKb6EUd3buMiyuW1cA5RCLAXggYuyCktCH"
XMR = "4AxSQnsnu8L3vR9P9DkWV5iT1CVYRZYFdYLEHCbT69cJ4snjCkNKqn6h3UPn6DBQQajGoJSRT9R8Kj54hyGzfGF47omudvt"
XMR_INTEGRATED = (
    "4Lf7RbhHWPr3vR9P9DkWV5iT1CVYRZYFdYLEHCbT69cJ4snjCkNKqn6h3UPn6DBQQajGoJSRT9R8Kj54hyGzfGF4BAu7XcpNJ4u4V4S4tz"
)
ETH_CHECKSUMMED = "0x7f9858A794697E0d679E93f7ad704FfADd971fc1"
ETH_LOWER = ETH_CHECKSUMMED.lower()


def _wallets(html: str) -> dict:
    return parse_homepage_html(html, page_url="https://example.com/")["crypto_wallets"]


class CryptoWalletExtractionTests(unittest.TestCase):
    def test_valid_addresses_are_extracted_and_keyed_by_chain(self) -> None:
        html = f"""
        <html><body>
          <p>BTC {BTC_P2PKH} or {BTC_P2SH}</p>
          <p>segwit {BTC_BECH32} taproot {BTC_BECH32M}</p>
          <p>BCH bitcoincash:{BCH_CASHADDR}</p>
          <p>LTC {LTC_P2PKH} / {LTC_P2SH} / {LTC_BECH32}</p>
          <p>DOGE {DOGE}</p>
          <p>TRX {TRON}</p>
          <p>XRP {XRP}</p>
          <p>XMR {XMR}</p>
          <p>XMR {XMR_INTEGRATED}</p>
          <p>SOL wallet {SOL}</p>
          <p>ETH: {ETH_CHECKSUMMED}</p>
        </body></html>
        """
        self.assertEqual(
            _wallets(html),
            {
                "bitcoin": sorted([BTC_P2PKH, BTC_P2SH, BTC_BECH32, BTC_BECH32M]),
                "bitcoin_cash": [BCH_CASHADDR],
                "dogecoin": [DOGE],
                "ethereum": [ETH_LOWER],
                "litecoin": sorted([LTC_P2PKH, LTC_P2SH, LTC_BECH32]),
                "monero": sorted([XMR, XMR_INTEGRATED]),
                "ripple": [XRP],
                "solana": [SOL],
                "tron": [TRON],
            },
        )

    def test_addresses_are_found_in_meta_tags_and_links(self) -> None:
        html = f"""
        <html><head>
          <meta name="donation:btc" content="{BTC_P2PKH}">
          <meta name="eth-wallet" content="{ETH_LOWER}">
        </head>
        <body><a href="https://etherscan.io/address/{TRON}">explorer</a></body></html>
        """
        self.assertEqual(_wallets(html), {"bitcoin": [BTC_P2PKH], "ethereum": [ETH_LOWER], "tron": [TRON]})

    def test_bip21_payment_uris_are_parsed(self) -> None:
        html = f"""
        <html><body>
          <a href="bitcoin:{BTC_P2PKH}?amount=0.015&label=Donate">Donate</a>
          <a href="litecoin:{LTC_P2PKH}">LTC</a>
          <a href="monero:{XMR}?tx_description=hi">XMR</a>
          <a href="ethereum:pay-{ETH_LOWER}@1/transfer">ETH</a>
        </body></html>
        """
        self.assertEqual(
            _wallets(html),
            {
                "bitcoin": [BTC_P2PKH],
                "ethereum": [ETH_LOWER],
                "litecoin": [LTC_P2PKH],
                "monero": [XMR],
            },
        )

    def test_checksum_corrupted_addresses_are_rejected(self) -> None:
        html = """
        <html><body>
          <p>BTC 1AgcmCFT24sRuNMxDLjSpVAR8idLdfsGkb</p>
          <p>segwit bc1qdgmn2pa023s70hqpf9x72dutvzqxehkn56akn8</p>
          <p>taproot bc1pprt4x8anym0sfc49dda8rwmp05mdm559hpex6qu4n3g35c4zt0cscwrnte</p>
          <p>BCH bitcoincash:qp4rwdg84a2xre7uq9y5mefh3dsgqmx76vade29k3p</p>
          <p>LTC LUua2QZH6j7VAB47PUik6WEBLvzcmYvEaT</p>
          <p>DOGE DEpiJTC6KUmiSNYYwvj1NFL21rMdtDwgxC</p>
          <p>TRX TKepmFdBAnzP4YRaocPALdrZ3WNeoboqmS</p>
          <p>XRP rwgcmUETph1Ru4MxDLjSFVwR35dLdC1Gkb</p>
          <p>XMR 4AxSQnsnu8L3vR9P9DkWV5iT1CVYRZYFdYLEHCbT69cJ4snjCkNKqn6h3UPn6DBQQajGoJSRT9R8Kj54hyGzfGF47omudvu</p>
          <p>ETH: 0x7F9858A794697E0d679E93f7ad704FfADd971fc1</p>
          <a href="bitcoin:1AgcmCFT24sRuNMxDLjSpVAR8idLdfsGkb?amount=1">donate</a>
        </body></html>
        """
        self.assertEqual(_wallets(html), {})

    def test_single_case_hex_is_not_treated_as_ethereum_without_context(self) -> None:
        html = """
        <html><body>
          <p>Build 0x8f3d1b0c9a5e2f7b4d6c8a0e1f2b3c4d5e6f7a8b from commit
             7f9858a794697e0d679e93f7ad704ffadd971fc1</p>
          <script src="/static/app.0X8F3D1B0C9A5E2F7B4D6C8A0E1F2B3C4D5E6F7A8B.js"></script>
        </body></html>
        """
        self.assertEqual(_wallets(html), {})

    def test_labelled_single_case_ethereum_is_accepted_once(self) -> None:
        html = f"""
        <html><body>
          <p>ETH wallet: {ETH_LOWER}</p>
          <p>same wallet, checksummed: {ETH_CHECKSUMMED}</p>
        </body></html>
        """
        self.assertEqual(_wallets(html), {"ethereum": [ETH_LOWER]})

    def test_solana_requires_an_explicit_label(self) -> None:
        self.assertEqual(_wallets(f"<html><body><p>build id {SOL}</p></body></html>"), {})
        self.assertEqual(
            _wallets(f'<html><body><a href="solana:{SOL}">pay</a></body></html>'),
            {"solana": [SOL]},
        )
        # Right length and alphabet, but does not decode to a 32-byte key.
        self.assertEqual(_wallets(f"<html><body><p>SOL wallet {'z' * 44}</p></body></html>"), {})

    def test_burn_and_documentation_addresses_are_rejected(self) -> None:
        html = """
        <html><body>
          <p>ETH wallet 0x0000000000000000000000000000000000000000</p>
          <p>ETH wallet 0x000000000000000000000000000000000000dEaD</p>
          <p>BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
          <p>BTC 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2</p>
          <p>BTC bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4</p>
          <p>TRX T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb</p>
          <a href="bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa">donate</a>
        </body></html>
        """
        self.assertEqual(_wallets(html), {})

    def test_pages_without_wallets_yield_an_empty_mapping(self) -> None:
        self.assertEqual(_wallets("<html><body><p>Contact us</p></body></html>"), {})
        self.assertEqual(parse_homepage_html("")["crypto_wallets"], {})

    def test_crypto_wallets_are_threaded_through_page_enrichment(self) -> None:
        enrichment = extract_page_enrichment(
            f"<html><body><p>BTC {BTC_P2PKH}</p></body></html>", base_url="https://example.com/"
        )
        self.assertEqual(enrichment["crypto_wallets"], {"bitcoin": [BTC_P2PKH]})


class SharedNormalizerTests(unittest.TestCase):
    """The normalizers every storage layer keys on (db.intel_db identifiers and
    selectors, core.analysis_service evidence values, utils.pairwise)."""

    def test_base58_wallet_case_is_preserved(self) -> None:
        # Base58Check encodes payload bytes in the case itself, so folding
        # yields a string that no longer decodes to a real address.
        for chain, address in (
            ("bitcoin", BTC_P2PKH),
            ("litecoin", LTC_P2PKH),
            ("tron", TRON),
            ("solana", SOL),
            ("monero", XMR),
        ):
            self.assertEqual(normalize_crypto_address(chain, address), address)

    def test_case_insensitive_encodings_are_folded(self) -> None:
        # Ethereum is hex (EIP-55 only overlays a checksum onto the case) and
        # bech32 is single-case, so one address has one key either way.
        self.assertEqual(
            normalize_crypto_address("ethereum", ETH_CHECKSUMMED),
            normalize_crypto_address("ethereum", ETH_LOWER),
        )
        self.assertEqual(normalize_crypto_address("bitcoin", BTC_BECH32.upper()), BTC_BECH32)

    def test_phone_international_prefixes_converge(self) -> None:
        self.assertEqual(normalize_contact_phone("+44 20 7946 0958"), "+442079460958")
        self.assertEqual(normalize_contact_phone("0044 20 7946 0958"), "+442079460958")

    def test_phone_placeholders_are_rejected(self) -> None:
        for placeholder in ("1234567890", "0000000000", "555-0100"):
            self.assertIsNone(normalize_contact_phone(placeholder))


class OperatorIdentityPrecisionTests(unittest.TestCase):
    """Identity extraction must describe the operator, not the vendors it names.

    Every case here is taken from a real pool entry whose privacy-policy
    boilerplate produced ~24 "legal entities" and ~20 "registered addresses"
    belonging to Google, Apple, Twitter, Disqus and a dozen ad networks. Because
    every site running the same consent text yields the same values, they became
    selectors shared by ~45 domains and linked unrelated sites to each other.
    """

    IMPRINT = "https://example.com/impressum"
    PRIVACY = "https://example.com/privacy-policy"

    def test_privacy_and_terms_pages_contribute_no_identity(self) -> None:
        for url in (self.PRIVACY, "https://example.com/privacy",
                    "https://example.com/terms", "https://example.com/datenschutz",
                    "https://example.com/legal/privacy-policy"):
            self.assertFalse(sw._is_operator_identity_page(url), url)

    def test_imprint_and_contact_pages_do_contribute_identity(self) -> None:
        for url in (self.IMPRINT, "https://example.com/imprint",
                    "https://example.com/legal", "https://example.com/kontakt",
                    "https://example.com/about"):
            self.assertTrue(sw._is_operator_identity_page(url), url)

    def test_page_class_is_judged_after_redirects(self) -> None:
        # extract_legal_page_signals is handed response.url, so a /legal that
        # lands on a privacy policy is treated as the privacy policy it is.
        html = "<html><body><p>Beispiel Medien GmbH</p></body></html>"
        landed = sw.extract_legal_page_signals(html, page_url=self.PRIVACY)
        self.assertEqual(landed["entity_names"], [])
        self.assertTrue(landed["normalized_text_hash"], "the page hash is still recorded")

    def test_processor_names_in_boilerplate_are_rejected(self) -> None:
        text = (
            "Impressum\n"
            "Betreiber: Beispiel Medien GmbH\n"
            "Taboola, Inc. and Spot.IM Ltd process comments.\n"
            "PubMatic, Inc. and Casale Media Inc serve ads.\n"
            "Google LLC provides analytics. Disqus, Inc. hosts comments.\n"
        )
        self.assertEqual(sw._extract_entity_names(text), ["Beispiel Medien GmbH"])

    def test_entity_names_do_not_span_a_line_break(self) -> None:
        # "\s+" between words matched newlines, gluing the operator to whatever
        # company was named on the next line.
        text = "Beispiel Medien GmbH\nTaboola, Inc.\n"
        self.assertEqual(sw._extract_entity_names(text), ["Beispiel Medien GmbH"])

    def test_entity_name_does_not_swallow_a_preceding_url_path(self) -> None:
        text = "See gb/privacy/privacy-policy/ Buchhandel Beispiel GmbH for details.\n"
        for name in sw._extract_entity_names(text):
            self.assertNotIn("/", name)

    def test_a_sentence_containing_a_street_word_is_not_an_address(self) -> None:
        text = (
            "Wenn Sie unsere Webseite nutzen, koennen Sie das Kommentarsystem "
            "Disqus (Disqus, Inc., 717 Market Street, Suite 700, San Francisco, "
            "CA 94103, USA) verwenden, um Kommentare zu hinterlassen und Ihre "
            "Erfahrungen mit anderen Nutzern zu teilen.\n"
        )
        self.assertEqual(sw._extract_addresses(text), [])

    def test_identity_values_are_capped(self) -> None:
        text = "".join(f"Beispielfirma Nummer{n} GmbH\n" for n in range(20))
        self.assertLessEqual(len(sw._extract_entity_names(text)), sw._MAX_IDENTITY_VALUES)


class ScrapedPhonePrecisionTests(unittest.TestCase):
    """Digit runs scraped from prose are mostly not phone numbers."""

    def test_bare_digit_runs_are_rejected(self) -> None:
        # Observed verbatim as "shared phone numbers" across ~45 domains that
        # merely embedded the same widgets.
        for junk in ("6789156", "1717103", "7768119", "3220216", "155833707900388"):
            self.assertEqual(sw._filter_phones([junk]), [], junk)

    def test_dialable_numbers_are_kept(self) -> None:
        for real in ("+74997500075", "030 12345678", "(495) 750-00-75", "+44 20 7946 0958"):
            self.assertEqual(sw._filter_phones([real]), [real], real)


class StoredPayloadReprojectionTests(unittest.TestCase):
    """Boilerplate must be filtered when *replaying* stored scans, not just at
    capture.

    Observations are append-only and no scan supersedes an earlier one, so a
    result captured before the extractor was fixed keeps re-projecting its
    privacy-policy boilerplate on every rebuild. Fixing extraction alone left
    the graph unchanged; this is the half that actually cleans it.
    """

    DIRTY = {
        "legal_pages": {
            # Flattened aggregate: a union across all pages, provenance gone.
            "entity_names": ["Google LLC", "Apple Inc", "Beispiel Medien GmbH"],
            "registration_ids": ["uid", "uid-bp", "HRB 12345"],
            "pages": [
                {
                    "url": "https://example.com/impressum",
                    "entity_names": ["Beispiel Medien GmbH"],
                    "addresses": ["Musterstr. 12, 10115 Berlin"],
                    "registration_ids": ["HRB 12345"],
                    "normalized_text_hash": "a" * 64,
                },
                {
                    "url": "https://example.com/privacy-policy",
                    "entity_names": ["Google LLC", "Disqus, Inc", "OpenX Technologies Inc"],
                    "addresses": ["Google LLC., 1600 Amphitheatre Parkway, "
                                  "Mountain View, CA 94043, USA"],
                    "registration_ids": ["uid", "uid-bp"],
                    "normalized_text_hash": "b" * 64,
                },
            ],
        }
    }

    def test_only_the_imprint_contributes_identity(self) -> None:
        signals = intel_db._legal_page_signals(self.DIRTY)
        self.assertEqual(signals.get("legal_entity"), ["beispiel medien gmbh"])
        self.assertEqual(signals.get("legal_address"), ["musterstr. 12, 10115 berlin"])
        self.assertEqual(signals.get("legal_registration"), ["hrb 12345"])

    def test_page_hashes_are_kept_for_every_page(self) -> None:
        # The hash describes the page itself, so it is not identity-scoped.
        self.assertEqual(len(intel_db._legal_page_signals(self.DIRTY)["legal_text_hash"]), 2)

    def test_aggregate_only_payload_still_filters_vendors(self) -> None:
        # Older payloads have no per-page entries at all, so provenance cannot
        # be recovered and the value itself has to carry the decision.
        signals = intel_db._legal_page_signals({"legal_pages": {
            "entity_names": ["Google LLC", "Beispiel Medien GmbH"],
            "addresses": ["Google LLC., 1600 Amphitheatre Parkway, Mountain View, CA 94043, USA",
                          "Musterstr. 12, 10115 Berlin"],
        }})
        self.assertEqual(signals.get("legal_entity"), ["beispiel medien gmbh"])
        self.assertEqual(signals.get("legal_address"), ["musterstr. 12, 10115 berlin"])

    def test_prose_registration_ids_are_rejected(self) -> None:
        # Results stored before _extract_registration_ids was narrowed to
        # structured tokens hold whole clauses. A registration number is the
        # heaviest selector there is, so a fragment like "business" shared
        # across ten sites would assert ten false ownership matches.
        signals = intel_db._legal_page_signals({"legal_pages": {
            "registration_ids": ["business", "site data", "announcements & company news",
                                 "Ltd , a company incorporated in England and Wales.",
                                 "HRB 12345", "DE123456789"],
        }})
        self.assertEqual(signals.get("legal_registration"), ["hrb 12345", "de123456789"])


class LegalPageSelectorTests(unittest.TestCase):
    """Imprint/legal-page identity projected into correlation selectors."""

    ENTRY = {
        "url": "https://example.com/impressum",
        "normalized_text_hash": "b" * 64,
        "entity_names": ["Example Trading GmbH", "Ltd"],
        "registration_ids": ["HRB 12345"],
        "addresses": ["Hauptstrasse 1, 10115 Berlin", "Office"],
        "phones": ["+49 30 1234567", "1234567890"],
        "emails": ["kontakt@example.com", "abuse@godaddy.com"],
    }

    def _signals(self, legal):
        from db.intel_db import _legal_page_signals

        return _legal_page_signals({"legal_pages": legal})

    def test_every_legal_signal_becomes_a_selector(self) -> None:
        signals = self._signals({"pages": [self.ENTRY]})
        self.assertEqual(
            set(signals),
            {"contact_phone", "contact_email", "legal_entity",
             "legal_registration", "legal_address", "legal_text_hash"},
        )

    def test_junk_values_are_not_selectors(self) -> None:
        signals = self._signals({"pages": [self.ENTRY]})
        # A template phone, a registrar role address, and bare parsing
        # fragments would each link two unrelated sites on nothing.
        self.assertNotIn("1234567890", signals["contact_phone"])
        self.assertEqual(signals["contact_email"], ["kontakt@example.com"])
        self.assertEqual(signals["legal_entity"], ["example trading gmbh"])
        self.assertEqual(signals["legal_address"], ["hauptstrasse 1, 10115 berlin"])

    def test_both_payload_shapes_are_accepted(self) -> None:
        # The aggregated dict core.analysis_service writes, and the older bare
        # list of per-page entries.
        from_dict = self._signals({"pages": [self.ENTRY]})
        from_list = self._signals([self.ENTRY])
        self.assertEqual(from_dict["legal_registration"], from_list["legal_registration"])
        self.assertEqual(self._signals({}), {})

    def test_every_kind_has_a_weight_and_an_explanation(self) -> None:
        from utils.check import _explain_selector
        from utils.evidence_meta import SELECTOR_BASE_WEIGHTS

        for kind in self._signals({"pages": [self.ENTRY]}):
            self.assertIn(kind, SELECTOR_BASE_WEIGHTS)
            self.assertTrue(_explain_selector(kind, None))


if __name__ == "__main__":
    unittest.main()
