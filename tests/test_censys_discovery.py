from __future__ import annotations

import unittest
from unittest import mock

from core import analysis_service
from sources import censys_discovery


def _hit(hostname: str, endpoint_hostnames: list[str] | None = None) -> dict:
    return {
        "webproperty_v1": {
            "resource": {
                "hostname": hostname,
                "port": 443,
                "endpoints": [{"hostname": name} for name in (endpoint_hostnames or [])],
            }
        }
    }


class _FakeGlobalData:
    """Stands in for sdk.global_data — records queries, replays fixture pages."""

    def __init__(self, pages_by_query: dict[str, list[dict]]):
        self.pages_by_query = pages_by_query
        self.queries: list[str] = []
        self._page_index: dict[str, int] = {}

    def search(self, *, search_query_input_body: dict) -> object:
        query = search_query_input_body["query"]
        self.queries.append(query)
        index = self._page_index.get(query, 0)
        self._page_index[query] = index + 1
        pages = self.pages_by_query.get(query) or [{"total_hits": 0, "hits": []}]
        page = pages[min(index, len(pages) - 1)]
        return mock.Mock(result={"result": page})


class _FakeSDK:
    def __init__(self, global_data: _FakeGlobalData):
        self.global_data = global_data

    def __enter__(self) -> "_FakeSDK":
        return self

    def __exit__(self, *exc) -> bool:
        return False


class SelectorCollectionTests(unittest.TestCase):
    def test_tracking_and_content_selectors_use_verified_fields(self) -> None:
        # candidate_selectors, not collect_selectors: this asserts the *field
        # mapping* for every supported selector kind, and collect_selectors now
        # deliberately returns only the two it will spend credits on.
        selectors = censys_discovery.candidate_selectors(
            {
                "google_analytics": ["UA-12345-1"],
                "gtm_ids": ["GTM-ABC"],
                "facebook_pixel": ["998877"],
                "yandex_metrika": ["424242"],
                "tiktok_pixel": ["TT-1"],
                "adsense_publisher_ids": ["pub-1234567890123456"],
                "favicon_md5": ["d41d8cd98f00b204e9800998ecf8427e"],
                "favicon_murmurhash3": -1234567890,
            }
        )
        by_kind = {item["kind"]: item for item in selectors}

        for kind in ("ga_property", "gtm_container", "fb_pixel", "yandex_metrika",
                     "tiktok_pixel", "adsense_publisher"):
            self.assertEqual(
                by_kind[kind]["field"],
                "web.endpoints.extracted.analytics_services.ids",
            )
        self.assertEqual(
            by_kind["favicon_md5"]["field"], "web.endpoints.http.favicons.hash_md5"
        )
        self.assertEqual(
            by_kind["favicon_mmh3"]["field"], "web.endpoints.http.favicons.hash_shodan"
        )
        self.assertEqual(
            by_kind["ga_property"]["query"],
            'web.endpoints.extracted.analytics_services.ids = "UA-12345-1"',
        )
        # murmurhash3 is an integer field: quoting it would not match.
        self.assertEqual(
            by_kind["favicon_mmh3"]["query"],
            "web.endpoints.http.favicons.hash_shodan = -1234567890",
        )

    def test_normalized_text_hash_is_not_wired_to_body_hash(self) -> None:
        # homepage_html_hash is a hash of extracted text, not the raw HTTP body,
        # so it can never match Censys' body_hash_sha256 — it must not produce a
        # query that would silently always return nothing.
        selectors = censys_discovery.collect_selectors({"homepage_html_hash": "a" * 64})
        self.assertEqual(selectors, [])

    def test_one_query_per_class_however_many_selectors_the_page_carries(self) -> None:
        # 50 tag-manager containers plus a favicon is 51 possible searches. The
        # bill must be two: one tracking, one content.
        meta = {
            "gtm_ids": [f"GTM-{n}" for n in range(50)],
            "favicon_sha256": ["b" * 64],
        }
        self.assertEqual(len(censys_discovery.candidate_selectors(meta)), 51)

        selectors = censys_discovery.collect_selectors(meta)
        self.assertEqual(len(selectors), censys_discovery.MAX_SELECTORS_PER_SCAN)
        self.assertEqual(
            sorted(item["selector_class"] for item in selectors),
            ["content", "tracking"],
        )

    def test_a_class_with_no_selectors_costs_nothing(self) -> None:
        # A page with only a favicon must spend one credit, not two: the cap is
        # a ceiling per class, not a quota to fill.
        selectors = censys_discovery.collect_selectors({"favicon_sha256": ["c" * 64]})
        self.assertEqual([item["selector_class"] for item in selectors], ["content"])

    def test_selectors_known_to_be_useless_lose_to_unqueried_ones(self) -> None:
        # Ranking is not "rarest first". A selector Censys has only ever seen on
        # one property (us) can return no new domain, so it must rank below one
        # whose prevalence we have never measured — even though it is rarer.
        candidates = censys_discovery.candidate_selectors(
            {"google_analytics": ["UA-SEEN-ONCE"], "gtm_ids": ["GTM-UNKNOWN"]}
        )
        ranked = censys_discovery.rank_selectors(
            candidates, {("ga_property", "UA-SEEN-ONCE"): 1}
        )
        self.assertEqual(ranked[0]["value"], "GTM-UNKNOWN")

    def test_the_useful_prevalence_band_outranks_everything(self) -> None:
        # 2..MAX_GLOBAL_HITS_TO_EXPAND is where a hit is evidence of shared
        # operation. It must beat both the unmeasured and the promiscuous.
        candidates = censys_discovery.candidate_selectors(
            {"google_analytics": ["UA-SHARED"], "gtm_ids": ["GTM-EVERYWHERE"],
             "facebook_pixel": ["111"]}
        )
        ranked = censys_discovery.rank_selectors(
            candidates,
            {
                ("ga_property", "UA-SHARED"): 6,
                ("gtm_container", "GTM-EVERYWHERE"):
                    censys_discovery.MAX_GLOBAL_HITS_TO_EXPAND + 1,
            },
        )
        self.assertEqual(ranked[0]["value"], "UA-SHARED")
        self.assertEqual(ranked[-1]["value"], "GTM-EVERYWHERE")

    def test_no_selectors_skips(self) -> None:
        result = censys_discovery.reverse_lookup({})
        self.assertTrue(result["skipped"])
        self.assertIn("no pivotable selectors", result["reason"])


class IpLiteralDiscoveryTests(unittest.TestCase):
    """Censys web properties are routinely keyed on a bare IP, not a hostname."""

    def test_apex_never_truncates_an_ip(self) -> None:
        from core import basic

        for ip in ("78.17.42.166", "2.26.109.159", "2001:db8::1"):
            self.assertEqual(basic._apex(ip), ip)

    def test_ip_keyed_web_properties_are_typed_as_ips_not_domains(self) -> None:
        from core import basic

        lookup = {
            "selectors": [
                {
                    "kind": "favicon_mmh3",
                    "value": "133209292",
                    "global_hits": 25,
                    "hostnames": ["78.17.42.166", "cdn.msimonyan.ru"],
                }
            ]
        }
        by_target = {
            c["target"]: c
            for c in censys_discovery.discovered_domains(lookup, "rt.com", basic._apex)
        }
        # The IP survives whole and is typed as one...
        self.assertEqual(by_target["78.17.42.166"]["target_type"], "ip")
        # ...instead of being mangled into the "domain" 42.166.
        self.assertNotIn("42.166", by_target)
        self.assertEqual(by_target["msimonyan.ru"]["target_type"], "domain")


class CredentialTests(unittest.TestCase):
    def test_missing_credentials_degrade_to_skipped(self) -> None:
        meta = {"favicon_md5": ["abc"]}
        with mock.patch.dict("os.environ", {"CENSYS_ORG_ID": "x"}, clear=False):
            with mock.patch.dict("os.environ", {}, clear=False):
                import os

                os.environ.pop("CENSYS_API_KEY", None)
                result = censys_discovery.reverse_lookup(meta)
        self.assertTrue(result["skipped"])
        self.assertIn("CENSYS_API_KEY", result["reason"])


class ReverseLookupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = mock.patch.dict(
            "os.environ", {"CENSYS_API_KEY": "t", "CENSYS_ORG_ID": "o"}, clear=False
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    def _run(self, meta: dict, pages_by_query: dict) -> tuple[dict, _FakeGlobalData]:
        global_data = _FakeGlobalData(pages_by_query)
        with mock.patch.dict(
            "sys.modules", {"censys_platform": mock.Mock(SDK=lambda **kw: _FakeSDK(global_data))}
        ):
            return censys_discovery.reverse_lookup(meta), global_data

    def test_captures_total_hits_and_hostnames(self) -> None:
        query = 'web.endpoints.extracted.analytics_services.ids = "UA-1"'
        result, global_data = self._run(
            {"google_analytics": ["UA-1"]},
            {query: [{"total_hits": 4, "hits": [_hit("www.other.com"), _hit("shop.other.com"), _hit("third.net")]}]},
        )
        selector = result["selectors"][0]
        self.assertEqual(global_data.queries, [query])
        self.assertEqual(selector["global_hits"], 4)
        self.assertEqual(
            selector["hostnames"], ["www.other.com", "shop.other.com", "third.net"]
        )

    def test_promiscuous_selector_records_count_but_harvests_nothing(self) -> None:
        query = 'web.endpoints.extracted.analytics_services.ids = "UA-1"'
        over = censys_discovery.MAX_GLOBAL_HITS_TO_EXPAND + 1
        result, global_data = self._run(
            {"google_analytics": ["UA-1"]},
            {query: [{"total_hits": over, "hits": [_hit("noise.com")], "next_page_token": "p2"}]},
        )
        selector = result["selectors"][0]
        self.assertEqual(selector["global_hits"], over)
        self.assertEqual(selector["hostnames"], [])
        self.assertIn("too common", selector["skipped_expansion"])
        # One page only — the whole point is not paying to paginate it.
        self.assertEqual(len(global_data.queries), 1)

    def test_pagination_is_capped(self) -> None:
        query = 'web.endpoints.http.favicons.hash_md5 = "abc"'
        page = {
            "total_hits": 400,
            "hits": [_hit("a.com")],
            "next_page_token": "more",
        }
        _, global_data = self._run({"favicon_md5": ["abc"]}, {query: [page]})
        self.assertEqual(len(global_data.queries), censys_discovery.MAX_PAGES_PER_SELECTOR)

    def test_domains_per_selector_capped(self) -> None:
        query = 'web.endpoints.http.favicons.hash_md5 = "abc"'
        hits = [_hit(f"host{n}.example{n}.com") for n in range(200)]
        result, _ = self._run(
            {"favicon_md5": ["abc"]}, {query: [{"total_hits": 200, "hits": hits}]}
        )
        self.assertEqual(
            len(result["selectors"][0]["hostnames"]),
            censys_discovery.MAX_DOMAINS_PER_SELECTOR,
        )
        self.assertTrue(result["selectors"][0]["truncated"])

    def test_selector_error_does_not_abort_other_selectors(self) -> None:
        good_query = 'web.endpoints.http.favicons.hash_md5 = "abc"'

        class _Boom(_FakeGlobalData):
            def search(self, *, search_query_input_body):
                if "analytics_services" in search_query_input_body["query"]:
                    raise RuntimeError("tier does not allow search")
                return super().search(search_query_input_body=search_query_input_body)

        global_data = _Boom({good_query: [{"total_hits": 2, "hits": [_hit("b.com")]}]})
        with mock.patch.dict(
            "sys.modules", {"censys_platform": mock.Mock(SDK=lambda **kw: _FakeSDK(global_data))}
        ):
            result = censys_discovery.reverse_lookup(
                {"google_analytics": ["UA-1"], "favicon_md5": ["abc"]}
            )
        by_kind = {item["kind"]: item for item in result["selectors"]}
        self.assertIn("tier does not allow", by_kind["ga_property"]["error"])
        self.assertEqual(by_kind["favicon_md5"]["hostnames"], ["b.com"])


class DiscoveredDomainTests(unittest.TestCase):
    def _apex(self, host: str) -> str:
        from core import basic

        return basic._apex(host)

    def test_rolls_up_to_registrable_domain_and_drops_origin(self) -> None:
        lookup = {
            "selectors": [
                {
                    "kind": "ga_property",
                    "value": "UA-1",
                    "field": censys_discovery.TRACKING_ID_FIELD,
                    "global_hits": 3,
                    "hostnames": ["www.origin.com", "shop.other.com", "other.com"],
                }
            ]
        }
        discovered = censys_discovery.discovered_domains(lookup, "origin.com", self._apex)
        self.assertEqual([item["target"] for item in discovered], ["other.com"])
        self.assertEqual(discovered[0]["global_hits"], 3)
        self.assertEqual(discovered[0]["selector_value"], "UA-1")

    def test_rarest_selector_wins_when_both_find_the_same_domain(self) -> None:
        lookup = {
            "selectors": [
                {"kind": "favicon_md5", "value": "abc", "global_hits": 300, "hostnames": ["x.com"]},
                {"kind": "ga_property", "value": "UA-1", "global_hits": 2, "hostnames": ["x.com"]},
            ]
        }
        discovered = censys_discovery.discovered_domains(lookup, "origin.com", self._apex)
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["selector_kind"], "ga_property")


class ScanProfileTests(unittest.TestCase):
    """Only the submitted domain spends Censys search credits.

    Everything the pipeline discovers gets the full scan minus the paid query,
    and every target gets host enrichment (credit-free, capped per day).
    """

    def test_seed_gets_full_scan(self) -> None:
        profile = analysis_service.profile_for(
            "sub.example.com", is_seed=True, discovery_kind="seed"
        )
        self.assertIs(profile, analysis_service.FULL_SCAN)
        self.assertTrue(profile.run_providers)
        self.assertTrue(profile.reverse_lookups)
        self.assertTrue(profile.censys_host_enrichment)

    def test_discovered_sibling_apex_does_not_get_the_paid_search(self) -> None:
        # The regression this whole change exists to prevent. An apex the
        # pipeline discovered used to satisfy `_apex(domain) == domain` and be
        # handed a FULL_SCAN, so each of the (up to five) siblings in a case ran
        # its own cert search *and* its own eight-selector reverse lookup —
        # about 83% of the Censys credits one ingest spent.
        profile = analysis_service.profile_for(
            "sibling.com", is_seed=False, discovery_kind="sibling_domain"
        )
        self.assertIs(profile, analysis_service.NO_PAID_SEARCH)
        self.assertFalse(profile.run_providers)
        self.assertFalse(profile.reverse_lookups)

    def test_subdomain_followup_gets_everything_but_the_paid_search(self) -> None:
        profile = analysis_service.profile_for(
            "sub.example.com", is_seed=False, discovery_kind="subdomain_followup"
        )
        self.assertIs(profile, analysis_service.NO_PAID_SEARCH)
        self.assertFalse(profile.run_providers)
        self.assertFalse(profile.reverse_lookups)
        self.assertTrue(profile.censys_host_enrichment)

    def test_reverse_lookup_discovery_is_enriched_but_cannot_recurse(self) -> None:
        profile = analysis_service.profile_for(
            "example.com",
            is_seed=False,
            discovery_kind=analysis_service.REVERSE_LOOKUP_DISCOVERY_KIND,
        )
        self.assertIs(profile, analysis_service.NO_PAID_SEARCH)
        self.assertFalse(profile.run_providers)
        self.assertFalse(profile.reverse_lookups)
        # Changed deliberately: these used to be denied host enrichment. It
        # costs no credits, so they now get it like every other target.
        self.assertTrue(profile.censys_host_enrichment)

    def test_every_non_seed_path_refuses_reverse_lookups(self) -> None:
        # The unbounded-crawl guard, asserted across every way a target can
        # enter the pool rather than only the reverse-lookup one.
        for kind in (
            "subdomain_followup",
            "sibling_domain",
            "wordlist_subdomain",
            analysis_service.REVERSE_LOOKUP_DISCOVERY_KIND,
            None,
        ):
            with self.subTest(discovery_kind=kind):
                profile = analysis_service.profile_for(
                    "example.com", is_seed=False, discovery_kind=kind
                )
                self.assertFalse(profile.reverse_lookups)
                self.assertFalse(profile.run_providers)

    def test_profile_toggles_the_enrichment_contextvar(self) -> None:
        # Both live profiles enable enrichment, so the mechanism is exercised
        # with an ad-hoc profile: what is under test is that _apply_profile
        # scopes the ContextVar, not which value the table happens to carry.
        disabled = analysis_service.ScanProfile(
            name="test_no_enrichment",
            run_providers=False,
            censys_host_enrichment=False,
            reverse_lookups=False,
        )
        self.assertTrue(analysis_service.CENSYS_ENRICHMENT_ALLOWED.get())
        with analysis_service._apply_profile(disabled):
            self.assertFalse(analysis_service.CENSYS_ENRICHMENT_ALLOWED.get())
        self.assertTrue(analysis_service.CENSYS_ENRICHMENT_ALLOWED.get())

    def test_live_profiles_all_enable_enrichment(self) -> None:
        for profile in (analysis_service.FULL_SCAN, analysis_service.NO_PAID_SEARCH):
            with self.subTest(profile=profile.name):
                self.assertTrue(profile.censys_host_enrichment)


class DiscoveryQueueingTests(unittest.TestCase):
    def test_discoveries_are_queued_with_the_non_recursion_kind(self) -> None:
        payload = {
            "censys_reverse_lookup": {
                "discovered": [
                    {
                        "target": "other.com",
                        "selector_kind": "ga_property",
                        "selector_value": "UA-1",
                        "global_hits": 3,
                    }
                ]
            }
        }
        targets = analysis_service._extract_discovered_targets(payload, "origin.com")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["target"], "other.com")
        self.assertEqual(
            targets[0]["kind"], analysis_service.REVERSE_LOOKUP_DISCOVERY_KIND
        )
        self.assertIn("UA-1", targets[0]["reason"])
        self.assertIn("3", targets[0]["reason"])


class PivotScoreTests(unittest.TestCase):
    def test_rarer_selectors_score_higher(self) -> None:
        from db.discovery_store import _pivot_score

        self.assertGreater(_pivot_score(2), _pivot_score(30))
        self.assertGreater(_pivot_score(30), _pivot_score(400))
        self.assertEqual(_pivot_score(None), 4)


if __name__ == "__main__":
    unittest.main()
