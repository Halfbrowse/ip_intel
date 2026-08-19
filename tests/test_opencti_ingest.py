"""
Tests for integrations/opencti_ingest.py — now a read-only OpenCTI query surface.

The module used to drive analysis (`_run`, `start_background_ingestion`,
`retry_source_errors`) through the async scan engine in core/ip_intel.py. Engine,
worker and their tests were removed together; the live sweep is
scripts/ingest_opencti_channels.py, which submits through CaseRuntime instead.

The channel-resolution behaviour those tests covered (a channel name that is
itself a domain, an external-reference URL, social-media platforms being
dropped, labels arriving in several dict shapes, tier extraction) still exists —
it moved behind `fetch_all_website_channel_data`, the one function the sweep
imports. These tests target it there rather than through the deleted
`_get_channel_domains`.

pycti is stubbed: no network access.
"""

from __future__ import annotations

import os
import sys
import types
import unittest

# Only pycti needs stubbing now — the module no longer imports core.ip_intel,
# db.intel_db or the alert integrations.
_ORIGINAL_PYCTI = sys.modules.get("pycti")

fake_pycti = types.ModuleType("pycti")
fake_pycti.OpenCTIApiClient = object
sys.modules["pycti"] = fake_pycti

import integrations.opencti_ingest as opencti_ingest

if _ORIGINAL_PYCTI is None:
    sys.modules.pop("pycti", None)
else:
    sys.modules["pycti"] = _ORIGINAL_PYCTI


class _FakeChannelApi:
    def __init__(self, channels: list[dict]) -> None:
        self._channels = channels

    def list(self, **_kwargs) -> list[dict]:
        return list(self._channels)


class _FakeApiWithChannels:
    def __init__(self, channels: list[dict]) -> None:
        self.channel = _FakeChannelApi(channels)


class _FakeApiWithoutChannels:
    """Simulates a pycti build that does not expose the channel API."""


_ENV_KEYS = ("OPENCTI_URL", "OPENCTI_TOKEN")


class OpenCtiChannelReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_client = opencti_ingest.OpenCTIApiClient
        self.original_env = {key: os.environ.get(key) for key in _ENV_KEYS}
        for key in _ENV_KEYS:
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        opencti_ingest.OpenCTIApiClient = self.original_client
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _set_opencti_env(self) -> None:
        os.environ["OPENCTI_URL"] = "https://opencti.example.com"
        os.environ["OPENCTI_TOKEN"] = "test-token"

    def _fetch(self, channels: list[dict]) -> dict[str, dict]:
        self._set_opencti_env()
        opencti_ingest.OpenCTIApiClient = lambda *_a, **_k: _FakeApiWithChannels(channels)
        return opencti_ingest.fetch_all_website_channel_data()

    def test_channel_name_that_is_a_domain(self) -> None:
        result = self._fetch([{"name": "RussiaHerald.com", "channel_types": ["website"]}])

        self.assertEqual(set(result), {"russiaherald.com"})

    def test_channel_external_reference_url(self) -> None:
        result = self._fetch([
            {
                "name": "Russia Herald",
                "channel_types": ["website"],
                "externalReferences": [{"url": "https://www.russiaherald.com/some/article?id=1"}],
            }
        ])

        self.assertEqual(set(result), {"russiaherald.com"})

    def test_social_media_domains_are_skipped(self) -> None:
        result = self._fetch([
            {
                "name": "Some Propaganda Channel",
                "channel_types": ["telegram"],
                "externalReferences": [
                    {"url": "https://t.me/somechannel"},
                    {"url": "https://www.youtube.com/@somechannel"},
                    {"url": "https://m.facebook.com/somechannel"},
                ],
            }
        ])

        self.assertEqual(result, {})

    def test_labels_merge_across_channels_resolving_to_one_domain(self) -> None:
        result = self._fetch([
            {"name": "Other Site", "externalReferences": [{"url": "http://other-site.example/about"}]},
            {"name": "Other Site Again", "externalReferences": [{"url": "https://other-site.example"}],
             "objectLabel": [{"value": "campaign-alpha"}]},
        ])

        self.assertEqual(set(result), {"other-site.example"})
        self.assertEqual(result["other-site.example"]["labels"], ["campaign-alpha"])

    def test_channel_labels_accept_multiple_dict_shapes(self) -> None:
        channel = {
            "objectLabel": [
                {"value": "Tier 3"},
                {"value": "campaign-alpha"},
                {"node": {"value": "platform-news"}},
            ],
            "labels": {
                "edges": [
                    {"node": {"value": "tier-2"}},
                    {"node": {"name": "source-opencti"}},
                    {"node": {"value": "campaign-alpha"}},
                ]
            },
        }

        labels = opencti_ingest._channel_labels(channel)

        self.assertEqual(labels, ["Tier 3", "campaign-alpha", "platform-news", "tier-2", "source-opencti"])
        self.assertEqual(opencti_ingest._extract_tier(labels), 2)

    def test_tier_is_surfaced_per_domain(self) -> None:
        result = self._fetch([
            {"name": "tiered.example", "channel_types": ["website"],
             "objectLabel": [{"value": "tier-1"}]},
        ])

        self.assertEqual(result["tiered.example"]["tier"], 1)

    def test_missing_channel_api_raises(self) -> None:
        self._set_opencti_env()
        opencti_ingest.OpenCTIApiClient = lambda *_a, **_k: _FakeApiWithoutChannels()

        with self.assertRaises(RuntimeError):
            opencti_ingest.fetch_all_website_channel_data()

    def test_missing_credentials_raise(self) -> None:
        with self.assertRaises(RuntimeError):
            opencti_ingest.fetch_all_website_channel_data()


if __name__ == "__main__":
    unittest.main()
