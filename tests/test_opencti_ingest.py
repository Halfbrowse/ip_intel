from __future__ import annotations

import os
import sys
import threading
import time
import types
import unittest

_MODULE_NAMES = ("core.ip_intel", "db.intel_db", "integrations.mattermost_alerts", "integrations.email_alerts", "pycti")
_ORIGINAL_MODULES = {name: sys.modules.get(name) for name in _MODULE_NAMES}

fake_ip_intel = types.ModuleType("core.ip_intel")
fake_ip_intel.analyze_domain = lambda *_args, **_kwargs: None

fake_intel_db = types.ModuleType("db.intel_db")
fake_intel_db.get_domains_with_source_errors = lambda _source=None: []

fake_alerts = types.ModuleType("integrations.mattermost_alerts")
fake_alerts.send_opencti_notification = lambda *_args, **_kwargs: True
fake_alerts.send_retry_notification = lambda *_args, **_kwargs: True

fake_email_alerts = types.ModuleType("integrations.email_alerts")
fake_email_alerts.send_opencti_email = lambda *_args, **_kwargs: True
fake_email_alerts.send_retry_email = lambda *_args, **_kwargs: True

fake_pycti = types.ModuleType("pycti")
fake_pycti.OpenCTIApiClient = object

sys.modules["core.ip_intel"] = fake_ip_intel
sys.modules["db.intel_db"] = fake_intel_db
sys.modules["integrations.mattermost_alerts"] = fake_alerts
sys.modules["integrations.email_alerts"] = fake_email_alerts
sys.modules["pycti"] = fake_pycti

import integrations.opencti_ingest as opencti_ingest

for name, original in _ORIGINAL_MODULES.items():
    if original is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = original


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


_ENV_KEYS = ("OPENCTI_URL", "OPENCTI_TOKEN", "OPENCTI_INGEST_CHANNELS")


class OpenCtiIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_workers = opencti_ingest._INGEST_WORKERS
        self.original_get_domains = opencti_ingest._get_domains
        self.original_get_channel_domains = opencti_ingest._get_channel_domains
        self.original_client = opencti_ingest.OpenCTIApiClient
        self.original_analyze_domain = opencti_ingest.ip_intel.analyze_domain
        self.original_send_notification = opencti_ingest.send_opencti_notification
        self.original_status = dict(opencti_ingest._status)
        self.original_started = opencti_ingest._started
        self.original_ingest_running = opencti_ingest._ingest_running
        self.original_env = {key: os.environ.get(key) for key in _ENV_KEYS}
        for key in _ENV_KEYS:
            os.environ.pop(key, None)
        opencti_ingest._ingest_running = False
        opencti_ingest._started = False
        opencti_ingest._status.update({
            "running": False,
            "started_at": None,
            "completed_at": None,
            "total": 0,
            "done": 0,
            "skipped": 0,
            "current": None,
            "last_error": None,
            "mode": None,
            "sources": {},
        })

    def tearDown(self) -> None:
        opencti_ingest._INGEST_WORKERS = self.original_workers
        opencti_ingest._get_domains = self.original_get_domains
        opencti_ingest._get_channel_domains = self.original_get_channel_domains
        opencti_ingest.OpenCTIApiClient = self.original_client
        opencti_ingest.ip_intel.analyze_domain = self.original_analyze_domain
        opencti_ingest.send_opencti_notification = self.original_send_notification
        opencti_ingest._status.clear()
        opencti_ingest._status.update(self.original_status)
        opencti_ingest._started = self.original_started
        opencti_ingest._ingest_running = self.original_ingest_running
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _set_opencti_env(self) -> None:
        os.environ["OPENCTI_URL"] = "https://opencti.example.com"
        os.environ["OPENCTI_TOKEN"] = "test-token"

    def test_run_processes_full_queue_with_bounded_concurrency(self) -> None:
        domains = [f"domain-{index}.example" for index in range(8)]
        seen: list[str] = []
        lock = threading.Lock()
        active = 0
        max_active = 0

        def fake_analyze_domain(domain: str, **_kwargs) -> None:
            nonlocal active, max_active
            with lock:
                seen.append(domain)
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1

        opencti_ingest._INGEST_WORKERS = 3
        opencti_ingest._get_domains = lambda: list(domains)
        opencti_ingest.ip_intel.analyze_domain = fake_analyze_domain
        opencti_ingest.send_opencti_notification = lambda *_args, **_kwargs: True

        opencti_ingest._run(force_reanalyse=False)

        self.assertEqual(len(seen), len(domains))
        self.assertEqual(set(seen), set(domains))
        self.assertEqual(opencti_ingest._status["mode"], "full_queue")
        self.assertEqual(opencti_ingest._status["total"], len(domains))
        self.assertEqual(opencti_ingest._status["done"], len(domains))
        self.assertEqual(opencti_ingest._status["skipped"], 0)
        self.assertFalse(opencti_ingest._status["running"])
        self.assertIsNone(opencti_ingest._status["current"])
        self.assertEqual(max_active, 3)

    def test_channel_name_that_is_a_domain(self) -> None:
        self._set_opencti_env()
        channels = [{"name": "RussiaHerald.com", "channel_types": ["website"]}]
        opencti_ingest.OpenCTIApiClient = lambda *_args, **_kwargs: _FakeApiWithChannels(channels)

        self.assertEqual(opencti_ingest._get_channel_domains(set()), ["russiaherald.com"])

    def test_channel_external_reference_url(self) -> None:
        self._set_opencti_env()
        channels = [
            {
                "name": "Russia Herald",
                "channel_types": ["website"],
                "externalReferences": [{"url": "https://www.russiaherald.com/some/article?id=1"}],
            }
        ]
        opencti_ingest.OpenCTIApiClient = lambda *_args, **_kwargs: _FakeApiWithChannels(channels)

        self.assertEqual(opencti_ingest._get_channel_domains(set()), ["russiaherald.com"])

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

    def test_channel_social_media_domains_are_skipped(self) -> None:
        self._set_opencti_env()
        channels = [
            {
                "name": "Some Propaganda Channel",
                "channel_types": ["telegram"],
                "externalReferences": [
                    {"url": "https://t.me/somechannel"},
                    {"url": "https://www.youtube.com/@somechannel"},
                    {"url": "https://m.facebook.com/somechannel"},
                ],
            }
        ]
        opencti_ingest.OpenCTIApiClient = lambda *_args, **_kwargs: _FakeApiWithChannels(channels)

        self.assertEqual(opencti_ingest._get_channel_domains(set()), [])

    def test_channel_domains_deduped_against_domain_observables(self) -> None:
        self._set_opencti_env()
        channels = [
            {"name": "russiaherald.com"},
            {"name": "Other Site", "externalReferences": [{"url": "http://other-site.example/about"}]},
            {"name": "Other Site Again", "externalReferences": [{"url": "https://other-site.example"}]},
        ]
        opencti_ingest.OpenCTIApiClient = lambda *_args, **_kwargs: _FakeApiWithChannels(channels)

        result = opencti_ingest._get_channel_domains({"russiaherald.com"})

        self.assertEqual(result, ["other-site.example"])

    def test_run_analyses_channel_domains_with_provenance(self) -> None:
        self._set_opencti_env()
        channels = [
            {"name": "russiaherald.com"},  # duplicate of the observable below
            {"name": "Channel Site", "externalReferences": [{"url": "https://www.channel-site.example/x"}]},
        ]
        opencti_ingest.OpenCTIApiClient = lambda *_args, **_kwargs: _FakeApiWithChannels(channels)
        opencti_ingest._get_domains = lambda: ["russiaherald.com"]

        seen: list[str] = []
        opencti_ingest.ip_intel.analyze_domain = lambda domain, **_kwargs: seen.append(domain)
        notifications: list[tuple[str, dict]] = []
        opencti_ingest.send_opencti_notification = lambda status, details=None: notifications.append((status, dict(details or {})))

        opencti_ingest._run(force_reanalyse=False)

        self.assertEqual(sorted(seen), ["channel-site.example", "russiaherald.com"])
        self.assertEqual(
            opencti_ingest._status["sources"],
            {"domain-observable": 1, "channel": 1},
        )
        self.assertEqual(len(notifications), 1)
        status, details = notifications[0]
        self.assertEqual(status, "completed")
        self.assertEqual(details["sources"], {"domain-observable": 1, "channel": 1})
        self.assertIn("Sources: 1 domain-observable, 1 channel.", details["note"])

    def test_channel_ingestion_toggle_off(self) -> None:
        self._set_opencti_env()
        os.environ["OPENCTI_INGEST_CHANNELS"] = "false"
        opencti_ingest._get_domains = lambda: ["observable.example"]

        def fail_channel_fetch(_exclude: set[str]) -> list[str]:
            raise AssertionError("_get_channel_domains must not be called when toggle is off")

        opencti_ingest._get_channel_domains = fail_channel_fetch

        seen: list[str] = []
        opencti_ingest.ip_intel.analyze_domain = lambda domain, **_kwargs: seen.append(domain)
        opencti_ingest.send_opencti_notification = lambda *_args, **_kwargs: True

        opencti_ingest._run(force_reanalyse=False)

        self.assertEqual(seen, ["observable.example"])
        self.assertEqual(opencti_ingest._status["sources"], {"domain-observable": 1, "channel": 0})

    def test_missing_channel_api_falls_back_to_domains_only(self) -> None:
        self._set_opencti_env()
        opencti_ingest.OpenCTIApiClient = lambda *_args, **_kwargs: _FakeApiWithoutChannels()

        self.assertEqual(opencti_ingest._get_channel_domains(set()), [])


if __name__ == "__main__":
    unittest.main()
