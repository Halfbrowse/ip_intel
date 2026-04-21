from __future__ import annotations

import sys
import threading
import time
import types
import unittest

_MODULE_NAMES = ("ip_intel", "intel_db", "mattermost_alerts", "pycti")
_ORIGINAL_MODULES = {name: sys.modules.get(name) for name in _MODULE_NAMES}

fake_ip_intel = types.ModuleType("ip_intel")
fake_ip_intel.analyze_domain = lambda *_args, **_kwargs: None

fake_intel_db = types.ModuleType("intel_db")
fake_intel_db.get_domains_with_source_errors = lambda _source=None: []

fake_alerts = types.ModuleType("mattermost_alerts")
fake_alerts.send_opencti_notification = lambda *_args, **_kwargs: True
fake_alerts.send_retry_notification = lambda *_args, **_kwargs: True

fake_pycti = types.ModuleType("pycti")
fake_pycti.OpenCTIApiClient = object

sys.modules["ip_intel"] = fake_ip_intel
sys.modules["intel_db"] = fake_intel_db
sys.modules["mattermost_alerts"] = fake_alerts
sys.modules["pycti"] = fake_pycti

import opencti_ingest

for name, original in _ORIGINAL_MODULES.items():
    if original is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = original


class OpenCtiIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_workers = opencti_ingest._INGEST_WORKERS
        self.original_get_domains = opencti_ingest._get_domains
        self.original_analyze_domain = opencti_ingest.ip_intel.analyze_domain
        self.original_send_notification = opencti_ingest.send_opencti_notification
        self.original_status = dict(opencti_ingest._status)
        self.original_started = opencti_ingest._started
        self.original_ingest_running = opencti_ingest._ingest_running
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
        })

    def tearDown(self) -> None:
        opencti_ingest._INGEST_WORKERS = self.original_workers
        opencti_ingest._get_domains = self.original_get_domains
        opencti_ingest.ip_intel.analyze_domain = self.original_analyze_domain
        opencti_ingest.send_opencti_notification = self.original_send_notification
        opencti_ingest._status.clear()
        opencti_ingest._status.update(self.original_status)
        opencti_ingest._started = self.original_started
        opencti_ingest._ingest_running = self.original_ingest_running

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


if __name__ == "__main__":
    unittest.main()
