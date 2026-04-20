from __future__ import annotations

import sys
import types
import unittest

dns_module = types.ModuleType("dns")
dns_module.asyncresolver = types.ModuleType("dns.asyncresolver")
dns_module.resolver = types.ModuleType("dns.resolver")
dns_module.reversename = types.ModuleType("dns.reversename")
dns_module.zone = types.ModuleType("dns.zone")
dns_module.query = types.ModuleType("dns.query")
dns_module.exception = types.ModuleType("dns.exception")
sys.modules.setdefault("dns", dns_module)
sys.modules.setdefault("dns.asyncresolver", dns_module.asyncresolver)
sys.modules.setdefault("dns.resolver", dns_module.resolver)
sys.modules.setdefault("dns.reversename", dns_module.reversename)
sys.modules.setdefault("dns.zone", dns_module.zone)
sys.modules.setdefault("dns.query", dns_module.query)
sys.modules.setdefault("dns.exception", dns_module.exception)

whois_module = types.ModuleType("whois")
sys.modules.setdefault("whois", whois_module)

ipwhois_module = types.ModuleType("ipwhois")
ipwhois_module.IPWhois = object
ipwhois_exceptions = types.ModuleType("ipwhois.exceptions")
ipwhois_exceptions.IPDefinedError = RuntimeError
sys.modules.setdefault("ipwhois", ipwhois_module)
sys.modules.setdefault("ipwhois.exceptions", ipwhois_exceptions)

from ip_intel import _select_wordlist_followup_targets


class IpIntelTests(unittest.TestCase):
    def test_select_wordlist_followup_targets_dedupes_and_limits(self) -> None:
        hits = [
            {"subdomain": "app.example.com", "ip": "203.0.113.10", "source": "wordlist probe"},
            {"subdomain": "app.example.com", "ip": "203.0.113.11", "source": "wordlist probe"},
            {"subdomain": "app.example.com", "ip": "203.0.113.10", "source": "wordlist probe"},
            {"subdomain": "blog.example.com", "ip": "198.51.100.20", "source": "wordlist probe"},
            {"subdomain": "cdn.example.com", "ip": "198.51.100.30", "source": "wordlist probe"},
            {"subdomain": "", "ip": "198.51.100.31", "source": "wordlist probe"},
        ]

        selected = _select_wordlist_followup_targets(hits, limit=2)

        self.assertEqual([item["subdomain"] for item in selected], ["app.example.com", "blog.example.com"])
        self.assertEqual(selected[0]["ips"], ["203.0.113.10", "203.0.113.11"])
        self.assertEqual(len(selected[0]["hits"]), 3)


if __name__ == "__main__":
    unittest.main()
