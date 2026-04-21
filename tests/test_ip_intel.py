from __future__ import annotations

import asyncio
import sys
import types
import unittest
from unittest.mock import patch

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

cryptography_module = types.ModuleType("cryptography")
cryptography_x509 = types.ModuleType("cryptography.x509")
cryptography_x509_oid = types.ModuleType("cryptography.x509.oid")
cryptography_hazmat = types.ModuleType("cryptography.hazmat")
cryptography_hazmat_primitives = types.ModuleType("cryptography.hazmat.primitives")
cryptography_serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")
cryptography_asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
cryptography_dsa = types.ModuleType("cryptography.hazmat.primitives.asymmetric.dsa")
cryptography_ec = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ec")
cryptography_ed25519 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
cryptography_ed448 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed448")
cryptography_rsa = types.ModuleType("cryptography.hazmat.primitives.asymmetric.rsa")

cryptography_x509.Certificate = type("Certificate", (), {})
cryptography_x509.SubjectAlternativeName = type("SubjectAlternativeName", (), {})
cryptography_x509.DNSName = type("DNSName", (), {})
cryptography_x509_oid.NameOID = object
cryptography_module.x509 = cryptography_x509
cryptography_module.hazmat = cryptography_hazmat
cryptography_hazmat.primitives = cryptography_hazmat_primitives
cryptography_hazmat_primitives.serialization = cryptography_serialization
cryptography_hazmat_primitives.asymmetric = cryptography_asymmetric
cryptography_asymmetric.dsa = cryptography_dsa
cryptography_asymmetric.ec = cryptography_ec
cryptography_asymmetric.ed25519 = cryptography_ed25519
cryptography_asymmetric.ed448 = cryptography_ed448
cryptography_asymmetric.rsa = cryptography_rsa
cryptography_serialization.Encoding = types.SimpleNamespace(DER="DER")
cryptography_serialization.PublicFormat = types.SimpleNamespace(SubjectPublicKeyInfo="SubjectPublicKeyInfo")
cryptography_dsa.DSAPublicKey = type("DSAPublicKey", (), {})
cryptography_ec.EllipticCurvePublicKey = type("EllipticCurvePublicKey", (), {})
cryptography_ed25519.Ed25519PublicKey = type("Ed25519PublicKey", (), {})
cryptography_ed448.Ed448PublicKey = type("Ed448PublicKey", (), {})
cryptography_rsa.RSAPublicKey = type("RSAPublicKey", (), {})
sys.modules.setdefault("cryptography", cryptography_module)
sys.modules.setdefault("cryptography.x509", cryptography_x509)
sys.modules.setdefault("cryptography.x509.oid", cryptography_x509_oid)
sys.modules.setdefault("cryptography.hazmat", cryptography_hazmat)
sys.modules.setdefault("cryptography.hazmat.primitives", cryptography_hazmat_primitives)
sys.modules.setdefault("cryptography.hazmat.primitives.serialization", cryptography_serialization)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric", cryptography_asymmetric)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.dsa", cryptography_dsa)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.ec", cryptography_ec)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.ed25519", cryptography_ed25519)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.ed448", cryptography_ed448)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.rsa", cryptography_rsa)

import ip_intel
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

    def test_analyze_domain_async_skips_urlscan_when_disabled(self) -> None:
        async def fake_dns(_domain):
            return {"A": [], "AAAA": [], "CAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": [], "SOA": []}

        async def fake_ct(_domain, _client):
            return {"subdomains": [], "total_certs": 0, "issuers": [], "cross_domain_sans": [], "certs": []}

        async def fake_historical_dns(_domain, _client):
            return {"records": [], "unique_historical_ips": []}

        async def fake_page_metadata(_domain, _client, _save_path):
            return {}

        async def fake_email_security(_domain):
            return {}

        async def fake_well_known(_domain, _client):
            return {}

        async def fake_legal_pages(_domain, _client):
            return []

        async def fake_mail_client(_domain, _client):
            return {}

        async def fake_tenant(_domain, _client):
            return {}

        async def fake_spf_details(_domain, _records):
            return {"origins": [], "includes": [], "records": []}

        async def fake_hackertarget(_domain, _client):
            return []

        async def fail_urlscan(*_args, **_kwargs):
            raise AssertionError("urlscan should not run when disabled")

        with (
            patch.object(ip_intel, "get_domain_whois", return_value={}),
            patch.object(ip_intel, "_aget_dns_records", side_effect=fake_dns),
            patch.object(ip_intel, "_acrt_sh_data", side_effect=fake_ct),
            patch.object(ip_intel, "_acircl_passive_dns", side_effect=fake_historical_dns),
            patch.object(ip_intel, "_afetch_page_metadata", side_effect=fake_page_metadata),
            patch.object(ip_intel, "_aget_dmarc_dkim", side_effect=fake_email_security),
            patch.object(ip_intel, "afetch_well_known_artifacts", side_effect=fake_well_known),
            patch.object(ip_intel, "ascrape_legal_pages", side_effect=fake_legal_pages),
            patch.object(ip_intel, "afetch_mail_client_config", side_effect=fake_mail_client),
            patch.object(ip_intel, "aprobe_microsoft_tenant", side_effect=fake_tenant),
            patch.object(ip_intel, "acollect_spf_details", side_effect=fake_spf_details),
            patch.object(ip_intel, "_ahackertarget_host_search", side_effect=fake_hackertarget),
            patch.object(ip_intel, "probe_mx_origins", return_value=[]),
            patch.object(ip_intel, "probe_subdomain_origins", return_value=[]),
            patch.object(ip_intel, "probe_wordlist_subdomains", return_value=[]),
            patch.object(ip_intel, "censys_cert_search", return_value={"hits": [], "origin_candidates": []}),
            patch.object(ip_intel, "shodan_cert_search", return_value={"hits": [], "origin_candidates": []}),
            patch.object(ip_intel, "netlas_cert_search", return_value={"hits": [], "origin_candidates": []}),
            patch.object(ip_intel, "_aurlscan_historical_ips", side_effect=fail_urlscan),
            patch.object(ip_intel, "_aurlscan_fetch_analytics", side_effect=fail_urlscan),
        ):
            result = asyncio.run(
                ip_intel._analyze_domain_async(
                    "example.com",
                    rate=1000,
                    persist=False,
                    enable_wordlist_probe=False,
                    enable_wordlist_followups=False,
                    enable_urlscan=False,
                )
            )

        self.assertEqual(result["origin_candidates"]["urlscan"], [])
        self.assertEqual(result.get("source_errors"), None)


if __name__ == "__main__":
    unittest.main()
