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

import core.ip_intel as ip_intel
from core.ip_intel import _select_wordlist_followup_targets


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
