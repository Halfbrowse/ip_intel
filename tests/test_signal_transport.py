from __future__ import annotations

import datetime as dt
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sources.signal_transport import parse_certificate_der


def _make_cert() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class SignalTransportTests(unittest.TestCase):
    def test_parse_certificate_der_includes_spki_hash(self) -> None:
        parsed = parse_certificate_der(_make_cert(), ip="203.0.113.10", port=443, sni_used="example.com")
        self.assertEqual(parsed["cn"], "example.com")
        self.assertIn("example.com", parsed["sans"])
        self.assertTrue(parsed["sha256"])
        self.assertTrue(parsed["spki_sha256"])
        self.assertNotEqual(parsed["sha256"], parsed["spki_sha256"])


if __name__ == "__main__":
    unittest.main()
