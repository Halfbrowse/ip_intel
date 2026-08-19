from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import shutil
import socket
import ssl
import subprocess
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

try:
    import paramiko
except Exception:  # noqa: BLE001
    paramiko = None


__all__ = [
    "build_best_effort_tls_transport_fingerprint",
    "build_tls_probe_fingerprint",
    "capture_best_effort_tls_transport_fingerprint",
    "fetch_ssh_host_key",
    "fetch_tls_certificate",
    "grab_ssh_host_keys",
    "parse_certificate_der",
    "tls_certificate_hashes",
]


def _load_certificate(certificate: bytes | x509.Certificate) -> tuple[x509.Certificate, bytes]:
    if isinstance(certificate, x509.Certificate):
        der = certificate.public_bytes(serialization.Encoding.DER)
        return certificate, der

    if isinstance(certificate, memoryview):
        certificate = certificate.tobytes()
    elif isinstance(certificate, bytearray):
        certificate = bytes(certificate)

    if not isinstance(certificate, bytes):
        raise TypeError("certificate must be a cryptography.x509.Certificate or bytes")
    if not certificate:
        raise ValueError("certificate payload is empty")

    try:
        if b"-----BEGIN CERTIFICATE-----" in certificate:
            cert = x509.load_pem_x509_certificate(certificate)
            der = cert.public_bytes(serialization.Encoding.DER)
            return cert, der
        return x509.load_der_x509_certificate(certificate), certificate
    except ValueError as exc:
        raise ValueError("certificate must be PEM or DER encoded") from exc


def _certificate_public_key(cert: x509.Certificate) -> Any | None:
    """Public key of `cert`, or None for a key algorithm we cannot load.

    Certificates keyed with algorithms cryptography has no support for (GOST,
    SM2, ...) are still worth keeping: their names, validity and leaf hash are
    all intact, so only the key-derived fields are dropped.
    """

    try:
        return cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        return None


def tls_certificate_hashes(certificate: bytes | x509.Certificate) -> dict[str, str | None]:
    """Return full-certificate and SubjectPublicKeyInfo SHA-256 hashes.

    The leaf hash covers the entire encoded certificate, so it changes on every
    renewal, re-issue or SAN edit. The SPKI hash covers only the public key,
    which operators overwhelmingly carry across those events rather than
    generating a fresh key pair — so it keeps linking an operator's hosts
    together long after their leaf fingerprints have diverged. This is the same
    value browsers pin in HPKP-style pins.
    """

    cert, der = _load_certificate(certificate)
    public_key = _certificate_public_key(cert)
    spki_der = (
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if public_key is not None
        else None
    )
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "spki_sha256": hashlib.sha256(spki_der).hexdigest() if spki_der is not None else None,
    }


def _server_hostname_for_tls(host: str, sni: str | None) -> str | None:
    if sni:
        return sni
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _shared_cipher_names(ssl_sock: ssl.SSLSocket) -> list[str]:
    try:
        shared = ssl_sock.shared_ciphers() or []
    except Exception:  # noqa: BLE001
        return []

    names: list[str] = []
    for item in shared:
        name = None
        if isinstance(item, dict):
            name = item.get("name")
        elif isinstance(item, (tuple, list)) and item:
            name = item[0]
        elif item:
            name = str(item)
        if name:
            names.append(str(name))
    return names


def _public_key_details(public_key: Any) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ec:{public_key.curve.name}", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsa", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "ed448", None
    return public_key.__class__.__name__.removesuffix("PublicKey").lower(), getattr(public_key, "key_size", None)


def _ssh_fingerprint_values(key_blob: bytes) -> dict[str, str]:
    digest = hashlib.sha256(key_blob).digest()
    sha256_b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return {
        "fingerprint_sha256": f"SHA256:{sha256_b64}",
        "sha256": sha256_b64,
        "sha256_hex": digest.hex(),
    }


def _ssh_host_key_record(
    host: str,
    *,
    port: int,
    key_type: str,
    key_blob: bytes,
    bits: int | None,
    source: str,
) -> dict[str, Any]:
    return {
        "host": host,
        "ip": host,
        "port": port,
        "key_type": key_type,
        "bits": bits,
        "source": source,
        **_ssh_fingerprint_values(key_blob),
    }


def parse_certificate_der(
    der: bytes,
    *,
    ip: str,
    port: int,
    sni_used: str | None = None,
) -> dict[str, Any] | None:
    if not der:
        return None

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        return None

    hashes = tls_certificate_hashes(cert)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_o_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa: BLE001
        pass

    try:
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        not_before = cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after.isoformat()

    return {
        "ip": ip,
        "port": port,
        "sni_used": sni_used,
        "cn": cn_attrs[0].value if cn_attrs else "",
        "sans": sans,
        "issuer_cn": issuer_cn_attrs[0].value if issuer_cn_attrs else "",
        "issuer_org": issuer_o_attrs[0].value if issuer_o_attrs else "",
        "not_before": not_before,
        "not_after": not_after,
        **hashes,
    }


def build_best_effort_tls_transport_fingerprint(
    ssl_sock: ssl.SSLSocket,
    cert_info: dict[str, Any] | None = None,
    *,
    host: str | None = None,
    port: int | None = None,
    server_hostname: str | None = None,
    peer_certificate: bytes | x509.Certificate | None = None,
) -> dict[str, Any]:
    """
    Best-effort TLS probe fingerprint for the current Python/OpenSSL client.

    This is intentionally not a JA3/JA4/JARM implementation. Python's stdlib
    exposes negotiated session details after the handshake but not the raw wire
    data needed to reproduce those fingerprints faithfully, so this helper only
    hashes stable, observable connection and certificate parameters.
    """
    cert_info = dict(cert_info or {})
    peer_der: bytes | None = None
    if peer_certificate is not None:
        _, peer_der = _load_certificate(peer_certificate)
    else:
        try:
            peer_der = ssl_sock.getpeercert(binary_form=True)
        except Exception:  # noqa: BLE001
            peer_der = None

    cert = None
    if peer_der:
        try:
            cert, _ = _load_certificate(peer_der)
        except ValueError:
            cert = None

    merged_cert_info = dict(cert_info)
    if cert is not None:
        cert_hashes = tls_certificate_hashes(cert)
        merged_cert_info.setdefault("sha256", cert_hashes["sha256"])
        merged_cert_info.setdefault("spki_sha256", cert_hashes["spki_sha256"])
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        merged_cert_info.setdefault("cn", cn_attrs[0].value if cn_attrs else "")
        merged_cert_info.setdefault("issuer_cn", issuer_cn_attrs[0].value if issuer_cn_attrs else "")

    cipher = None
    try:
        cipher = ssl_sock.cipher()
    except Exception:  # noqa: BLE001
        cipher = None

    alpn = None
    try:
        alpn = ssl_sock.selected_alpn_protocol()
    except Exception:  # noqa: BLE001
        alpn = None

    version = None
    try:
        version = ssl_sock.version()
    except Exception:  # noqa: BLE001
        version = None

    compression = None
    try:
        compression = ssl_sock.compression()
    except Exception:  # noqa: BLE001
        compression = None

    public_key_type = None
    public_key_bits = None
    signature_hash_algorithm = None
    signature_algorithm_oid = None
    if cert is not None:
        public_key_type, public_key_bits = _public_key_details(cert.public_key())
        signature_hash = getattr(cert, "signature_hash_algorithm", None)
        signature_hash_algorithm = getattr(signature_hash, "name", None)
        signature_algorithm_oid = cert.signature_algorithm_oid.dotted_string

    raw = {
        "fingerprint_kind": "best_effort_tls_transport",
        "kind": "best_effort_tls_probe",
        "host": host or merged_cert_info.get("ip"),
        "port": port if port is not None else merged_cert_info.get("port"),
        "server_hostname": server_hostname or merged_cert_info.get("sni_used"),
        "tls_version": version,
        "cipher_name": cipher[0] if cipher else None,
        "cipher_protocol": cipher[1] if cipher else None,
        "cipher_bits": cipher[2] if cipher else None,
        "shared_cipher_names": _shared_cipher_names(ssl_sock)[:32],
        "alpn": alpn,
        "compression": compression,
        "sni_used": merged_cert_info.get("sni_used") or server_hostname,
        "cert_cn": merged_cert_info.get("cn"),
        "cert_issuer_cn": merged_cert_info.get("issuer_cn"),
        "cert_sha256": merged_cert_info.get("sha256"),
        "spki_sha256": merged_cert_info.get("spki_sha256"),
        "public_key_type": public_key_type,
        "public_key_bits": public_key_bits,
        "signature_hash_algorithm": signature_hash_algorithm,
        "signature_algorithm_oid": signature_algorithm_oid,
    }
    fingerprint_payload = {
        "tls_version": raw["tls_version"],
        "cipher_name": raw["cipher_name"],
        "cipher_protocol": raw["cipher_protocol"],
        "cipher_bits": raw["cipher_bits"],
        "shared_cipher_names": raw["shared_cipher_names"],
        "alpn": raw["alpn"],
        "compression": raw["compression"],
        "server_hostname": raw["server_hostname"],
        "cert_sha256": raw["cert_sha256"],
        "spki_sha256": raw["spki_sha256"],
        "public_key_type": raw["public_key_type"],
        "public_key_bits": raw["public_key_bits"],
        "signature_hash_algorithm": raw["signature_hash_algorithm"],
        "signature_algorithm_oid": raw["signature_algorithm_oid"],
    }
    serialized = json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"))
    raw["fingerprint_sha256"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return raw


def build_tls_probe_fingerprint(ssl_sock: ssl.SSLSocket, cert_info: dict[str, Any] | None = None) -> dict[str, Any]:
    return build_best_effort_tls_transport_fingerprint(ssl_sock, cert_info)


def fetch_tls_certificate(
    ip: str,
    *,
    sni: str | None = None,
    port: int = 443,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    server_hostname = _server_hostname_for_tls(ip, sni)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as ssl_sock:
                der = ssl_sock.getpeercert(binary_form=True)
                cert_info = parse_certificate_der(der, ip=ip, port=port, sni_used=server_hostname)
                if cert_info is None:
                    return None
                cert_info["transport_fingerprint"] = build_best_effort_tls_transport_fingerprint(
                    ssl_sock,
                    cert_info,
                    host=ip,
                    port=port,
                    server_hostname=server_hostname,
                )
                return cert_info
    except Exception:  # noqa: BLE001
        return None


def capture_best_effort_tls_transport_fingerprint(
    host: str,
    *,
    sni: str | None = None,
    port: int = 443,
    timeout: float = 5.0,
    alpn_protocols: list[str] | tuple[str, ...] = ("h2", "http/1.1"),
) -> dict[str, Any] | None:
    server_hostname = _server_hostname_for_tls(host, sni)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn_protocols:
        try:
            ctx.set_alpn_protocols(list(alpn_protocols))
        except NotImplementedError:
            pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as ssl_sock:
                return build_best_effort_tls_transport_fingerprint(
                    ssl_sock,
                    host=host,
                    port=port,
                    server_hostname=server_hostname,
                )
    except Exception:  # noqa: BLE001
        return None


def _grab_ssh_host_keys_paramiko(host: str, *, port: int, timeout: float) -> list[dict[str, Any]]:
    if paramiko is None:
        return []

    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        if key is None:
            return []
        return [
            _ssh_host_key_record(
                host,
                port=port,
                key_type=key.get_name(),
                key_blob=key.asbytes(),
                bits=key.get_bits(),
                source="paramiko",
            )
        ]
    except Exception:  # noqa: BLE001
        return []
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:  # noqa: BLE001
            pass


def _grab_ssh_host_keys_ssh_keyscan(host: str, *, port: int, timeout: float) -> list[dict[str, Any]]:
    ssh_keyscan = shutil.which("ssh-keyscan")
    if not ssh_keyscan:
        return []

    timeout_seconds = max(1, int(math.ceil(timeout)))
    try:
        proc = subprocess.run(
            [
                ssh_keyscan,
                "-T",
                str(timeout_seconds),
                "-p",
                str(port),
                "-t",
                "ed25519,ecdsa,rsa",
                host,
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds + 1,
        )
    except Exception:  # noqa: BLE001
        return []

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        key_type = parts[1]
        key_data = parts[2]
        dedupe_key = (key_type, key_data)
        if dedupe_key in seen:
            continue

        try:
            key_blob = base64.b64decode(key_data.encode("ascii"), validate=True)
        except Exception:  # noqa: BLE001
            continue

        seen.add(dedupe_key)
        results.append(
            _ssh_host_key_record(
                host,
                port=port,
                key_type=key_type,
                key_blob=key_blob,
                bits=None,
                source="ssh-keyscan",
            )
        )

    return results


def grab_ssh_host_keys(host: str, *, port: int = 22, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Return SSH host-key fingerprints, preferring paramiko when available."""

    keys = _grab_ssh_host_keys_paramiko(host, port=port, timeout=timeout)
    if keys:
        return keys
    return _grab_ssh_host_keys_ssh_keyscan(host, port=port, timeout=timeout)


def fetch_ssh_host_key(ip: str, *, port: int = 22, timeout: float = 5.0) -> dict[str, Any] | None:
    keys = grab_ssh_host_keys(ip, port=port, timeout=timeout)
    return keys[0] if keys else None
