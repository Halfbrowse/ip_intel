"""
Outbound proxy helpers.

External OSINT providers (crt.sh, CIRCL pDNS, HackerTarget, urlscan.io,
RIPE Stat, target-site probes, ...) rate-limit per source IP. To bypass
that, outbound provider HTTP traffic can be routed through the org VPN by
setting OUTBOUND_PROXY_URL to an http:// or socks5:// proxy URL (e.g. the
gluetun sidecar in docker-compose: ``http://vpn:8888``).

When OUTBOUND_PROXY_URL is unset or empty, every helper returns an empty /
None value so call sites behave exactly as before (direct connection).

Intentionally NOT proxied: internal services (Mattermost, OpenCTI,
Postgres), DNS lookups, and raw-socket TLS/SSH probes — those never go
through these helpers.

Usage:

    from utils.outbound import requests_kwargs, httpx_kwargs

    requests.get(url, timeout=15, **requests_kwargs())
    httpx.AsyncClient(timeout=..., **httpx_kwargs())
"""

from __future__ import annotations

import os
from typing import Any

OUTBOUND_PROXY_ENV = "OUTBOUND_PROXY_URL"


def outbound_proxy_url() -> str | None:
    """The configured outbound proxy URL, or None for direct connections."""
    url = os.environ.get(OUTBOUND_PROXY_ENV, "").strip()
    return url or None


def requests_proxies() -> dict[str, str] | None:
    """Value for the ``proxies=`` argument of `requests` calls (or None)."""
    url = outbound_proxy_url()
    if url is None:
        return None
    return {"http": url, "https": url}


def requests_kwargs() -> dict[str, Any]:
    """Kwargs to splat into ``requests.get/post/head(...)`` calls."""
    proxies = requests_proxies()
    return {"proxies": proxies} if proxies is not None else {}


def httpx_kwargs() -> dict[str, Any]:
    """Kwargs to splat into ``httpx.Client(...)`` / ``httpx.AsyncClient(...)``."""
    url = outbound_proxy_url()
    return {"proxy": url} if url is not None else {}
