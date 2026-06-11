"""Tests for utils.outbound — proxy-aware client helpers."""

import httpx
import pytest

from utils.outbound import (
    OUTBOUND_PROXY_ENV,
    httpx_kwargs,
    outbound_proxy_url,
    requests_kwargs,
    requests_proxies,
)


# ── Unset env → direct connection, behavior identical to before ──────────────

def test_unset_env_returns_no_proxy_config(monkeypatch):
    monkeypatch.delenv(OUTBOUND_PROXY_ENV, raising=False)
    assert outbound_proxy_url() is None
    assert requests_proxies() is None
    assert requests_kwargs() == {}
    assert httpx_kwargs() == {}


def test_empty_or_whitespace_env_treated_as_unset(monkeypatch):
    for value in ("", "   "):
        monkeypatch.setenv(OUTBOUND_PROXY_ENV, value)
        assert outbound_proxy_url() is None
        assert requests_kwargs() == {}
        assert httpx_kwargs() == {}


# ── Set env → correct proxy config for both stacks ───────────────────────────

@pytest.mark.parametrize("url", ["http://vpn:8888", "socks5://vpn:1080"])
def test_set_env_requests_path(monkeypatch, url):
    monkeypatch.setenv(OUTBOUND_PROXY_ENV, url)
    assert outbound_proxy_url() == url
    assert requests_proxies() == {"http": url, "https": url}
    assert requests_kwargs() == {"proxies": {"http": url, "https": url}}


@pytest.mark.parametrize("url", ["http://vpn:8888", "socks5://vpn:1080"])
def test_set_env_httpx_path(monkeypatch, url):
    monkeypatch.setenv(OUTBOUND_PROXY_ENV, url)
    assert httpx_kwargs() == {"proxy": url}


def test_httpx_kwargs_accepted_by_clients(monkeypatch):
    """httpx.Client / AsyncClient must accept the kwargs and mount the proxy."""
    monkeypatch.setenv(OUTBOUND_PROXY_ENV, "http://vpn:8888")
    with httpx.Client(**httpx_kwargs()) as client:
        transport = client._transport_for_url(httpx.URL("https://example.com"))
        assert isinstance(transport, httpx.HTTPTransport)
        assert transport._pool._proxy_url.host == b"vpn"

    async_client = httpx.AsyncClient(**httpx_kwargs())
    transport = async_client._transport_for_url(httpx.URL("https://example.com"))
    assert transport._pool._proxy_url.host == b"vpn"


def test_env_read_at_call_time(monkeypatch):
    monkeypatch.setenv(OUTBOUND_PROXY_ENV, "http://vpn:8888")
    assert httpx_kwargs() == {"proxy": "http://vpn:8888"}
    monkeypatch.delenv(OUTBOUND_PROXY_ENV)
    assert httpx_kwargs() == {}
    assert requests_kwargs() == {}
