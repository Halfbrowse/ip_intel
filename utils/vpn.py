"""
ProtonVPN IP rotation.

Ported from the tiktok_tool project (utils/vpn.py), adapted to ip_intel's
httpx stack. Drives the protonvpn-cli-community control API (the shared
container on ``shared_net``) to rotate the VPN exit IP, so per-source-IP
rate limits — most notably urlscan.io's ~50 unauthenticated requests/day —
can be reset between provider batches.

This module ONLY rotates the exit IP. Outbound provider traffic reaches that
IP via the tinyproxy sidecar that shares the VPN container's network
namespace; the app routes through it with OUTBOUND_PROXY_URL (see
utils.outbound). DB, DNS, and raw-socket probes are never proxied.

Config (env):
    VPN_API_BASE_URL    control API base, e.g. http://protonvpn-cli:8000
    COUNTRY_CODES       comma+space list of exit countries, e.g. "NL, DE, LT"
    DEFAULT_COUNTRY_CODE preferred exit country (overrides random pick)
    VPN_ROTATE_DISABLE  set to "1" to make rotation a no-op (local/dev)

Usage:
    from utils.vpn import vpn_rotation_batch

    async with vpn_rotation_batch():
        ...  # provider calls that should run from a fresh exit IP
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import logging
import os
import random
import time
from contextlib import asynccontextmanager

import httpx

logger = logging.getLogger(__name__)

BASE_URL = os.getenv("VPN_API_BASE_URL")
COUNTRY_CODES = [
    c for c in (os.getenv("COUNTRY_CODES", "NL, DE, LT").split(", ")) if c
]

_rotate_lock = asyncio.Lock()
_rotation_depth = contextvars.ContextVar("vpn_rotation_depth", default=0)
_active_country_code = contextvars.ContextVar("vpn_active_country_code", default=None)


def get_active_vpn_country_code() -> str | None:
    """Return the country code selected by the outermost active rotation."""
    return _active_country_code.get()


async def _api(method: str, path: str, *, json=None, timeout: float = 20.0):
    if not BASE_URL:
        raise RuntimeError("VPN_API_BASE_URL is not set; cannot reach the VPN control API")
    url = f"{BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.request(method.upper(), url, json=json)
            ctype = (resp.headers.get("content-type") or "").lower()
            if "application/json" in ctype:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
            else:
                body = resp.text
            if resp.status_code >= 400:
                raise RuntimeError(f"VPN API {method} {path} failed (status={resp.status_code}): {body}")
            return body
    except httpx.ConnectError as exc:
        raise RuntimeError(f"VPN API unreachable at {url} — DNS/network failure: {exc}") from exc
    except httpx.TimeoutException as exc:
        raise RuntimeError(f"VPN API timed out ({timeout}s) for {method} {url}: {exc}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"VPN API request error ({method} {url}): {exc}") from exc


async def _status():
    body = await _api("GET", "/status", timeout=8)
    out = body.get("output", "") if isinstance(body, dict) else str(body)
    connected = False
    ip = None
    for line in out.splitlines():
        if line.startswith("Status:"):
            connected = "Connected" in line
        elif line.startswith("IP:"):
            ip = line.split(":", 1)[1].strip()
    return connected, ip, out


async def _wait_for_state(*, want_connected: bool, wait: float = 25.0, poll: float = 0.5):
    deadline = time.time() + wait
    last_ip = None
    while time.time() < deadline:
        connected, ip, _ = await _status()
        last_ip = ip
        if connected == want_connected:
            return ip
        await asyncio.sleep(poll)
    return last_ip


async def _disconnect_silent():
    try:
        connected, _, _ = await _status()
        if connected:
            await _api("POST", "/disconnect", timeout=20)
            await _wait_for_state(want_connected=False, wait=20, poll=0.5)
    except Exception:
        logger.warning("Disconnect failed or timed out; continuing", exc_info=True)


async def _connect(*, protocol="udp", country_code=None, server=None):
    payload = {"protocol": protocol}
    if server:
        payload["server"] = server
    elif country_code:
        payload["country_code"] = country_code
    else:
        payload["fastest"] = True
    return await _api("POST", "/connect", json=payload, timeout=40)


async def _reconnect(*, protocol="udp", country_code=None):
    try:
        payload = {"protocol": protocol}
        if country_code:
            payload["country_code"] = country_code
        await _api("POST", "/reconnect", json=payload, timeout=40)
    except Exception as e:
        logger.warning("Reconnect endpoint failed (%s); falling back to connect", e)
        await _connect(protocol=protocol, country_code=country_code)


def _resolve_rotation_inputs(protocol, country_code):
    effective_protocol = (protocol or "udp").lower()
    effective_cc = (
        country_code
        or os.getenv("DEFAULT_COUNTRY_CODE")
        or (random.choice(COUNTRY_CODES) if COUNTRY_CODES else None)
    )
    if effective_cc:
        effective_cc = effective_cc.upper()
    return effective_protocol, effective_cc


async def _rotate_vpn_connection(
    *,
    protocol="udp",
    country_code=None,
    require_change: bool = True,
    attempts: int = 3,
    wait: float = 25.0,
    poll: float = 0.5,
    min_cooldown: float = 2.0,
):
    effective_protocol, effective_cc = _resolve_rotation_inputs(protocol, country_code)

    async with _rotate_lock:
        try:
            _, prev_ip, _ = await _status()
        except Exception:
            logger.warning("Could not read VPN status; proceeding with rotation", exc_info=True)
            prev_ip = None

        last_ip = prev_ip
        last_err = None

        for i in range(1, attempts + 1):
            step = "reconnect"
            try:
                try:
                    await _reconnect(protocol=effective_protocol, country_code=effective_cc)
                except Exception:
                    step = "connect"
                    await _disconnect_silent()
                    await _connect(protocol=effective_protocol, country_code=effective_cc)

                step = "wait_for_connected"
                new_ip = await _wait_for_state(want_connected=True, wait=wait, poll=poll)
                last_ip = new_ip
                if not require_change or (prev_ip is None) or (new_ip and new_ip != prev_ip):
                    logger.info("VPN rotated: %s -> %s (attempt %d/%d)", prev_ip, new_ip, i, attempts)
                    return effective_cc

                logger.warning("Connected but IP did not change (prev=%s, current=%s)", prev_ip, new_ip)

            except Exception as exc:
                last_err = exc
                logger.warning(
                    "Rotation attempt %d/%d failed at step '%s' [protocol=%s, country=%s]: %s",
                    i, attempts, step, effective_protocol, effective_cc, exc, exc_info=True,
                )
                effective_protocol = "tcp" if effective_protocol == "udp" else "udp"
                if i == attempts - 1:
                    effective_cc = None

            if i < attempts:
                await asyncio.sleep(min_cooldown)

        raise RuntimeError(
            f"Failed to rotate VPN IP after {attempts} attempts "
            f"(prev={prev_ip}, last_seen={last_ip}, last_err={last_err})"
        ) from last_err


@asynccontextmanager
async def vpn_rotation_batch(
    *,
    protocol="udp",
    country_code=None,
    require_change: bool = True,
    attempts: int = 3,
    wait: float = 25.0,
    poll: float = 0.5,
    min_cooldown: float = 2.0,
    nested_label: str | None = None,
):
    """Rotate the VPN exit IP, then run the wrapped block from that IP.

    No-op when VPN_ROTATE_DISABLE=1 or no VPN_API_BASE_URL is configured, so
    local runs without a VPN behave exactly as before. Nested uses inside an
    already-active rotation are skipped (the outer rotation already applies)."""
    if os.getenv("VPN_ROTATE_DISABLE") == "1" or not BASE_URL:
        yield
        return

    current_depth = _rotation_depth.get()
    if current_depth > 0:
        if nested_label:
            logger.debug("VPN rotation already active; skipping nested rotation for %s", nested_label)
        yield
        return

    _, effective_cc = _resolve_rotation_inputs(protocol, country_code)
    token = _rotation_depth.set(current_depth + 1)
    country_token = _active_country_code.set(effective_cc)

    try:
        resolved_cc = await _rotate_vpn_connection(
            protocol=protocol,
            country_code=country_code,
            require_change=require_change,
            attempts=attempts,
            wait=wait,
            poll=poll,
            min_cooldown=min_cooldown,
        )
        if resolved_cc and resolved_cc != effective_cc:
            _active_country_code.set(resolved_cc)
        yield
    finally:
        _active_country_code.reset(country_token)
        _rotation_depth.reset(token)


def rotate_vpn_ip_async(*, protocol="udp", country_code=None,
                        require_change: bool = True, attempts: int = 3,
                        wait: float = 25.0, poll: float = 0.5,
                        min_cooldown: float = 2.0):
    def _decorator(func):
        if not asyncio.iscoroutinefunction(func):
            raise TypeError("rotate_vpn_ip_async can only decorate async functions")

        @functools.wraps(func)
        async def _wrapped(*args, **kwargs):
            async with vpn_rotation_batch(
                protocol=protocol,
                country_code=country_code,
                require_change=require_change,
                attempts=attempts,
                wait=wait,
                poll=poll,
                min_cooldown=min_cooldown,
                nested_label=func.__name__,
            ):
                return await func(*args, **kwargs)

        return _wrapped
    return _decorator
