"""check_outbound.py — verify the outbound proxy and VPN control API.

The analysis pipeline sends every external OSINT request through the ProtonVPN
sidecar: HTTP traffic via the ``OUTBOUND_PROXY_URL`` proxy (protonvpn-cli:8888)
and exit-IP rotation via the ``VPN_API_BASE_URL`` control API
(protonvpn-cli:8000). When the sidecar is down, every provider fails with
``ProxyError('Unable to connect to proxy ... Connection refused')`` and scans
persist only thin, DNS-only results — so this script gives a fast, standalone
health check independent of running a scan.

Run inside the app container so it uses the same env and network the pipeline
sees:

    docker compose exec ip-intel python -m scripts.check_outbound
    docker compose exec ip-intel python -m scripts.check_outbound --rotate

``--rotate`` additionally forces a VPN exit-IP change and reports the before/
after egress IP, confirming rotation actually works end to end.

Exit code is 0 only if the proxy is reachable and (when configured) the VPN
control API reports Connected — so it doubles as a CI/monitoring probe.
"""

from __future__ import annotations

import argparse
import os
import sys

import requests

from utils.outbound import outbound_proxy_url, requests_kwargs

# Plain-text "what is my IP" endpoints, tried in order. Kept tiny and
# text/plain so the check doesn't depend on parsing JSON or a single provider
# being up.
_IP_ECHO_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)


def _egress_ip(*, use_proxy: bool, timeout: float = 15.0) -> tuple[str | None, str | None]:
    """Return (ip, error). Fetches the egress IP directly or via the proxy."""
    kwargs = requests_kwargs() if use_proxy else {}
    last_err = None
    for url in _IP_ECHO_URLS:
        try:
            resp = requests.get(url, timeout=timeout, **kwargs)
            resp.raise_for_status()
            ip = resp.text.strip()
            if ip:
                return ip, None
        except Exception as exc:  # noqa: BLE001 - report, don't raise
            last_err = f"{type(exc).__name__}: {exc}"
    return None, last_err


def _check_proxy() -> bool:
    proxy = outbound_proxy_url()
    print("== Outbound proxy ==")
    if not proxy:
        print("  OUTBOUND_PROXY_URL is unset — provider traffic goes out directly (no VPN).")
        direct_ip, err = _egress_ip(use_proxy=False)
        print(f"  direct egress IP: {direct_ip or f'FAILED ({err})'}")
        # Not an error state per se: this is how local/dev runs behave.
        return direct_ip is not None

    print(f"  OUTBOUND_PROXY_URL = {proxy}")
    proxied_ip, err = _egress_ip(use_proxy=True)
    if proxied_ip is None:
        print(f"  proxied egress IP: FAILED ({err})")
        print("  -> proxy is DOWN or unreachable. Every OSINT provider will fail with ProxyError.")
        return False

    direct_ip, _ = _egress_ip(use_proxy=False)
    print(f"  proxied egress IP: {proxied_ip}")
    print(f"  direct  egress IP: {direct_ip or 'n/a'}")
    if direct_ip and direct_ip == proxied_ip:
        print("  -> WARNING: proxied and direct IPs match; traffic may not be routing through the VPN.")
    else:
        print("  -> proxy reachable; provider traffic egresses via the VPN IP above.")
    return True


def _check_vpn_api(*, rotate: bool) -> bool:
    # Imported lazily so a missing/misconfigured VPN module never blocks the
    # proxy check above, which is the more common failure to diagnose.
    from utils import vpn

    print("\n== VPN control API ==")
    if not vpn.BASE_URL:
        print("  VPN_API_BASE_URL is unset — rotation disabled (expected for local/dev).")
        return True
    print(f"  VPN_API_BASE_URL = {vpn.BASE_URL}")

    try:
        connected, ip = vpn._status_sync()
    except Exception as exc:  # noqa: BLE001
        print(f"  status: UNREACHABLE ({type(exc).__name__}: {exc})")
        print("  -> control API is down; the pipeline cannot rotate IPs when rate-limited.")
        return False

    print(f"  status: {'Connected' if connected else 'DISCONNECTED'} (IP: {ip or 'unknown'})")

    if not rotate:
        return connected

    print("  rotating exit IP (this can take ~10-40s)...")
    # min_interval=0 overrides the cross-worker cooldown so an on-demand check
    # always actually rotates instead of being skipped as "rotated recently".
    new_ip = vpn.rotate_vpn_ip_sync(min_interval=0.0)
    if new_ip and new_ip != ip:
        print(f"  rotated: {ip} -> {new_ip}")
        after_ip, err = _egress_ip(use_proxy=True)
        print(f"  proxied egress IP after rotation: {after_ip or f'FAILED ({err})'}")
        return True
    print(f"  rotation did not change the IP (still {new_ip or ip}) — see logs for why.")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Force a VPN exit-IP rotation and report the before/after egress IP.",
    )
    args = parser.parse_args()

    proxy_ok = _check_proxy()
    vpn_ok = _check_vpn_api(rotate=args.rotate)

    print("\n== Summary ==")
    print(f"  proxy: {'OK' if proxy_ok else 'FAIL'}   vpn control API: {'OK' if vpn_ok else 'FAIL'}")
    sys.exit(0 if (proxy_ok and vpn_ok) else 1)


if __name__ == "__main__":
    main()
