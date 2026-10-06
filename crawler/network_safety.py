"""Network target validation for crawler egress.

The crawler processes domains controlled by third parties. Every HTTP redirect
and every raw TLS connection must stay on globally routable addresses so a
public domain cannot be used to reach loopback, RFC1918, link-local, Tailscale
CGNAT, documentation/reserved, multicast, or other non-public networks.
"""

import asyncio
import ipaddress
import socket

import httpx


class UnsafeNetworkTarget(RuntimeError):
    """Raised when a hostname resolves to a non-public address."""


async def resolve_public_addresses(hostname: str) -> tuple[str, ...]:
    if not hostname:
        raise UnsafeNetworkTarget("missing target hostname")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if not literal.is_global:
            raise UnsafeNetworkTarget(f"non-public target blocked: {literal.compressed}")
        return (literal.compressed,)

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise

    addresses = tuple(
        dict.fromkeys(info[4][0] for info in infos if info and info[4])
    )
    if not addresses:
        raise UnsafeNetworkTarget("target resolved to no addresses")

    unsafe = []
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            unsafe.append(address.compressed)

    if unsafe:
        raise UnsafeNetworkTarget(
            "non-public target blocked: " + ", ".join(sorted(set(unsafe)))
        )

    return addresses


async def enforce_public_http_request(request: httpx.Request) -> None:
    """httpx request hook; runs for the initial request and each redirect."""
    host = request.url.host
    await resolve_public_addresses(host or "")
