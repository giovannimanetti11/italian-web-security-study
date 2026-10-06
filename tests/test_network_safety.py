import socket

import httpx
import pytest

from crawler.network_safety import (
    UnsafeNetworkTarget,
    enforce_public_http_request,
    resolve_public_addresses,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "100.64.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
    ],
)
async def test_literal_non_public_addresses_are_blocked(host: str) -> None:
    with pytest.raises(UnsafeNetworkTarget):
        await resolve_public_addresses(host)


@pytest.mark.asyncio
async def test_public_literal_is_allowed() -> None:
    assert await resolve_public_addresses("1.1.1.1") == ("1.1.1.1",)


@pytest.mark.asyncio
async def test_hostname_with_private_resolution_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = __import__("asyncio").get_running_loop()

    async def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(UnsafeNetworkTarget):
        await resolve_public_addresses("attacker.example")


@pytest.mark.asyncio
async def test_http_request_hook_blocks_private_redirect_target() -> None:
    request = httpx.Request("GET", "http://127.0.0.1/internal")
    with pytest.raises(UnsafeNetworkTarget):
        await enforce_public_http_request(request)
