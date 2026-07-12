"""Raw TLS handshake — a separate network operation from the main HTTP
fetch, since it needs socket-level access to certificate/cipher/protocol
info a normal HTTP client doesn't expose. Passive: standard TLS handshakes
only (one per protocol version being probed), no payloads, ported from
insights.f-hack.com's checks/tls.py but made asyncio-native.

Always probes the bare requested domain on port 443, independent of
whatever the HTTP fetch's own redirect chain did.
"""

import asyncio
import ssl
import time

from crawler.models import TLSFetchResult

PORT = 443
CONNECT_TIMEOUT = 8.0  # real handshake — unchanged

# TLS 1.0/1.1 support probes: measured cost showed these dominating
# fetch_tls's total time (up to 2x CONNECT_TIMEOUT worst case) on the vast
# majority of modern sites that simply don't support the legacy versions
# and reject/drop near-instantly. A server that explicitly rejects an
# unsupported version responds within a normal RTT; only a silently
# packet-dropping middlebox needs to wait out a full timeout, which this
# shorter budget still accommodates without paying the full 8s twice for
# the common case.
LEGACY_PROBE_TIMEOUT = 3.0


async def _supports_version(domain: str, version: ssl.TLSVersion, timeout: float) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = version
    ctx.maximum_version = version
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, PORT, ssl=ctx, server_hostname=domain),
            timeout=timeout,
        )
        return True
    except Exception:
        return False
    finally:
        if writer is not None:
            writer.close()


async def fetch_tls(domain: str) -> TLSFetchResult:
    t0 = time.monotonic()
    tls10_supported = await _supports_version(domain, ssl.TLSVersion.TLSv1, LEGACY_PROBE_TIMEOUT)
    tls11_supported = await _supports_version(
        domain, ssl.TLSVersion.TLSv1_1, LEGACY_PROBE_TIMEOUT
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, PORT, ssl=ctx, server_hostname=domain),
            timeout=CONNECT_TIMEOUT,
        )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return TLSFetchResult(
            domain=domain,
            tls_ok=False,
            tls_version_negotiated=None,
            cipher_suite=None,
            tls10_supported=tls10_supported,
            tls11_supported=tls11_supported,
            peer_cert_der=None,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_ms=elapsed_ms,
        )

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cipher = ssl_object.cipher()
        peer_cert_der = ssl_object.getpeercert(binary_form=True)
        version_negotiated = ssl_object.version()
    finally:
        writer.close()

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return TLSFetchResult(
        domain=domain,
        tls_ok=True,
        tls_version_negotiated=version_negotiated,
        cipher_suite=cipher[0] if cipher else None,
        tls10_supported=tls10_supported,
        tls11_supported=tls11_supported,
        peer_cert_der=peer_cert_der,
        error=None,
        elapsed_ms=elapsed_ms,
    )
