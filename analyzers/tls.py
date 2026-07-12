"""Pure TLS/certificate analysis. Operates on an already-fetched
TLSFetchResult (crawler/tls_fetcher.py owns the actual handshake) — no I/O
here, testable against hand-built fixtures with real or synthetic
certificate DER bytes.

Deliberately measurement-only, not an active TLS vulnerability scanner:
protocol version, cipher suite, and certificate metadata, nothing more.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crawler.models import TLSFetchResult

ANALYZER_VERSION = "0.1.0"

# Cipher-name substrings considered weak by current guidance (Mozilla SSL
# Configuration Generator / IANA TLS Cipher Suite Registry deprecation
# notes) — documented here rather than left as an unexplained check.
_WEAK_CIPHER_MARKERS = ("RC4", "DES", "MD5", "NULL", "EXPORT")


@dataclass(frozen=True)
class TLSResult:
    tls_supported: bool
    tls_version_negotiated: str | None
    tls10_supported: bool
    tls11_supported: bool
    cipher_suite: str | None
    weak_cipher: bool


@dataclass(frozen=True)
class CertificateResult:
    subject_cn: str | None
    issuer_cn: str | None
    issuer_org: str | None
    not_before: datetime | None
    not_after: datetime | None
    days_until_expiry: int | None
    self_signed: bool
    key_type: str | None
    key_size: int | None
    san_count: int


def analyze_tls(fetch: TLSFetchResult) -> TLSResult:
    cipher = fetch.cipher_suite
    weak = bool(cipher) and any(marker in cipher.upper() for marker in _WEAK_CIPHER_MARKERS)
    return TLSResult(
        tls_supported=fetch.tls_ok,
        tls_version_negotiated=fetch.tls_version_negotiated,
        tls10_supported=fetch.tls10_supported,
        tls11_supported=fetch.tls11_supported,
        cipher_suite=cipher,
        weak_cipher=weak,
    )


def _key_info(public_key) -> tuple[str | None, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    return type(public_key).__name__, getattr(public_key, "key_size", None)


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def analyze_certificate(fetch: TLSFetchResult) -> CertificateResult | None:
    if not fetch.peer_cert_der:
        return None

    cert = x509.load_der_x509_certificate(fetch.peer_cert_der)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_left = (not_after - datetime.now(UTC)).days

    subject_cn = _common_name(cert.subject)
    issuer_cn = _common_name(cert.issuer)
    issuer_org_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    issuer_org = issuer_org_attrs[0].value if issuer_org_attrs else None

    key_type, key_size = _key_info(cert.public_key())

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_count = len(san.value)
    except x509.ExtensionNotFound:
        san_count = 0

    return CertificateResult(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_left,
        self_signed=(issuer_cn is not None and issuer_cn == subject_cn),
        key_type=key_type,
        key_size=key_size,
        san_count=san_count,
    )
