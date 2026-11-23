"""Collector-side TLS helpers: HTTPS-only URLs, always-verifying clients, CA pinning by fingerprint, readable errors.
Imports nothing from collector.config (the setup page uses it before any config exists). Verification is never disabled."""
import datetime as dt
import hashlib
import ssl
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TLSProblem(Exception):
    """Carries a message that is safe and understandable to show to a user."""


def require_https(url: str) -> str:
    u = urlparse((url or "").strip())
    if u.scheme != "https":
        raise TLSProblem("The server URL must use https:// - unencrypted collector connections are refused.")
    if not u.hostname:
        raise TLSProblem("The server URL has no host name.")
    return url.strip().rstrip("/")


def make_context(ca_pem_path=None) -> ssl.SSLContext:
    """Certificate AND host-name verification on, TLS >= 1.2. A pinned private CA replaces (not extends) the system store."""
    ctx = ssl.create_default_context(cafile=str(ca_pem_path)) if ca_pem_path else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def build_client(ca_pem_path=None, timeout=5.0, headers=None) -> httpx.Client:
    return httpx.Client(verify=make_context(ca_pem_path), timeout=timeout, headers=headers or {}, trust_env=False)


def _chain(exc):
    seen = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def explain_tls_error(exc) -> str:
    """Map a transport exception to an understandable message (no certificate contents, no secrets)."""
    for e in _chain(exc):
        if isinstance(e, ssl.SSLCertVerificationError):
            msg = (getattr(e, "verify_message", "") or str(e)).lower()
            if "expired" in msg:
                return "The server's certificate has EXPIRED. Ask the host to renew it. Nothing was sent."
            if "not yet valid" in msg:
                return "The server's certificate is not valid yet - check this laptop's clock. Nothing was sent."
            if "hostname" in msg or "doesn't match" in msg or "does not match" in msg or "ip address mismatch" in msg:
                return "The certificate is for a different server name than the one you entered - possible wrong URL or interception. Nothing was sent."
            if "self-signed" in msg or "self signed" in msg:
                return "The server presented a self-signed certificate that this laptop does not trust. Nothing was sent."
            if "unable to get local issuer" in msg or "unknown ca" in msg or "unable to verify" in msg:
                return ("The server's certificate was not issued by a trusted authority. For a private host, install the host's "
                        "CA certificate (and verify its fingerprint) in the setup page. Nothing was sent.")
            return "Certificate verification failed, so the connection was refused. Nothing was sent."
        if isinstance(e, ssl.SSLError):
            return "A secure (TLS) connection could not be established. Nothing was sent."
    if isinstance(exc, httpx.ConnectTimeout) or isinstance(exc, httpx.ReadTimeout):
        return "The server did not answer in time."
    if isinstance(exc, httpx.ConnectError):
        return "Cannot reach the server (is it running and is the tunnel up?)."
    return f"Request failed ({type(exc).__name__})."


def tls_error_kind(exc):
    """Coarse, value-free category of a certificate problem (safe to report to the host): expired | hostname | self_signed |
    untrusted | other; None when the error is not a TLS error."""
    for e in _chain(exc):
        if isinstance(e, ssl.SSLCertVerificationError):
            msg = (getattr(e, "verify_message", "") or str(e)).lower()
            if "expired" in msg or "not yet valid" in msg:
                return "expired"
            if "hostname" in msg or "doesn't match" in msg or "does not match" in msg or "ip address mismatch" in msg:
                return "hostname"
            if "self-signed" in msg or "self signed" in msg:
                return "self_signed"
            if "local issuer" in msg or "unknown ca" in msg or "unable to verify" in msg:
                return "untrusted"
            return "other"
        if isinstance(e, ssl.SSLError):
            return "other"
    return None


def is_tls_error(exc) -> bool:
    return any(isinstance(e, ssl.SSLError) for e in _chain(exc))


# ------------------------------------------------------------------------------------------------ CA pinning
def _load_cert(pem: str):
    try:
        return x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)
    except Exception:
        raise TLSProblem("That is not a valid PEM certificate.")


def fingerprint(pem: str) -> str:
    der = _load_cert(pem).public_bytes(serialization.Encoding.DER)
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def check_ca(pem: str, expected_fp: str) -> dict:
    """Accept a private CA only if (1) its SHA-256 fingerprint equals the one the host gave out-of-band, (2) it is a CA,
    (3) it is currently valid. Raises TLSProblem with a readable reason otherwise."""
    cert = _load_cert(pem)
    want = "".join(c for c in (expected_fp or "").upper() if c in "0123456789ABCDEF")
    got = fingerprint(pem).replace(":", "")
    if len(want) != 64:
        raise TLSProblem("Enter the host CA fingerprint (SHA-256, 64 hex characters) exactly as the host shows it.")
    if want != got:
        raise TLSProblem("The CA certificate does NOT match the fingerprint you entered - it may be the wrong file or tampered with. Not trusted.")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bc.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise TLSProblem("That certificate is not a certificate authority.")
    now = dt.datetime.now(dt.timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    if now < nb:
        raise TLSProblem("The CA certificate is not valid yet (check this laptop's clock).")
    if now > na:
        raise TLSProblem("The CA certificate has expired. Ask the host for a new one.")
    return {"fingerprint": fingerprint(pem), "not_after": na.isoformat(), "subject": cert.subject.rfc4514_string()}
