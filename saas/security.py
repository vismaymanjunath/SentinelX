import datetime as dt
import hashlib
import hmac
import ipaddress
import os
import secrets as pysecrets
import time

from .config import CERT_DIR
from .db import db


def hash_pw(pw: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    d = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 120_000)
    return salt.hex() + "$" + d.hex()


def verify_pw(pw: str, stored: str) -> bool:
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)), stored)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_key() -> str:
    return "sx_" + pysecrets.token_urlsafe(32)


def login(username: str, password: str):
    u = db.one("SELECT * FROM users WHERE username=?", (username,))
    if not u or not verify_pw(password, u["pw_hash"]):
        return None
    token = pysecrets.token_urlsafe(32)
    db.exec("INSERT INTO sessions VALUES(?,?,?,?,?,?)",
            (token, u["id"], u["tenant_id"], u["username"], u["role"], time.time() + 12 * 3600))
    return {"token": token, "tenant_id": u["tenant_id"], "username": u["username"], "role": u["role"]}


def session_for(token: str | None):
    if not token:
        return None
    s = db.one("SELECT * FROM sessions WHERE token=?", (token,))
    if not s or s["expires"] < time.time():
        return None
    return s


def collector_for_key(key: str | None):
    if not key:
        return None
    return db.one("SELECT * FROM collectors WHERE key_hash=?", (hash_key(key),))


def _sans(names):
    from cryptography import x509
    out = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def _days_left(path):
    from cryptography import x509
    try:
        c = x509.load_pem_x509_certificate(path.read_bytes())
        return (c.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400
    except Exception:
        return -1


def tls_info():
    """Public facts about the host's local TLS material (no private keys): CA fingerprint + expiry, server cert expiry/names."""
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    ca_crt, srv_crt = CERT_DIR / "ca.pem", CERT_DIR / "server.pem"
    out = {"ca_fingerprint_sha256": None, "ca_days_left": None, "server_days_left": None, "server_names": []}
    try:
        ca = x509.load_pem_x509_certificate(ca_crt.read_bytes())
        h = hashlib.sha256(ca.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
        out["ca_fingerprint_sha256"] = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
        out["ca_days_left"] = round(_days_left(ca_crt), 1)
        srv = x509.load_pem_x509_certificate(srv_crt.read_bytes())
        out["server_days_left"] = round(_days_left(srv_crt), 1)
        san = srv.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        out["server_names"] = [str(n.value) for n in san]
    except Exception:
        pass
    return out


def ensure_tls():
    """Local CA (persisted) + server certificate whose SANs are localhost, 127.0.0.1 and any SAAS_TLS_NAMES
    (e.g. the Tailscale IP). The server cert is re-issued, under the same CA, whenever the name list changes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from .config import TLS_NAMES

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    ca_crt, srv_crt, srv_key = CERT_DIR / "ca.pem", CERT_DIR / "server.pem", CERT_DIR / "server.key"
    ca_key_f, marker = CERT_DIR / "ca.key", CERT_DIR / "names.txt"
    names = sorted({"localhost", "127.0.0.1", *TLS_NAMES})
    want = ",".join(names)
    have_ca = ca_crt.exists() and ca_key_f.exists() and _days_left(ca_crt) > 30      # an (almost) expired CA is replaced
    if (have_ca and srv_crt.exists() and srv_key.exists() and marker.exists() and marker.read_text() == want
            and _days_left(srv_crt) > 30):                                              # the server cert is renewed before it expires
        return ca_crt, srv_crt, srv_key
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    if have_ca:
        ca_key = serialization.load_pem_private_key(ca_key_f.read_bytes(), None)
        ca_name = x509.load_pem_x509_certificate(ca_crt.read_bytes()).subject
        ca = None
    else:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SentinelX Dev CA")])
    ca = None if have_ca else (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now)
          .not_valid_after(now + dt.timedelta(days=825))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(_sans(names)), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    if ca is not None:
        ca_crt.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        ca_key_f.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                  serialization.NoEncryption()))
    marker.write_text(want)
    srv_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    srv_key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    return ca_crt, srv_crt, srv_key
