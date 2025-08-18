# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""Direct-TLS-handshake cert inspection.

A small replacement for `testssl.sh` and `openssl s_client | openssl x509`
when all you need are the structured fields off the leaf certificate plus
the negotiated protocol/cipher. Sub-second for a single host:port.

Used by:
  - app/server.py for the inline "Test (TLS)" button on cert-shape testssl
    findings (cert_trust_wildcard, cert_subjectAltName, etc.) — bypasses
    a 30-second testssl.sh -S run when a TLS handshake answers the
    question directly.
  - toolkit/probes/cert_wildcard.py for the Challenge-button validation.

Both consumers want the same fields, so the parsing logic lives once here.
"""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class CertInfo:
    """Structured snapshot of a leaf certificate + handshake state.

    Field choices are driven by what the cert-shape testssl IDs and the
    cert_wildcard probe need to render a verdict — not a complete x509
    dump. If you need something not here, add it; consumers just read
    the named fields they care about.
    """
    ok: bool = True
    error: Optional[str] = None
    host: str = ""
    port: int = 0

    # Handshake metadata
    protocol: str = ""           # e.g. 'TLSv1.3'
    cipher: str = ""             # negotiated cipher suite name
    elapsed_ms: int = 0

    # Leaf cert fields
    subject: str = ""            # RFC 4514 string
    issuer: str = ""             # RFC 4514 string
    common_name: str = ""        # CN attribute of subject (may be empty)
    sans: list[str] = field(default_factory=list)   # DNS SAN entries
    san_ips: list[str] = field(default_factory=list)
    not_before: str = ""         # ISO 8601 UTC
    not_after: str = ""          # ISO 8601 UTC
    days_until_expiry: Optional[int] = None
    serial: str = ""             # hex
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_size: Optional[int] = None  # bits, when meaningful
    is_self_signed: bool = False

    # Convenience derived flags
    @property
    def has_wildcard_san(self) -> bool:
        """True when any DNS SAN entry begins with '*.'. Wildcard matches
        only one DNS label, but for our purposes any '*' prefix counts."""
        return any(s.startswith("*.") for s in self.sans)

    @property
    def wildcard_sans(self) -> list[str]:
        return [s for s in self.sans if s.startswith("*.")]


def _decode_pubkey(pubkey) -> tuple[str, Optional[int]]:
    """Return (algorithm-name, size-in-bits-or-None). Size is meaningful
    for RSA/DSA (modulus) and EC (curve order). For Ed25519/Ed448 the
    size is fixed by the algorithm so we report None there."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return ("RSA", pubkey.key_size)
    if isinstance(pubkey, dsa.DSAPublicKey):
        return ("DSA", pubkey.key_size)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return (f"EC ({pubkey.curve.name})", pubkey.curve.key_size)
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return ("Ed25519", None)
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return ("Ed448", None)
    return (type(pubkey).__name__, None)


def _name_to_string(name: x509.Name) -> str:
    """RFC 4514 string for an x509 Name. Matches the format `openssl
    x509 -text` prints, modulo attribute ordering."""
    try:
        return name.rfc4514_string()
    except Exception:
        # Fallback if the name uses an OID without a short name
        return ", ".join(f"{a.oid.dotted_string}={a.value}"
                         for a in name)


def _common_name(name: x509.Name) -> str:
    """First CN attribute, or empty string if the name has none. Many
    modern certs omit CN entirely and rely on SANs; that's fine."""
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _san_entries(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """Return (dns_names, ip_addresses) from the cert's SAN extension.
    Empty lists if the extension isn't present — a CN-only cert is
    valid CA/B-ineligible legacy."""
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return ([], [])
    san = ext.value
    dns = list(san.get_values_for_type(x509.DNSName))
    ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return (dns, ips)


def fetch_cert(host: str, port: int = 443,
               timeout: float = 8.0,
               sni: Optional[str] = None) -> CertInfo:
    """Open a single TLS connection, return the leaf cert + handshake
    state. Verification is OFF — we want to inspect the cert as the
    server presents it, including expired or self-signed ones, not get
    blocked by the validation chain.

    Parameters
    ----------
    host : str
        Hostname to connect to.
    port : int
        TCP port. Defaults to 443.
    timeout : float
        Total time-budget for connect + handshake.
    sni : Optional[str]
        Server Name Indication value. Defaults to `host` — overriding
        is occasionally useful when the analyst wants to test how the
        server behaves under a different name (e.g. virtual-host probes).
    """
    if not host:
        return CertInfo(ok=False, error="missing host", host="", port=port)
    sni_name = sni or host

    info = CertInfo(host=host, port=port)
    t_start = time.monotonic()

    # Verification off — we want the *presented* cert, including expired
    # / self-signed / wrong-name ones. The caller decides how to react.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni_name) as ssock:
                der = ssock.getpeercert(binary_form=True)
                info.protocol = ssock.version() or ""
                cipher = ssock.cipher()
                info.cipher = cipher[0] if cipher else ""
    except socket.gaierror as e:
        info.ok = False
        info.error = f"dns_resolution_failed: {e}"
        return info
    except (TimeoutError, socket.timeout):
        info.ok = False
        info.error = "tls_handshake_timeout"
        return info
    except (ConnectionRefusedError, ConnectionResetError) as e:
        info.ok = False
        info.error = f"connection_refused: {type(e).__name__}"
        return info
    except ssl.SSLError as e:
        info.ok = False
        info.error = f"tls_error: {e}"
        return info
    except OSError as e:
        info.ok = False
        info.error = f"network_error: {e}"
        return info

    if not der:
        info.ok = False
        info.error = "no_peer_cert"
        info.elapsed_ms = int((time.monotonic() - t_start) * 1000)
        return info

    # Parse the leaf cert. We never look at intermediates here — every
    # cert-shape testssl ID we fast-path is answered by the leaf alone.
    cert = x509.load_der_x509_certificate(der)
    info.subject = _name_to_string(cert.subject)
    info.issuer = _name_to_string(cert.issuer)
    info.common_name = _common_name(cert.subject)
    info.sans, info.san_ips = _san_entries(cert)
    info.serial = format(cert.serial_number, "x")

    # cryptography 42+ deprecates the naive accessors in favor of the
    # _utc variants. Prefer the new ones; fall back to the old plus an
    # explicit UTC tag on host environments still on cryptography <42.
    from datetime import datetime, timezone
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    info.not_before = nb.isoformat()
    info.not_after = na.isoformat()
    # Days until expiry — negative means already expired. Useful for
    # the cert_validityPeriod / cert_notAfter fast-path verdicts.
    info.days_until_expiry = (na - datetime.now(timezone.utc)).days

    # Signature algorithm: the OID's friendly name (e.g. 'sha256WithRSAEncryption').
    try:
        info.signature_algorithm = cert.signature_algorithm_oid._name or \
                                    cert.signature_algorithm_oid.dotted_string
    except Exception:
        info.signature_algorithm = ""

    # Public key
    try:
        algo, size = _decode_pubkey(cert.public_key())
        info.public_key_algorithm = algo
        info.public_key_size = size
    except Exception:
        info.public_key_algorithm = ""
        info.public_key_size = None

    info.is_self_signed = (cert.subject == cert.issuer)
    info.elapsed_ms = int((time.monotonic() - t_start) * 1000)
    return info
