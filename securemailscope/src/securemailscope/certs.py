"""
M5: parse and validate the server X.509 certificate with the cryptography
library. Reports the facts the rule engine needs; it does not decide severity.
"""
import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

from .models import CertInfo


def _common_name(name: x509.Name) -> str:
    try:
        attr = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if attr:
            return attr[0].value
    except Exception:
        pass
    return name.rfc4514_string()


def parse_certificate(der: bytes) -> Optional[CertInfo]:
    if not der:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", pub.key_size
    else:
        key_type, key_bits = pub.__class__.__name__, 0

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.datetime.now(datetime.timezone.utc)

    return CertInfo(
        subject=_common_name(cert.subject),
        issuer=_common_name(cert.issuer),
        self_signed=cert.subject == cert.issuer,
        not_before=not_before.strftime("%Y-%m-%d"),
        not_after=not_after.strftime("%Y-%m-%d"),
        expired=(now > not_after or now < not_before),
        key_type=key_type,
        key_bits=key_bits,
        sig_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
    )
