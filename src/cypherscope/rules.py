"""
M6: the rule engine. Turns the facts gathered by the earlier stages into a list
of findings with severities pulled from rules.yaml.
"""
import os
from functools import lru_cache

import yaml

from .models import Finding
from .starttls import credentials_in_cleartext

_OBSOLETE_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "MD5")


@lru_cache(maxsize=1)
def _catalog():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _make(code: str, detail: str) -> Finding:
    meta = _catalog()[code]
    return Finding(
        code=code,
        severity=meta["severity"],
        title=meta["title"],
        detail=detail,
    )


def evaluate(session) -> None:
    findings = []
    state = session.starttls_state

    if state == "PLAINTEXT_ONLY":
        extra = " Credentials were sent in the clear." if credentials_in_cleartext(session) else ""
        findings.append(_make("NO_ENCRYPTION",
                              f"{session.protocol} session on port {session.server_port} used no TLS.{extra}"))
    elif state == "STARTTLS_STRIPPED":
        extra = " Credentials were sent in the clear." if credentials_in_cleartext(session) else ""
        findings.append(_make("STARTTLS_STRIPPED",
                              f"Server advertised STARTTLS but the session stayed in cleartext.{extra}"))

    tls = session.tls
    if tls is not None:
        if tls.version in _OBSOLETE_VERSIONS:
            findings.append(_make("OBSOLETE_TLS", f"Negotiated {tls.version} ({tls.version_code})."))
        if any(tok in tls.cipher for tok in _WEAK_CIPHER_TOKENS):
            findings.append(_make("WEAK_CIPHER", f"Negotiated {tls.cipher}."))
        if not tls.forward_secrecy:
            findings.append(_make("NO_FORWARD_SECRECY", f"{tls.cipher} does not provide forward secrecy."))

    cert = session.cert
    if cert is not None:
        if cert.expired:
            findings.append(_make("CERT_EXPIRED",
                                  f"Certificate for '{cert.subject}' valid {cert.not_before} to {cert.not_after}."))
        if cert.self_signed:
            findings.append(_make("CERT_SELF_SIGNED", f"Certificate for '{cert.subject}' is self-signed."))
        if cert.key_type == "RSA" and cert.key_bits < 2048:
            findings.append(_make("WEAK_KEY", f"{cert.key_type} key is only {cert.key_bits} bits."))

    session.findings = findings
