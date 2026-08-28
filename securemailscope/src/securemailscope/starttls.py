"""
M3: work out the encryption state of each session.

States:
  IMPLICIT_TLS       server port is an implicit-TLS port (465/993/995)
  STARTTLS_UPGRADED  plaintext protocol issued STARTTLS/STLS and TLS followed
  STARTTLS_STRIPPED  server offered STARTTLS but the session stayed in cleartext
  PLAINTEXT_ONLY     no encryption offered or used at all
"""
from .handshake import find_tls_start

_UPGRADE_TOKENS = (b"STARTTLS", b"STLS")
_CRED_TOKENS = (b"USER ", b"PASS ", b"AUTH LOGIN", b"AUTH PLAIN")


def classify(session) -> str:
    if session.implicit_tls:
        session.starttls_state = "IMPLICIT_TLS"
        return session.starttls_state

    has_tls = find_tls_start(session.server_bytes) >= 0
    client_up = any(t in session.client_bytes.upper() for t in _UPGRADE_TOKENS)
    server_offered = any(t in session.server_bytes.upper() for t in _UPGRADE_TOKENS)

    if client_up and has_tls:
        state = "STARTTLS_UPGRADED"
    elif server_offered and not has_tls:
        state = "STARTTLS_STRIPPED"
    elif has_tls:
        state = "STARTTLS_UPGRADED"
    else:
        state = "PLAINTEXT_ONLY"

    session.starttls_state = state
    return state


def credentials_in_cleartext(session) -> bool:
    blob = session.client_bytes.upper()
    return any(t.upper() in blob for t in _CRED_TOKENS)
