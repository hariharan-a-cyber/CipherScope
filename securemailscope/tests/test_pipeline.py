"""
End to end checks: each bundled capture must produce the expected verdict.
Run from the project root with:  PYTHONPATH=src pytest
"""
import os
import pytest

from securemailscope.analyze import analyze_pcap

DATA = os.path.join(os.path.dirname(__file__), "..", "data")


def top(pcap):
    sessions = analyze_pcap(os.path.join(DATA, pcap))
    assert len(sessions) == 1
    return sessions[0]


def codes(session):
    return {f.code for f in session.findings}


def test_secure_imaps():
    s = top("01_imaps_secure.pcap")
    assert s.protocol == "IMAP" and s.server_port == 993
    assert s.starttls_state == "IMPLICIT_TLS"
    assert s.tls.version == "TLS 1.2"
    assert s.severity == "SECURE"
    assert s.findings == []


def test_weak_smtps():
    s = top("02_smtps_weak_tls.pcap")
    assert s.tls.version == "TLS 1.0"
    assert "RC4" in s.tls.cipher
    assert s.cert.key_bits == 1024 and s.cert.expired
    assert s.severity == "HIGH"
    assert {"OBSOLETE_TLS", "WEAK_CIPHER", "CERT_EXPIRED", "WEAK_KEY"} <= codes(s)


def test_plaintext_pop3():
    s = top("03_pop3_plaintext.pcap")
    assert s.protocol == "POP3"
    assert s.starttls_state == "PLAINTEXT_ONLY"
    assert s.severity == "CRITICAL"
    assert "NO_ENCRYPTION" in codes(s)


def test_starttls_upgraded():
    s = top("04_smtp_starttls_secure.pcap")
    assert s.starttls_state == "STARTTLS_UPGRADED"
    assert s.tls.version == "TLS 1.2" and s.tls.forward_secrecy
    assert s.severity == "SECURE"


def test_starttls_stripped():
    s = top("05_smtp_starttls_stripped.pcap")
    assert s.starttls_state == "STARTTLS_STRIPPED"
    assert s.severity == "CRITICAL"
    assert "STARTTLS_STRIPPED" in codes(s)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
