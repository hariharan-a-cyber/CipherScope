"""
End to end checks: each bundled capture must produce the expected verdict.
Run from the project root with:  PYTHONPATH=src pytest
"""
import os
import pytest

from cypherscope.analyze import analyze_pcap

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


def test_nonstandard_port_detected_by_banner():
    s = top("06_smtp_nonstandard_port.pcap")
    assert s.protocol == "SMTP" and s.server_port == 2525
    assert s.detected_by == "banner"
    assert s.starttls_state == "PLAINTEXT_ONLY"
    assert s.severity == "CRITICAL"
    assert "NO_ENCRYPTION" in codes(s)


def test_tls13_server_hello_parsed():
    # A TLS 1.3 ServerHello carries legacy_version 0x0303 and the real version in
    # the supported_versions extension as a bare 2-byte value. It must come out as
    # TLS 1.3 with forward secrecy, not as TLS 1.2 without it.
    import struct
    from cypherscope.handshake import parse_handshake
    ext = b"\x00\x2b" + struct.pack(">H", 2) + b"\x03\x04"
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs
    tls, cert = parse_handshake(record)
    assert tls.version == "TLS 1.3"
    assert tls.cipher == "TLS_AES_128_GCM_SHA256"
    assert tls.forward_secrecy and tls.aead
    assert cert is None


def test_non_mail_traffic_is_ignored(tmp_path):
    # An HTTP exchange on port 8080 must not be reported as an email session.
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    pkts = [
        Ether() / IP(src="10.0.0.10", dst="10.0.0.80") / TCP(sport=51007, dport=8080, flags="PA", seq=1, ack=1)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        Ether() / IP(src="10.0.0.80", dst="10.0.0.10") / TCP(sport=8080, dport=51007, flags="PA", seq=1, ack=30)
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    ]
    path = str(tmp_path / "http.pcap")
    wrpcap(path, pkts)
    assert analyze_pcap(path) == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
