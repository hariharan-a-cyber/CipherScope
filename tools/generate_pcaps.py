"""
Generate the sample packet captures used for the CypherScope demo.

This builds real X.509 certificates and standards-shaped TLS handshake records,
then frames them in TCP/IP and writes them to data/*.pcap. It lets the team own
its dataset and regenerate it at any time. Run:

    python tools/generate_pcaps.py

No network access or capture privileges are needed.
"""
import datetime
import os
import struct

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, Raw, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")

# TLS version codes
TLS10 = b"\x03\x01"
TLS11 = b"\x03\x02"
TLS12 = b"\x03\x03"

# Cipher suite codes (value, readable name)
ECDHE_RSA_AES256_GCM = (b"\xc0\x30", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
RSA_RC4_128_SHA = (b"\x00\x05", "TLS_RSA_WITH_RC4_128_SHA")


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------
def build_cert(common_name, key_size, sig_hash, days_valid, valid_from_days_ago=1,
               issuer_cn=None, signing_key=None):
    """Self-signed by default. Pass issuer_cn + signing_key to make it CA-issued."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    if issuer_cn and signing_key is not None:
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        sign_key = signing_key
    else:
        issuer = subject
        sign_key = key
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=valid_from_days_ago))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(sign_key, sig_hash())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# TLS record / handshake byte builders
# ---------------------------------------------------------------------------
def u24(n):
    return struct.pack(">I", n)[1:]


def handshake(msg_type, body):
    return bytes([msg_type]) + u24(len(body)) + body


def tls_record(content_type, version, payload):
    return bytes([content_type]) + version + struct.pack(">H", len(payload)) + payload


def server_hello(version, cipher_code):
    body = (
        version
        + (b"\x11" * 32)          # server random
        + b"\x00"                  # session id length 0
        + cipher_code              # chosen cipher suite
        + b"\x00"                  # compression: null
        + struct.pack(">H", 0)     # no extensions
    )
    return handshake(2, body)


def certificate_msg(der_list):
    certs = b""
    for der in der_list:
        certs += u24(len(der)) + der
    body = u24(len(certs)) + certs
    return handshake(11, body)


def client_hello():
    body = TLS12 + (b"\x22" * 32) + b"\x00" + struct.pack(">H", 2) + b"\xc0\x30" + b"\x01\x00" + struct.pack(">H", 0)
    return handshake(1, body)


def tls_handshake_flight_server(version, cipher_code, der_list):
    rec = tls_record(22, version, server_hello(version, cipher_code))
    if der_list:
        rec += tls_record(22, version, certificate_msg(der_list))
    return rec


# ---------------------------------------------------------------------------
# TCP framing
# ---------------------------------------------------------------------------
def build_session(client_ip, server_ip, sport, dport, exchange):
    """exchange: list of ("c"/"s", bytes). Returns a list of scapy packets."""
    pkts = []
    cseq, sseq = 1000, 5000
    for direction, payload in exchange:
        if direction == "c":
            p = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(load=payload)
            cseq += len(payload)
        else:
            p = Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(load=payload)
            sseq += len(payload)
        pkts.append(p)
    return pkts


def write(name, pkts):
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, name)
    wrpcap(path, pkts)
    print("wrote", os.path.relpath(path))


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------
def main():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    strong = build_cert("mail.example.gov.in", 2048, hashes.SHA256, days_valid=365,
                        issuer_cn="Example Trusted CA", signing_key=ca_key)
    weak = build_cert("legacy.example.local", 1024, hashes.SHA256, days_valid=-10, valid_from_days_ago=400)

    # 1. IMAPS on 993, TLS 1.2, ECDHE + AES-GCM, strong cert -> SECURE
    write("01_imaps_secure.pcap", build_session(
        "10.0.0.10", "10.0.0.20", 51001, 993,
        [("c", client_hello()),
         ("s", tls_handshake_flight_server(TLS12, ECDHE_RSA_AES256_GCM[0], [strong]))],
    ))

    # 2. SMTPS on 465, TLS 1.0, RC4, expired 1024-bit self-signed cert -> HIGH/CRITICAL
    write("02_smtps_weak_tls.pcap", build_session(
        "10.0.0.10", "10.0.0.30", 51002, 465,
        [("c", client_hello()),
         ("s", tls_handshake_flight_server(TLS10, RSA_RC4_128_SHA[0], [weak]))],
    ))

    # 3. POP3 on 110, no TLS ever, credentials in cleartext -> CRITICAL
    write("03_pop3_plaintext.pcap", build_session(
        "10.0.0.10", "10.0.0.40", 51003, 110,
        [("s", b"+OK POP3 server ready\r\n"),
         ("c", b"USER investigator\r\n"),
         ("s", b"+OK\r\n"),
         ("c", b"PASS Sup3rSecret!\r\n"),
         ("s", b"+OK logged in\r\n")],
    ))

    # 4. SMTP submission on 587, STARTTLS issued and upgraded to TLS 1.2 secure -> SECURE (upgraded)
    write("04_smtp_starttls_secure.pcap", build_session(
        "10.0.0.10", "10.0.0.50", 51004, 587,
        [("s", b"220 mail.example.gov.in ESMTP ready\r\n"),
         ("c", b"EHLO client\r\n"),
         ("s", b"250-mail.example.gov.in\r\n250-STARTTLS\r\n250 OK\r\n"),
         ("c", b"STARTTLS\r\n"),
         ("s", b"220 Ready to start TLS\r\n"),
         ("c", client_hello()),
         ("s", tls_handshake_flight_server(TLS12, ECDHE_RSA_AES256_GCM[0], [strong]))],
    ))

    # 5. SMTP on 587, STARTTLS advertised but never used, login sent in cleartext -> CRITICAL (stripped)
    write("05_smtp_starttls_stripped.pcap", build_session(
        "10.0.0.10", "10.0.0.60", 51005, 587,
        [("s", b"220 mail.example.gov.in ESMTP ready\r\n"),
         ("c", b"EHLO client\r\n"),
         ("s", b"250-mail.example.gov.in\r\n250-STARTTLS\r\n250 AUTH LOGIN\r\n"),
         ("c", b"AUTH LOGIN\r\n"),
         ("s", b"334 VXNlcm5hbWU6\r\n"),
         ("c", b"aW52ZXN0aWdhdG9y\r\n"),
         ("s", b"334 UGFzc3dvcmQ6\r\n"),
         ("c", b"U3VwM3JTZWNyZXQh\r\n")],
    ))

    # 6. SMTP on a non-standard port (2525), no STARTTLS offered, login in cleartext -> CRITICAL
    #    Exercises banner-based protocol detection: nothing about port 2525 says "mail".
    write("06_smtp_nonstandard_port.pcap", build_session(
        "10.0.0.10", "10.0.0.70", 51006, 2525,
        [("s", b"220 relay.example.local ESMTP Postfix\r\n"),
         ("c", b"EHLO client\r\n"),
         ("s", b"250-relay.example.local\r\n250 AUTH LOGIN PLAIN\r\n"),
         ("c", b"AUTH LOGIN\r\n"),
         ("s", b"334 VXNlcm5hbWU6\r\n"),
         ("c", b"aW52ZXN0aWdhdG9y\r\n"),
         ("s", b"334 UGFzc3dvcmQ6\r\n"),
         ("c", b"U3VwM3JTZWNyZXQh\r\n"),
         ("s", b"235 Authentication successful\r\n")],
    ))


if __name__ == "__main__":
    main()
