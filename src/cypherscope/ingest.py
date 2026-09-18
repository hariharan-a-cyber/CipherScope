"""
M1 + M2: read a PCAP, group packets into email TCP sessions, and reassemble
each direction of the byte stream.

A session is recognised as email traffic in one of two ways:

  port    the server side is on a well-known mail port (25/587/465/143/993/110/995)
  banner  the reassembled stream starts with a recognisable SMTP, IMAP or POP3
          greeting or command, whatever the port

Banner detection only works while the conversation is still in cleartext, so
an implicit-TLS server on a non-standard port cannot be identified and is
skipped. Everything else (HTTP, SSH, DNS over TCP ...) is dropped.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP, Raw

from .models import EmailSession

# well-known email server ports
PORT_PROTOCOL = {
    25: "SMTP", 587: "SMTP", 465: "SMTP",
    143: "IMAP", 993: "IMAP",
    110: "POP3", 995: "POP3",
}
IMPLICIT_TLS_PORTS = {465, 993, 995}

# First line each side sends when the protocol is still in the clear.
# Server greetings are the strongest signal; client commands back them up.
_SERVER_BANNERS = (
    (re.compile(rb"^220[ -].*", re.I), "SMTP"),        # 220 mail.example ESMTP ready
    (re.compile(rb"^\* (OK|PREAUTH|BYE)\b", re.I), "IMAP"),  # * OK IMAP4rev1 ready
    (re.compile(rb"^\+OK\b", re.I), "POP3"),           # +OK POP3 server ready
)
_CLIENT_COMMANDS = (
    (re.compile(rb"^(EHLO|HELO|MAIL FROM|RCPT TO|STARTTLS)\b", re.I), "SMTP"),
    (re.compile(rb"^[A-Z0-9]+ (CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|NOOP|ID)\b", re.I), "IMAP"),
    (re.compile(rb"^(USER|PASS|CAPA|STLS|APOP|AUTH)\b", re.I), "POP3"),
)


def _first_line(data: bytes) -> bytes:
    return data.split(b"\n", 1)[0].rstrip(b"\r")[:128]


def detect_protocol(server_bytes: bytes, client_bytes: bytes) -> Optional[str]:
    """Identify the mail protocol from the opening lines, or None if not mail."""
    line = _first_line(server_bytes)
    for pattern, proto in _SERVER_BANNERS:
        if pattern.match(line):
            return proto
    line = _first_line(client_bytes)
    for pattern, proto in _CLIENT_COMMANDS:
        if pattern.match(line):
            return proto
    return None


def _known_server(a: Tuple[str, int], b: Tuple[str, int]):
    """Return (server, client) endpoints if one side is on a well-known mail port."""
    if b[1] in PORT_PROTOCOL:
        return b, a
    if a[1] in PORT_PROTOCOL:
        return a, b
    return None, None


def load_sessions(pcap_path: str) -> List[EmailSession]:
    packets = rdpcap(pcap_path)

    # bucket every TCP payload by connection, keeping direction and TCP seq;
    # which side is the server is decided after the whole capture is read
    conns: Dict[frozenset, dict] = {}
    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        src, dst = (ip.src, int(tcp.sport)), (ip.dst, int(tcp.dport))
        key = frozenset({src, dst})
        conn = conns.setdefault(key, {"first_sender": src, "chunks": {src: [], dst: []}})
        conn["chunks"].setdefault(src, []).append((int(tcp.seq), bytes(pkt[Raw].load)))

    sessions: List[EmailSession] = []
    for conn in conns.values():
        endpoints = list(conn["chunks"].keys())
        if len(endpoints) != 2:
            continue  # only one side ever spoke; nothing to grade
        server, client = _known_server(endpoints[0], endpoints[1])
        if server is None:
            # Mail servers always greet first, so on an unknown port the side
            # that sent the first payload is the server.
            server = conn["first_sender"]
            client = endpoints[0] if endpoints[1] == server else endpoints[1]

        server_bytes = _reassemble(conn["chunks"][server])
        client_bytes = _reassemble(conn["chunks"][client])

        protocol = PORT_PROTOCOL.get(server[1])
        detected_by = "port"
        if protocol is None:
            protocol = detect_protocol(server_bytes, client_bytes)
            detected_by = "banner"
        if protocol is None:
            continue  # not email traffic

        sessions.append(EmailSession(
            stream_id=len(sessions),
            protocol=protocol,
            server_ip=server[0],
            server_port=server[1],
            client_ip=client[0],
            implicit_tls=server[1] in IMPLICIT_TLS_PORTS,
            detected_by=detected_by,
            client_bytes=client_bytes,
            server_bytes=server_bytes,
        ))
    return sessions


def _reassemble(chunks: List[Tuple[int, bytes]]) -> bytes:
    """Order by TCP sequence number and concatenate, skipping overlaps."""
    if not chunks:
        return b""
    chunks = sorted(chunks, key=lambda c: c[0])
    out = bytearray()
    next_seq = chunks[0][0]
    for seq, payload in chunks:
        if seq < next_seq:
            # overlap already covered, skip the overlapping prefix
            skip = next_seq - seq
            payload = payload[skip:]
            seq = next_seq
        out += payload
        next_seq = seq + len(payload)
    return bytes(out)
