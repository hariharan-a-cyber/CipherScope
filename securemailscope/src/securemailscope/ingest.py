"""
M1 + M2: read a PCAP, group packets into email TCP sessions, and reassemble
each direction of the byte stream.
"""
import logging
from typing import Dict, List, Tuple

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


def _server_port(sport: int, dport: int):
    """Return (server_port, server_is_dst) if this looks like email traffic."""
    if dport in PORT_PROTOCOL:
        return dport, True
    if sport in PORT_PROTOCOL:
        return sport, False
    return None, None


def load_sessions(pcap_path: str) -> List[EmailSession]:
    packets = rdpcap(pcap_path)

    # bucket packets by connection, keeping direction and TCP seq
    conns: Dict[frozenset, dict] = {}
    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        server_port, server_is_dst = _server_port(tcp.sport, tcp.dport)
        if server_port is None:
            continue

        if server_is_dst:
            server_ip, client_ip = ip.dst, ip.src
        else:
            server_ip, client_ip = ip.src, ip.dst

        key = frozenset({(ip.src, tcp.sport), (ip.dst, tcp.dport)})
        conn = conns.setdefault(key, {
            "server_ip": server_ip, "server_port": server_port,
            "client_ip": client_ip, "c": [], "s": [],
        })
        payload = bytes(pkt[Raw].load)
        direction = "s" if ip.src == server_ip else "c"
        conn[direction].append((int(tcp.seq), payload))

    sessions: List[EmailSession] = []
    for i, conn in enumerate(conns.values()):
        sessions.append(EmailSession(
            stream_id=i,
            protocol=PORT_PROTOCOL[conn["server_port"]],
            server_ip=conn["server_ip"],
            server_port=conn["server_port"],
            client_ip=conn["client_ip"],
            implicit_tls=conn["server_port"] in IMPLICIT_TLS_PORTS,
            client_bytes=_reassemble(conn["c"]),
            server_bytes=_reassemble(conn["s"]),
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
