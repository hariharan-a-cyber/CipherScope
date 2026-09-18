"""Run the full pipeline over a PCAP and return scanned sessions."""
from typing import List

from .ingest import load_sessions
from .starttls import classify
from .handshake import parse_handshake
from .certs import parse_certificate
from .rules import evaluate
from .models import EmailSession


def analyze_pcap(pcap_path: str) -> List[EmailSession]:
    sessions = load_sessions(pcap_path)
    for s in sessions:
        classify(s)                                  # M3
        if s.starttls_state in ("IMPLICIT_TLS", "STARTTLS_UPGRADED"):
            tls, cert_der = parse_handshake(s.server_bytes)   # M4
            s.tls = tls
            if cert_der:
                s.cert = parse_certificate(cert_der)          # M5
        evaluate(s)                                  # M6
    return sessions
