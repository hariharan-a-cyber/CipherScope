"""Shared data structures for the analysis pipeline."""
from dataclasses import dataclass, field
from typing import List, Optional


SEVERITY_ORDER = {"SECURE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    remediation: str


@dataclass
class TLSInfo:
    version: Optional[str] = None          # e.g. "TLS 1.2"
    version_code: Optional[str] = None     # e.g. "0x0303"
    cipher: Optional[str] = None           # readable cipher suite name
    cipher_code: Optional[str] = None      # e.g. "0xc030"
    forward_secrecy: bool = False
    aead: bool = False


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    self_signed: bool = False
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    key_type: str = ""
    key_bits: int = 0
    sig_algorithm: str = ""


@dataclass
class EmailSession:
    stream_id: int
    protocol: str                 # SMTP / IMAP / POP3
    server_ip: str
    server_port: int
    client_ip: str
    implicit_tls: bool
    client_bytes: bytes = b""
    server_bytes: bytes = b""
    starttls_state: str = "UNKNOWN"
    tls: Optional[TLSInfo] = None
    cert: Optional[CertInfo] = None
    findings: List[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if not self.findings:
            return "SECURE"
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    @property
    def label(self) -> str:
        side = "implicit TLS" if self.implicit_tls else "STARTTLS"
        return f"{self.protocol} :{self.server_port} ({side})"
