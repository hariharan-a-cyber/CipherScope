"""
M4: parse the TLS handshake out of the reassembled server stream.

We locate the first TLS record, walk the record layer, join the handshake
messages, and pull the negotiated version, cipher suite, and the server
certificate. No external tools: this reads the bytes directly.
"""
import struct
from typing import List, Optional, Tuple

from .models import TLSInfo

VERSION_NAMES = {
    b"\x03\x00": "SSL 3.0",
    b"\x03\x01": "TLS 1.0",
    b"\x03\x02": "TLS 1.1",
    b"\x03\x03": "TLS 1.2",
    b"\x03\x04": "TLS 1.3",
}

# minimal cipher-suite table covering what the demo captures use, plus common ones
CIPHER_NAMES = {
    b"\xc0\x30": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    b"\xc0\x2f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    b"\x13\x01": "TLS_AES_128_GCM_SHA256",
    b"\x13\x02": "TLS_AES_256_GCM_SHA384",
    b"\x00\x05": "TLS_RSA_WITH_RC4_128_SHA",
    b"\x00\x0a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    b"\x00\x2f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    b"\x00\x35": "TLS_RSA_WITH_AES_256_CBC_SHA",
}


def find_tls_start(data: bytes) -> int:
    """Return the offset of the first plausible TLS handshake record, or -1."""
    for i in range(len(data) - 5):
        if data[i] == 0x16 and data[i + 1] == 0x03 and data[i + 2] <= 0x04:
            length = struct.unpack(">H", data[i + 3:i + 5])[0]
            if 0 < length <= 0x4000 and data[i + 5:i + 6] in (b"\x02", b"\x01"):
                return i
    return -1


def _records(data: bytes, start: int) -> List[Tuple[int, bytes]]:
    """Split the record layer into (content_type, body) from offset start."""
    out, i = [], start
    while i + 5 <= len(data):
        ctype = data[i]
        length = struct.unpack(">H", data[i + 3:i + 5])[0]
        body = data[i + 5:i + 5 + length]
        if len(body) < length:
            break
        out.append((ctype, body))
        i += 5 + length
    return out


def _handshake_messages(handshake_bytes: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i + 4 <= len(handshake_bytes):
        mtype = handshake_bytes[i]
        length = int.from_bytes(handshake_bytes[i + 1:i + 4], "big")
        body = handshake_bytes[i + 4:i + 4 + length]
        if len(body) < length:
            break
        out.append((mtype, body))
        i += 4 + length
    return out


def _parse_server_hello(body: bytes) -> Tuple[Optional[TLSInfo], None]:
    legacy_version = body[0:2]
    idx = 2 + 32                      # version + random
    sid_len = body[idx]; idx += 1 + sid_len
    cipher_code = body[idx:idx + 2]; idx += 2
    idx += 1                          # compression method

    version = legacy_version
    # look for supported_versions extension (0x002b), used by TLS 1.3
    if idx + 2 <= len(body):
        ext_total = struct.unpack(">H", body[idx:idx + 2])[0]; idx += 2
        end = idx + ext_total
        while idx + 4 <= min(end, len(body)):
            etype = body[idx:idx + 2]
            elen = struct.unpack(">H", body[idx + 2:idx + 4])[0]
            edata = body[idx + 4:idx + 4 + elen]
            if etype == b"\x00\x2b" and len(edata) >= 3:
                version = edata[1:3]
            idx += 4 + elen

    cipher_name = CIPHER_NAMES.get(cipher_code, "0x" + cipher_code.hex())
    info = TLSInfo(
        version=VERSION_NAMES.get(version, "0x" + version.hex()),
        version_code="0x" + version.hex(),
        cipher=cipher_name,
        cipher_code="0x" + cipher_code.hex(),
        forward_secrecy=("ECDHE" in cipher_name or "DHE" in cipher_name),
        aead=("GCM" in cipher_name or "CHACHA20" in cipher_name or "CCM" in cipher_name),
    )
    return info, None


def parse_handshake(server_bytes: bytes) -> Tuple[Optional[TLSInfo], Optional[bytes]]:
    """Return (TLSInfo, first server certificate DER) or (None, None)."""
    start = find_tls_start(server_bytes)
    if start < 0:
        return None, None

    handshake_blob = b"".join(b for ct, b in _records(server_bytes, start) if ct == 22)
    tls_info, cert_der = None, None
    for mtype, body in _handshake_messages(handshake_blob):
        if mtype == 2:               # ServerHello
            tls_info, _ = _parse_server_hello(body)
        elif mtype == 11:            # Certificate
            cert_der = _first_certificate(body)
    return tls_info, cert_der


def _first_certificate(cert_message: bytes) -> Optional[bytes]:
    if len(cert_message) < 6:
        return None
    # skip 3-byte total length, then first cert is 3-byte length + DER
    first_len = int.from_bytes(cert_message[3:6], "big")
    der = cert_message[6:6 + first_len]
    return der or None
