"""Build report structures and a plain terminal table from scanned sessions."""
from typing import List, Dict

from .models import EmailSession, SEVERITY_ORDER

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SECURE": 4}


def session_to_dict(s: EmailSession) -> dict:
    return {
        "stream_id": s.stream_id,
        "protocol": s.protocol,
        "detected_by": s.detected_by,
        "server": f"{s.server_ip}:{s.server_port}",
        "client": s.client_ip,
        "encryption_state": s.starttls_state,
        "severity": s.severity,
        "tls": None if not s.tls else {
            "version": s.tls.version,
            "cipher": s.tls.cipher,
            "forward_secrecy": s.tls.forward_secrecy,
            "aead": s.tls.aead,
        },
        "certificate": None if not s.cert else {
            "subject": s.cert.subject,
            "issuer": s.cert.issuer,
            "self_signed": s.cert.self_signed,
            "valid_from": s.cert.not_before,
            "valid_to": s.cert.not_after,
            "expired": s.cert.expired,
            "key": f"{s.cert.key_type} {s.cert.key_bits}-bit",
            "signature": s.cert.sig_algorithm,
        },
        "findings": [
            {"code": f.code, "severity": f.severity, "title": f.title,
             "detail": f.detail, "remediation": f.remediation}
            for f in s.findings
        ],
    }


def build_report(pcap_name: str, sessions: List[EmailSession]) -> dict:
    counts: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for s in sessions:
        counts[s.severity] += 1
    ordered = sorted(sessions, key=lambda s: SEVERITY_RANK[s.severity])
    return {
        "source": pcap_name,
        "session_count": len(sessions),
        "summary": counts,
        "sessions": [session_to_dict(s) for s in ordered],
    }


def terminal_table(report: dict) -> str:
    lines = []
    lines.append(f"Source: {report['source']}   Sessions: {report['session_count']}")
    s = report["summary"]
    lines.append(f"Summary: CRITICAL={s['CRITICAL']}  HIGH={s['HIGH']}  "
                 f"MEDIUM={s['MEDIUM']}  LOW={s['LOW']}  SECURE={s['SECURE']}")
    lines.append("-" * 78)
    lines.append(f"{'SEVERITY':<9} {'PROTO':<5} {'PORT':<5} {'ENCRYPTION':<18} {'TLS / CIPHER'}")
    lines.append("-" * 78)
    for sess in report["sessions"]:
        tls = sess["tls"]
        tls_txt = f"{tls['version']} / {tls['cipher']}" if tls else "-"
        proto_port = sess["server"].split(":")[-1]
        lines.append(f"{sess['severity']:<9} {sess['protocol']:<5} {proto_port:<5} "
                     f"{sess['encryption_state']:<18} {tls_txt}")
        if sess.get("detected_by") == "banner":
            lines.append(f"    (non-standard port; protocol identified from the {sess['protocol']} banner)")
        for f in sess["findings"]:
            lines.append(f"    [{f['severity']}] {f['title']}: {f['detail']}")
    lines.append("-" * 78)
    return "\n".join(lines)
