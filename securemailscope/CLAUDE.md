# Project context for Claude Code

SecureMailScope is a passive email TLS posture analyzer for SIH 2026 (SIH26159, NTRO).
It reads a PCAP of SMTP/IMAP/POP3 traffic, parses the TLS handshake and certificate,
and grades each session from SECURE to CRITICAL with findings and fixes.

## Ground rules

- Pure Python. Do not add a dependency on a live Wireshark install or live capture.
- The pipeline order is fixed: ingest -> starttls -> handshake -> certs -> rules -> report.
- Detection logic lives in `rules.py`. Severity and remediation text live in `rules.yaml`.
- Keep `EmailSession` in `models.py` as the object passed between stages.
- Every change must keep `PYTHONPATH=src python -m pytest` green.
- Run from the project root with `PYTHONPATH=src`.

## Not built yet (finale work)

- ML risk scoring and anomaly detection (a separate module fed by rule-engine output as labels)
- PDF report export
- Robustness on large or malformed captures

When adding a module, also add its test in `tests/` and a sample capture in `data/`
if it needs one (extend `tools/generate_pcaps.py`).
