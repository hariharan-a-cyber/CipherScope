# Sample captures

These five captures are the demo dataset. They were generated with
`tools/generate_pcaps.py`, which builds real X.509 certificates and
standards-shaped TLS handshake records. No private email content is present.

Each file and the verdict the tool should produce:

| File | Traffic | Expected result |
|------|---------|-----------------|
| `01_imaps_secure.pcap` | IMAPS on 993, TLS 1.2, ECDHE + AES-256-GCM, CA-issued cert | SECURE |
| `02_smtps_weak_tls.pcap` | SMTPS on 465, TLS 1.0, RC4, expired 1024-bit self-signed cert | HIGH |
| `03_pop3_plaintext.pcap` | POP3 on 110, no TLS, USER/PASS in the clear | CRITICAL |
| `04_smtp_starttls_secure.pcap` | SMTP on 587, STARTTLS upgrade to TLS 1.2 secure | SECURE |
| `05_smtp_starttls_stripped.pcap` | SMTP on 587, STARTTLS offered but login sent in cleartext | CRITICAL |
| `06_smtp_nonstandard_port.pcap` | SMTP on 2525 (non-standard port), identified from its banner, login in cleartext | CRITICAL |
| `07_real_gmail_outlook.pcapng` | **Real capture.** Wireshark, IPv6, `openssl s_client` to Gmail IMAPS (993), Outlook IMAPS (993) and Outlook SMTP STARTTLS (587). TLS 1.3 throughout. | 3 x SECURE |

`07_real_gmail_outlook.pcapng` is the only capture taken from live traffic. It
contains handshakes only; no login was attempted, so it holds no credentials
or mail content. Because the sessions are TLS 1.3, the certificate is sent
encrypted and the certificate checks do not apply.

To regenerate them:

    python tools/generate_pcaps.py

To make your own from real servers later, capture SMTP/IMAP/POP3 traffic with
Wireshark and drop the `.pcap` here, then scan it from the dashboard.
