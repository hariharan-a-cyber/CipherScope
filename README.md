# CypherScope

CypherScope reads a packet capture of email traffic and reports how strong or weak
the TLS encryption was. It finds SMTP, IMAP and POP3 sessions, parses the TLS
handshake, checks the server certificate, and grades each session from SECURE to
CRITICAL with the reason.

Live demo: https://cipher-scope-prototype.vercel.app

Built for Smart India Hackathon 2026, problem statement SIH26159 (NTRO).

## Status: prototype

This is a working prototype built for the shortlisting round. It is honest about
what it can and cannot do:

**It does**

- read `.pcap` and `.pcapng` files offline, IPv4 and IPv6, no Wireshark or root needed
- find SMTP, IMAP and POP3 sessions on their standard ports, and on any other
  port when the session opens with a recognisable cleartext greeting
- tell plaintext, STARTTLS-upgraded, STARTTLS-stripped and implicit-TLS sessions apart
- read the negotiated TLS version (SSL 3.0 through TLS 1.3) and cipher suite
- parse the server certificate and check expiry, key size and self-signing
- grade each session and explain why
- run as a web dashboard or from the command line, with JSON output

**It does not (yet)**

- capture live traffic; it reads files only
- verify the certificate chain against a trust store, or check that the
  certificate name matches the server
- inspect certificates in TLS 1.3 sessions, where the certificate is sent
  encrypted; version, cipher and forward secrecy are still graded
- identify implicit-TLS servers on non-standard ports (no cleartext banner to read)
- handle captures that are large, truncated or damaged; it has only been
  exercised on small, well formed captures
- on the hosted demo, accept uploads over 4 MB or scans over 60 seconds

Do not treat its output as an audit result. Treat it as a first look that points
you at the sessions worth checking by hand.

## What it checks

Each session is scored against these rules. Severity and wording live in
`src/cypherscope/rules.yaml`; detection logic in `src/cypherscope/rules.py`.

| Code | Severity | Triggered when |
|------|----------|----------------|
| `NO_ENCRYPTION` | CRITICAL | the session never used TLS |
| `STARTTLS_STRIPPED` | CRITICAL | the server offered STARTTLS but the session stayed in cleartext |
| `OBSOLETE_TLS` | HIGH | SSL 3.0, TLS 1.0 or TLS 1.1 was negotiated |
| `WEAK_CIPHER` | HIGH | the cipher suite uses RC4, 3DES, DES, NULL, EXPORT or MD5 |
| `CERT_EXPIRED` | HIGH | the certificate is expired or not yet valid |
| `CERT_SELF_SIGNED` | MEDIUM | the certificate subject and issuer are the same |
| `WEAK_KEY` | MEDIUM | an RSA key under 2048 bits |
| `NO_FORWARD_SECRECY` | MEDIUM | the key exchange is static RSA rather than ECDHE/DHE |

A session with no findings is SECURE. When credentials (`USER`/`PASS`,
`AUTH LOGIN`, `AUTH PLAIN`) are visible in a cleartext session, the finding says so.

The tool never reads message contents. TLS encrypts the mail itself, but the
handshake that sets up the encryption is sent in the clear, and the handshake is
all this tool needs.

## How it works

The pipeline runs in fixed stages, one module each under `src/cypherscope/`:

1. `ingest.py`: read the PCAP, group packets into TCP connections, decide which
   side is the server, identify the mail protocol by port or by banner
2. `ingest.py`: reassemble each direction of the byte stream by TCP sequence number
3. `starttls.py`: work out the encryption state, including STARTTLS upgrades and stripping
4. `handshake.py`: parse the TLS records for the negotiated version and cipher suite
5. `certs.py`: parse and check the server certificate
6. `rules.py`: apply the rules and score the session

Everything is plain Python on top of `scapy` (packet reading) and
`cryptography` (certificate parsing).

## Install

Python 3.9 or newer.

    pip install -r requirements.txt

For the test suite as well:

    pip install -r requirements-dev.txt

## Run the dashboard locally

From the project folder:

    # Linux or macOS
    ./run_demo.sh

    # Windows
    run_demo.bat

Then open http://127.0.0.1:8000. Upload a capture, or click Scan on one of the
bundled samples. You get a summary of severities and a per-session breakdown with
the problem.

If the scripts do not run, start it directly:

    # Linux or macOS
    PYTHONPATH=src python -m cypherscope serve

    # Windows (PowerShell)
    $env:PYTHONPATH="src"; python -m cypherscope serve

## Command line

The same scanner runs from a terminal without the dashboard. Set `PYTHONPATH`
once per shell so Python can find the package under `src/`:

    # Linux or macOS
    export PYTHONPATH=src

    # Windows (PowerShell)
    $env:PYTHONPATH="src"

Or run `pip install -e .` once and skip the `PYTHONPATH` step for good.

Scan one capture:

    python -m cypherscope scan data/02_smtps_weak_tls.pcap

The stages tick off one by one, then the report prints: a summary count per
severity and a row per session with protocol, port, encryption state, TLS
version and cipher, followed by each finding.

Scan several at once, or your own file:

    python -m cypherscope scan data/*.pcap
    python -m cypherscope scan /path/to/capture.pcap

Also write the report as JSON:

    python -m cypherscope scan data/03_pop3_plaintext.pcap --json report.json

With more than one input the JSON file holds a list, one entry per capture.

Options:

    --json PATH      also write the report as JSON to this path
    --no-progress    skip the stage-by-stage display

The progress display goes to stderr and is skipped automatically when stderr is
not a terminal, so piping stdout to a file or another tool gives you the table
alone. Exit status is 0 if at least one capture was scanned and 1 otherwise.

Start the dashboard from the same command:

    python -m cypherscope serve --port 8000

Run `python -m cypherscope --help` or `python -m cypherscope scan --help` for
the full list.

## Sample data

Six captures are included in `data/`. `data/README.md` lists the expected
result of each.

| File | Scenario | Expected |
|------|----------|----------|
| `01_imaps_secure.pcap` | IMAPS on 993, TLS 1.2, ECDHE + AES-GCM, CA-issued certificate | SECURE |
| `02_smtps_weak_tls.pcap` | SMTPS on 465, TLS 1.0, RC4, expired 1024-bit self-signed certificate | HIGH |
| `03_pop3_plaintext.pcap` | POP3 on 110, no TLS, `USER`/`PASS` in the clear | CRITICAL |
| `04_smtp_starttls_secure.pcap` | SMTP on 587, STARTTLS upgraded to TLS 1.2 | SECURE |
| `05_smtp_starttls_stripped.pcap` | SMTP on 587, STARTTLS offered but login sent in cleartext | CRITICAL |
| `06_smtp_nonstandard_port.pcap` | SMTP on 2525, found by its banner, login in cleartext | CRITICAL |
| `07_real_gmail_outlook.pcapng` | Real Wireshark capture over IPv6: Gmail and Outlook IMAPS, Outlook SMTP STARTTLS, all TLS 1.3 | 3 x SECURE |

Captures 01 to 06 are synthetic. `tools/generate_pcaps.py` builds real X.509
certificates and standards-shaped TLS records and frames them in TCP/IP, but no
real mail server was involved. They prove the pipeline. Capture 07 is real
traffic, recorded with Wireshark against Gmail and Outlook using
`openssl s_client`; it contains handshakes only, no logins. Regenerate the
synthetic ones with:

    python tools/generate_pcaps.py

## Capturing a real PCAP

You need a capture that contains the start of a mail session, because the TLS
handshake and any STARTTLS exchange happen in the first few packets. Use
Wireshark or `tcpdump`; the tool reads both `.pcap` and `.pcapng`.

Against a public mail server, from your own machine (no server access or mail
account needed; the handshake alone is enough):

    # start capturing on your active interface, only mail ports, save to a file
    sudo tcpdump -i any -w mail.pcap 'tcp port 25 or 465 or 587 or 143 or 993 or 110 or 995'

    # in a second terminal, open a session so there is something to capture
    openssl s_client -connect imap.gmail.com:993 -servername imap.gmail.com < /dev/null
    openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null

    # stop tcpdump with Ctrl+C, then scan
    python -m cypherscope scan mail.pcap

On Windows, install Wireshark (which bundles the Npcap capture driver), pick
your network adapter, set the capture filter to
`tcp port 25 or 465 or 587 or 143 or 993 or 110 or 995`, start capturing, run
the `openssl s_client` commands above (OpenSSL ships with Git for Windows as
`C:\Program Files\Git\usr\bin\openssl.exe`), stop the capture and save it with
**File > Save As** (the default `.pcapng` format is fine).

Or point a real mail client (Thunderbird, Outlook) at your own account while
capturing; the login sequence is exactly what the tool grades. Captures of your
own traffic on your own machine need no permission from anyone. Do not capture
other people's traffic.

Expect modern providers to come out SECURE on TLS 1.3 or 1.2. For a weak or
plaintext example you control end to end, run a throwaway SMTP server locally
and talk to it over the loopback interface:

    docker run --rm -p 2525:1025 mailhog/mailhog      # SMTP with no TLS at all
    tcpdump -i lo -w local.pcap 'tcp port 2525'
    python -c "import smtplib; s=smtplib.SMTP('127.0.0.1',2525); s.ehlo(); s.quit()"

Port 2525 is non-standard on purpose: the scanner still finds the session from
its SMTP banner and grades it CRITICAL for running in the clear.

## Tests

    python -m pytest

Nine tests: one per bundled capture checking the expected verdict (including
the real Gmail/Outlook capture), one that non-mail traffic (HTTP) is ignored,
and one that a TLS 1.3 ServerHello is parsed correctly.

## Deploying

The dashboard is a FastAPI app and runs on Vercel as a single Python function.
`api/index.py` is the entry point and `vercel.json` routes every path to it and
ships `src/` and `data/` with the bundle.

    npm i -g vercel
    vercel
    vercel --prod

Two platform limits apply to the hosted version. The app rejects uploads over
4 MB with a clear message, and Vercel stops any function run at 60 seconds. If
you need full-size captures, run it locally or on a normal server.

## Project layout

    cypherscope/
      run_demo.sh, run_demo.bat     start the dashboard locally
      requirements.txt              runtime dependencies
      requirements-dev.txt          runtime plus pytest
      pyproject.toml
      vercel.json                   Vercel routing and function config
      api/index.py                  Vercel entry point
      data/                         sample captures and notes
      tools/generate_pcaps.py       builds the sample captures
      tests/test_pipeline.py        end to end checks
      src/cypherscope/
        ingest.py                   read PCAP, find mail sessions, reassemble streams
        starttls.py                 encryption state and STARTTLS logic
        handshake.py                TLS handshake parser
        certs.py                    certificate parsing and checks
        rules.py                    rule engine
        rules.yaml                  severity and title per finding
        report.py                   report building and terminal output
        webapp.py                   FastAPI dashboard
        __main__.py                 scan and serve commands
        templates/, static/         dashboard UI

## Roadmap

The problem statement (SIH26159, NTRO) asks for a tool that assesses the
cryptographic security posture of email traffic from packet captures. The
prototype is a single-file, offline, first-look grader: one PCAP in, one
severity per session out. The product is a system an analyst runs continuously
against real traffic and trusts. The table below is the gap, area by area.

### Prototype vs. product

| Area | Prototype (today) | Product |
|---|---|---|
| Input | One uploaded `.pcap`/`.pcapng`, small and well formed | Live capture from an interface or SPAN port, multi-GB files, streaming ingest, batch folders, graceful handling of truncated or damaged captures |
| Protocol coverage | SMTP, IMAP, POP3 on standard ports, or any port with a cleartext banner | Implicit TLS on non-standard ports via handshake fingerprinting, Exchange/MAPI over HTTPS, webmail, submission variants |
| TLS analysis | Negotiated version and cipher, forward-secrecy and AEAD flags | Full ClientHello analysis (offered versions and ciphers, downgrade risk), extensions (SNI, ALPN, renegotiation, session tickets), TLS 1.3 groups and key shares, JA3/JA3S fingerprints, known-vulnerable configurations |
| Certificates | Expiry, key size, self-signed; only when the certificate is sent in the clear (TLS 1.2 and below) | Chain validation against a trust store, hostname match against SNI, revocation (OCSP/CRL), Certificate Transparency presence, weak signature algorithms, key reuse across hosts, interception signatures |
| Findings | Severity, title and detail from a static `rules.yaml` | Scored posture model per host and domain over time, configurable policy profiles, CVE mapping, confidence levels |
| Output | HTML page, JSON, terminal table | Persistent database, dashboards with trends, per-host and per-domain drill-down, PDF/CSV exports, alerting to SIEM/syslog/webhook, REST API |
| Scale | Everything in memory, one process | Worker pool or stream processor, indexed storage, de-duplication across captures, millions of flows |
| Trust | Explicitly "not an audit result" | Validated against a corpus of real traffic, fuzz-tested parsers, fails closed to "unparseable" and never to a false SECURE |
| Operations | `run_demo.bat`, no auth, no users | Packaged deployment (Docker or appliance), RBAC, audit logging, air-gapped install, signed releases |
| Correlation | Each session judged on its own | Sessions rolled up into server posture; changes over time (downgrades, new certificates, new interception); cross-checked with DNS, MTA-STS and DANE records |

### The three gaps that matter most

1. **Identity is not verified.** A valid certificate for the wrong host, talking
   to a client that asked for `imap.gmail.com`, grades SECURE today. Chain and
   hostname verification is the check that turns a cipher checker into an
   interception detector.
2. **Only the server's answer is graded, not the client's offer.** A client that
   still offers TLS 1.0 and RC4 is a downgrade risk even when the server picks
   TLS 1.3. The product parses both sides of the handshake.
3. **Nothing is remembered between scans.** Posture assessment is "how has this
   server behaved across thousands of sessions over months, and what changed".
   That needs storage, correlation and trend views.

### Phases

**Phase 1: prove it on real traffic**

1. Grow the real-world validation set: Zoho, a TLS 1.2-only server, a
   self-hosted Postfix/Dovecot with deliberately weak settings, so the HIGH and
   CRITICAL paths are proven on real captures and not only on synthetic ones.
2. Certificate chain and hostname verification against the system trust store
   and the SNI.
3. ClientHello parsing: offered versions, cipher list, extensions.
4. Robust parsing: out-of-order and retransmitted segments, TLS records split
   across TCP segments, truncated captures. A fuzz-style test feeds damaged
   captures and asserts the tool degrades to "unparseable" rather than
   crashing or reporting SECURE.

**Phase 2: make it usable at scale**

5. Streaming ingest and live capture from an interface.
6. Persistent storage keyed by server, with de-duplication across captures.
7. Dashboards with per-host history and change detection.
8. Handshake fingerprinting to find implicit-TLS servers on any port.

**Phase 3: make it deployable**

9. Policy profiles and a scored posture model replacing the flat rule catalog.
10. Exports (PDF/CSV), REST API, and alerting into SIEM/syslog/webhook.
11. Packaged deployment, RBAC, audit logging, air-gapped install.
12. Cross-checks against DNS, MTA-STS and DANE for the domains observed.
