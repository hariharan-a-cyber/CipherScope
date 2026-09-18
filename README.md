# CypherScope

CypherScope reads a packet capture of email traffic and reports how strong or weak
the TLS encryption was. It finds SMTP, IMAP and POP3 sessions, parses the TLS
handshake, checks the server certificate, and grades each session from SECURE to
CRITICAL with the reason and a fix.

Live demo: https://cipher-scope-prototype.vercel.app

Built for Smart India Hackathon 2026, problem statement SIH26159 (NTRO).

## Status: prototype

This is a working prototype built for the shortlisting round. It is honest about
what it can and cannot do:

**It does**

- read `.pcap` and `.pcapng` files offline, no Wireshark or root needed
- find SMTP, IMAP and POP3 sessions on their standard ports, and on any other
  port when the session opens with a recognisable cleartext greeting
- tell plaintext, STARTTLS-upgraded, STARTTLS-stripped and implicit-TLS sessions apart
- read the negotiated TLS version (SSL 3.0 through TLS 1.3) and cipher suite
- parse the server certificate and check expiry, key size and self-signing
- grade each session and explain what to fix
- run as a web dashboard or from the command line, with JSON output

**It does not (yet)**

- capture live traffic; it reads files only
- verify the certificate chain against a trust store, or check that the
  certificate name matches the server
- inspect certificates in TLS 1.3 sessions, where the certificate is sent
  encrypted; version, cipher and forward secrecy are still graded
- identify implicit-TLS servers on non-standard ports (no cleartext banner to read)
- handle IPv6, or captures that are large, truncated or damaged; it has only
  been exercised on small, well formed captures
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
the problem and the fix.

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
version and cipher, followed by each finding and its fix.

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

These captures are synthetic. `tools/generate_pcaps.py` builds real X.509
certificates and standards-shaped TLS records and frames them in TCP/IP, but no
real mail server was involved. They prove the pipeline; they do not prove it
against real-world traffic. Regenerate them with:

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

Eight tests: one per bundled capture checking the expected verdict, one that
non-mail traffic (HTTP) is ignored, and one that a TLS 1.3 ServerHello is parsed
correctly.

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
        rules.yaml                  severity and remediation text
        report.py                   report building and terminal output
        webapp.py                   FastAPI dashboard
        __main__.py                 scan and serve commands
        templates/, static/         dashboard UI

## Roadmap

The problem statement (SIH26159, NTRO) asks for a tool that assesses the
cryptographic security posture of email traffic from packet captures. The
prototype covers the core of that. The plan below is ordered by what moves the
tool from "demo" to "something an analyst would actually run", which is also
the order in which it earns credibility with evaluators.

### Phase 1: prove it on real traffic (before the finals)

1. **Real-world validation set.** Capture sessions against real servers
   (Gmail, Outlook, Zoho, a self-hosted Postfix/Dovecot with deliberately weak
   settings) and add them to `data/` with expected verdicts and tests. Every
   claim in this README should be backed by a capture a judge can re-run.
2. **Certificate chain and hostname verification.** Validate the chain against
   the system trust store and match the certificate name against SNI. A
   trusted-looking certificate for the wrong host is the fingerprint of
   interception, and it is the check NTRO's analysts will ask about first.
3. **Client-side weakness.** Parse the ClientHello's offered versions and cipher
   list. A strong server talking to a client that still offers RC4 or TLS 1.0
   is a downgrade risk; today only the negotiated result is graded.
4. **Robust parsing.** Out-of-order and retransmitted segments, TLS records
   split across TCP segments, IPv6, truncated captures. Add a fuzz-style test
   that feeds damaged captures and asserts the tool degrades to "unparseable"
   instead of crashing or, worse, reporting SECURE.

### Phase 2: make it usable at scale (finals to deployment)

5. **Large captures.** Stream packets instead of loading the file into memory,
   report progress from the real pipeline, and profile against a multi-GB
   capture. Target: an hour of mail traffic from a mid-size organisation on a
   laptop.
6. **Organisation-wide view.** Group findings by server, not just by session:
   "mail.example.gov.in negotiated TLS 1.0 in 340 of 400 sessions". That is the
   report an administrator acts on.
7. **Export and integration.** PDF/HTML report for hand-off, JSON already
   exists, `--fail-on SEVERITY` exit codes for CI, and a schema so the output
   can be fed to a SIEM.
8. **Live capture.** `tcpdump -w - | cypherscope scan -` and a capture-interface
   mode, once the offline path is proven on real data.

### Phase 3: beyond mail

9. **Broader protocol coverage.** The TLS and certificate stages are protocol
   agnostic. Adding HTTPS, LDAPS, FTPS and XMPP is mostly a matter of session
   identification, which the banner detector already abstracts.
10. **Policy packs.** The rule set is a YAML file. Ship profiles aligned to
    published baselines (for example CERT-In and NIST SP 800-52r2 TLS
    guidance) so a scan can answer "does this comply with X" rather than only
    "is this weak".

### What we will not do

- No machine learning for the grading. TLS weaknesses are defined by
  standards, and a rule that cites the standard is more useful to an analyst
  than a score without a reason. ML may earn a place later for anomaly
  detection across many servers, but not before the deterministic checks are
  complete and validated.
- No decryption of message content. The tool grades the handshake only, and
  that boundary is what makes it safe to run on captures containing real mail.
