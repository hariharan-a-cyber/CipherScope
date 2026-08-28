# SecureMailScope

A passive tool that reads a packet capture of email traffic and reports how strong
or weak the TLS encryption was. It looks at SMTP, IMAP and POP3 sessions, reads the
TLS handshake, checks the certificate, and grades each session from SECURE to
CRITICAL with a clear reason and a fix.

Built for Smart India Hackathon 2026, problem statement SIH26159 (NTRO).

## What it does

Give it a `.pcap` file. For every email session it finds, it will:

- identify the protocol (SMTP, IMAP or POP3) and whether TLS was used
- detect STARTTLS upgrades, and flag sessions that stayed in cleartext
- read the negotiated TLS version, cipher suite and key exchange from the handshake
- pull the server certificate and check expiry, key size and whether it is self-signed
- apply a rule set and produce findings with severity and remediation

It never reads message contents. TLS encrypts the emails, but the handshake that
sets up the encryption is sent in the clear, and that handshake is all this tool needs.

## How it works

The pipeline runs in stages:

1. read the PCAP and group packets into TCP sessions (ingest)
2. reassemble each direction of the byte stream
3. work out the encryption state, including STARTTLS
4. parse the TLS handshake for version and cipher
5. parse and validate the certificate
6. run the rule engine and score the session

Everything is plain Python. It does not need Wireshark installed and it does not
capture live traffic.

## Install

Python 3.9 or newer.

    pip install -r requirements.txt

## Run the demo (web dashboard)

From the project folder:

    # Linux or macOS
    ./run_demo.sh

    # Windows
    run_demo.bat

Then open http://127.0.0.1:8000 in your browser. Upload a capture, or click Scan on
one of the bundled samples. You will see a summary of severities and a per-session
breakdown with the exact problem and the fix.

If the scripts do not run, start it directly:

    # Linux or macOS
    PYTHONPATH=src python -m securemailscope serve

    # Windows (PowerShell)
    $env:PYTHONPATH="src"; python -m securemailscope serve

## Command line

    PYTHONPATH=src python -m securemailscope scan data/*.pcap
    PYTHONPATH=src python -m securemailscope scan data/02_smtps_weak_tls.pcap --json report.json

## Sample data

Five captures are included in `data/`, covering a secure session, weak TLS with an
expired certificate, a plaintext POP3 login, a STARTTLS upgrade, and a STARTTLS
stripping case. See `data/README.md` for the expected result of each. Regenerate
them any time with:

    python tools/generate_pcaps.py

## Tests

    PYTHONPATH=src python -m pytest

The tests check that each bundled capture produces the expected verdict.

## Project layout

    securemailscope/
      run_demo.sh, run_demo.bat     start the dashboard
      requirements.txt, pyproject.toml
      rules.yaml                    severity and remediation text
      data/                         sample captures + notes
      tools/generate_pcaps.py       builds the sample captures
      tests/test_pipeline.py        end to end checks
      src/securemailscope/
        ingest.py                   read PCAP, group and reassemble sessions
        starttls.py                 encryption state and STARTTLS logic
        handshake.py                TLS handshake parser
        certs.py                    certificate parsing and validation
        rules.py                    rule engine
        report.py                   report building and terminal output
        webapp.py                   FastAPI dashboard
        __main__.py                 scan and serve commands
        templates/, static/         dashboard UI

## Scope

This is the core prototype for the shortlisting round. It handles SMTP, IMAP and
POP3 over TLS on the standard ports. Planned for the grand finale: a machine
learning layer for risk scoring and anomaly detection, PDF report export, and
support for larger and messier captures.
