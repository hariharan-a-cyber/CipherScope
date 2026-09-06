# CypherScope

CypherScope reads a packet capture of email traffic and reports how strong or weak
the TLS encryption was. It looks at SMTP, IMAP and POP3 sessions, parses the TLS
handshake, checks the server certificate, and grades each session from SECURE to
CRITICAL with the reason and a fix.

Live demo: https://cipher-scope-prototype.vercel.app

Built for Smart India Hackathon 2026, problem statement SIH26159 (NTRO).

## Status: prototype

This is an early prototype, not a finished product. It was built for the
shortlisting round and it has real limits:

- it handles SMTP, IMAP and POP3 on the standard ports only
- it reads `.pcap` files offline and does not capture live traffic
- it has been tested on small, well formed captures, not on large or damaged ones
- the hosted demo caps uploads at 4 MB and each scan at 60 seconds, so use the
  local install for anything bigger

Do not treat its output as an audit result. Treat it as a first look that points
you at the sessions worth checking by hand.

## What it does

Give it a `.pcap` file. For every email session it finds, it will:

- identify the protocol (SMTP, IMAP or POP3) and whether TLS was used
- detect STARTTLS upgrades and flag sessions that stayed in cleartext
- read the negotiated TLS version, cipher suite and key exchange from the handshake
- pull the server certificate and check expiry, key size and whether it is self-signed
- apply the rule set and produce findings with a severity and a remediation step

It never reads message contents. TLS encrypts the mail itself, but the handshake
that sets up the encryption is sent in the clear, and the handshake is all this
tool needs.

## How it works

The pipeline runs in fixed stages:

1. read the PCAP and group packets into TCP sessions (ingest)
2. reassemble each direction of the byte stream
3. work out the encryption state, including STARTTLS
4. parse the TLS handshake for version and cipher
5. parse and validate the certificate
6. run the rule engine and score the session

Everything is plain Python. It does not need Wireshark installed.

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
bundled samples. You get a summary of severities and a per session breakdown with
the problem and the fix.

If the scripts do not run, start it directly:

    # Linux or macOS
    PYTHONPATH=src python -m cypherscope serve

    # Windows (PowerShell)
    $env:PYTHONPATH="src"; python -m cypherscope serve

## Command line

    PYTHONPATH=src python -m cypherscope scan data/*.pcap
    PYTHONPATH=src python -m cypherscope scan data/02_smtps_weak_tls.pcap --json report.json

## Sample data

Five captures are included in `data/`, covering a secure session, weak TLS with an
expired certificate, a plaintext POP3 login, a STARTTLS upgrade, and a STARTTLS
stripping case. `data/README.md` lists the expected result of each. Regenerate them
with:

    python tools/generate_pcaps.py

## Tests

    python -m pytest

The tests check that each bundled capture produces the expected verdict.

## Deploying

The dashboard is a FastAPI app and runs on Vercel as a single Python function.
`api/index.py` is the entry point and `vercel.json` routes every path to it and
ships `src/` and `data/` with the bundle.

    npm i -g vercel
    vercel
    vercel --prod

Two platform limits apply to the hosted version. Request bodies are capped at
about 4.5 MB, so large captures cannot be uploaded, and a function run is capped
at 60 seconds, which is short for a capture with many sessions. The app rejects
oversized uploads with a clear message instead of failing silently. If you need
full size captures, run it locally or on a normal server.

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
        ingest.py                   read PCAP, group and reassemble sessions
        starttls.py                 encryption state and STARTTLS logic
        handshake.py                TLS handshake parser
        certs.py                    certificate parsing and validation
        rules.py                    rule engine
        rules.yaml                  severity and remediation text
        report.py                   report building and terminal output
        webapp.py                   FastAPI dashboard
        __main__.py                 scan and serve commands
        templates/, static/         dashboard UI

## Planned next

- a machine learning layer for risk scoring and anomaly detection
- PDF report export
- handling of larger and malformed captures
