"""
Command line entry point.

    python -m cypherscope scan data/*.pcap
    python -m cypherscope scan data/03_pop3_plaintext.pcap --json out.json
    python -m cypherscope serve
"""
import argparse
import json
import os
import sys
import time

from .analyze import analyze_pcap
from .report import build_report, terminal_table


# Mirrors the stage list in static/app.js so the CLI and web demo tell the
# same story. The pipeline itself finishes in well under a second, so each
# stage is held on screen briefly; otherwise the scan looks like it never ran.
STAGES = [
    ("Reading packet capture", 0.7),
    ("Reassembling TCP streams", 1.1),
    ("Detecting STARTTLS upgrades", 0.9),
    ("Parsing TLS handshake", 1.3),
    ("Validating server certificates", 1.2),
    ("Applying rule engine", 0.6),
    ("Building report", 0.4),
]


def _progress(name, enabled):
    """Print the stage walk-through to stderr, leaving stdout clean for piping."""
    if not enabled:
        return
    err = sys.stderr
    print(f"Scanning {name}", file=err)
    for label, hold in STAGES:
        err.write(f"  [ ] {label}...")
        err.flush()
        time.sleep(hold)
        err.write("\r  [x] " + label + "   \n")
        err.flush()
    print(file=err)


def cmd_scan(args):
    reports = []
    show = not args.no_progress and sys.stderr.isatty()
    for path in args.pcaps:
        if not os.path.exists(path):
            print(f"skip (not found): {path}", file=sys.stderr)
            continue
        name = os.path.basename(path)
        _progress(name, show)
        report = build_report(name, analyze_pcap(path))
        print(terminal_table(report))
        print()
        reports.append(report)

    if args.json:
        out = reports[0] if len(reports) == 1 else reports
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"wrote {args.json}")
    return 0 if reports else 1


def cmd_serve(args):
    import uvicorn
    uvicorn.run("cypherscope.webapp:app", host=args.host, port=args.port, reload=False)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cypherscope",
                                     description="Assess the TLS security posture of email traffic in a PCAP.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan one or more PCAP files")
    p_scan.add_argument("pcaps", nargs="+", help="paths to .pcap files")
    p_scan.add_argument("--json", help="also write the report as JSON to this path")
    p_scan.add_argument("--no-progress", action="store_true",
                        help="skip the stage-by-stage progress display (it is also skipped when stderr is not a terminal)")
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="start the web dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
