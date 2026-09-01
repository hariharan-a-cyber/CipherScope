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

from .analyze import analyze_pcap
from .report import build_report, terminal_table


def cmd_scan(args):
    reports = []
    for path in args.pcaps:
        if not os.path.exists(path):
            print(f"skip (not found): {path}", file=sys.stderr)
            continue
        report = build_report(os.path.basename(path), analyze_pcap(path))
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

    p_scan = sub.add_parser("scan", help="analyse one or more PCAP files")
    p_scan.add_argument("pcaps", nargs="+", help="paths to .pcap files")
    p_scan.add_argument("--json", help="also write the report as JSON to this path")
    p_scan.set_defaults(func=cmd_scan)

    p_serve = sub.add_parser("serve", help="start the web dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
