"""
aagcp/cli.py — the console entry point declared in pyproject.

Thin on purpose. Every gate lives in aagcp.core; this parses arguments and
prints what the journal already says.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aagcp")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("acceptance", help="run the acceptance harness")
    a.add_argument("--config")
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--journal", default="./aagcp-acceptance.jsonl")
    a.add_argument("--exec-restart", action="store_true")

    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--journal", default="./aagcp.jsonl")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8088)

    v = sub.add_parser("audit", help="verify a journal and print its health")
    v.add_argument("--journal", required=True)
    v.add_argument("--request")

    c = sub.add_parser("checkpoint", help="print the head for external witnessing")
    c.add_argument("--journal", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "acceptance":
        import acceptance
        argv2 = ["--journal", args.journal]
        if args.dry_run:
            argv2.append("--dry-run")
        if args.config:
            argv2 += ["--config", args.config]
        if args.exec_restart:
            argv2.append("--exec-restart")
        sys.argv = ["acceptance.py"] + argv2
        return acceptance.main()

    from .core.journal import Journal
    from .core.observability import health

    if args.cmd == "serve":
        from . import api
        from .core.journal import Principal
        print("aagcp serve is a demonstration surface, not a hardened one: "
              "no TLS, no rate limiting, no tenant isolation. Put it behind "
              "a proxy and an identity provider.", file=sys.stderr)
        # Tokens come from AAGCP_TOKENS because a restarted process must
        # recognise the same principals: comma-separated entries of
        #   token:principal_id:role:max_approval_tier
        # e.g.  AAGCP_TOKENS=tk-dpo:dpo@acme.example:privacy-officer:4
        # tier 0 means the principal may not approve anything (an agent).
        tokens = {}
        raw = os.environ.get("AAGCP_TOKENS", "")
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            if len(parts) != 4 or not parts[0]:
                print(f"ignoring malformed AAGCP_TOKENS entry: {entry!r} "
                      f"(want token:principal_id:role:tier)", file=sys.stderr)
                continue
            try:
                tier = int(parts[3])
            except ValueError:
                print(f"ignoring AAGCP_TOKENS entry with non-integer tier: "
                      f"{entry!r}", file=sys.stderr)
                continue
            tokens[parts[0]] = Principal(principal_id=parts[1],
                                         role=parts[2],
                                         max_approval_tier=tier)
        registry = api.Registry(tokens=tokens)
        server, thread = api.serve(args.journal, registry, args.host, args.port)
        print(f"listening on http://{args.host}:{args.port} "
              f"({len(tokens)} principal(s) configured)" if tokens else
              f"listening on http://{args.host}:{args.port} "
              f"(no tokens configured; every authenticated route will 401)")
        try:
            thread.join()
        except KeyboardInterrupt:
            server.shutdown()
        return 0

    journal = Journal(args.journal)

    if args.cmd == "checkpoint":
        print(json.dumps(journal.checkpoint().to_dict(), indent=2))
        return 0

    if args.cmd == "audit":
        print(journal.explain(args.request))
        print()
        print(health(journal, now=time.time()).explain())
        problems = journal.verify_chain() + journal.verify_bindings(args.request)
        return 1 if problems else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
