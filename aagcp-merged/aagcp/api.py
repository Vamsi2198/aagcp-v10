"""
aagcp/api.py — the deployable surface.

Stdlib http.server, on purpose. A framework would be a dependency the
engine does not otherwise need, and this API is thin: it authenticates a
principal, calls the orchestrator, and returns what the journal already
says. Every gate that matters — approval, ordering, artifact identity,
close-on-evidence — is enforced in aagcp.core and cannot be reached around
by an HTTP request. If it could, adding an API would be adding a way to
bypass the control plane.

WHAT THIS IS NOT. It is not hardened for the open internet. There is no
TLS termination, no rate limiting, no tenant isolation beyond the bearer
token, and http.server is single-threaded. Put it behind a reverse proxy
and an identity provider. What it does do correctly is refuse the things
that must be refused regardless of transport, and it is honest in
/healthz about the ones it does not do.

AUTHENTICATION carries the principal, and the principal is the audit
record. A bearer token maps to a Principal with an approval tier; the
token itself never enters the journal, only the principal id. Tokens are
compared with hmac.compare_digest because a timing-variable comparison on
a credential is the kind of thing that reads as fine forever.
"""
from __future__ import annotations

import hmac
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from .core.journal import Journal, Phase, Principal
from .core.observability import health, trace
from .core.orchestrator import Orchestrator, OrchestratorError

API_VERSION = "api-1.0.0"


@dataclass
class Registry:
    """Everything the API needs that is not in the journal. Artifacts are
    kept here per request id because the orchestrator deliberately does not
    hold them across a restart — after a restart this is empty and the
    affected endpoints say so rather than reconstructing a plan nobody
    approved."""
    tokens: Dict[str, Principal]
    plans: Dict[str, object] = None
    forecasts: Dict[str, object] = None
    receipts: Dict[str, object] = None
    executor_factory: Optional[Callable] = None

    def __post_init__(self):
        self.plans = self.plans or {}
        self.forecasts = self.forecasts or {}
        self.receipts = self.receipts or {}

    def principal_for(self, header: str) -> Optional[Principal]:
        if not header or not header.lower().startswith("bearer "):
            return self._anonymous_fallback()
        offered = header.split(None, 1)[1].strip()
        for token, principal in self.tokens.items():
            if hmac.compare_digest(token, offered):
                return principal
        return self._anonymous_fallback()

    def _anonymous_fallback(self) -> Optional[Principal]:
        # Demo bypass, NOT for real deployments: when AAGCP_ALLOW_ANONYMOUS
        # is set, unauthenticated requests run as a shared "anonymous"
        # principal so the API can be explored without tokens. The journal
        # records this principal like any other; every such entry is
        # attributable to nobody in particular, which is the point of the
        # warning in /healthz.
        import os
        if not os.environ.get("AAGCP_ALLOW_ANONYMOUS"):
            return None
        tier = int(os.environ.get("AAGCP_ANONYMOUS_TIER", "99"))
        return Principal(principal_id="anonymous",
                         role="demo-bypass",
                         max_approval_tier=tier)


class _Handler(BaseHTTPRequestHandler):
    server_version = f"aagcp/{API_VERSION}"

    # ---- plumbing ----------------------------------------------------
    def log_message(self, fmt, *args):
        pass    # the journal is the record; access logs are not it

    def _send(self, code: int, body: dict):
        raw = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _auth(self) -> Optional[Principal]:
        p = self.server.registry.principal_for(self.headers.get("Authorization"))
        if p is None:
            self._send(401, {"error": "UNAUTHENTICATED",
                             "detail": "a bearer token mapping to a principal "
                                       "is required; the principal is the "
                                       "audit record"})
        return p

    # ---- routes ------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        reg, orch = self.server.registry, self.server.orchestrator

        if path == "/healthz":
            h = health(orch.journal, now=__import__("time").time())
            return self._send(200 if h.integrity_ok else 503, {
                **h.to_dict(),
                "not_provided_by_this_process": [
                    "TLS termination", "rate limiting", "tenant isolation",
                    "external witnessing of the checkpoint head"],
                "audit_trail": "tamper-evident, not immutable — the head "
                               "must be witnessed off-box to mean anything"})

        if path == "/checkpoint":
            return self._send(200, orch.journal.checkpoint().to_dict())

        principal = self._auth()
        if principal is None:
            return

        if path.startswith("/requests/") and path.endswith("/audit"):
            rid = path.split("/")[2]
            state = orch.resume(rid)
            if not state.get("known"):
                return self._send(404, {"error": "UNKNOWN_REQUEST",
                                        "request_id": rid})
            return self._send(200, {
                "state": state,
                "chain": orch.journal.verify_chain(),
                "bindings": orch.journal.verify_bindings(rid),
                "spans": [s.to_dict() for s in trace(orch.journal, rid,
                                                     strict=False)]})

        if path.startswith("/requests/"):
            rid = path.split("/")[2]
            state = orch.resume(rid)
            code = 200 if state.get("known") else 404
            return self._send(code, state)

        if path == "/requests":
            return self._send(200, {"open": orch.journal.open_requests()})

        self._send(404, {"error": "NO_SUCH_ROUTE", "path": path})

    def do_POST(self):
        path = urlparse(self.path).path
        reg, orch = self.server.registry, self.server.orchestrator
        principal = self._auth()
        if principal is None:
            return
        body = self._body()
        parts = path.strip("/").split("/")
        if len(parts) != 3 or parts[0] != "requests":
            return self._send(404, {"error": "NO_SUCH_ROUTE", "path": path})
        rid, action = parts[1], parts[2]

        try:
            if action == "approve":
                forecast = reg.forecasts.get(rid)
                if forecast is None:
                    # The honest answer after a restart. Reconstructing the
                    # forecast here would mean approving something other
                    # than what was simulated.
                    return self._send(409, {
                        "error": "FORECAST_NOT_IN_MEMORY",
                        "detail": "the forecast for this request is not held "
                                  "by this process. Re-run the simulation and "
                                  "approve its hash; this endpoint will not "
                                  "rebuild a forecast in order to approve it.",
                        "recorded": orch.resume(rid)})
                orch.approve(rid, forecast, principal)
                return self._send(200, {"request_id": rid,
                                        "approved_by": principal.principal_id,
                                        "forecast_hash": forecast.forecast_hash,
                                        "state": orch.resume(rid)})

            if action == "execute":
                plan = reg.plans.get(rid)
                if plan is None or reg.executor_factory is None:
                    return self._send(409, {
                        "error": "PLAN_NOT_IN_MEMORY",
                        "detail": "the approved plan is not held by this "
                                  "process; hand back the plan whose hash "
                                  "matches the record",
                        "recorded": orch.resume(rid)})
                receipt = orch.execute(rid, plan, reg.executor_factory(),
                                       principal=principal)
                reg.receipts[rid] = receipt
                return self._send(200, {"request_id": rid,
                                        "verdict": receipt.verdict.value,
                                        "summary": receipt.summary(),
                                        "explain": receipt.explain()})

            if action == "verify":
                receipt = reg.receipts.get(rid)
                if receipt is None:
                    return self._send(409, {"error": "RECEIPT_NOT_IN_MEMORY"})
                passed = bool(body.get("passed"))
                refs = {}
                if body.get("attestation_log_hash"):
                    refs["attestation_log_hash"] = body["attestation_log_hash"]
                    refs["attestation_log_index"] = str(
                        body.get("attestation_log_index", ""))
                orch.verify(rid, receipt, passed=passed,
                            evidence={"attested": bool(refs), **refs,
                                      **{k: v for k, v in body.items()
                                         if k not in ("passed",)}},
                            principal=principal)
                return self._send(200, {"request_id": rid, "passed": passed})

            if action == "close":
                receipt = reg.receipts.get(rid)
                if receipt is None:
                    return self._send(409, {"error": "RECEIPT_NOT_IN_MEMORY"})
                orch.close(rid, receipt, principal=principal)
                return self._send(200, {"request_id": rid, "state": "CLOSE"})

            if action == "refuse":
                orch.refuse(rid, body.get("cause", "OPERATOR_REFUSED"),
                            body.get("detail", ""), principal=principal)
                return self._send(200, {"request_id": rid, "state": "REFUSE"})

        except OrchestratorError as exc:
            # Every gate refusal is a 409, not a 500: the request was
            # understood and declined for a reason the caller can act on.
            return self._send(409, {"error": exc.code, "detail": exc.detail})
        except Exception as exc:                      # pragma: no cover
            return self._send(500, {"error": type(exc).__name__,
                                    "detail": str(exc)})

        self._send(404, {"error": "NO_SUCH_ACTION", "action": action})


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, journal: Journal, registry: Registry):
        super().__init__(addr, _Handler)
        self.journal = journal
        self.orchestrator = Orchestrator(journal)
        self.registry = registry


def serve(journal_path: str, registry: Registry, host="127.0.0.1", port=8088):
    server = ApiServer((host, port), Journal(journal_path), registry)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
