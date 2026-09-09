"""Demo server: the aagcp API plus the console page at / (same origin, no CORS).

Product API (approve/execute/verify/close/refuse) is used untouched.
Demo additions, for the full lifecycle in the browser:
  * observe / analyze / plan / simulate endpoints, backed by the orchestrator
  * those endpoints accept a JSON payload (inventory, inspections, findings,
    intent) — the same objects the real scan layer would produce. Empty body
    falls back to the built-in demo estate.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from urllib.parse import urlparse
from http.server import ThreadingHTTPServer

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.plan import Finding, compile_plan
from aagcp.core.coverage import assess, Column, Inventory, Inspection
from aagcp.core.simulate import StaticDependencyGraph
from aagcp.core.executors import SnowflakeExecutor
from aagcp.core.executors.mock import MockEngine
from aagcp.core.executors.snowflake import _policy_name
from aagcp.core.journal import Journal, Principal
from aagcp.core.orchestrator import Orchestrator, OrchestratorError
from aagcp import api

HOST, PORT = "127.0.0.1", 8099
HERE = os.path.dirname(os.path.abspath(__file__))
JPATH = os.path.join(HERE, "demo-api-journal.jsonl")
HTML = os.path.join(HERE, "demo_ui.html")

ANALYST = Principal("dinesh@acme.example", "data-eng", max_approval_tier=0)
DPO = Principal("dpo@acme.example", "privacy-officer", max_approval_tier=4)
TOKENS = {"tk-analyst": ANALYST, "tk-dpo": DPO}

DEFAULT_SLOTS = dict(action="mask", scope_kind="schema",
                     scope_value="SALES.PUBLIC", scope_exclude=[],
                     policy_id="dpdp", audience=["DPO"], confidence=0.95)
FINDINGS = [
    Finding("ACME", "PUBLIC", "customers", "email",  "email", "EMAIL", .99, 184000),
    Finding("ACME", "PUBLIC", "customers", "mobile", "phone", "PHONE", .98, 184000),
]
COLUMNS = [Column("ACME", "PUBLIC", "customers", f.column, "VARCHAR", 184000)
           for f in FINDINGS]
INV = Inventory(tuple(COLUMNS), source="snowflake catalog", complete=True)
INSP = [Inspection(c.target, "content_sample", 5000, f.identifier_key, .99)
        for c, f in zip(COLUMNS, FINDINGS)]
GRAPH = StaticDependencyGraph({}, known=["ACME.PUBLIC.customers"])

# estate per request id: what observe recorded, reused by later phases
ESTATES = {}


def _build_estate(body):
    """Map a caller payload onto the core types. Missing pieces fall back
    to the demo estate — this is a demo, not a schema validator."""
    body = body or {}
    if not any(k in body for k in ("columns", "inspections", "findings")):
        return {"inv": INV, "insp": INSP, "fnd": FINDINGS,
                "policy": REGISTRY[DEFAULT_SLOTS["policy_id"]]}
    cols = [Column(c["database"], c["schema"], c["table"], c["column"],
                   c.get("data_type", ""), int(c.get("row_estimate", 0)))
            for c in body.get("columns", [])]
    meta = body.get("inventory", {})
    inv = Inventory(tuple(cols), source=meta.get("source", "api caller"),
                    complete=meta.get("complete"))
    insp = [Inspection(i["target"], i.get("method", "none"),
                       int(i.get("sampled_rows", 0)),
                       i.get("identifier_key", ""),
                       float(i.get("confidence", 0.0)),
                       i.get("error", ""))
            for i in body.get("inspections", [])]
    fnd = [Finding(f["database"], f["schema"], f["table"], f["column"],
                   f["identifier_key"], f.get("detector", ""),
                   float(f.get("confidence", 1.0)),
                   int(f.get("row_estimate", 0)))
           for f in body.get("findings", [])]
    policy = REGISTRY.get(body.get("policy_id"), REGISTRY["dpdp"])
    return {"inv": inv, "insp": insp, "fnd": fnd, "policy": policy}


def _estate(rid, body):
    if body or rid not in ESTATES:
        ESTATES[rid] = _build_estate(body)
    return ESTATES[rid]


def make_executor(names):
    return SnowflakeExecutor(MockEngine(
        queries={"aagcp:prestate": [],
                 "POLICY_REFERENCES": [(n,) for n in names],
                 "INFORMATION_SCHEMA.COLUMNS": []}))


PHASE_ACTIONS = ("observe", "analyze", "plan", "simulate")


class Handler(api._Handler):
    """The product API + console page + demo-only phase endpoints."""

    def do_GET(self):
        if urlparse(self.path).path in ("/", "/index.html"):
            with open(HTML, "rb") as fh:
                raw = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        super().do_GET()

    def do_POST(self):
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "requests":
            if parts[2] in PHASE_ACTIONS:
                return self._phase(parts[1], parts[2])
            if parts[2] == "execute":
                return self._execute(parts[1])
        super().do_POST()

    # ---- demo-only: the in-process phases, payload-aware -------------
    def _phase(self, rid, action):
        principal = self._auth()
        if principal is None:
            return
        orch, reg = self.server.orchestrator, self.server.registry
        body = self._body()
        try:
            if action == "observe":
                e = _estate(rid, body)
                report = orch.observe(rid, e["inv"], e["insp"],
                                      policy=e["policy"], findings=e["fnd"],
                                      principal=principal)
                return self._send(200, {
                    "request_id": rid,
                    "report_hash": report.report_hash,
                    "coverage": report.rate("estate").render(),
                    "counts": report.counts,
                    "denominator_verified": report.denominator_verified,
                    "anomalies": len(report.anomalies)})

            if action == "analyze":
                e = _estate(rid, body)
                digest = orch.analyze(rid, e["fnd"], principal=principal)
                return self._send(200, {
                    "request_id": rid,
                    "findings_digest": digest,
                    "findings": [
                        f"{f.fqn}.{f.column}  [{f.identifier_key}]  "
                        f"confidence={f.confidence}  rows={f.row_estimate}"
                        for f in e["fnd"]]})

            if action == "plan":
                e = _estate(rid, body)
                slots = dict(DEFAULT_SLOTS, policy_id=e["policy"].policy_id)
                slots.update((body or {}).get("intent") or {})
                intent = from_slots(slots, REGISTRY)
                plan = orch.plan(rid, intent, e["fnd"], principal=principal)
                reg.plans[rid] = plan
                return self._send(200, {
                    "request_id": rid,
                    "plan_hash": plan.plan_hash,
                    "summary": plan.summary(),
                    "unresolved": plan.unresolved,
                    "sql": {o.target: o.statements for o in plan.operations}})

            if action == "simulate":
                plan = reg.plans.get(rid)
                if plan is None:
                    return self._send(409, {
                        "error": "PLAN_NOT_IN_MEMORY",
                        "detail": "run the plan step first; this demo will not "
                                  "rebuild a plan the journal did not record"})
                e = _estate(rid, None)
                cov = assess(e["inv"], e["insp"], policy=e["policy"],
                             plan=plan, findings=e["fnd"])
                f = orch.simulate(rid, plan, graph=GRAPH,
                                  executor=make_executor(
                                      [_policy_name(o) for o in plan.operations]),
                                  coverage=cov, principal=principal)
                reg.forecasts[rid] = f
                return self._send(200, {
                    "request_id": rid,
                    "forecast_hash": f.forecast_hash,
                    "tier": f.tier.label,
                    "decision": f.decision.value,
                    "signals": [
                        {"signal": s.name, "measurement": s.measurement.value,
                         "detail": s.detail}
                        for s in f.signals]})
        except OrchestratorError as exc:
            return self._send(409, {"error": exc.code, "detail": exc.detail})

    # ---- execute, re-implemented so verification matches THIS plan ---
    def _execute(self, rid):
        principal = self._auth()
        if principal is None:
            return
        orch, reg = self.server.orchestrator, self.server.registry
        plan = reg.plans.get(rid)
        if plan is None:
            return self._send(409, {
                "error": "PLAN_NOT_IN_MEMORY",
                "detail": "the approved plan is not held by this process; "
                          "hand back the plan whose hash matches the record",
                "recorded": orch.resume(rid)})
        try:
            receipt = orch.execute(rid, plan,
                                   make_executor([_policy_name(o)
                                                  for o in plan.operations]),
                                   principal=principal)
        except OrchestratorError as exc:
            return self._send(409, {"error": exc.code, "detail": exc.detail})
        reg.receipts[rid] = receipt
        return self._send(200, {"request_id": rid,
                                "verdict": receipt.verdict.value,
                                "summary": receipt.summary(),
                                "explain": receipt.explain()})


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, journal, registry):
        super().__init__(addr, Handler)
        self.journal = journal
        self.orchestrator = Orchestrator(journal)
        self.registry = registry


def main():
    serve_only = "--serve-only" in sys.argv
    registry = api.Registry(tokens=TOKENS)

    if not serve_only and os.path.exists(JPATH):
        os.remove(JPATH)

    server = Server((HOST, PORT), Journal(JPATH), registry)
    mode = "same journal, EMPTY in-memory registry (restart demo)" if serve_only \
           else "fresh journal — start a request from the UI"
    print(f"=== aagcp full-lifecycle console on http://{HOST}:{PORT}/  [{mode}] ===")
    print("tokens: tk-analyst (you, tier 0) | tk-dpo (approver, tier 4)")
    print("Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
