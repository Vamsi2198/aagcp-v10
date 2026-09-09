"""prod_ui.py — the real-warehouse app.

Connects to a real Snowflake account (trial account is fine), scans a schema
for real identifiers, then drives the governed flow from aagcp.core:
observe -> analyze -> plan -> simulate -> approve -> execute -> verify -> close,
with execute running real DDL through the adapter in aagcp/real.py.

Credential handling: passed via the connect form (kept in server memory only,
single-operator demo) or a gitignored snowflake.local.json. Never logged,
never journaled. For real deployments use key-pair auth + a secrets manager.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataclasses import dataclass
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer

from aagcp.core.intent import from_slots
from aagcp.core.policy import REGISTRY
from aagcp.core.coverage import assess
from aagcp.core.simulate import StaticDependencyGraph
from aagcp.core.executors import SnowflakeExecutor
from aagcp.core.journal import Journal, Principal
from aagcp.core.orchestrator import Orchestrator, OrchestratorError
from aagcp import api
from aagcp.real import (Credentials, SnowflakeAdapter, connect,
                        load_credentials, scan_schema, test_connection)

HOST, PORT = "127.0.0.1", 8100
HERE = os.path.dirname(os.path.abspath(__file__))
JPATH = os.path.join(HERE, "prod-journal.jsonl")
HTML = os.path.join(HERE, "prod_ui.html")

ANALYST = Principal("dinesh@acme.example", "data-eng", max_approval_tier=0)
DPO = Principal("dpo@acme.example", "privacy-officer", max_approval_tier=4)
TOKENS = {"tk-analyst": ANALYST, "tk-dpo": DPO}


@dataclass
class ProdRegistry(api.Registry):
    conn: object = None
    creds: Credentials = None
    estate: dict = None          # {inv, insp, fnd, policy_id, scan} from /api/scan


class Handler(api._Handler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._html()
        if path == "/api/policies":
            return self._send(200, {"policies": [
                {"policy_id": p.policy_id, "name": p.name,
                 "authority": p.authority, "closed_list": p.closed_list,
                 "drop_treatments": sorted({
                     i.key for i in p.identifiers
                     if i.treatment.value == "drop"})}
                for p in REGISTRY.values()]})
        if path == "/api/connection":
            reg = self.server.registry
            if reg.creds is None:
                return self._send(200, {"connected": False})
            return self._send(200, {
                "connected": reg.conn is not None,
                "account": reg.creds.account, "database": reg.creds.database,
                "schema": reg.creds.schema, "user": reg.creds.user})
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/connect":
            return self._connect()
        if path == "/api/scan":
            return self._scan()
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "requests":
            if parts[2] in ("observe", "analyze", "plan", "simulate"):
                return self._phase(parts[1], parts[2])
            if parts[2] == "execute":
                return self._execute(parts[1])
            if parts[2] == "reconcile":
                return self._reconcile(parts[1])
        super().do_POST()

    # ---- plumbing ----------------------------------------------------
    def _html(self):
        with open(HTML, "rb") as fh:
            raw = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _connect(self):
        principal = self._auth()
        if principal is None:
            return
        body = self._body()
        try:
            creds = Credentials(
                account=body["account"].strip(), user=body["user"].strip(),
                password=body.get("password", ""),
                warehouse=body.get("warehouse", "COMPUTE_WH"),
                database=body.get("database", "").upper(),
                schema=body.get("schema", "PUBLIC").upper(),
                role=body.get("role", "ACCOUNTADMIN"))
            info = test_connection(creds)
        except KeyError as exc:
            return self._send(400, {"error": "MISSING_FIELD",
                                    "detail": f"{exc} is required"})
        except Exception as exc:
            return self._send(409, {"error": "CONNECTION_FAILED",
                                    "detail": str(exc)[:400]})
        old = self.server.registry.conn
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
        self.server.registry.conn = connect(creds)
        self.server.registry.creds = creds
        return self._send(200, {"connected": True, **info})

    def _scan(self):
        principal = self._auth()
        if principal is None:
            return
        reg = self.server.registry
        if reg.conn is None or reg.creds is None:
            return self._send(409, {"error": "NOT_CONNECTED",
                                    "detail": "connect to Snowflake first"})
        body = self._body()
        policy_id = body.get("policy_id", "dpdp")
        if policy_id not in REGISTRY:
            return self._send(409, {"error": "UNKNOWN_POLICY",
                                    "detail": f"'{policy_id}' not in registry"})
        try:
            result = scan_schema(reg.creds,
                                 sample_size=int(body.get("sample_size", 500)))
        except Exception as exc:
            return self._send(409, {"error": "SCAN_FAILED",
                                    "detail": str(exc)[:400]})
        reg.estate = {"inv": result.inventory, "insp": result.inspections,
                      "fnd": result.findings, "policy_id": policy_id,
                      "scan": result.summary()}
        return self._send(200, {"policy_id": policy_id, **result.summary()})

    def _phase(self, rid, action):
        principal = self._auth()
        if principal is None:
            return
        orch, reg = self.server.orchestrator, self.server.registry
        body = self._body()
        if reg.estate is None:
            return self._send(409, {"error": "SCAN_REQUIRED",
                                    "detail": "run a scan first — the demo will "
                                              "not govern an estate it never "
                                              "looked at"})
        e = reg.estate
        policy = REGISTRY[e["policy_id"]]
        try:
            if action == "observe":
                report = orch.observe(rid, e["inv"], e["insp"], policy=policy,
                                      findings=e["fnd"], principal=principal)
                return self._send(200, {
                    "request_id": rid, "report_hash": report.report_hash,
                    "coverage": report.rate("estate").render(),
                    "counts": report.counts,
                    "denominator_verified": report.denominator_verified,
                    "anomalies": len(report.anomalies),
                    "explain": report.explain()})

            if action == "analyze":
                digest = orch.analyze(rid, e["fnd"], principal=principal)
                return self._send(200, {
                    "request_id": rid, "findings_digest": digest,
                    "findings": e["scan"]["findings"]})

            if action == "plan":
                slots = dict(action=body.get("action", "mask"),
                             scope_kind="schema",
                             scope_value=(f"{reg.creds.database}.{reg.creds.schema}"
                                          if reg.creds else "UNKNOWN"),
                             scope_exclude=[], policy_id=e["policy_id"],
                             audience=body.get("audience", ["DPO"]),
                             confidence=0.95)
                intent = from_slots(slots, REGISTRY)
                plan = orch.plan(rid, intent, e["fnd"], principal=principal)
                reg.plans[rid] = plan
                return self._send(200, {
                    "request_id": rid, "plan_hash": plan.plan_hash,
                    "summary": plan.summary(), "unresolved": plan.unresolved,
                    "irreversible": [o.target for o in plan.irreversible_ops],
                    "sql": {o.target: o.statements for o in plan.operations}})

            if action == "simulate":
                plan = reg.plans.get(rid)
                if plan is None:
                    return self._send(409, {"error": "PLAN_NOT_IN_MEMORY",
                                            "detail": "run the plan step first"})
                cov = assess(e["inv"], e["insp"], policy=policy, plan=plan,
                             findings=e["fnd"])
                tables = sorted({c.fqn for c in e["inv"].columns})
                graph = StaticDependencyGraph({}, known=tables)
                executor = (SnowflakeExecutor(SnowflakeAdapter(reg.conn))
                            if reg.conn is not None else None)
                f = orch.simulate(rid, plan, graph=graph, executor=executor,
                                  coverage=cov, principal=principal)
                reg.forecasts[rid] = f
                return self._send(200, {
                    "request_id": rid, "forecast_hash": f.forecast_hash,
                    "tier": f.tier.label, "decision": f.decision.value,
                    "signals": [
                        {"signal": s.name, "measurement": s.measurement.value,
                         "detail": s.detail} for s in f.signals]})
        except OrchestratorError as exc:
            return self._send(409, {"error": exc.code, "detail": exc.detail})

    def _execute(self, rid):
        principal = self._auth()
        if principal is None:
            return
        orch, reg = self.server.orchestrator, self.server.registry
        if reg.conn is None:
            return self._send(409, {"error": "NOT_CONNECTED",
                                    "detail": "connect to Snowflake first"})
        plan = reg.plans.get(rid)
        if plan is None:
            return self._send(409, {
                "error": "PLAN_NOT_IN_MEMORY",
                "detail": "the approved plan is not held by this process; "
                          "hand back the plan whose hash matches the record",
                "recorded": orch.resume(rid)})
        try:
            receipt = orch.execute(
                rid, plan,
                SnowflakeExecutor(SnowflakeAdapter(reg.conn)),
                principal=principal)
        except OrchestratorError as exc:
            return self._send(409, {"error": exc.code, "detail": exc.detail})
        except Exception as exc:
            return self._send(500, {"error": type(exc).__name__,
                                    "detail": str(exc)[:400]})
        reg.receipts[rid] = receipt
        return self._send(200, {"request_id": rid,
                                "verdict": receipt.verdict.value,
                                "summary": receipt.summary(),
                                "explain": receipt.explain()})

    def _reconcile(self, rid):
        principal = self._auth()
        if principal is None:
            return
        orch, reg = self.server.orchestrator, self.server.registry
        if reg.conn is None:
            return self._send(409, {"error": "NOT_CONNECTED",
                                    "detail": "connect to Snowflake first"})
        plan = reg.plans.get(rid)
        if plan is None:
            return self._send(409, {
                "error": "PLAN_NOT_IN_MEMORY",
                "detail": "the plan for this request is not held by this "
                          "process. Re-run the plan + simulate + approve "
                          "steps; then reconcile the dangling attempt",
                "recorded": orch.resume(rid)})
        try:
            receipt = orch.reconcile(
                rid, plan, SnowflakeExecutor(SnowflakeAdapter(reg.conn)),
                principal=principal)
        except OrchestratorError as exc:
            return self._send(409, {"error": exc.code, "detail": exc.detail})
        reg.receipts[rid] = receipt
        return self._send(200, {"request_id": rid,
                                "verdict": receipt.verdict.value,
                                "reconciled": True,
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
    registry = ProdRegistry(tokens=TOKENS)

    if not serve_only and os.path.exists(JPATH):
        os.remove(JPATH)

    creds = load_credentials()
    if creds is not None:
        try:
            info = test_connection(creds)
            registry.creds = creds
            registry.conn = connect(creds)
            print(f"connected from snowflake.local.json: {info['account']} "
                  f"as {info['user']} (db={creds.database}, "
                  f"schema={creds.schema})")
        except Exception as exc:
            print(f"snowflake.local.json present but connection failed: {exc}")

    server = Server((HOST, PORT), Journal(JPATH), registry)
    mode = ("same journal, EMPTY in-memory registry (restart demo)"
            if serve_only else "fresh journal")
    print(f"=== aagcp real-warehouse console on http://{HOST}:{PORT}/  "
          f"[{mode}] ===")
    print("tokens: tk-analyst (you, tier 0) | tk-dpo (approver, tier 4)")
    print("Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
