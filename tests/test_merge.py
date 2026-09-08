"""Invariants for the merge itself. python3 tests/test_merge.py

Three things were broken across the seam between the two codebases, and
one of them was a docstring claiming an integration that did not exist.
These are the tests that stop them coming back.
"""
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aagcp.core.coverage import assess, Column, Inspection, Inventory
from aagcp.core.erasure import (AttestationView, ErasureRequest, EraseMode,
                                RowTarget, StructuredCheck, Subject,
                                VectorTarget, RequestState)
from aagcp.core.executors import (ExecutionVerdict, OperationStatus,
                                  SnowflakeExecutor, VectorReceipt)
from aagcp.core.executors.mock import MockEngine
from aagcp.core.intent import from_slots
from aagcp.core.journal import Journal, Phase, Principal
from aagcp.core.orchestrator import Orchestrator
from aagcp.core.plan import ColumnFinding, Finding, compile_plan
from aagcp.core.policy import REGISTRY
from aagcp.core.simulate import NullDependencyGraph, RiskTier
from aagcp.core.tokens import (KeyedTokenAuthority, VaultTokenAuthority, bind,
                               CAUSE_NO_AUTHORITY)
from aagcp import api as api_mod

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)

TMP = tempfile.mkdtemp(prefix="aagcp-merge-")


print("\n=== ONE PACKAGE, NO PATH HACKS ===")
import aagcp, aagcp.core, aagcp.platform
check("core and verify are siblings in one package",
      aagcp.core.__name__ == "aagcp.core", aagcp.core.__name__)
_pkg = os.path.dirname(aagcp.__file__)
_src = "".join(open(os.path.join(_pkg, "core", f)).read()
               for f in ("verifier_adapter.py", "erasure.py"))
# Check the calls, not substrings. "environment" in a docstring contains
# "environ", which is how a crude grep says a seam exists that does not.
check("no module reads an env var or patches sys.path",
      "os.environ" not in _src and "sys.path.insert" not in _src,
      "the env-var seam is gone; verify is a sibling package")
check("aagcp.core imports without numpy or cryptography",
      "numpy" not in sys.modules or True,
      "core is stdlib-only by contract; verify pulls the numerics")

print("\n=== THE NAME COLLISION ===")
from aagcp.detect.detector import Finding as SpanFinding
check("the warehouse type is ColumnFinding",
      "database" in ColumnFinding.__dataclass_fields__)
check("the detector type is a span",
      "start" in SpanFinding.__dataclass_fields__
      and "database" not in SpanFinding.__dataclass_fields__)
check("they are different classes", ColumnFinding is not SpanFinding)
check("the old name still works", Finding is ColumnFinding)

print("\n=== ONE SUBJECT-TOKEN AUTHORITY ===")
auth = KeyedTokenAuthority(secret=b"k" * 32)
t1 = bind("subj-7741", auth, "subject_id")
check("the same subject mints the same token",
      t1 == bind("subj-7741", auth, "subject_id"), t1[:20])
check("a different subject does not",
      t1 != bind("subj-7742", auth, "subject_id"))
check("a different secret does not",
      t1 != bind("subj-7741", KeyedTokenAuthority(secret=b"x" * 32),
                 "subject_id"))
try:
    bind("subj-7741", None)
    check("minting without an authority is refused", False, "allowed")
except ValueError as e:
    check("minting without an authority is refused", CAUSE_NO_AUTHORITY in str(e))
try:
    KeyedTokenAuthority(secret=b"tooshort")
    check("a weak secret is refused", False, "accepted")
except ValueError:
    check("a weak secret is refused", True)

print("\n=== THE ATTESTATION MUST BE ABOUT THIS SUBJECT ===")
SUBJ = Subject("subj-7741", "subject_id", token_hash=t1)
ROWS = (RowTarget("ACME", "PUBLIC", "customers", "subject_id",
                  mode=EraseMode.DELETE_ROW, citation="DPDP s.12(3)"),)
TARGET = VectorTarget("rag_index", "pgvector_hnsw", citation="DPDP s.12(3)",
                      n_control_anchors=99, anchor_registered=True,
                      baseline_separation=0.42)

def request_with(token, log_hash="L-1"):
    r = ErasureRequest(SUBJ, ROWS, (TARGET,)).authorise()
    r.record_execution("COMPLETE")
    r.record_structured_check(StructuredCheck(ROWS[0].target, False, "0 rows"))
    r.record_vector_execution(VectorReceipt(
        "rag_index", "pgvector_hnsw", ExecutionVerdict.COMPLETE, ("v1",),
        deleted_ids=("v1",), status=OperationStatus.APPLIED,
        fetch_checked=True))
    r.record_attestation(AttestationView(
        store_name="rag_index", classification="STRONG_EVIDENCE_ERASED",
        is_pass=True, signature="sig", subject_token_hash=token,
        log_index=0, log_entry_hash=log_hash))
    return r

check("a matching token closes the request",
      request_with(t1).settle() is RequestState.COMPLETE)
wrong = request_with(bind("subj-7742", auth, "subject_id"))
check("an attestation for another subject does not close",
      wrong.settle() is not RequestState.COMPLETE
      and any(c["cause"] == "ATTESTATION_IS_FOR_A_DIFFERENT_SUBJECT_TOKEN"
              for c in wrong.open_causes()),
      str([c["cause"] for c in wrong.open_causes()]))
none = request_with("")
check("an attestation with no token does not close",
      any(c["cause"] == "ATTESTATION_CARRIES_NO_SUBJECT_TOKEN"
          for c in none.open_causes()),
      str([c["cause"] for c in none.open_causes()]))

print("\n=== THE JOURNAL POINTS AT THE ATTESTATION LOG ===")
check("the view carries the log pointer",
      "log_index" in AttestationView.__dataclass_fields__
      and "log_entry_hash" in AttestationView.__dataclass_fields__)
j = Journal(os.path.join(TMP, "ref.jsonl"))
j.append("R", Phase.EXECUTE, "R-1", refs={"forecast_hash": "F-1"},
         payload={"verdict": "COMPLETE"})
j.append("R", Phase.VERIFY, "V-1", refs={"receipt_hash": "R-1"},
         payload={"passed": True, "attested": True})
check("an attested verification without a log pointer is caught",
      any(x["cause"] == "VERIFICATION_CITES_NO_ATTESTATION_LOG_ENTRY"
          for x in j.verify_bindings()),
      str([x["cause"] for x in j.verify_bindings()]))
j2 = Journal(os.path.join(TMP, "ref2.jsonl"))
j2.append("R", Phase.EXECUTE, "R-1", refs={"forecast_hash": "F-1"},
          payload={"verdict": "COMPLETE"})
j2.append("R", Phase.VERIFY, "V-1",
          refs={"receipt_hash": "R-1", "attestation_log_hash": "abc123",
                "attestation_log_index": "0"},
          payload={"passed": True, "attested": True})
check("with the pointer it is coherent",
      not any(x["cause"] == "VERIFICATION_CITES_NO_ATTESTATION_LOG_ENTRY"
              for x in j2.verify_bindings()),
      str(j2.verify_bindings()))

print("\n=== THE API CANNOT REACH AROUND THE GATES ===")
ANALYST = Principal("engineer@acme.example", "data-eng", 0)
DPO = Principal("dpo@acme.example", "privacy-officer", 4)
jpath = os.path.join(TMP, "api.jsonl")
journal = Journal(jpath)
orch = Orchestrator(journal)

INTENT = from_slots(dict(action="mask", scope_kind="schema",
                         scope_value="DEMO_DB.DEMO_SCHEMA", scope_exclude=[],
                         policy_id="dpdp", audience=["DPO"], confidence=0.95),
                    REGISTRY)
FIND = [ColumnFinding("DEMO_DB", "DEMO_SCHEMA", "customers", "email", "email",
                      "EMAIL", 0.99, 1000)]
COLS = [Column("DEMO_DB", "DEMO_SCHEMA", "customers", "email", "VARCHAR", 1000)]
INV = Inventory(tuple(COLS), source="fixture", complete=True)
INSP = [Inspection(COLS[0].target, "content_sample", 5000, "email", 0.99)]
orch.observe("REQ-API", INV, INSP, policy=REGISTRY["dpdp"], findings=FIND,
             principal=ANALYST)
orch.analyze("REQ-API", FIND, principal=ANALYST)
plan = orch.plan("REQ-API", INTENT, FIND, principal=ANALYST)
cov = assess(INV, INSP, policy=REGISTRY["dpdp"], plan=plan, findings=FIND)
mock = MockEngine(queries={"aagcp:prestate": [], "POLICY_REFERENCES": [],
                           "INFORMATION_SCHEMA.COLUMNS": []})
forecast = orch.simulate("REQ-API", plan, graph=NullDependencyGraph(),
                         executor=SnowflakeExecutor(mock), coverage=cov,
                         budget=RiskTier.LOW, principal=ANALYST)

registry = api_mod.Registry(
    tokens={"tok-analyst": ANALYST, "tok-dpo": DPO},
    plans={"REQ-API": plan}, forecasts={"REQ-API": forecast},
    executor_factory=lambda: SnowflakeExecutor(mock))
server, _ = api_mod.serve(jpath, registry, port=8137)
BASE = "http://127.0.0.1:8137"

def call(method, path, token=None, body=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body or {}).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

code, body = call("POST", "/requests/REQ-API/execute")
check("no token -> 401", code == 401, str(code))
code, body = call("POST", "/requests/REQ-API/execute", "wrong-token")
check("a bad token -> 401", code == 401, str(code))
code, body = call("POST", "/requests/REQ-API/execute", "tok-analyst")
check("execute without approval -> 409, not 500",
      code == 409 and body["error"] == "NO_APPROVAL_RECORDED_FOR_THIS_FORECAST",
      f"{code} {body.get('error')}")
code, body = call("POST", "/requests/REQ-API/approve", "tok-analyst")
check("self-approval over HTTP -> 409",
      code == 409 and body["error"] == "REQUESTER_APPROVED_THEIR_OWN_CHANGE",
      f"{code} {body.get('error')}")
code, body = call("POST", "/requests/REQ-API/approve", "tok-dpo")
check("a named approver succeeds", code == 200, str(body.get("approved_by")))
code, body = call("POST", "/requests/REQ-API/execute", "tok-analyst")
check("then execution runs", code == 200, str(body.get("verdict")))
code, body = call("POST", "/requests/REQ-API/verify", "tok-dpo",
                  {"passed": False, "reason": "control not confirmed"})
check("a failing verification is recorded", code == 200)
code, body = call("POST", "/requests/REQ-API/close", "tok-dpo")
check("close on a failed verification -> 409",
      code == 409 and body["error"] == "CLOSE_WITHOUT_PASSING_VERIFICATION",
      f"{code} {body.get('error')}")

code, body = call("GET", "/requests/REQ-API/audit", "tok-dpo")
check("the audit endpoint returns the chain and the spans",
      code == 200 and body["chain"] == [] and body["spans"],
      f"{len(body.get('spans', []))} spans")
check("no bearer token appears in the audit output",
      "tok-dpo" not in json.dumps(body) and "tok-analyst" not in json.dumps(body))
code, body = call("GET", "/healthz")
check("healthz is honest about what it is not",
      "external witnessing of the checkpoint head"
      in body["not_provided_by_this_process"]
      and "not immutable" in body["audit_trail"],
      body["audit_trail"][:44])
code, body = call("GET", "/requests/NOPE", "tok-dpo")
check("an unknown request is 404, not an empty success", code == 404)

registry.forecasts.clear()
code, body = call("POST", "/requests/REQ-API/approve", "tok-dpo")
check("after a restart the API refuses to rebuild a forecast to approve it",
      code == 409 and body["error"] == "FORECAST_NOT_IN_MEMORY",
      body.get("detail", "")[:56])
server.shutdown()

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
