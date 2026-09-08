"""Invariants for the erase path executors. python3 test_erase_executors.py

Until now an erasure plan was refused at preview and the vector store was
verified without ever being deleted from. These are the tests for the two
holes.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys

from aagcp.core.intent import Intent, Scope, Action, ScopeKind
from aagcp.core.erasure import (Subject, RowTarget, VectorTarget, EraseMode,
                          compile_erasure_plan, ErasureRequest,
                          AttestationView, RequestState)
from aagcp.core.executors import (SnowflakeExecutor, SnowflakeEraseExecutor,
                            PostgresEraseExecutor, VectorEraseExecutor,
                            AnchorHandle, ExecutionVerdict, OperationStatus)
from aagcp.core.executors.base import TransportError, CapabilityError
from aagcp.core.executors.mock import MockEngine, Rule

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)

INTENT = Intent(action=Action.ERASE, scope=Scope(ScopeKind.SUBJECT, "s-7741"),
                policy_id="dpdp")
SUBJ = Subject("s-7741", "subject_id", token_hash="ab" * 32)
ROWS = (
    RowTarget("ACME", "PUBLIC", "customers", "subject_id",
              mode=EraseMode.DELETE_ROW, citation="DPDP s.12(3)"),
    RowTarget("ACME", "PUBLIC", "orders", "subject_id",
              mode=EraseMode.NULL_FIELDS, fields=("subject_id", "ship_addr"),
              citation="DPDP s.12(3); retained under tax rules"),
)
PLAN = compile_erasure_plan(INTENT, SUBJ, ROWS, "snowflake")
PG_PLAN = compile_erasure_plan(INTENT, SUBJ, ROWS, "postgres")

def sf(rows=0, retention=0, rules=()):
    return SnowflakeEraseExecutor(
        MockEngine(rules=rules, queries={"aagcp:verify": [(rows,)]}),
        SUBJ, retention_days=retention)


print("\n=== THE PLAN NOW EXECUTES ===")
plain = SnowflakeExecutor(MockEngine())
r = plain.execute_staged(PLAN)
check("the masking executor still refuses erase ops",
      r.verdict is ExecutionVerdict.REFUSED
      and r.refusal["cause"] == "OPERATION_NOT_SUPPORTED_BY_EXECUTOR",
      r.refusal["cause"])
ex = sf(rows=0, retention=0)
r = ex.execute_staged(PLAN)
check("the erase executor runs it", r.verdict is ExecutionVerdict.COMPLETE,
      r.explain())
check("both DELETE and UPDATE were issued",
      any(s.startswith("DELETE") for s in ex.conn.ddl())
      and any(s.startswith("UPDATE") for s in ex.conn.ddl()),
      str([s.split()[0] for s in ex.conn.ddl()]))

print("\n=== AN ERASE EXECUTOR IS SCOPED TO ONE SUBJECT ===")
try:
    SnowflakeEraseExecutor(MockEngine(), "s-7741")
    check("a bare string is not a subject", False, "accepted")
except CapabilityError as e:
    check("a bare string is not a subject", "scoped to one subject" in str(e))

print("\n=== TIME TRAVEL: ZERO ROWS IS NOT ABSENCE ===")
for retention, expected, verdict in ((0, False, ExecutionVerdict.COMPLETE),
                                     (1, None, ExecutionVerdict.INCONCLUSIVE),
                                     (90, None, ExecutionVerdict.INCONCLUSIVE),
                                     (None, None, ExecutionVerdict.INCONCLUSIVE)):
    e = sf(rows=0, retention=retention)
    chk = e.structured_check(PLAN.operations[0])
    check(f"retention={retention} -> subject_present {expected}",
          chk.subject_present is expected, chk.detail[:70])
    check(f"retention={retention} -> {verdict.value}",
          e.execute_staged(PLAN).verdict is verdict)
check("an open retention window names the cause",
      "ROWS_STILL_RECOVERABLE_THROUGH_TIME_TRAVEL"
      in sf(0, 7).structured_check(PLAN.operations[0]).detail)
check("unread retention is not assumed to be zero",
      "unknown" in sf(0, None).structured_check(PLAN.operations[0]).detail)

print("\n=== POSTGRES CONFIRMS ABSENCE, AND NAMES THE RESIDUE ===")
pg = PostgresEraseExecutor(
    MockEngine(queries={"aagcp:verify": [(0,)]}), SUBJ)
chk = pg.structured_check(PG_PLAN.operations[0])
check("a deleted row is confirmed absent by query",
      chk.subject_present is False, str(chk.subject_present))
check("heap and backup residue is named, not implied",
      "VACUUM" in chk.detail and "backup" in chk.detail, chk.detail[:70])
check("postgres needs no grant snapshot for an erasure",
      pg.preview(PG_PLAN).executable, str(pg.preview(PG_PLAN).capability_errors))

print("\n=== THE SUBJECT STILL BEING THERE ===")
e = sf(rows=3, retention=0)
r = e.execute_staged(PLAN)
check("a surviving subject fails verification",
      r.verdict is not ExecutionVerdict.COMPLETE, r.verdict.value)
check("the check reports presence",
      e.structured_check(PLAN.operations[0]).subject_present is True)
e = sf(rows=0, retention=0, rules=[Rule("aagcp:verify", message="no select grant")])
check("a re-query that cannot run is None, not clean",
      e.structured_check(PLAN.operations[0]).subject_present is None,
      e.structured_check(PLAN.operations[0]).detail[:52])

print("\n=== NO UNDO ===")
e = sf(retention=0)
check("can_reverse is False for every erase op",
      all(e.can_reverse(o)[0] is False for o in PLAN.operations))
r = e.execute_staged(PLAN)
rb = e.rollback(r, PLAN)
check("rollback refuses both operations",
      len(rb.refusal["all"]) == 2
      and all(x["cause"] == "IRREVERSIBLE_OPERATION" for x in rb.refusal["all"]),
      str([x["cause"] for x in rb.refusal["all"]]))
e2 = sf(retention=0, rules=[Rule("UPDATE", message="denied")])
r2 = e2.execute_staged(PLAN)
nulled = [o for o in r2.operations if o.op == "erase_fields"]
check("a failed UPDATE nulls nothing, so it is FAILED and not partial",
      nulled and nulled[0].status is OperationStatus.FAILED,
      nulled[0].status.value if nulled else "")
check("and leaves no residue to clean up",
      nulled and nulled[0].residual_artifacts == [],
      str(nulled[0].residual_artifacts if nulled else ""))

print("\n=== VECTOR: NO ANCHOR, NO DELETE ===")
class FakeStore:
    def __init__(self, ids, fail=None, fetch_raises=False):
        self.data = {i: object() for i in ids}
        self.fail, self.fetch_raises = fail, fetch_raises
        self.deleted = []
    def delete(self, ids):
        if self.fail:
            raise self.fail
        self.deleted += list(ids)
        for i in ids:
            self.data.pop(i, None)
    def fetch(self, ids):
        if self.fetch_raises:
            raise RuntimeError("index unavailable")
        return {i: self.data.get(i) for i in ids}

TARGET = VectorTarget("rag_index", "pgvector_hnsw", citation="DPDP s.12(3)",
                      n_control_anchors=99, anchor_registered=True,
                      baseline_separation=0.42)
ANCHOR = AnchorHandle(token_hash="ab" * 32, store_name="rag_index",
                      registered_at="1757000000.0", baseline_separation=0.42,
                      record_ids=("v1", "v2"))

store = FakeStore(["v1", "v2", "v9"])
vx = VectorEraseExecutor(store, TARGET)
rv = vx.execute(None, ["v1", "v2"])
check("no anchor -> REFUSED", rv.verdict is ExecutionVerdict.REFUSED)
check("the cause is the ordering, not a missing flag",
      rv.cause == "ANCHOR_NOT_REGISTERED_BEFORE_DELETE", rv.cause)
check("nothing was deleted", store.deleted == [], str(store.deleted))
check("an anchor for another store is refused",
      vx.execute(AnchorHandle("ab" * 32, "other_index", "1.0"),
                 ["v1"]).cause == "ANCHOR_NOT_REGISTERED_BEFORE_DELETE")
check("no record ids is refused, not treated as a no-op",
      vx.execute(AnchorHandle("ab" * 32, "rag_index", "1.0"), []).cause
      == "NO_RECORD_IDS_SUPPLIED_FOR_THE_SUBJECT")
try:
    AnchorHandle("", "rag_index", "")
    check("an empty anchor handle is rejected", False, "accepted")
except CapabilityError:
    check("an empty anchor handle is rejected", True)

print("\n=== VECTOR: DELETION ===")
store = FakeStore(["v1", "v2", "v9"])
rv = VectorEraseExecutor(store, TARGET).execute(ANCHOR)
check("ids come from the anchor when not supplied",
      sorted(store.deleted) == ["v1", "v2"], str(store.deleted))
check("a clean delete is COMPLETE", rv.verdict is ExecutionVerdict.COMPLETE)
check("the receipt ties back to the registration",
      rv.anchor["handle_hash"] == ANCHOR.handle_hash, ANCHOR.handle_hash)
check("it refuses to call itself an erasure",
      "only the attestation" in rv.explain(), rv.explain().splitlines()[-1][:52])

class StubbornStore(FakeStore):
    def delete(self, ids):
        self.deleted += list(ids)          # says yes, does nothing

rv = VectorEraseExecutor(StubbornStore(["v1", "v2"]), TARGET).execute(ANCHOR)
check("records still fetchable -> PARTIAL", rv.verdict is ExecutionVerdict.PARTIAL,
      rv.verdict.value)
check("the survivors are named", rv.still_addressable == ("v1", "v2"),
      str(rv.still_addressable))

rv = VectorEraseExecutor(FakeStore(["v1", "v2"], fetch_raises=True),
                         TARGET).execute(ANCHOR)
check("delete accepted but fetch unavailable -> INCONCLUSIVE",
      rv.verdict is ExecutionVerdict.INCONCLUSIVE, rv.verdict.value)
check("fetch_checked is None, not False", rv.fetch_checked is None)

rv = VectorEraseExecutor(FakeStore(["v1"], fail=TransportError("reset")),
                         TARGET).execute(ANCHOR)
check("a dropped connection is UNKNOWN, not failed",
      rv.status is OperationStatus.UNKNOWN
      and rv.verdict is ExecutionVerdict.INCONCLUSIVE, rv.status.value)
rv = VectorEraseExecutor(FakeStore(["v1"], fail=RuntimeError("bad ids")),
                         TARGET).execute(ANCHOR)
check("a rejected delete is FAILED", rv.status is OperationStatus.FAILED)

print("\n=== END TO END: BOTH HALVES MUST BE CLEAN ===")
def build_request(retention, vector_store, attested):
    ex = sf(rows=0, retention=retention)
    receipt = ex.execute_staged(PLAN)
    vrec = VectorEraseExecutor(vector_store, TARGET).execute(ANCHOR)
    req = ErasureRequest(SUBJ, ROWS, (TARGET,)).authorise()
    req.record_execution(receipt.verdict.value)
    for op in PLAN.operations:
        req.record_structured_check(ex.structured_check(op))
    req.record_vector_execution(vrec)
    req.record_attestation(AttestationView(
        store_name="rag_index", classification=attested,
        is_pass=attested in ("STRONG_EVIDENCE_ERASED",
                             "MODERATE_EVIDENCE_ERASED"),
        signature="sig", subject_token_hash=SUBJ.token_hash))
    return req, vrec

req, _ = build_request(0, FakeStore(["v1", "v2"]), "STRONG_EVIDENCE_ERASED")
check("everything clean closes the request",
      req.settle() is RequestState.COMPLETE,
      str([c["cause"] for c in req.open_causes()]))

req, _ = build_request(7, FakeStore(["v1", "v2"]), "STRONG_EVIDENCE_ERASED")
check("an open Time Travel window keeps it open",
      req.settle() is not RequestState.COMPLETE
      and any(c["cause"] == "STRUCTURED_STORE_NOT_RE_QUERIED"
              for c in req.open_causes()),
      str([c["cause"] for c in req.open_causes()]))

req, _ = build_request(0, FakeStore(["v1", "v2"]), "RESIDUE_DETECTED")
check("a clean warehouse does not rescue a residual index",
      req.settle() is not RequestState.COMPLETE,
      str([c["cause"] for c in req.open_causes()]))

req, vrec = build_request(0, StubbornStore(["v1", "v2"]),
                          "STRONG_EVIDENCE_ERASED")
check("a passing attestation cannot close over still-fetchable records",
      req.settle() is not RequestState.COMPLETE
      and any(c["cause"] == "STORE_STILL_ADDRESSABLE_DESPITE_ATTESTATION"
              for c in req.open_causes()),
      str([c["cause"] for c in req.open_causes()]))

no_delete = ErasureRequest(SUBJ, ROWS, (TARGET,)).authorise()
no_delete.record_execution("COMPLETE")
for op in PLAN.operations:
    no_delete.record_structured_check(sf(0, 0).structured_check(op))
no_delete.record_attestation(AttestationView(
    store_name="rag_index", classification="STRONG_EVIDENCE_ERASED",
    is_pass=True, signature="sig"))
check("an attestation with no deletion receipt does not close",
      no_delete.settle() is not RequestState.COMPLETE
      and any(c["cause"] == "NO_VECTOR_DELETION_RECORDED"
              for c in no_delete.open_causes()),
      str([c["cause"] for c in no_delete.open_causes()]))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
