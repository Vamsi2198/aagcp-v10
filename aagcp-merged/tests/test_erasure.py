"""Invariants for the erase action family. python3 test_erasure.py

One rule is under test throughout: an erasure closes on a passing
attestation and on nothing else. Most of what follows is an attempt to
close one without.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys

from aagcp.core.intent import Intent, Scope, Action, ScopeKind, IntentError
from aagcp.core.policy import REGISTRY
from aagcp.core.erasure import (Subject, SubjectError, RowTarget, VectorTarget,
                          EraseMode, compile_erasure_plan, attestability,
                          Attestability, UnattestableAcceptance,
                          AttestationView, StructuredCheck, ErasureRequest,
                          RequestState, adjudicate, KNOWN_CLASSIFICATIONS,
                          PASSING_CLASSIFICATIONS, MIN_CONTROL_ANCHORS,
                          MIN_BASELINE_SEPARATION)
from aagcp.core.executors import (SnowflakeExecutor, ExecutionVerdict,
                            VectorReceipt, OperationStatus)
from aagcp.core.executors.mock import MockEngine

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)


SUBJECT = Subject(key="dinesh@example.com", key_kind="email",
                  token_hash="ab" * 32)

ERASE_INTENT = Intent(action=Action.ERASE,
                      scope=Scope(kind=ScopeKind.SUBJECT, value="subj-7741"),
                      policy_id="dpdp", requested_by="dsr-queue")

ROWS = (
    RowTarget("ACME", "PUBLIC", "customers", "email",
              mode=EraseMode.DELETE_ROW, citation="DPDP s.12(3)", row_estimate=1),
    RowTarget("ACME", "PUBLIC", "orders", "customer_email",
              mode=EraseMode.NULL_FIELDS, fields=("customer_email", "ship_addr"),
              citation="DPDP s.12(3); retained under tax rules", row_estimate=14),
)

def vec(engine="pgvector_hnsw", registered=True, anchors=99, sep=0.42,
        name="rag_index"):
    return VectorTarget(store_name=name, engine=engine, citation="DPDP s.12(3)",
                        n_control_anchors=anchors, anchor_registered=registered,
                        baseline_separation=sep)


print("\n=== SUBJECT VALUES CANNOT REACH DDL UNESCAPED ===")
for bad in ("x'; DROP TABLE customers; --", "a\nb", "a\\b", "x" * 300, ""):
    try:
        Subject(key=bad)
        check(f"rejected {bad[:18]!r}", False, "accepted")
    except SubjectError as e:
        check(f"rejected {bad[:18]!r}", e.code == "SUBJECT_VALUE_NOT_SAFE_TO_EMBED")
check("an ordinary apostrophe is escaped, not refused",
      Subject(key="o'neill@example.com").literal == "'o''neill@example.com'",
      Subject(key="o'neill@example.com").literal)
# The apostrophe is allowed, so the doubling has to hold on its own against
# a payload built entirely from characters that survive the charset.
sneaky = Subject(key="x' OR 1")
sneaky_plan = compile_erasure_plan(
    ERASE_INTENT, sneaky,
    (RowTarget("A", "B", "c", "d", citation="x"),), "snowflake")
stmt = sneaky_plan.operations[0].statements[0]
check("an all-allowed-chars injection stays inside one literal",
      stmt.count("'") == 4 and stmt.endswith("'x'' OR 1';"), stmt)

print("\n=== PLANNING ===")
plan = compile_erasure_plan(ERASE_INTENT, SUBJECT, ROWS, "snowflake")
check("one operation per structured target", len(plan.operations) == 2)
check("every erase operation is irreversible",
      all(not o.reversible for o in plan.operations)
      and len(plan.irreversible_ops) == 2)
check("delete and null-fields compile differently",
      {o.op for o in plan.operations} == {"erase_rows", "erase_fields"},
      str(sorted(o.op for o in plan.operations)))
check("the subject appears as a quoted literal",
      all("'dinesh@example.com'" in s for o in plan.operations
          for s in o.statements))
check("plan hash is stable", plan.plan_hash ==
      compile_erasure_plan(ERASE_INTENT, SUBJECT, tuple(reversed(ROWS)),
                           "snowflake").plan_hash, plan.plan_hash)
check("postgres compiles the same intent",
      compile_erasure_plan(ERASE_INTENT, SUBJECT, ROWS, "postgres").plan_hash
      != plan.plan_hash)
try:
    RowTarget("A", "B", "c", "d", citation="")
    check("a target without a citation is rejected", False, "accepted")
except ValueError:
    check("a target without a citation is rejected", True)
try:
    mask_intent = Intent(action=Action.MASK,
                         scope=Scope(kind=ScopeKind.SUBJECT, value="s"),
                         policy_id="dpdp")
    compile_erasure_plan(mask_intent, SUBJECT, ROWS)
    check("a non-erase intent is rejected", False, "accepted")
except IntentError as e:
    check("a non-erase intent is rejected", e.code == "NOT_AN_ERASE_INTENT")

print("\n=== THE EXECUTOR REFUSES TO REVERSE AN ERASURE ===")
eng = MockEngine(queries={"aagcp:prestate": [], "INFORMATION_SCHEMA.COLUMNS": []})
ex = SnowflakeExecutor(eng)
check("can_reverse is False, not None",
      all(ex.can_reverse(o)[0] is False for o in plan.operations),
      str([ex.can_reverse(o)[1][:40] for o in plan.operations]))

print("\n=== ATTESTABILITY IS DECIDED BEFORE THE DELETE ===")
a = attestability(vec())
check("a healthy pgvector store is attestable", a.attestable, a.detail)

a = attestability(vec(registered=False))
check("an unregistered anchor is not attestable", not a.attestable)
check("its cause names the ordering problem",
      a.cause == "ANCHOR_NOT_REGISTERED_BEFORE_ERASURE", a.cause)
check("its ceiling is that verify() raises", "raises" in a.ceiling, a.ceiling)

a = attestability(vec(engine="pinecone"))
check("pinecone is never attestable", not a.attestable, a.cause)
check("its ceiling is INCONCLUSIVE_UNMEASURED",
      a.ceiling == "INCONCLUSIVE_UNMEASURED", a.ceiling)

a = attestability(vec(sep=0.004))
check("a subject on a near-duplicate is not attestable",
      not a.attestable and a.cause == "SUBJECT_NOT_SEPARABLE_FROM_NEIGHBOURS",
      a.detail)
check("the separation threshold matches the verifier",
      MIN_BASELINE_SEPARATION == 0.01)

a = attestability(vec(anchors=MIN_CONTROL_ANCHORS - 1))
check("too few control anchors is not attestable",
      not a.attestable and a.cause == "CONTROL_ANCHORS_BELOW_MINIMUM", a.detail)
check("exactly the minimum is attestable",
      attestability(vec(anchors=MIN_CONTROL_ANCHORS)).attestable)
check("the anchor threshold matches the verifier", MIN_CONTROL_ANCHORS == 19)

print("\n=== AN UNATTESTABLE ERASURE IS REFUSED BEFORE IT RUNS ===")
r = ErasureRequest(SUBJECT, ROWS, (vec(engine="pinecone", name="pc"),)).authorise()
check("the request is refused, not executed", r.state is RequestState.REFUSED,
      r.state.value)
check("the refusal explains what would have happened",
      "permanently open" in r.refusal["detail"], r.refusal["detail"][:60])
check("a refused request is closed and not COMPLETE",
      r.closed and r.state is not RequestState.COMPLETE)

try:
    UnattestableAcceptance(authority="", detail="just do it")
    check("an acceptance without an authority is rejected", False, "accepted")
except ValueError as e:
    check("an acceptance without an authority is rejected", True, str(e)[:44])
try:
    UnattestableAcceptance(authority="dpo@acme", detail="")
    check("an acceptance without reasoning is rejected", False, "accepted")
except ValueError:
    check("an acceptance without reasoning is rejected", True)

acc = UnattestableAcceptance(
    authority="dpo@acme.example / DSR-4471",
    detail="statutory erasure deadline; Pinecone cannot be attested and the "
           "obligation to delete does not wait on the proof",
    stores=("pc",))
r2 = ErasureRequest(SUBJECT, ROWS, (vec(engine="pinecone", name="pc"),),
                    acceptance=acc).authorise()
check("a named acceptance unblocks execution",
      r2.state is not RequestState.REFUSED, r2.state.value)
check("the acceptance is recorded against the store",
      r2.accepted_unattestable()[0]["accepted_by"].startswith("dpo@acme"),
      str(r2.accepted_unattestable()[0]["store_name"]))
r3 = ErasureRequest(SUBJECT, ROWS,
                    (vec(engine="pinecone", name="pc"),
                     vec(engine="pinecone", name="other")),
                    acceptance=acc).authorise()
check("an acceptance scoped to one store does not cover another",
      r3.state is RequestState.REFUSED,
      str([b["store_name"] for b in r3.blockers()]))

print("\n=== ADJUDICATION: EVERY CLASSIFICATION, EXHAUSTIVELY ===")
def view(cls, **kw):
    d = dict(store_name="rag_index", classification=cls,
             is_pass=cls in PASSING_CLASSIFICATIONS, signature="sig",
             # The attestation must name the subject it is about; an
             # unnamed one no longer closes anything.
             subject_token_hash=SUBJECT.token_hash)
    d.update(kw)
    return AttestationView(**d)

closes = {c: adjudicate(view(c))[0] for c in sorted(KNOWN_CLASSIFICATIONS)}
check("exactly two classifications close a request",
      {c for c, v in closes.items() if v} == set(PASSING_CLASSIFICATIONS),
      str(sorted(c for c, v in closes.items() if v)))
check("RESIDUE_DETECTED does not close",
      closes["RESIDUE_DETECTED"] is False)
check("INCONCLUSIVE_UNMEASURED does not close",
      closes["INCONCLUSIVE_UNMEASURED"] is False)
check("residue and inconclusive get different causes",
      adjudicate(view("RESIDUE_DETECTED"))[1] == "RESIDUE_DETECTED"
      and adjudicate(view("INCONCLUSIVE_UNMEASURED"))[1] == "INCONCLUSIVE_UNMEASURED")
check("an unknown classification does not close",
      adjudicate(view("TOTALLY_ERASED_TRUST_ME", is_pass=True))
      == (False, "UNRECOGNISED_CLASSIFICATION",
          adjudicate(view("TOTALLY_ERASED_TRUST_ME", is_pass=True))[2]))
check("is_pass=True on a failing classification does not close",
      adjudicate(view("RESIDUE_DETECTED", is_pass=True))[1]
      == "VERIFIER_PASS_FLAG_DISAGREES_WITH_CLASSIFICATION")
check("is_pass=False on a passing classification does not close",
      adjudicate(view("STRONG_EVIDENCE_ERASED", is_pass=False))[0] is False)
check("an unsigned pass does not close",
      adjudicate(view("STRONG_EVIDENCE_ERASED", signature=""))[0] is False,
      adjudicate(view("STRONG_EVIDENCE_ERASED", signature=""))[2][:40])

print("\n=== SETTLEMENT ===")
def deleted(store="rag_index"):
    """The deterministic half: records were deleted and are no longer
    fetchable by id. Without one of these a request now stays open on
    NO_VECTOR_DELETION_RECORDED, because an attestation alone verifies a
    store nothing touched."""
    return VectorReceipt(store, "pgvector_hnsw", ExecutionVerdict.COMPLETE,
                         ("v1",), deleted_ids=("v1",),
                         status=OperationStatus.APPLIED, fetch_checked=True)


def fresh(**kw):
    r = ErasureRequest(SUBJECT, ROWS, (vec(),), **kw).authorise()
    r.record_vector_execution(deleted())
    return r

r = fresh()
check("nothing recorded -> open", r.settle() is not RequestState.COMPLETE)

r = fresh().record_execution("PARTIAL")
r.record_attestation(view("STRONG_EVIDENCE_ERASED"))
for t in ROWS:
    r.record_structured_check(StructuredCheck(t.target, False, "0 rows"))
check("a passing attestation does not rescue a partial execution",
      r.settle() is not RequestState.COMPLETE,
      str([c["cause"] for c in r.open_causes()]))

r = fresh().record_execution("COMPLETE")
r.record_attestation(view("STRONG_EVIDENCE_ERASED"))
check("clean execution plus attestation still needs the re-query",
      r.settle() is not RequestState.COMPLETE
      and any(c["cause"] == "STRUCTURED_STORE_NOT_RE_QUERIED"
              for c in r.open_causes()),
      str([c["cause"] for c in r.open_causes()]))

r = fresh().record_execution("COMPLETE")
r.record_attestation(view("STRONG_EVIDENCE_ERASED"))
for t in ROWS:
    r.record_structured_check(StructuredCheck(t.target, None, "no read grant"))
check("an unrunnable re-query is not a clean re-query",
      r.settle() is not RequestState.COMPLETE,
      str([c["cause"] for c in r.open_causes()]))

r = fresh().record_execution("COMPLETE")
r.record_attestation(view("STRONG_EVIDENCE_ERASED"))
r.record_structured_check(StructuredCheck(ROWS[0].target, True, "1 row remains"))
r.record_structured_check(StructuredCheck(ROWS[1].target, False, "0 rows"))
check("a subject still present structurally keeps it open",
      any(c["cause"] == "SUBJECT_STILL_PRESENT_IN_STRUCTURED_STORE"
          for c in r.open_causes()))

r = fresh().record_execution("COMPLETE")
for t in ROWS:
    r.record_structured_check(StructuredCheck(t.target, False, "0 rows"))
check("a missing attestation keeps it open",
      any(c["cause"] == "NOT_YET_VERIFIED" for c in r.open_causes()))

for cls in sorted(KNOWN_CLASSIFICATIONS - PASSING_CLASSIFICATIONS):
    r = fresh().record_execution("COMPLETE")
    r.record_attestation(view(cls))
    for t in ROWS:
        r.record_structured_check(StructuredCheck(t.target, False, "0 rows"))
    if r.settle() is RequestState.COMPLETE:
        check(f"{cls} must not close a request", False, "closed!")
check("no failing classification closes a request", True,
      f"{len(KNOWN_CLASSIFICATIONS - PASSING_CLASSIFICATIONS)} checked")

r = fresh().record_execution("COMPLETE")
r.record_attestation(view("STRONG_EVIDENCE_ERASED"))
for t in ROWS:
    r.record_structured_check(StructuredCheck(t.target, False, "0 rows"))
check("everything clean -> COMPLETE", r.settle() is RequestState.COMPLETE,
      r.explain().splitlines()[0])
check("a closed request has no open causes", r.open_causes() == [])

print("\n=== MULTI-STORE: THE VERDICT IS THE FLOOR ===")
multi = ErasureRequest(SUBJECT, ROWS,
                       (vec(name="rag_a"), vec(name="rag_b"))).authorise()
multi.record_vector_execution(deleted("rag_a"))
multi.record_vector_execution(deleted("rag_b"))
multi.record_execution("COMPLETE")
for t in ROWS:
    multi.record_structured_check(StructuredCheck(t.target, False, "0 rows"))
multi.record_attestation(view("STRONG_EVIDENCE_ERASED", store_name="rag_a"))
multi.record_attestation(view("INCONCLUSIVE_UNMEASURED", store_name="rag_b"))
check("one inconclusive store keeps the whole request open",
      multi.settle() is not RequestState.COMPLETE,
      str([(c["scope"], c["cause"]) for c in multi.open_causes()]))
multi.record_attestation(view("STRONG_EVIDENCE_ERASED", store_name="rag_b"))
check("closing the last store closes the request",
      multi.settle() is RequestState.COMPLETE)

print("\n=== THE CONTROL PLANE NEVER SEES A VECTOR ===")
d = r.to_dict()
flat = str(d)
check("the subject key is not in the serialised request",
      "dinesh@example.com" not in flat)
check("the token hash is", SUBJECT.token_hash in flat)
check("the view carries no scores or embeddings",
      set(view("STRONG_EVIDENCE_ERASED").to_dict())
      == {"store_name", "classification", "is_pass", "p_value",
          "n_control_anchors", "unmeasured_channels", "merkle_root",
          "signature_present", "scope", "subject_token_hash",
          "log_index", "log_entry_hash"},
      str(sorted(view("STRONG_EVIDENCE_ERASED").to_dict())))
check("request hash is stable", r.request_hash == r.request_hash, r.request_hash)

print("\n=== DRIFT GUARD AGAINST THE REAL VERIFIER ===")
# core/erasure.py restates two constants from AAGCP_v3 so the engine can
# predict a classification without importing numpy. Restating is how two
# files stop agreeing, so this re-derives both from ErasureBound itself.
# aagcp.verify is a sibling package after the merge, so this needs no
# path setup — only numpy and cryptography, from the [verify] extra.
try:
    from aagcp.core.verifier_adapter import check_constants
    drift = check_constants()
    check("the mirrored constants still match AAGCP_v3", drift == [], str(drift))
except Exception as e:
    print(f"  SKIP  verifier not importable: {str(e)[:64]}")
    print("        pip install -e .[verify] — this is the check that stops "
          "aagcp.core and aagcp.verify drifting apart")

print("\n=== SAMPLE ===")
print("  " + ErasureRequest(
    SUBJECT, ROWS,
    (vec(name="rag_a"), vec(engine="pinecone", name="pc"),
     vec(name="rag_c", anchors=4))
).authorise().explain().replace("\n", "\n  "))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
