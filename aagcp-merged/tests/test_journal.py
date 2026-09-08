"""Invariants for the journal. python3 test_journal.py

Two questions kept apart throughout: was the file edited, and does the
story hold up. A chain answers the first. Only the bindings answer the
second, and a coherent-looking history is exactly what someone editing on
purpose would produce.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import json
import os
import sys
import tempfile

from aagcp.core.journal import (Journal, Phase, Principal, Checkpoint, JournalError,
                          GENESIS)

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)


TMP = tempfile.mkdtemp(prefix="aagcp-journal-")
def path(n):
    return os.path.join(TMP, f"{n}.jsonl")

ANALYST = Principal("dinesh@acme.example", "data-eng", max_approval_tier=0)
DPO = Principal("dpo@acme.example", "privacy-officer", max_approval_tier=4)
JUNIOR = Principal("intern@acme.example", "analyst", max_approval_tier=1)


def good_run(j, rid="REQ-1", tier=3, decision="APPROVAL_REQUIRED",
             approver=DPO, passed=True):
    j.append(rid, Phase.PLAN, "P-AAA111", principal=ANALYST)
    j.append(rid, Phase.SIMULATE, "F-BBB222", refs={"plan_hash": "P-AAA111"},
             payload={"tier": tier, "decision": decision})
    if approver is not None:
        j.append(rid, Phase.APPROVE, "F-BBB222",
                 refs={"forecast_hash": "F-BBB222"}, principal=approver)
    # The write-ahead attempt. Real executions are two records now: one
    # before the engine is touched and one after, tied by attempt_id.
    j.append(rid, Phase.EXECUTE_ATTEMPT, "P-AAA111",
             refs={"attempt_id": "AT-1", "forecast_hash": "F-BBB222",
                   "plan_hash": "P-AAA111"})
    j.append(rid, Phase.EXECUTE, "R-CCC333",
             refs={"attempt_id": "AT-1", "forecast_hash": "F-BBB222",
                   "plan_hash": "P-AAA111"},
             payload={"verdict": "COMPLETE"})
    j.append(rid, Phase.VERIFY, "V-DDD444", refs={"receipt_hash": "R-CCC333"},
             payload={"passed": passed})
    if passed:
        j.append(rid, Phase.CLOSE, "R-CCC333", refs={"receipt_hash": "R-CCC333"})
    return j


print("\n=== A CLEAN RUN ===")
j = good_run(Journal(path("clean")))
check("the chain is consistent", j.verify_chain() == [], str(j.verify_chain()))
check("the bindings are coherent", j.verify_bindings() == [],
      str(j.verify_bindings()))
check("the head advances", j.head() != GENESIS)
check("an execution is preceded by its attempt",
      j.replay("REQ-1")["phases"].index("execute_attempt")
      < j.replay("REQ-1")["phases"].index("execute"))
check("every phase is recorded",
      j.replay("REQ-1")["phases"] == ["plan", "simulate", "approve",
                                      "execute_attempt", "execute",
                                      "verify", "close"],
      str(j.replay("REQ-1")["phases"]))
check("the request reads as closed", j.replay("REQ-1")["closed"])
check("no open requests remain", j.open_requests() == [], str(j.open_requests()))

print("\n=== SURVIVING A PROCESS RESTART ===")
p = path("restart")
j1 = Journal(p)
j1.append("REQ-9", Phase.PLAN, "P-XYZ", principal=ANALYST)
j1.append("REQ-9", Phase.SIMULATE, "F-XYZ", refs={"plan_hash": "P-XYZ"},
          payload={"tier": 3, "decision": "APPROVAL_REQUIRED"})
head_before, n_before = j1.head(), len(j1.entries)
del j1                                     # the process dies here

j2 = Journal(p)                            # a new process opens the same file
check("state is rebuilt from disk, not memory", len(j2.entries) == n_before,
      f"{len(j2.entries)} of {n_before}")
check("the head survives", j2.head() == head_before, j2.head()[:16])
check("the request is still open and knows where it got to",
      j2.replay("REQ-9")["current_phase"] == "simulate"
      and not j2.replay("REQ-9")["closed"],
      j2.replay("REQ-9")["current_phase"])
check("it appears in open_requests after restart", "REQ-9" in j2.open_requests())
j2.append("REQ-9", Phase.APPROVE, "F-XYZ", refs={"forecast_hash": "F-XYZ"},
          principal=DPO)
check("the chain continues across the restart", j2.verify_chain() == [],
      str(j2.verify_chain()))
check("and so do the bindings", j2.verify_bindings("REQ-9") == [],
      str(j2.verify_bindings("REQ-9")))

print("\n=== A CRASH MID-WRITE COSTS ONE LINE, NOT THE HISTORY ===")
p = path("torn")
good_run(Journal(p))
with open(p, "a") as fh:
    fh.write('{"seq": 6, "request_id": "REQ-1", "phas')   # power cut
j3 = Journal(p)
check("the complete entries still load", len(j3.entries) == 7,
      str(len(j3.entries)))
check("the torn line is reported, not swallowed",
      any(x["cause"] == "TRAILING_ENTRY_INCOMPLETE" for x in j3.load_errors),
      str(j3.load_errors))
check("verify_chain surfaces it too",
      any(x["cause"] == "TRAILING_ENTRY_INCOMPLETE" for x in j3.verify_chain()))
check("the surviving history is otherwise intact",
      [x for x in j3.verify_chain()
       if x["cause"] != "TRAILING_ENTRY_INCOMPLETE"] == [])

print("\n=== TAMPERING ===")
def tampered(mutate):
    p = path(f"t{abs(hash(str(mutate)))%99999}")
    good_run(Journal(p))
    lines = [json.loads(l) for l in open(p).read().splitlines() if l.strip()]
    lines = mutate(lines)
    with open(p, "w") as fh:
        for l in lines:
            fh.write(json.dumps(l, sort_keys=True, separators=(",", ":")) + "\n")
    return Journal(p)

def edit_payload(lines):
    lines[5]["payload"]["passed"] = True
    lines[5]["subject_hash"] = "V-FORGED"
    return lines

t = tampered(edit_payload)
check("an edited entry is caught",
      any(x["cause"] == "ENTRY_HASH_DOES_NOT_MATCH_ITS_BODY"
          for x in t.verify_chain()), str(t.verify_chain()[:1]))

t = tampered(lambda ls: ls[:3] + ls[4:])
check("a deleted entry is caught",
      any(x["cause"] in ("CHAIN_LINK_DOES_NOT_MATCH_PREDECESSOR",
                         "SEQUENCE_NUMBER_OUT_OF_ORDER")
          for x in t.verify_chain()), str(t.verify_chain()[:1]))

t = tampered(lambda ls: ls[:2] + [ls[3], ls[2]] + ls[4:])
check("a reordered pair is caught",
      t.verify_chain() != [], str(t.verify_chain()[:1]))

def rehash_everything(lines):
    """The operator does not edit one line — they rebuild the whole file
    and recompute every hash. This is the case a local chain cannot
    detect, and the reason checkpoint() exists."""
    from aagcp.core.journal import Entry
    prev = GENESIS
    out = []
    for i, l in enumerate(lines):
        if l["seq"] == 5:
            l["payload"]["passed"] = True
        l["seq"], l["previous"] = i, prev
        e = Entry.from_dict(l)
        e.entry_hash = e.compute_hash()
        prev = e.entry_hash
        out.append(json.loads(e.to_line()))
    return out

# The realistic attack: a verification came back FAILED, and the operator
# rebuilds the file so it reads as passed. Nothing is left inconsistent.
p_rw = path("rewrite")
witnessed = good_run(Journal(p_rw), passed=False).checkpoint()
lines = [json.loads(l) for l in open(p_rw).read().splitlines() if l.strip()]
with open(p_rw, "w") as fh:
    for l in rehash_everything(lines):
        fh.write(json.dumps(l, sort_keys=True, separators=(",", ":")) + "\n")
t = Journal(p_rw)
check("a wholesale rewrite passes verify_chain — the documented limit",
      t.verify_chain() == [], "a local chain cannot constrain the operator")
check("the rewritten head differs from the witnessed one",
      t.head() != witnessed.head,
      f"{witnessed.head[:12]} -> {t.head()[:12]}")
check("the entry count is unchanged, so only the head betrays it",
      t.checkpoint().entries == witnessed.entries, str(witnessed.entries))
check("and the rewritten history now reads as a pass",
      t.entries[5].payload["passed"] is True,
      "which is exactly why the head must be witnessed")

print("\n=== BINDINGS: AN UNTAMPERED CHAIN CAN STILL BE WRONG ===")
j = Journal(path("b1"))
j.append("R", Phase.PLAN, "P-1", principal=ANALYST)
j.append("R", Phase.SIMULATE, "F-1", refs={"plan_hash": "P-OTHER"},
         payload={"tier": 2, "decision": "APPROVAL_REQUIRED"})
check("a forecast for a different plan is caught",
      any(x["cause"] == "FORECAST_IS_FOR_A_DIFFERENT_PLAN"
          for x in j.verify_bindings()), str(j.verify_bindings()[:1]))
check("the chain itself is fine", j.verify_chain() == [])

j = Journal(path("b2"))
good_run(j, approver=None)
check("execution without an approval is caught",
      any(x["cause"] == "EXECUTION_WITHOUT_AN_APPROVAL"
          for x in j.verify_bindings()),
      str([x["cause"] for x in j.verify_bindings()]))

j = Journal(path("b3"))
good_run(j, decision="AUTONOMOUS", approver=None)
check("an autonomous forecast needs no approval",
      j.verify_bindings() == [], str(j.verify_bindings()))

j = Journal(path("b4"))
# A senior requester, so the tier rule cannot fire and self-approval is the
# only thing under test. A test that trips two rules proves neither.
SENIOR = Principal("dinesh@acme.example", "data-eng", max_approval_tier=4)
j.append("REQ-1", Phase.PLAN, "P-AAA111", principal=SENIOR)
j.append("REQ-1", Phase.SIMULATE, "F-BBB222", refs={"plan_hash": "P-AAA111"},
         payload={"tier": 3, "decision": "APPROVAL_REQUIRED"})
j.append("REQ-1", Phase.APPROVE, "F-BBB222",
         refs={"forecast_hash": "F-BBB222"}, principal=SENIOR)
check("self-approval is caught on its own",
      [x["cause"] for x in j.verify_bindings()]
      == ["REQUESTER_APPROVED_THEIR_OWN_CHANGE"],
      str([x["cause"] for x in j.verify_bindings()]))
check("seniority does not excuse it",
      SENIOR.max_approval_tier == 4)

j = Journal(path("b5"))
good_run(j, tier=4, approver=JUNIOR)
check("approving above your tier is caught",
      any(x["cause"] == "PRINCIPAL_APPROVED_ABOVE_THEIR_TIER"
          for x in j.verify_bindings()),
      str([x["cause"] for x in j.verify_bindings()]))
check("the same approver is fine within their tier",
      good_run(Journal(path("b6")), tier=1,
               approver=JUNIOR).verify_bindings() == [])

j = Journal(path("b7"))
good_run(j, passed=False)
j.append("REQ-1", Phase.CLOSE, "R-CCC333", refs={"receipt_hash": "R-CCC333"})
check("closing on a failed verification is caught",
      any(x["cause"] == "CLOSED_WITHOUT_A_PASSING_VERIFICATION"
          for x in j.verify_bindings()),
      str([x["cause"] for x in j.verify_bindings()]))

j = Journal(path("b8"))
j.append("R", Phase.VERIFY, "V-1", refs={"receipt_hash": "R-NEVER"},
         payload={"passed": True})
check("verifying an execution that never happened is caught",
      any(x["cause"] == "VERIFICATION_REFERENCES_NO_RECORDED_EXECUTION"
          for x in j.verify_bindings()))

print("\n=== APPROVAL REQUIRES A PRINCIPAL, STRUCTURALLY ===")
try:
    Journal(path("b9")).append("R", Phase.APPROVE, "F-1",
                               refs={"forecast_hash": "F-1"})
    check("an anonymous approval is refused", False, "accepted")
except JournalError as e:
    check("an anonymous approval is refused",
          e.code == "ENTRY_REQUIRES_A_PRINCIPAL")
try:
    Principal("")
    check("a principal without an id is refused", False, "accepted")
except JournalError:
    check("a principal without an id is refused", True)

print("\n=== CHECKPOINT SAYS WHAT IT IS ===")
cp = good_run(Journal(path("cp"))).checkpoint()
check("it carries the head and the count",
      cp.head and cp.entries == 7, f"{cp.entries} entries")
check("it states the limit rather than claiming immutability",
      "other than the operator" in cp.to_dict()["note"], cp.to_dict()["note"][:52])

print("\n=== MULTI-REQUEST ===")
j = Journal(path("multi"))
good_run(j, rid="REQ-A")
j.append("REQ-B", Phase.PLAN, "P-B", principal=ANALYST)
check("closed and open requests are told apart",
      j.open_requests() == ["REQ-B"], str(j.open_requests()))
check("bindings scope to one request",
      j.verify_bindings("REQ-A") == [], str(j.verify_bindings("REQ-A")))
check("an unknown request reports unknown, not empty",
      j.replay("REQ-NOPE")["known"] is False)

print("\n=== SAMPLE ===")
print("  " + j.explain().replace("\n", "\n  "))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
