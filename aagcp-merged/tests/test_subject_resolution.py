"""Invariants for subject resolution. python3 test_subject_resolution.py

Two failure modes under test. Erasing the wrong person, which is loud.
And erasing one of a person's three identities and closing the request,
which is silent and therefore worse.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
import sys

from aagcp.core.subject_resolution import (
    KeyKind, IdentityRecord, StaticIdentityIndex, ResolutionVerdict,
    ResolverAuthority, ResolutionError, resolve, collision_profile, Resolution)
from aagcp.core.erasure import (Subject, RowTarget, VectorTarget, ErasureRequest,
                          StructuredCheck, RequestState, EraseMode,
                          AttestationView, SubjectError)

F = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    if not cond: F.append(name)


def rec(sid, name=None, email=None, phone=None, account=None, dob=None,
        objects=("ACME.PUBLIC.customers",)):
    keys = []
    for kind, val in ((KeyKind.SUBJECT_ID, sid), (KeyKind.NAME, name),
                      (KeyKind.EMAIL, email), (KeyKind.PHONE, phone),
                      (KeyKind.ACCOUNT, account), (KeyKind.DOB, dob)):
        if val:
            keys.append((kind, val))
    return IdentityRecord(sid, tuple(keys), objects)


# Two distinct people sharing a name. The whole problem, minimally.
RAJESH_A = rec("subj-0001", "Rajesh Kumar", "rajesh.kumar@example.com",
               "+919800000001", "ACC-1001", "1987-03-04")
RAJESH_B = rec("subj-0002", "Rajesh Kumar", "r.kumar@other.example",
               "+919800000002", "ACC-1002", "1991-11-19",
               objects=("ACME.PUBLIC.customers", "ACME.MART.dim_customer"))
PRIYA = rec("subj-0003", "Priya Nair", "priya@example.com", "+919800000003",
            "ACC-1003", "1990-01-01")

FULL = StaticIdentityIndex([RAJESH_A, RAJESH_B, PRIYA], complete=True)
PARTIAL = StaticIdentityIndex([RAJESH_A, RAJESH_B, PRIYA], complete=None)


print("\n=== A NAME NEVER RESOLVES A SUBJECT ===")
r = resolve(FULL, [(KeyKind.NAME, "Rajesh Kumar")])
check("a shared name is AMBIGUOUS_SUBJECT",
      r.verdict is ResolutionVerdict.AMBIGUOUS_SUBJECT, r.verdict.value)
check("both people are candidates", len(r.candidates) == 2)
check("the cause names the collision",
      r.cause == "MULTIPLE_DISTINCT_SUBJECTS_MATCH", r.cause)

u = resolve(FULL, [(KeyKind.NAME, "Priya Nair")])
check("a UNIQUE name still does not resolve",
      u.verdict is ResolutionVerdict.AMBIGUOUS_UNVERIFIED, u.verdict.value)
check("its cause is the rule, not the count",
      u.cause == "NAME_ALONE_CANNOT_IDENTIFY_A_SUBJECT", u.cause)

print("\n=== UNIQUENESS IN A SAMPLE IS NOT UNIQUENESS ===")
p = resolve(PARTIAL, [(KeyKind.SUBJECT_ID, "subj-0003")])
check("a strong key in an unasserted index does not resolve",
      p.verdict is ResolutionVerdict.AMBIGUOUS_UNVERIFIED
      and p.cause == "IDENTITY_INDEX_COMPLETENESS_NOT_ASSERTED", p.cause)
check("the same key in an asserted index resolves",
      resolve(FULL, [(KeyKind.SUBJECT_ID, "subj-0003")]).verdict
      is ResolutionVerdict.RESOLVED)

print("\n=== KEY STRENGTH ===")
em = resolve(FULL, [(KeyKind.EMAIL, "priya@example.com")])
check("a near-unique email alone does not resolve",
      em.verdict is ResolutionVerdict.AMBIGUOUS_UNVERIFIED
      and em.cause == "KEY_IS_NOT_UNIQUE_BY_CONSTRUCTION", em.cause)
check("email plus name resolves by corroboration",
      resolve(FULL, [(KeyKind.EMAIL, "priya@example.com"),
                     (KeyKind.NAME, "Priya Nair")]).cause
      == "CORROBORATED_BY_SECOND_KEY")
check("a strong key alone resolves",
      resolve(FULL, [(KeyKind.ACCOUNT, "ACC-1003")]).cause
      == "MATCHED_ON_KEY_UNIQUE_BY_CONSTRUCTION")
check("corroboration narrows rather than widens",
      resolve(FULL, [(KeyKind.NAME, "Rajesh Kumar"),
                     (KeyKind.DOB, "1991-11-19")]).verdict
      is ResolutionVerdict.RESOLVED,
      resolve(FULL, [(KeyKind.NAME, "Rajesh Kumar"),
                     (KeyKind.DOB, "1991-11-19")]).detail)
check("two keys that disagree find nobody",
      resolve(FULL, [(KeyKind.NAME, "Priya Nair"),
                     (KeyKind.DOB, "1987-03-04")]).verdict
      is ResolutionVerdict.NOT_FOUND)

print("\n=== NOT FOUND IS NOT ERASED, AND UNAVAILABLE IS NOT EMPTY ===")
nf = resolve(FULL, [(KeyKind.ACCOUNT, "ACC-9999")])
check("no match is NOT_FOUND", nf.verdict is ResolutionVerdict.NOT_FOUND)
check("it says so explicitly", "already been erased" in nf.detail)
blind = StaticIdentityIndex([RAJESH_A], complete=True,
                            unavailable_kinds=[KeyKind.EMAIL])
ua = resolve(blind, [(KeyKind.EMAIL, "rajesh.kumar@example.com")])
check("an index that cannot answer is INDEX_UNAVAILABLE",
      ua.verdict is ResolutionVerdict.INDEX_UNAVAILABLE, ua.verdict.value)
check("an unanswered lookup is not an empty result",
      "not an empty result" in ua.detail)

print("\n=== THE REFUSAL MUST NOT LEAK THE OTHER PEOPLE ===")
serialised = str(r.to_dict()) + r.explain() + r.resolution_hash
secrets = ["rajesh.kumar@example.com", "r.kumar@other.example",
           "+919800000001", "+919800000002", "ACC-1001", "ACC-1002",
           "1987-03-04", "1991-11-19", "subj-0001", "subj-0002",
           "Rajesh Kumar"]
leaked = [x for x in secrets if x in serialised]
check("no candidate value appears in the control-plane refusal",
      leaked == [], str(leaked))
check("the query value itself is masked in the record",
      all("Rajesh Kumar" not in str(q) for q in r.to_dict()["query"]),
      str(r.to_dict()["query"]))
check("what IS disclosed is which fields differ",
      set(r.candidates[0].discriminator_fields) >= {"email", "phone", "dob"},
      str(r.candidates[0].discriminator_fields))
check("a field every candidate shares is not called a discriminator",
      "name" not in r.candidates[0].discriminator_fields,
      str(r.candidates[0].discriminator_fields))
check("candidate tokens are stable and opaque",
      r.candidates[0].token.startswith("S-") and len(r.candidates[0].token) == 14,
      r.candidates[0].token)

print("\n=== DISCLOSURE REQUIRES A NAMED AUTHORITY ===")
for bad in (None, "dpo@acme", 42):
    try:
        r.resolver_view(bad)
        check(f"resolver_view rejects {type(bad).__name__}", False, "allowed")
    except ResolutionError as e:
        check(f"resolver_view rejects {type(bad).__name__}",
              e.code == "CANDIDATE_DISCLOSURE_REQUIRES_AUTHORITY")
for kw in (dict(authority="", reason="x"), dict(authority="dpo", reason="")):
    try:
        ResolverAuthority(**kw)
        check(f"authority rejects {kw}", False, "accepted")
    except ResolutionError:
        check(f"authority rejects missing field", True)

auth = ResolverAuthority("dpo@acme.example / DSR-4471",
                         "breaking a name collision on a DSR erasure")
view = r.resolver_view(auth)
check("the resolver sees masked values, not raw",
      all("@example.com" not in str(v) or "*" in str(v)
          for c in view["candidates"] for v in c["discriminators"].values()),
      str(view["candidates"][0]["discriminators"]))
check("the disclosure records who saw it",
      view["disclosed_to"].startswith("dpo@acme"), view["disclosed_to"])
check("the resolver view is not part of the audit record",
      "disclosed_to" not in str(r.to_dict()))

print("\n=== A HUMAN TIE-BREAK IS RECORDED, NOT ANONYMOUS ===")
picked = r.select(RAJESH_B.token, auth)
check("selection resolves", picked.verdict is ResolutionVerdict.RESOLVED)
check("it names who chose",
      picked.provenance["selected_by"].startswith("dpo@acme"),
      str(picked.provenance["selected_by"]))
check("it records what was rejected",
      len(picked.provenance["from_candidates"]) == 2,
      str(picked.provenance["from_candidates"]))
check("it records the verdict it overrode",
      picked.provenance["prior_verdict"] == "AMBIGUOUS_SUBJECT")
try:
    r.select("S-NOTREAL00000", auth)
    check("selecting an unlisted candidate is rejected", False, "accepted")
except ResolutionError as e:
    check("selecting an unlisted candidate is rejected",
          e.code == "UNKNOWN_CANDIDATE")

print("\n=== AN UNRESOLVED SUBJECT CANNOT BECOME A REQUEST ===")
ROWS = (RowTarget("ACME", "PUBLIC", "customers", "account",
                  mode=EraseMode.DELETE_ROW, citation="DPDP s.12(3)"),)
for bad_res in (r, u, em, nf, ua):
    try:
        ErasureRequest.from_resolution(bad_res, ROWS, (),
                                       [Subject(key="ACC-1002")])
        check(f"{bad_res.verdict.value} cannot build a request", False, "built!")
    except SubjectError as ex:
        check(f"{bad_res.verdict.value} cannot build a request",
              ex.code == "SUBJECT_NOT_RESOLVED_TO_ONE_PERSON")

good = resolve(FULL, [(KeyKind.ACCOUNT, "ACC-1002")])
req = ErasureRequest.from_resolution(
    good, ROWS, (), [Subject(key="ACC-1002", key_kind="account",
                             token_hash="cd" * 32)])
check("a resolved subject builds a request", req.state is RequestState.OPEN)

print("\n=== FRAGMENTATION: THE SILENT FAILURE ===")
check("resolution returns every key the person holds",
      len(good.linked_keys) == 6, str([k for k, _ in good.linked_keys]))
req.record_execution("COMPLETE")
req.record_structured_check(StructuredCheck(ROWS[0].target, False, "0 rows"))
causes = [c["cause"] for c in req.open_causes()]
check("erasing one key of six keeps the request open",
      "LINKED_IDENTITY_KEY_NOT_COVERED_BY_ERASURE" in causes, str(sorted(set(causes))))
check("it does not close", req.settle() is not RequestState.COMPLETE)
check("the uncovered kinds are named",
      {g["key_kind"] for g in req.uncovered_linked_keys()}
      == {"subject_id", "name", "email", "phone", "dob"},
      str(sorted(g["key_kind"] for g in req.uncovered_linked_keys())))

full_req = ErasureRequest.from_resolution(
    good, ROWS, (),
    [Subject(key=v, key_kind=k, token_hash="cd" * 32)
     for k, v in good.linked_keys])
full_req.record_execution("COMPLETE")
full_req.record_structured_check(StructuredCheck(ROWS[0].target, False, "0 rows"))
check("covering every linked key closes it",
      full_req.settle() is RequestState.COMPLETE,
      str([c["cause"] for c in full_req.open_causes()]))
check("the subject values do not reach the serialised request",
      "rajesh" not in str(full_req.to_dict()).lower()
      and "ACC-1002" not in str(full_req.to_dict()),
      "")

print("\n=== COLLISION PROFILE: MEASURE YOUR OWN CORPUS ===")
# A synthetic corpus built to the SHAPE of Dinesh's measurement — 600
# records, 154 names shared by two or more people, 61% of records on a
# shared name. His 61% is his corpus, not a constant; this shows the
# function reproduces the figure so a customer can compute theirs.
corpus, sid = [], 0
for i in range(154):        # 58 names held by 3 people, 96 by 2 -> 366 subjects
    n = 3 if i < 58 else 2
    for _ in range(n):
        sid += 1
        corpus.append(rec(f"s{sid:04d}", f"Shared Name {i}",
                          email=f"u{sid}@example.com"))
shared_records = len(corpus)
while len(corpus) < 600:                   # the rest carry unique names
    sid += 1
    corpus.append(rec(f"s{sid:04d}", f"Unique Name {sid}",
                      email=f"u{sid}@example.com"))

prof = collision_profile(corpus, KeyKind.NAME)
check("600 subjects profiled", prof["subjects_total"] == 600,
      str(prof["subjects_total"]))
check("154 names shared by two or more people",
      prof["values_shared_by_multiple_subjects"] == 154,
      str(prof["values_shared_by_multiple_subjects"]))
check("about 61% of subjects sit on a shared name",
      0.60 <= prof["share_of_subjects_on_a_shared_value"] <= 0.62,
      f"{prof['share_of_subjects_on_a_shared_value']:.3f} "
      f"({shared_records} of 600)")
check("name is never safe to key on", not prof["safe_to_key_on"])
check("a unique-by-construction key with no collisions is safe",
      collision_profile(corpus, KeyKind.SUBJECT_ID)["safe_to_key_on"])
check("email in this corpus has no collisions but is still not safe to key on",
      collision_profile(corpus, KeyKind.EMAIL)[
          "values_shared_by_multiple_subjects"] == 0
      and not collision_profile(corpus, KeyKind.EMAIL)["safe_to_key_on"])

print("\n=== DETERMINISM ===")
check("same input, same resolution hash",
      resolve(FULL, [(KeyKind.NAME, "Rajesh Kumar")]).resolution_hash
      == r.resolution_hash, r.resolution_hash)

print("\n=== SAMPLE REFUSAL (control-plane safe) ===")
print("  " + r.explain().replace("\n", "\n  "))

print("\n" + "=" * 62)
print("ALL PASS" if not F else f"FAILURES: {F}")
sys.exit(1 if F else 0)
