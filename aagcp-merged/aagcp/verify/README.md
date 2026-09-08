# aagcp/verify — Erasure Verification

Additive module. Nothing in `aagcp/store/`, `aagcp/vault.py`, `server.py` or
anywhere else in the engine is modified. It reads the existing connector and
vault through their public interfaces.

```
python3 aagcp/verify/test_erasure_verifier.py     # from the repo root
```

## The problem

`vault.crypto_shred_identity(iid)` returns success. The honest question is
not "did the call succeed" but "is the subject still recoverable". Today that
claim is unfalsifiable in both directions — nobody, including the vendor, can
check it. This module makes it checkable, and refuses to answer where it
cannot.

## Usage

```python
from aagcp.verify import ErasureVerifier

ev = ErasureVerifier(store=engine.store, vault=engine.vault,
                     log_path="attestations.json")

# BEFORE erasure — you cannot probe a region you never located
anchor = ev.register("id_42", subject_embedding, record_id="doc_17_chunk_3")

# ... engine.erase(...) ...

att = ev.verify(anchor, n_control_anchors=100)
print(att.bound.explain())
ev.forget(anchor.token_hash)        # destroy the anchor after attestation
```

### Pinecone

```python
from aagcp.verify import ErasureVerifier, PineconeProbeAdapter

adapter = PineconeProbeAdapter(engine.store)      # wraps PineconeConnector
ev = ErasureVerifier(store=adapter, vault=engine.vault)

anchor = ev.register("id_42", vec, record_id="subj")
att = ev.verify(anchor, n_control_anchors=100,
                settle_seconds=10, retry_on_residue=2)   # eventual consistency

print(PineconeProbeAdapter.attest_non_retrievability(att))
```

The adapter exists because `PineconeConnector` builds every record as
`VectorRecord(id, None, ...)` — no values — so control sampling finds nothing;
because a full `list()`+`fetch` scan does not scale as a probe budget; and
because on a **euclidean** index lower score means nearer, which would invert
the paired test and make a present subject read as erased.

## Three safety invariants

**I1 — an unmeasured channel can never produce a pass.**
`ChannelStatus` has three states, not two: `CLEAN`, `RESIDUE`, `UNAVAILABLE`.
Every `EngineType` declares the internal state that must be accounted for; the
channels start `UNAVAILABLE` and only a real measurement upgrades them. Any
remaining `UNAVAILABLE` forces `INCONCLUSIVE_UNMEASURED`.

**I2 — a subject that is still present is never classified as erased.**
False negatives are the catastrophic direction. Tested on both stores, all
three Pinecone metrics, and both clustered and unclustered geometry.

**I3 — confidence comes from control anchors, never probe count.**
Probes around one anchor are correlated; 5000 of them are roughly one
independent observation. Minimum attainable p is 1/(m+1), so 100 control
anchors are needed for a p ≤ 0.01 claim. Probe budget buys precision within a
region; only control anchors buy confidence.

## How verification works

**Stage 0 — inspection** (deterministic, engine-specific). Real SQL against
`pg_stat_user_tables`, `pg_stat_replication` and `pageinspect`. Any query
failure returns `UNAVAILABLE`, never `CLEAN`.

**Stage 1 — deterministic sweep** (engine-agnostic). Streams the index for the
subject's vault tokens in `source_text`/metadata. A hit is proof of
non-erasure; no statistics needed.

**Stage 2 — paired pre/post test** (primary statistic). At registration the
verifier records the subject's region score *with* its record visible and
*with it excluded*. Those are the two hypotheses. Verification checks which
one the post-erasure measurement matches. Because the region is compared
against itself, a legitimate near neighbour cannot masquerade as residue —
the failure mode a control-arm test alone cannot avoid.

When the two baselines are within 0.01 — a near-duplicate shares the region —
the result is `INCONCLUSIVE_INDISTINGUISHABLE` and no claim is issued.
`register()` warns about this at registration, before the DSAR clock starts.

**Stage 2b — conformal cross-check.** The subject's region score is ranked
against *m* control regions: `p = (1 + #{s_i >= s_0}) / (1 + m)`. Exact under
exchangeability — no calibration constant, no normal approximation. Null
p-values run uniform.

## What Pinecone can and cannot attest

Pinecone exposes no tombstone count, no compaction state, no replica lag, so
`EngineType.PINECONE` declares those three channels permanently `UNAVAILABLE`
and caps every Pinecone result at `INCONCLUSIVE_UNMEASURED`.

That cap is correct, not a defect. `MockPineconeIndex.storage_contains()`
demonstrates it in the test suite: after `delete()`, every probe reports the
subject as gone while the vector is still resident in storage. A tombstoned
vector is filtered from query results by design, so a query-path probe cannot
see it.

On Pinecone you can honestly attest: **the subject is not retrievable through
the query API over the sampled index state, in this namespace.** You cannot
attest the vector is gone. `attest_non_retrievability()` emits that narrower
claim with its limits stated. Deletes are also per-namespace — verify each
namespace the subject appears in.

For pgvector, inspection is the real evidence and the probe is the
cross-check. That asymmetry is deliberate: use the strong method where the
engine allows it.

## Privacy — this module is a data controller

Probing needs the subject's anchor embedding, and embeddings are invertible.
So the verifier holds personal data about the person it is proving was erased.
That is retention for a legal obligation (GDPR Art. 17(3)(b) / DPDP s.8), not
a loophole. Enforced in code:

- anchors are AESGCM-encrypted at rest under a key derived separately from
  both the vault key and the signing key
- the constructor **rejects** `anchor_key == vault.secret`
- `SubjectAnchor` carries no embedding — only a token hash
- `forget()` destroys the ciphertext; `shutdown()` zeroes the key
- attestations and spans carry `token_hash` only, never a name or a value

## Attestations

Ed25519 signature over canonical JSON (floats `.12e`, so `1e-9` and `4e-7` do
not collide), PEM public key, Merkle index commitment, and a file-backed
hash-chained log. `verify_attestation(att_dict, public_key_pem)` runs
standalone from JSON plus the public key — no index access.

Honest limit: the log is signed and held by the same party. It detects edits
by anyone *without* the signing key; it does not constrain the operator.
Publish `log.head()` to an external witness for that.

## Telemetry

`ev.span_attrs(att)` returns attributes for `aagcp/govern/telemetry.py`,
carrying `token_hash` only. This matters because `server.py` currently emits
`TRACE.span("erase_request", op="erase", subject=subject)` with the raw
display name, which writes the subject's name into an observability backend
that has no deletion path — at the exact moment they exercised Article 17.
This module does not repeat that.

## Scope

`RETRIEVAL_ONLY`. Does not cover model weights if the subject's data reached
training or fine-tuning (machine unlearning is unsolved and out of scope);
replicas, snapshots, backups or WAL outside the committed state except where
an inspection channel reports on them; derived embeddings, caches or features;
or application logs, traces and observability backends.

The conformal p-value tests whether the subject's region is distinguishable
from matched control regions. It is not a probability that the subject is
recoverable, and it must not be quoted as one.
