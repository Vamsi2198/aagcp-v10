# AAGCP

Agent governance control plane. Structured data and vector stores, in one
package.

```
pip install -e .[all]
python3 -m aagcp.cli acceptance --dry-run
```

## Layout

```
aagcp/core/          the engine — stdlib only, no I/O, deterministic
aagcp/verify/        erasure verification (numpy, cryptography)
aagcp/vault/         pseudonym vault — the subject-token authority
aagcp/store/         vector store connectors
aagcp/detect/        span-level detection
aagcp/platform.py    warehouse config and connections
aagcp/api.py         HTTP surface over the orchestrator
aagcp/cli.py         console entry point
acceptance.py        the acceptance harness
tests/               11 suites
```

`aagcp.core` is stdlib-only by contract. `aagcp.core.verifier_adapter` is
the only file in it that knows numpy exists, and it imports lazily.

## The loop

Observe → Analyze → Resolve → Plan → Simulate → Approve → Execute →
Verify → Close, driven by `aagcp.core.orchestrator` and recorded in
`aagcp.core.journal`. State lives in the journal, not in memory: a
restarted process reads back where it got to, and artifacts must be handed
in again and hash-matched, so what executes is provably what was approved.

## Crash consistency

`tests/test_crash.py` runs real subprocesses and kills them with
`os._exit(9)` at four points, then opens the same journal in a fresh
process:

| kill point | expected | result |
|---|---|---|
| after authorization | authorized, not executed | no DDL reached the engine |
| after the engine changed, before the journal wrote | discovered, not repeated | `reconcile()` observes the engine, issues no DDL, records the outcome |
| after execution, before verification | execution preserved | receipt rehydrates from the journal, verification resumes |
| after verification, before settlement | settle, no duplicate work | closes without re-executing or re-verifying |

Execution is two journal records, not one. The attempt is written before
the executor runs, so a crash between the DDL landing and the outcome
being recorded leaves an unresolved attempt rather than silence. A restart
finds it, refuses to execute, and reconciles from engine state. An
operation whose state cannot be read comes back UNKNOWN, never
NOT_ATTEMPTED — the cost of that mistake is applying a change twice.

## What it refuses

- executing a forecast that required approval and did not get one
- executing the same plan twice, or executing over an unresolved attempt
- approving your own change, at any tier
- approving above your tier
- closing an erasure without a passing signed attestation
- closing when the attestation names a different subject token
- closing an erasure while Snowflake Time Travel can still return the rows
- deleting from a vector store without an anchor registered beforehand
- emitting an identifier-shaped value to a telemetry backend

## What it does not claim

The audit trail is tamper-**evident**, not immutable. A hash chain written
and held by the operator is worth nothing against the operator, and
`tests/test_journal.py` contains a rewrite that passes `verify_chain`
cleanly to prove it. Export `aagcp checkpoint` to a party that is not you;
that is the step that makes it evidence.

The `_Signer` in `aagcp/verify` generates an ephemeral key when none is
supplied, so attestations from different processes verify against
different public keys. Pin a persistent key before treating a signature as
identity.

## Running

    for t in tests/*.py; do python3 $t; done

`test_erasure.py` and `test_erasure_live.py` need `.[verify]`. The first
SKIPS its drift guard without it — the check that re-derives the two
constants `aagcp.core.erasure` mirrors from `aagcp.verify`. That skip is
the one to watch.

    cp platform.example.yaml platform.yaml     # then edit
    python3 -m aagcp.cli acceptance --config platform.yaml

The harness reports the worst outcome across its gates, not an average.
SKIP is not a pass.
