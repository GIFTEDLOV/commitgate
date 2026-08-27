# Bradbury proof

Network target: GenLayer Bradbury production-like testnet, chain ID 4221,
`https://rpc-bradbury.genlayer.com`. Studionet is prohibited for this release.

## Required proof protocol

For every state-changing transaction:

1. read the precondition;
2. broadcast exactly once;
3. persist the transaction hash immediately;
4. reconcile that same hash after any timeout or restart;
5. require FINALIZED and successful execution;
6. read and verify the expected stored state/digest before the next action.

Never rebroadcast because of an RPC timeout, refresh, polling failure, or ambiguous
client result. A hash, HTTP success, ACCEPTED, or FINALIZED-with-error is not proof.

## Representative lifecycle

The public fixture is part of this repository and has exact immutable history:

- repository: `GIFTEDLOV/commitgate`
- base: `82a3775101d4815392375d22ff0a71feb62c944b`
- target: `0b552ac0c71367d6389cb9e231a58d11c7f77584`
- review path: `fixtures/release_guard.py`
- policy: `A protected release may be published only by an active release manager.`
- acceptance criteria: `may_publish(actor) returns true only when both
  actor.is_release_manager and actor.is_active are true; callers missing either
  permission are denied.`
- policy/criteria digest:
  `6e55e5cdf613e79aa38206184fbb1f4c4c3dc86104b13fe718afe6b8c91862b1`

The base permits every actor. The target changes only the bounded review path and
requires both immutable authorization facts. The public remote serves both exact
SHAs.

The single representative live proof must show creation, activation, submission,
repository/lineage/content authentication, independent validator adjudication,
PROVISIONAL_APPROVE, challenge-window enforcement, FINAL_APPROVED, the exact final
authorization digest, and downstream exact-target acceptance.

## Runtime reconciliation

On 2026-08-26, the failed deployment was reread from Bradbury by hash. The
receipt reports status `7` (`FINALIZED`) and `txExecutionResult` `2`; the same
transaction's debug trace reports result code `2`, GenVM
`v0.2.11-x86_64-linux-release`, and:

`runner py-genlayer:9b8kjyda2ycxyq4ea6g4yfpnydxhd52gqba5rb8dw7krkh5mn9p0 not found`

The receipt records five committed/revealed validator votes and no equivalence
outputs. This confirms a finalized failed deployment, not a live contract. The
transaction is never rebroadcast.

Before selecting the replacement target, a read-only Bradbury
`gen_getContractSchema` request was made with a minimal contract whose first
line pinned:

`py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`

Bradbury returned a valid schema for `Probe.get() -> int`. The same read-only
method accepted the exact corrected CommitGate deployable artifact and returned
all 16 expected public methods with no RPC error. This is the smallest verified
runner target currently supported by both the official documentation and the
live Bradbury-visible runtime; these are schema probes, not deployments.

## Compact evidence read probe

Before any replacement deployment, a read-only ordinary-HTTPS probe of the exact
fixture endpoints returned HTTP 200 with these body sizes:

| Endpoint | Bytes | Bound |
|---|---:|---:|
| repository metadata | 5,108 | 16,384 |
| base Git Data commit | 909 | 32,768 |
| target Git Data commit | 1,148 | 32,768 |
| base raw review file | 196 | 24,576 |
| target raw review file | 227 | 24,576 |

No redirect was observed. The target Git Data object exposes the base as a direct
parent, so the representative fixture fits the bounded ancestry path. This is a
read-only response-shape check, not a semantic transaction or deployment proof.

## Current status

The first deployment attempt, transaction
`0x09abe169acbba1eb5c45d667dcf1e1b19844a9247e5cee22fb5cc8419fa80549`, remains a
preserved finalized runner-resolution failure. The corrected deployment at
`0x3709b06c21c133093b93DC4DCCBc0445b5dc9849` completed a gate lifecycle, but its
semantic submission
`0x03e59bc91dd08c11a0a8a5ff25852549331d9b255393d5d00cf877cc76b9fff5` finalized
with `FINISHED_WITH_ERROR`, `DISAGREE`, and five
`DETERMINISTIC_VIOLATION` votes. The trace error was:
`EVIDENCE_ERROR: HTTP response exceeds bound`.

A read-only ordinary-HTTPS measurement of the same public fixture recorded the
legacy base `/commits/{sha}` response at 229,774 bytes against the former
196,608-byte body bound. The compact evidence repair replaces that heavy endpoint,
the compare endpoint, and Contents JSON with bounded repository metadata, Git Data
commit objects plus bounded parent traversal, and exact raw commit-pinned bytes.
The same compact path is used for challenge evidence. This is a transport repair,
not a semantic verdict change and not a weakening of authentication or model
authority.

The existing deployment and failed semantic transaction remain historical only and
will not be retried. A replacement deployment is permitted only after the repaired
source passes the complete release gate, exact-head CI, and a read-only Bradbury
response-shape probe. Failed or superseded attempts must remain in the proof
artifact and never be deleted for cosmetic reasons.

## Replacement live proof

The repaired artifact was deployed once at
`0x6DaC39672bB4a3a684897FbEf31f131429D28023` by transaction
`0x91cab49673eb657d6dce40966fa6fdfdef66516a482b495ce24c98b00f31cd74`.
The transaction finalized successfully with `AGREE` and
`FINISHED_WITH_RETURN`, and the initial gate count was zero.

The one representative gate is
`074843a3e30066338eec51d1d9e5a23481c6837891608467a402098f1ae43fbc`.
Creation finalized in `0x8555dde31c6415455ff6a1682c2cf9d419aad23b13b9728fcaeea59dd496f534`;
activation finalized in
`0x77ada20ceb4144354a1e7a112ca0f038a4ca970ef318c10c868a84ea1e6845c8`.

The exact target submission finalized in
`0x91867d19c7c4a49d06ebaaa8248e62649cb6777907a447edbb57f29f14ad7ec9` with
`AGREE`, `FINISHED_WITH_RETURN`, and verdict `APPROVE`. The actual validator vote
sequence is preserved exactly: `AGREE, DETERMINISTIC_VIOLATION, AGREE, AGREE,
TIMEOUT`. The stored evidence manifest digest is
`dc85f338f46a424d88872cfbd53a1db69ec039b8cf686d3a307bacebc635e3c1`; the
assessment digest is
`93095bb54b1cc71af4c1c5b5bf6604c6cb78db9f89be7a61fdbe40c215cabe60`.

After the stored 60-second challenge deadline, uncontested finalization finalized
successfully in
`0x0ee0757765039e9eb938fbbcc9f7abdb90197e0530b314d09a9c52fa7c144a0b` with
five `AGREE` finalization votes. The gate is `FINAL_APPROVED` for target
`0b552ac0c71367d6389cb9e231a58d11c7f77584`; its final authorization digest is
`e679be060abb2574794a5066439f50e17a03d88fa6fbba44568cdef1709588b5`.

The read-only reference consumer reread the live gate and authorization view,
accepted the exact target and rejected a different target. All failed and superseded
attempts remain recorded in `artifacts/final-release-proof.json`.
