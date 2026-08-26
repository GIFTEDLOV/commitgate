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

## Current status

The first deployment attempt, transaction
`0x09abe169acbba1eb5c45d667dcf1e1b19844a9247e5cee22fb5cc8419fa80549`,
finalized with consensus `AGREE` on `FINISHED_WITH_ERROR`. The trace is an
`invalid_contract` error because Bradbury GenVM `v0.2.11` could not resolve the
v0.3 runner pin `py-genlayer:9b8kjyda2ycxyq4ea6g4yfpnydxhd52gqba5rb8dw7krkh5mn9p0`.
All five revealed votes were `DISAGREE` with the leader's invalid execution result.
This transaction is a preserved failed attempt, not a deployment proof.

The Bradbury-compatible runner port is complete at commit
`0541f2be119e9bb73a87609f67af13f8159f8e80`. The exact-head release gate is green in
CI run `32945387329`. Deployment and representative live proof remain pending a
separate preconditioned one-time write; no successful live behavior is claimed until
`artifacts/final-release-proof.json` contains reconciled deployment hashes, execution
result names, consensus results, state reads, and digests.

Failed or superseded attempts must be appended to the proof artifact and never
deleted for cosmetic reasons.
