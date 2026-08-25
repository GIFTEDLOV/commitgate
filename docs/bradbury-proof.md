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
requires both immutable authorization facts. Repository publication is still
pending; these commits are not claimed as GitHub evidence until the public remote
serves both exact SHAs.

The single representative live proof must show creation, activation, submission,
repository/lineage/content authentication, independent validator adjudication,
PROVISIONAL_APPROVE, challenge-window enforcement, FINAL_APPROVED, the exact final
authorization digest, and downstream exact-target acceptance.

## Current status

Bradbury deployment and lifecycle are pending an exact-head public GitHub repository,
exact-head CI, and available authenticated deployment account state. No successful
live behavior is claimed until `artifacts/final-release-proof.json`
contains reconciled hashes, execution result names, consensus results, state reads,
and digests.

Failed or superseded attempts must be appended to the proof artifact and never
deleted for cosmetic reasons.
