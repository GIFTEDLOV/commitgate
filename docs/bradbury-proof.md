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

The intended public fixture contains a vulnerable base and a descendant remediation
target for a small authorization guard at `src/guard.py`. The immutable policy
requires denial of unauthenticated/non-admin access before the protected operation;
the acceptance criteria require the target to enforce the check without trusting a
caller-provided authorization claim.

The single representative live proof must show creation, activation, submission,
repository/lineage/content authentication, independent validator adjudication,
PROVISIONAL_APPROVE, challenge-window enforcement, FINAL_APPROVED, the exact final
authorization digest, and downstream exact-target acceptance.

## Current status

Bradbury deployment and lifecycle are pending release gates, a public fixture, an
exact-head public GitHub repository, and available authenticated deployment account
state. No successful live behavior is claimed until `artifacts/final-release-proof.json`
contains reconciled hashes, execution result names, consensus results, state reads,
and digests.

Failed or superseded attempts must be appended to the proof artifact and never
deleted for cosmetic reasons.

