# Runtime baseline

Verified on 2026-08-25 before implementation. This repository did not inherit
runtime assumptions or code from another GenLayer project.

## Pinned execution surface

- Local CLI: `genlayer 0.39.1`; selected network: `testnet-bradbury`.
- Local testing: official `genlayer-testing-suite` commit
  `343e3a358f9e235a93b49c60721ce7676585ff07` (package version 0.29.2).
  The released 0.29.2 loader is v0.2-only; the exact current official commit
  adds the required v0.3 import/storage compatibility. Direct Mode is
  unit/in-memory testing, while five-validator GLSim is the RPC integration
  surface used here.
- Local linter: `genvm-linter 0.11.0`; `check` combines AST lint and SDK semantic
  validation for v0.2. Its schema loader still imports the removed
  `genlayer.py.get_schema` path. CommitGate runs its unchanged AST lint and the
  narrow `tools/genvm_v03_validate.py` compatibility shim, which uses the
  linter's own artifact resolution and current official
  `genlayer._internal.get_schema` import.
- Contract runner: `py-genlayer:9b8kjyda2ycxyq4ea6g4yfpnydxhd52gqba5rb8dw7krkh5mn9p0`
  (current official v0.3 runner). Initial implementation used the older documented
  v0.2.4 pin, but current GenVM semantic validation could no longer resolve that
  runner archive. That verified compatibility blocker required migration before
  release rather than shipping a contract the current validator could not load.
- Runner bundle: official `genlayerlabs/genvm-manager` release `v0.6.0-rc2`,
  asset `genvm-universal.tar.xz`. CI pins and caches that exact release asset.

## Current official rules applied

- Storage proxy objects must be copied with `gl.storage.copy_to_memory` before
  capture by nondeterministic closures. Primitive `TreeMap[str, str]` reads are
  already memory strings (and are not storage proxy objects); CommitGate parses
  and canonical-round-trips those strings
  into fresh memory objects before closure capture. Nondeterministic blocks cannot
  read or write contract storage.
- Web and LLM calls belong inside an equivalence-principle block. Storage writes,
  contract calls, and message emission happen only after consensus returns.
- For the pinned v0.3 runner, custom leader/validator consensus uses
  `gl.vm.run_nondet` (the renamed v0.2 `run_nondet_unsafe` behavior). Validator exceptions count as disagreement and are
  handled explicitly.
- Independent verification is substantive: a validator refetches authenticated
  GitHub evidence and independently invokes the semantic evaluator. Checking only
  leader schema or plausibility is forbidden.
- `gl.nondet.web.get`/`request` returns bounded response status, headers, and body.
  CommitGate constructs only `https://api.github.com` URLs and rejects all 3xx.
- LLM output is parsed without repair. The pinned runtime may return either raw
  JSON text or an already parsed JSON object; CommitGate strictly accepts both
  surfaces only with one exact `verdict` key. Raw text uses duplicate-key detection;
  a pre-parsed object cannot retain duplicate-key information, which is documented.
- Transaction time is deterministic in ordinary contract execution and pinned to
  the transaction timestamp. The current runner exposes it through
  `gl.vm.get_timestamp()`; CommitGate reads it only outside nondeterministic
  blocks.
- IC view calls are synchronous. The reference consumer rereads CommitGate in its
  write transaction; emitted writes would be asynchronous and are not used for the
  authorization decision.
- `on='finalized'` is the safe mode for downstream messages/value transfer. The
  reference consumer records an action locally and does not need value transfer.
- `ACCEPTED` is not finality. `FINALIZED` means validation and appeal processing
  completed, but proof also requires successful execution and expected state.
- Bradbury is the production-like public testnet at
  `https://rpc-bradbury.genlayer.com`, chain ID 4221. Studionet is excluded.

## Authoritative references

- https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle
- https://docs.genlayer.com/developers/intelligent-contracts/features/non-determinism
- https://docs.genlayer.com/developers/intelligent-contracts/features/web-access
- https://docs.genlayer.com/developers/intelligent-contracts/features/transaction-context
- https://docs.genlayer.com/developers/intelligent-contracts/features/interacting-with-intelligent-contracts
- https://docs.genlayer.com/developers/intelligent-contracts/testing
- https://docs.genlayer.com/understand-genlayer-protocol/core-concepts/transactions/transaction-statuses
- https://docs.genlayer.com/developers/networks
- https://sdk.genlayer.com/main/_static/ai/api.txt
- https://github.com/genlayerlabs/genvm-linter

## Current documentation changes found

The current SDK mainline has the v0.3 API: direct `import genlayer as gl`,
`gl.contract.Contract`, and `gl.vm.run_nondet` replacing the v0.2 unsafe name.
Current product documentation still contains some v0.2 examples. CommitGate first
tested that older pin, recorded its validation failure, and migrated wholly to v0.3
rather than mixing contract API generations. The current released linter and test
package lag that runner; all test-only compatibility adapters are isolated under
`tests/v03_direct_compat.py` and `tools/glsim_v03.py` and do not enter deployed
source.
