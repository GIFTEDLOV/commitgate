# Runtime baseline

Reconciled on 2026-08-26 after power-loss recovery. This baseline combines the
current official documentation, the exact cached official runner bundle, and a
read-only Bradbury schema probe. This repository did not inherit runtime
assumptions or code from another GenLayer project.

## Pinned execution surface

- Local CLI: `genlayer 0.39.1`; selected network: `testnet-bradbury`.
- Local testing: official `genlayer-testing-suite` commit
  `343e3a358f9e235a93b49c60721ce7676585ff07` (package version 0.29.2).
  Its released Direct loader is v0.2-shaped. Direct Mode is unit/in-memory
  testing, while five-validator GLSim is the RPC integration surface used here.
- Local linter: `genvm-linter 0.11.0`; `check` combines AST lint and SDK semantic
  validation for v0.2. Its schema loader still imports the removed
  `genlayer.py.get_schema` path. CommitGate runs its unchanged AST lint and the
  narrow `tools/genvm_v03_validate.py` compatibility shim with the exact v0.2.12
  artifact bundle.
- Contract runner: `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`.
  This is the hash in the current official first-contract documentation and it
  resolves in the official v0.2.12 bundle.
- Runner bundle: official GenVM release `v0.2.12`, asset
  `genvm-universal.tar.xz`. CI pins and caches that exact release asset.

## Current official rules applied

- Storage proxy objects must be copied with `gl.storage.copy_to_memory` before
  capture by nondeterministic closures. Primitive `TreeMap[str, str]` reads are
  already memory strings (and are not storage proxy objects); CommitGate parses
  and canonical-round-trips those strings
  into fresh memory objects before closure capture. Nondeterministic blocks cannot
  read or write contract storage.
- Web and LLM calls belong inside an equivalence-principle block. Storage writes,
  contract calls, and message emission happen only after consensus returns.
- For the Bradbury-compatible v0.2.12 runner, custom leader/validator consensus
  uses the sandboxed `gl.vm.run_nondet` API. The validator independently
  refetches and derives the full result; validator exceptions are handled as
  disagreement and cannot become an accepted result.
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
  the transaction timestamp. v0.2.12 exposes the raw ISO timestamp through
  `gl.message_raw["datetime"]`; CommitGate parses that value only outside
  nondeterministic blocks. It never reads host wall-clock time.
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

## Bradbury runtime evidence

- Official documentation, checked 2026-08-26:
  `https://docs.genlayer.com/developers/intelligent-contracts/first-contract`
  publishes the exact `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
  dependency and `from genlayer import *` API.
- Bradbury read-only probe, checked 2026-08-26: `gen_getContractSchema` accepted
  a minimal contract with that exact dependency and returned a schema containing
  constructor `Probe()` and view `get() -> int`. This proves the hash is
  resolvable by the current Bradbury-visible runtime; it is not a deployment.
- The same read-only schema method accepted the exact corrected
  `artifacts/commitgate_deployable.py` and returned all 16 expected public
  methods with no RPC error. This verifies the intended artifact's runner/API
  surface before any deployment broadcast.
- Historical live transaction `0x09abe169acbba1eb5c45d667dcf1e1b19844a9247e5cee22fb5cc8419fa80549`
  proved the old v0.3 hash was not resolvable on the observed Bradbury GenVM
  `v0.2.11-x86_64-linux-release`; that failure remains immutable provenance.

All compatibility adapters remain test-only under `tests/v02_direct_compat.py`
and `tools/glsim_v02.py`; none enters deployed source.
