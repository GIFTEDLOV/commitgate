# Security and trust model

## Authority boundary

Deterministic code controls caller authentication, immutable gate fields,
repository and commit identity, lineage, path admissibility, content hashes,
deadlines, state transitions, response limits, target binding, authorization
digests, and consumer behavior. The model controls exactly one value:

```json
{"verdict":"APPROVE|REJECT|INCONCLUSIVE"}
```

APPROVE means authenticated evidence sufficiently establishes satisfaction.
REJECT means it affirmatively establishes non-satisfaction. INCONCLUSIVE means the
authenticated/admissible evidence exists but the semantic question cannot be
resolved reliably. INCONCLUSIVE is not rejection.

Infrastructure, evidence, integrity, model, and consensus failures are not business
verdicts. The code and tests distinguish `EVIDENCE_ERROR`, `INTEGRITY_ERROR`,
`MODEL_ERROR`, `CONSENSUS_ERROR`, and `BUSINESS_REJECT`. Nondeterministic failures
leave storage untouched; validator errors disagree and trigger consensus rotation.

## Model parser

Raw model text uses strict UTF-8 decoding, a 256-byte maximum, standard JSON
parsing with duplicate-key rejection, and an exact one-key schema. Supported
runners may return an already parsed JSON object; it receives the same canonical
byte bound and exact key/type/enum checks. Duplicate-key ambiguity cannot survive
an upstream parser, which is an explicit runtime limitation. Arrays, nesting,
null, wrong types, missing/extra keys, unknown enums, fences, and malformed JSON
become MODEL_ERROR. Nothing is repaired.

## Independent validator derivation

Current official documentation recommends `gl.vm.run_nondet_unsafe` for custom
leader/validator patterns. The pinned Bradbury-compatible v0.2.x runner used by
the frozen artifact exposes the compatibility surface `gl.vm.run_nondet`. A leader constructs
and retrieves the authenticated GitHub evidence, hashes exact content, invokes the
model, and returns only the stable verdict/manifest/digests. Each validator
independently repeats that complete evidence and semantic path and compares the
canonical result. It never accepts because the leader output is well formed,
plausible, or defensible.

Only primitive strings are read from storage. They are parsed and canonicalized
into fresh memory dicts before closure capture. The SDK already returns primitive
`TreeMap[str, str]` values in memory and rejects passing them to
`copy_to_memory`; no storage proxy or mutable storage object is captured. Storage
writes occur only after `run_nondet` returns consensus.

## State machine

`CREATED → ACTIVE → (execution-phase ASSESSING) → ACTIVE | PROVISIONAL_APPROVE`

- REJECT and INCONCLUSIVE record an assessment and return the gate to ACTIVE so a
  different target may be submitted.
- APPROVE becomes PROVISIONAL_APPROVE and opens a deterministic challenge window.
- An authenticated challenge moves to CHALLENGED and guarantees the submitter a
  deterministic response window.
- Challenge adjudication APPROVE becomes FINAL_APPROVED for the exact response
  target; REJECT becomes FINAL_REJECTED; INCONCLUSIVE remains CHALLENGED for a
  bounded retry while time remains.
- No valid response before expiry deterministically becomes FINAL_REJECTED as a
  process consequence, not an AI verdict.
- Unchallenged provisional approval becomes FINAL_APPROVED only after the challenge
  deadline. Equal-to-deadline remains open; finalization requires `now > deadline`.

`ASSESSING` is an explicit execution phase rather than persisted pre-consensus
state: persisting it would violate the no-storage-write-before-consensus rule.
Technical failure therefore leaves the durable state ACTIVE or CHALLENGED.

## Final authorization and consumer

The final authorization binds gate ID, repository, base SHA, exact final target,
policy/criteria digest, evidence manifest digest, assessment digest, and deterministic
finalization timestamp. `is_target_authorized` requires both FINAL_APPROVED and the
exact SHA.

The reference consumer synchronously rereads `get_gate` and
`is_target_authorized` in its write transaction immediately before recording the
downstream action. It checks repository configuration and exact target and supports
one-shot consumption. Frontend state and user-supplied claims have no authority.

## Threats covered

- repository/host/path/branch substitution and redirects;
- shortened, uppercase, cross-repository, nonexistent, unrelated, or duplicate
  commit submissions;
- traversal, Windows paths, URL paths, control characters, duplicates, and bounds;
- missing/mutated/malformed/oversized evidence and GitHub unavailability;
- hostile model JSON and model exceptions;
- leader-trusting validators, validator disagreement, storage capture, and writes
  before consensus;
- wrong caller, early/late challenge and response, early/duplicate finalization,
  wrong-target/cross-gate authorization, and one-shot reuse.

## Limitations

- GitHub is an external availability dependency and content digests do not preserve
  future GitHub availability.
- V1 reviews at most four small UTF-8 text files and requires each at base and target;
  binary, added-only, deleted-only, submodule, LFS, and large-file review is excluded.
- GitHub account/repository ownership at gate creation is not a DNS-style identity
  proof; evidence authenticity means the exact public GitHub repository/commit/path
  responses satisfied the recorded deterministic bindings at adjudication time.
- V1 has no consensus-critical CI evidence.
- Semantic quality depends on validator model capability. Strict consensus may leave
  a transaction undetermined; it never grants authorization on disagreement.
- This code has extensive adversarial tests but no external audit claim.
