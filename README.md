# CommitGate

## Product

CommitGate is a reusable GenLayer Intelligent Contract that turns authenticated,
commit-pinned software evidence into challenge-aware release authorization. Given
an immutable repository, base commit, policy, acceptance criteria, review paths,
and an exact target commit, it returns one consensus-critical semantic result:

```json
{"verdict":"APPROVE|REJECT|INCONCLUSIVE"}
```

Approval is never a decorative certificate. It is provisional until its challenge
window closes or a challenge/response is adjudicated. A reference consumer rereads
CommitGate and refuses a release action unless the requested exact repository and
target have `FINAL_APPROVED` authorization.

## Problem

Software gates often mix two different questions: “what bytes are we reviewing?”
and “do those bytes satisfy the policy?” An LLM can interpret code but cannot
authenticate arbitrary URLs, repository identity, commit ancestry, or content
integrity. A frontend approval badge also cannot safely authorize a downstream
deployment.

CommitGate separates those authorities and makes the resulting authorization
reusable by release, upgrade, publication, milestone, governance, payout, and
deployment contracts.

## Why GenLayer

The gate's semantic question needs code-aware natural-language judgment, while its
security boundary needs deterministic state and independent verification. GenLayer
provides native web/LLM execution plus the Equivalence Principle: every validator
refetches the same authenticated evidence and independently derives its own verdict
before any state mutation.

**Consensus proves agreement about interpretation; it does not authenticate
evidence.** CommitGate authenticates repository, commits, ancestry, exact paths,
and content digests first; consensus begins only after deterministic admissibility.

## How it works

1. A creator commits immutable repository, base SHA, policy, criteria, review paths,
   parties, and bounded challenge/response windows, then activates the gate.
2. Only the authorized submitter can submit an exact lowercase 40-hex target.
3. Leader and validators independently call constructed GitHub endpoints to
   verify both commits in the declared repository, base→target ancestry, and exact
   base/target content at each immutable path.
4. Exact decoded bytes are SHA-256 hashed into a canonical evidence manifest.
5. Each validator independently asks only the semantic question and strictly parses
   one `APPROVE | REJECT | INCONCLUSIVE` value.
6. APPROVE opens a challenge window. REJECT and INCONCLUSIVE record evidence and
   leave the gate active for another target.
7. A challenge is an exact commit-pinned UTF-8 artifact under
   `.commitgate/challenges/`. It is authenticated participant-authored content—not
   automatically true—and opens a guaranteed response window.
8. Uncontested approval finalizes after the deadline. Challenged approval finalizes
   only after response adjudication; no response can deterministically reject as a
   process consequence.
9. The downstream consumer synchronously rereads the final exact-target authorization
   before acting and optionally consumes it once.

## Architecture

- [`contracts/commitgate_core.py`](contracts/commitgate_core.py) — pure validation,
  canonicalization, GitHub evidence parsing, hashing, state-transition rules, strict
  verdict parsing, and authorization digest construction.
- [`contracts/commitgate.py`](contracts/commitgate.py) — multi-gate storage, caller
  rights, independent leader/validator execution, challenge/response, finalization,
  and public authorization views.
- [`artifacts/commitgate_deployable.py`](artifacts/commitgate_deployable.py) — exact
  generated single-file contract used for lint, validation, tests, and deployment.
- [`integrations/commitgate_execution_gate.py`](integrations/commitgate_execution_gate.py)
  — reusable read gate plus one-shot downstream execution example.
- [`tests`](tests) and [`tools/mutation_test.py`](tools/mutation_test.py) — pure,
  adversarial, Direct Mode, five-validator GLSim RPC, consumer, and mutation tests.

Durable states are `CREATED`, `ACTIVE`, `PROVISIONAL_APPROVE`, `CHALLENGED`,
`FINAL_APPROVED`, and `FINAL_REJECTED`. `ASSESSING` is the explicit execution phase
but is deliberately not written before consensus. Technical failures remain outside
business states.

## Use

Requirements are Python 3.12+, `genvm-linter 0.11.0`, and exact official
`genlayer-testing-suite` commit
`343e3a358f9e235a93b49c60721ce7676585ff07`. The commit pin is required because
the released 0.29.2 Direct loader is v0.2-only; see the runtime baseline for the
fully pinned Bradbury-compatible v0.2.12 runner bundle and compatibility rationale.

```bash
python tools/make_deployable.py
python -m pytest tests -m "not multivalidator"
python tools/mutation_test.py
python -m genvm_linter.cli lint artifacts/commitgate_deployable.py --json
python tools/genvm_v03_validate.py artifacts/commitgate_deployable.py
python tools/genvm_v03_validate.py integrations/commitgate_execution_gate.py
python tools/secret_scan.py
python tools/source_hash.py
```

For the production-shaped local RPC test, start five-validator GLSim and explicitly
enable the test:

```bash
python tools/glsim_v02.py --port 4011 --validators 5 --max-rotations 3 --seed commitgate --no-browser
COMMITGATE_GLSIM=1 python -m pytest tests/integration/test_glsim_multivalidator.py -q
```

Public write flow:

```text
create_gate(...) -> gate_id
activate_gate(gate_id)
submit_target(gate_id, target_sha) -> submission_id
challenge(gate_id, challenge_commit_sha, challenge_path) -> challenge_id  # optional
respond(gate_id, response_target_sha) -> assessment_id                    # if challenged
finalize_uncontested(gate_id)                                             # if not challenged
```

## Live proof

The exact proof record is [`artifacts/final-release-proof.json`](artifacts/final-release-proof.json)
and the transaction protocol is [`docs/bradbury-proof.md`](docs/bradbury-proof.md).
Bradbury is a production-like testnet, not mainnet. No live success is claimed while
the proof artifact says `NOT_RUN` or lacks finalized successful execution plus an
expected state read.

After all release gates and exact-head CI pass, one representative Bradbury lifecycle
will be recorded without blind rebroadcasts or cosmetic reruns. Isolated validator
divergence, failed transactions, and superseded attempts remain in provenance.

## Security/trust model

Repository and commit evidence is authenticated before semantic use. Content hashes
preserve the exact adjudicated evidence identity. Challenge artifacts are authenticated
participant-authored content, not trusted facts. INCONCLUSIVE is not rejection, and
infrastructure/model/consensus failures are not business verdicts. FINAL_APPROVED is
challenge-aware, and the consumer rereads on-chain authorization.

CommitGate constructs only three exact bounded endpoint families--repository metadata,
Git Data commits, and commit-pinned raw files--accepts no URLs, rejects redirects,
verifies bounded ancestry, bounds all inputs/responses, and stores only bounded
manifests and digests. CI evidence is honestly excluded from V1 because stable public
exact-SHA check evidence is not reliable enough without credentials.

See [`docs/security-model.md`](docs/security-model.md) and
[`docs/evidence-model.md`](docs/evidence-model.md).

## Limitations

- Public GitHub availability remains an external dependency; digests do not preserve
  future availability.
- V1 requires 1–4 small UTF-8 review files present at both commits; binary, LFS,
  submodule, added-only, deleted-only, and large-file review is out of scope.
- V1 excludes consensus-critical CI/check-run evidence.
- Semantic decisions depend on independent validator model capability and may remain
  undetermined or INCONCLUSIVE.
- The five-validator local proof uses mocked web/model responses; it proves the RPC,
  consensus, state, and authorization shape, not live GitHub/model behavior.
- No mainnet, privacy, external audit, perfect agreement, or permanent GitHub
  availability claim is made.

## Developer/API detail

Views:

- `is_final_approved(gate_id) -> bool`
- `is_target_authorized(gate_id, target_sha) -> bool`
- `get_gate(gate_id) -> canonical JSON`
- `get_gate_count() -> int`, `get_gate_id(index) -> str`
- `get_submission(submission_id) -> canonical JSON`
- `get_assessment(assessment_id) -> canonical JSON`
- `get_challenge(challenge_id) -> canonical JSON`
- `get_final_authorization(gate_id) -> canonical JSON or empty string`

The final authorization digest binds gate ID, repository owner/name, base SHA, final
target SHA, policy/criteria digest, evidence manifest digest, assessment digest, and
finalization timestamp. Gate security terms never change; changed scope requires a
new gate. Target submissions are unique per gate, and challenge response attempts are
bounded to three while the deterministic transaction-time window remains open.

Runtime decisions and official sources are recorded in
[`docs/runtime-baseline.md`](docs/runtime-baseline.md). Exact evidence fields and all
bounds are in [`docs/evidence-model.md`](docs/evidence-model.md).
