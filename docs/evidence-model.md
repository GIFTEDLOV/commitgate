# Evidence model

CommitGate follows one permanent trust sequence:

party authentication -> immutable gate definition -> repository authentication ->
commit identity validation -> commit lineage validation -> exact commit-pinned
content retrieval -> content integrity -> deterministic evidence admissibility ->
semantic adjudication -> independent validator consensus -> provisional ruling ->
challenge -> guaranteed response -> final authorization -> downstream execution.

**Consensus proves agreement about interpretation; it does not authenticate
evidence.** GitHub evidence is authenticated and reduced deterministically before
the model sees it.

## V1 endpoints

The contract constructs every URL itself from validated gate fields. No public
method accepts an evidence URL. The evidence path is deliberately reduced before
semantic adjudication:

- `GET https://api.github.com/repos/{owner}/{repo}` authenticates the declared
  repository and extracts only the positive integer `id` and exact `full_name`.
- `GET https://api.github.com/repos/{owner}/{repo}/git/commits/{sha}` authenticates
  an exact full SHA in the declared repository. The response `sha`, API `url`,
  GitHub `html_url`, and bounded parent SHA list must match the constructed
  identity. Target ancestry is proven by a deterministic breadth-first traversal
  of those parent SHAs, not by the heavyweight compare endpoint.
- `GET https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}` retrieves
  exact bytes at an exact commit. The raw response must be HTTP 200, contain no
  accepted redirect, remain within the file bound, and decode as strict UTF-8.

All 3xx responses are rejected. The only origins the contract requests are
`https://api.github.com` for repository/commit metadata and
`https://raw.githubusercontent.com` for commit-pinned bytes. Any non-200 response,
malformed JSON, unavailable network, missing content, oversized response, invalid
repository binding, or unavailable ancestry is an evidence or integrity
failure--not REJECT and not INCONCLUSIVE.

## Manifest and content identity

Review paths are normalized and lexicographically ordered at creation. For every
path, both base and target files must exist as bounded UTF-8 text. The manifest
stores `PRESENT` states and SHA-256 of the exact bytes. Its canonical JSON includes
schema, repository ID, repository, base/target SHA, ordered paths, file hashes,
confirmed bounded lineage, and the explicit V1 CI status. The manifest digest is
SHA-256 over UTF-8 canonical JSON (`sort_keys`, no whitespace, no NaN).

Stored digests preserve the exact adjudicated evidence identity. They do not
guarantee that GitHub will preserve or serve those bytes forever.

## Challenges and responses

Challenges accept only a commit SHA and a repository-relative path under
`.commitgate/challenges/`. The target must be an ancestor of the challenge commit
(or the same commit), and the artifact is fetched through the same exact-pinned
raw-byte endpoint and hashed over exact UTF-8 bytes. Challenge commit identity and
ancestry use the same Git Data commit path and traversal bound.

A challenge artifact is authenticated participant-authored content, not an
automatically trusted fact. During response adjudication, every validator refetches
the original target evidence, challenge artifact, and response-target evidence.
The response target must equal or descend from the challenged target and must also
descend from the immutable base.

## CI evidence status

CI is `NOT_USED_V1`. Public GitHub check-run endpoints require authorization in
common configurations and their changing collections/statuses add availability and
stability risk. CommitGate does not fake a CI attestation. A future gate version may
add CI only with an exact target-SHA binding, stable-field reduction, and explicit
unavailability semantics.

## Deterministic bounds

| Input | Bound |
|---|---:|
| Repository owner | 1-39 safe ASCII characters |
| Repository name | 1-100 safe ASCII characters |
| Commit SHA | exactly 40 lowercase hex |
| Review paths | 1-4, sorted, unique |
| Path | 1-180 safe repository-relative characters |
| Policy | 1-4,096 UTF-8 bytes |
| Acceptance criteria | 1-8,192 UTF-8 bytes |
| Each review file/raw response | at most 24,576 bytes |
| Challenge artifact/raw response | at most 16,384 bytes |
| Repository metadata response | at most 16,384 bytes |
| Git Data commit response | at most 32,768 bytes |
| Ancestry commits visited | at most 128 |
| Parents per commit object | at most 8 |
| Model response | at most 256 canonical UTF-8 bytes |
| Challenge/response window | 60-604,800 seconds |
| Response attempts after INCONCLUSIVE | at most 3 |

Paths reject absolute syntax, empty/`.`/`..` segments, backslashes, colons/URLs,
control characters, unsafe characters, duplicates, and traversal. Repository
components reject URL syntax, slash injection, whitespace, controls, and unsafe
characters.
