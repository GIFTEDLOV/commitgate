"""Pure deterministic security core for CommitGate.

This module intentionally has no GenLayer dependency.  The deployable contract is
built from this file plus ``commitgate.py`` so the same validated helpers are used
on-chain and in ordinary unit tests.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable


SCHEMA_VERSION = "commitgate-evidence-v1"
AUTHORIZATION_VERSION = "commitgate-authorization-v1"
GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_RAW_ORIGIN = "https://raw.githubusercontent.com"

MAX_OWNER_LENGTH = 39
MAX_REPO_LENGTH = 100
MAX_POLICY_BYTES = 4096
MAX_CRITERIA_BYTES = 8192
MAX_REVIEW_PATHS = 4
MAX_PATH_LENGTH = 180
MAX_REVIEW_FILE_BYTES = 24_576
MAX_CHALLENGE_BYTES = 16_384
MAX_REPOSITORY_METADATA_BYTES = 16_384
MAX_COMMIT_OBJECT_BYTES = 32_768
MAX_ANCESTRY_COMMITS = 128
MAX_COMMIT_PARENTS = 8
MAX_MODEL_RESPONSE_BYTES = 256
MIN_CHALLENGE_WINDOW = 60
MAX_CHALLENGE_WINDOW = 604_800
MIN_RESPONSE_WINDOW = 60
MAX_RESPONSE_WINDOW = 604_800
MAX_RESPONSE_ATTEMPTS = 3

VERDICTS = ("APPROVE", "REJECT", "INCONCLUSIVE")
STATES = (
    "CREATED",
    "ACTIVE",
    "ASSESSING",
    "PROVISIONAL_APPROVE",
    "CHALLENGED",
    "FINAL_APPROVED",
    "FINAL_REJECTED",
)
ERROR_CLASSES = (
    "EVIDENCE_ERROR",
    "INTEGRITY_ERROR",
    "MODEL_ERROR",
    "CONSENSUS_ERROR",
    "BUSINESS_REJECT",
)

_REPO_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class GateError(ValueError):
    """A deterministic, explicitly classified CommitGate failure."""

    def __init__(self, code: str, message: str):
        if code not in ERROR_CLASSES:
            raise ValueError("unknown CommitGate error class")
        self.code = code
        super().__init__(f"{code}:{message}")


def canonical_json(value: Any) -> str:
    """RFC-8259 JSON with deterministic ordering and no insignificant bytes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_hex(canonical_json(value).encode("utf-8"))


def _require_plain_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise GateError("INTEGRITY_ERROR", f"{field} must be text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise GateError("INTEGRITY_ERROR", f"{field} is not valid UTF-8") from exc
    if not encoded or not value.strip():
        raise GateError("INTEGRITY_ERROR", f"{field} must be nonempty")
    if len(encoded) > maximum:
        raise GateError("INTEGRITY_ERROR", f"{field} exceeds {maximum} bytes")
    if _CONTROL_RE.search(value):
        raise GateError("INTEGRITY_ERROR", f"{field} contains control characters")
    return value


def validate_repo_component(value: Any, field: str) -> str:
    maximum = MAX_OWNER_LENGTH if field == "repo_owner" else MAX_REPO_LENGTH
    value = _require_plain_text(value, field, maximum)
    if not _REPO_COMPONENT_RE.fullmatch(value):
        raise GateError("INTEGRITY_ERROR", f"{field} contains unsafe characters")
    if value in (".", "..") or "/" in value or "\\" in value or ":" in value:
        raise GateError("INTEGRITY_ERROR", f"{field} is not a repository component")
    return value


def validate_sha(value: Any, field: str = "commit_sha") -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise GateError("INTEGRITY_ERROR", f"{field} must be exact lowercase 40-hex")
    return value


def validate_digest(value: Any, field: str = "digest") -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise GateError("INTEGRITY_ERROR", f"{field} must be exact lowercase 64-hex")
    return value


def validate_address(value: Any, field: str) -> str:
    if isinstance(value, (bytes, bytearray)) and len(value) == 20:
        text = "0x" + bytes(value).hex()
    else:
        text = str(value)
    if not _ADDRESS_RE.fullmatch(text):
        raise GateError("INTEGRITY_ERROR", f"{field} must be an EVM address")
    return text.lower()


def validate_review_path(value: Any, *, challenge: bool = False) -> str:
    value = _require_plain_text(value, "path", MAX_PATH_LENGTH)
    if value.startswith(("/", "\\")) or "\\" in value:
        raise GateError("INTEGRITY_ERROR", "path must be repository-relative POSIX syntax")
    if "://" in value or ":" in value or not _PATH_RE.fullmatch(value):
        raise GateError("INTEGRITY_ERROR", "path contains URL or unsafe characters")
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise GateError("INTEGRITY_ERROR", "path contains empty or traversal segments")
    normalized = "/".join(segments)
    if challenge and not normalized.startswith(".commitgate/challenges/"):
        raise GateError("INTEGRITY_ERROR", "challenge path is outside .commitgate/challenges/")
    return normalized


def validate_review_paths(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple)):
        raise GateError("INTEGRITY_ERROR", "review_paths must be a sequence")
    if not 1 <= len(values) <= MAX_REVIEW_PATHS:
        raise GateError("INTEGRITY_ERROR", f"review_paths count must be 1..{MAX_REVIEW_PATHS}")
    normalized = [validate_review_path(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise GateError("INTEGRITY_ERROR", "duplicate review path")
    return sorted(normalized)


def validate_gate_terms(
    repo_owner: Any,
    repo_name: Any,
    base_commit_sha: Any,
    software_policy: Any,
    acceptance_criteria: Any,
    review_paths: Any,
    challenge_window_seconds: Any,
    response_window_seconds: Any,
) -> dict[str, Any]:
    if not isinstance(challenge_window_seconds, int) or isinstance(challenge_window_seconds, bool):
        raise GateError("INTEGRITY_ERROR", "challenge window must be an integer")
    if not isinstance(response_window_seconds, int) or isinstance(response_window_seconds, bool):
        raise GateError("INTEGRITY_ERROR", "response window must be an integer")
    if not MIN_CHALLENGE_WINDOW <= challenge_window_seconds <= MAX_CHALLENGE_WINDOW:
        raise GateError("INTEGRITY_ERROR", "challenge window is outside deterministic bounds")
    if not MIN_RESPONSE_WINDOW <= response_window_seconds <= MAX_RESPONSE_WINDOW:
        raise GateError("INTEGRITY_ERROR", "response window is outside deterministic bounds")
    return {
        "repo_owner": validate_repo_component(repo_owner, "repo_owner"),
        "repo_name": validate_repo_component(repo_name, "repo_name"),
        "base_commit_sha": validate_sha(base_commit_sha, "base_commit_sha"),
        "software_policy": _require_plain_text(software_policy, "software_policy", MAX_POLICY_BYTES),
        "acceptance_criteria": _require_plain_text(
            acceptance_criteria, "acceptance_criteria", MAX_CRITERIA_BYTES
        ),
        "review_paths": validate_review_paths(review_paths),
        "challenge_window_seconds": challenge_window_seconds,
        "response_window_seconds": response_window_seconds,
    }


def checked_deadline(now: int, window: int) -> int:
    if not isinstance(now, int) or now < 0 or not isinstance(window, int) or window < 0:
        raise GateError("INTEGRITY_ERROR", "invalid deadline operands")
    deadline = now + window
    if deadline > 9_223_372_036_854_775_807:
        raise GateError("INTEGRITY_ERROR", "deadline overflow")
    return deadline


_TRANSITIONS = {
    "CREATED": {"ACTIVE"},
    "ACTIVE": {"ASSESSING"},
    "ASSESSING": {"ACTIVE", "PROVISIONAL_APPROVE"},
    "PROVISIONAL_APPROVE": {"CHALLENGED", "FINAL_APPROVED"},
    "CHALLENGED": {"CHALLENGED", "FINAL_APPROVED", "FINAL_REJECTED"},
    "FINAL_APPROVED": set(),
    "FINAL_REJECTED": set(),
}


def require_transition(current: str, target: str) -> None:
    if current not in _TRANSITIONS or target not in _TRANSITIONS[current]:
        raise GateError("INTEGRITY_ERROR", f"invalid state transition {current}->{target}")


def github_repository_url(owner: str, repo: str) -> str:
    validate_repo_component(owner, "repo_owner")
    validate_repo_component(repo, "repo_name")
    return f"{GITHUB_API_ORIGIN}/repos/{owner}/{repo}"


def github_git_commit_url(owner: str, repo: str, sha: str) -> str:
    validate_repo_component(owner, "repo_owner")
    validate_repo_component(repo, "repo_name")
    validate_sha(sha)
    return f"{GITHUB_API_ORIGIN}/repos/{owner}/{repo}/git/commits/{sha}"


def github_raw_url(owner: str, repo: str, path: str, sha: str) -> str:
    validate_repo_component(owner, "repo_owner")
    validate_repo_component(repo, "repo_name")
    path = validate_review_path(path)
    validate_sha(sha)
    return f"{GITHUB_RAW_ORIGIN}/{owner}/{repo}/{sha}/{path}"


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError("INTEGRITY_ERROR", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_bytes(body: bytes, *, maximum: int) -> Any:
    if not isinstance(body, bytes):
        raise GateError("EVIDENCE_ERROR", "HTTP body is not bytes")
    if len(body) > maximum:
        raise GateError("EVIDENCE_ERROR", "HTTP response exceeds bound")
    try:
        text = body.decode("utf-8", "strict")
        return json.loads(text, object_pairs_hook=_pairs_no_duplicates)
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GateError("EVIDENCE_ERROR", "malformed GitHub JSON") from exc


Fetch = Callable[[str], tuple[int, dict[str, str], bytes]]


def _fetch_body(fetch: Fetch, url: str, *, maximum: int) -> bytes:
    try:
        status, _headers, body = fetch(url)
    except GateError:
        raise
    except Exception as exc:
        # Preserve only the bounded exception class for technical diagnosis;
        # never persist or surface an unbounded provider message/body.
        raise GateError(
            "EVIDENCE_ERROR", f"GitHub request failed:{type(exc).__name__}"
        ) from exc
    if not isinstance(status, int):
        raise GateError("EVIDENCE_ERROR", "HTTP status is malformed")
    if 300 <= status < 400:
        raise GateError("INTEGRITY_ERROR", "redirects are not admissible")
    if status != 200:
        raise GateError("EVIDENCE_ERROR", f"GitHub HTTP {status}")
    if not isinstance(body, bytes):
        raise GateError("EVIDENCE_ERROR", "HTTP body is not bytes")
    if len(body) > maximum:
        raise GateError("EVIDENCE_ERROR", "HTTP response exceeds bound")
    return body


def _fetch_json(fetch: Fetch, url: str, *, maximum: int) -> dict[str, Any]:
    body = _fetch_body(fetch, url, maximum=maximum)
    value = parse_json_bytes(body, maximum=maximum)
    if not isinstance(value, dict):
        raise GateError("EVIDENCE_ERROR", "GitHub response must be an object")
    return value


def verify_repository(fetch: Fetch, owner: str, repo: str) -> int:
    url = github_repository_url(owner, repo)
    data = _fetch_json(fetch, url, maximum=MAX_REPOSITORY_METADATA_BYTES)
    repository_id = data.get("id")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id <= 0
        or data.get("full_name") != f"{owner}/{repo}"
    ):
        raise GateError("INTEGRITY_ERROR", "repository identity mismatch")
    return repository_id


def verify_commit(fetch: Fetch, owner: str, repo: str, sha: str) -> dict[str, Any]:
    url = github_git_commit_url(owner, repo, sha)
    data = _fetch_json(fetch, url, maximum=MAX_COMMIT_OBJECT_BYTES)
    html_url = f"https://github.com/{owner}/{repo}/commit/{sha}"
    parents = data.get("parents")
    if (
        data.get("sha") != sha
        or data.get("url") != url
        or data.get("html_url") != html_url
        or not isinstance(parents, list)
        or len(parents) > MAX_COMMIT_PARENTS
    ):
        raise GateError("INTEGRITY_ERROR", "commit identity or repository binding mismatch")
    for parent in parents:
        if not isinstance(parent, dict):
            raise GateError("INTEGRITY_ERROR", "commit parent shape mismatch")
        validate_sha(parent.get("sha"), "parent_commit_sha")
    return data


def verify_lineage(
    fetch: Fetch,
    owner: str,
    repo: str,
    base_sha: str,
    target_sha: str,
    *,
    allow_equal: bool = False,
) -> int:
    validate_sha(base_sha, "base_commit_sha")
    validate_sha(target_sha, "target_commit_sha")
    repository_id = verify_repository(fetch, owner, repo)
    if base_sha == target_sha:
        if not allow_equal:
            raise GateError("INTEGRITY_ERROR", "base and target commits must differ")
        verify_commit(fetch, owner, repo, target_sha)
        return repository_id
    queue = [target_sha]
    queued = {target_sha}
    visited: set[str] = set()
    while queue:
        if len(visited) >= MAX_ANCESTRY_COMMITS:
            raise GateError("EVIDENCE_ERROR", "lineage unavailable within traversal bound")
        current = queue.pop(0)
        queued.discard(current)
        if current in visited:
            continue
        commit_data = verify_commit(fetch, owner, repo, current)
        visited.add(current)
        if current == base_sha:
            return repository_id
        for parent in commit_data["parents"]:
            parent_sha = parent["sha"]
            if parent_sha not in visited and parent_sha not in queued:
                if len(queue) >= MAX_ANCESTRY_COMMITS:
                    raise GateError("EVIDENCE_ERROR", "lineage unavailable within traversal bound")
                queue.append(parent_sha)
                queued.add(parent_sha)
    raise GateError("INTEGRITY_ERROR", "target is not a descendant of the required base")


def fetch_content(fetch: Fetch, owner: str, repo: str, path: str, sha: str, *, maximum: int) -> bytes:
    url = github_raw_url(owner, repo, path, sha)
    return _fetch_body(fetch, url, maximum=maximum)


def collect_review_evidence(
    fetch: Fetch,
    owner: str,
    repo: str,
    base_sha: str,
    target_sha: str,
    review_paths: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    paths = validate_review_paths(review_paths)
    repository_id = verify_lineage(fetch, owner, repo, base_sha, target_sha)
    entries: list[dict[str, Any]] = []
    semantic_inputs: list[dict[str, Any]] = []
    for path in paths:
        base_content = fetch_content(
            fetch, owner, repo, path, base_sha, maximum=MAX_REVIEW_FILE_BYTES
        )
        target_content = fetch_content(
            fetch, owner, repo, path, target_sha, maximum=MAX_REVIEW_FILE_BYTES
        )
        try:
            base_text = base_content.decode("utf-8", "strict")
            target_text = target_content.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise GateError("EVIDENCE_ERROR", "review content must be bounded UTF-8 text") from exc
        entries.append(
            {
                "path": path,
                "base_presence": "PRESENT",
                "target_presence": "PRESENT",
                "base_content_sha256": sha256_hex(base_content),
                "target_content_sha256": sha256_hex(target_content),
            }
        )
        semantic_inputs.append({"path": path, "base": base_text, "target": target_text})
    manifest = {
        "schema": SCHEMA_VERSION,
        "repo_owner": owner,
        "repo_name": repo,
        "github_repository_id": repository_id,
        "base_commit_sha": base_sha,
        "target_commit_sha": target_sha,
        "review_paths": paths,
        "files": entries,
        "lineage_verified": True,
        "ci": "NOT_USED_V1",
    }
    return manifest, semantic_inputs


def collect_challenge_evidence(
    fetch: Fetch,
    owner: str,
    repo: str,
    target_sha: str,
    challenge_sha: str,
    challenge_path: str,
) -> tuple[dict[str, Any], str]:
    path = validate_review_path(challenge_path, challenge=True)
    repository_id = verify_lineage(
        fetch, owner, repo, target_sha, challenge_sha, allow_equal=True
    )
    content = fetch_content(fetch, owner, repo, path, challenge_sha, maximum=MAX_CHALLENGE_BYTES)
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise GateError("EVIDENCE_ERROR", "challenge artifact must be UTF-8 text") from exc
    evidence = {
        "schema": "commitgate-challenge-v1",
        "repo_owner": owner,
        "repo_name": repo,
        "github_repository_id": repository_id,
        "challenged_target_sha": target_sha,
        "challenge_commit_sha": challenge_sha,
        "challenge_path": path,
        "challenge_content_sha256": sha256_hex(content),
    }
    return evidence, text


def strict_parse_verdict(raw: Any) -> str:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise GateError("MODEL_ERROR", "model response is not UTF-8") from exc
        if len(encoded) > MAX_MODEL_RESPONSE_BYTES:
            raise GateError("MODEL_ERROR", "model response exceeds bound")
        try:
            value = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
        except GateError as exc:
            raise GateError("MODEL_ERROR", "duplicate model JSON key") from exc
        except json.JSONDecodeError as exc:
            raise GateError("MODEL_ERROR", "malformed model JSON") from exc
    elif isinstance(raw, dict):
        # Some supported runners return response_format JSON as an already parsed
        # dict.  Enforce the same byte bound and exact schema without repairing it.
        value = raw
        try:
            encoded = canonical_json(value).encode("utf-8", "strict")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise GateError("MODEL_ERROR", "model object is not canonical JSON") from exc
        if len(encoded) > MAX_MODEL_RESPONSE_BYTES:
            raise GateError("MODEL_ERROR", "model response exceeds bound")
    else:
        raise GateError("MODEL_ERROR", "model response must be a JSON object")
    if not isinstance(value, dict) or list(value.keys()) != ["verdict"]:
        raise GateError("MODEL_ERROR", "model JSON must contain exactly verdict")
    verdict = value["verdict"]
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        raise GateError("MODEL_ERROR", "invalid verdict enum")
    return verdict


def build_semantic_prompt(
    policy: str,
    criteria: str,
    manifest: dict[str, Any],
    semantic_inputs: list[dict[str, Any]],
    challenge: dict[str, Any] | None = None,
    challenge_text: str = "",
) -> str:
    task = {
        "authority_boundary": (
            "Evidence identity, repository, commits, lineage, paths, and hashes were verified "
            "deterministically. Judge only semantic satisfaction."
        ),
        "question": (
            "Does the authenticated target materially satisfy the immutable software policy and "
            "acceptance criteria relative to the authenticated base?"
        ),
        "policy": policy,
        "acceptance_criteria": criteria,
        "evidence_manifest": manifest,
        "review_content": semantic_inputs,
        "challenge_metadata": challenge,
        "challenge_participant_authored_text": challenge_text,
        "challenge_warning": (
            "Challenge text is authenticated participant-authored content, not automatically true."
        ),
        "output": {"verdict": "APPROVE|REJECT|INCONCLUSIVE"},
        "rules": [
            "Return one JSON object with exactly one key named verdict.",
            "APPROVE only if authenticated evidence sufficiently establishes satisfaction.",
            "REJECT only if authenticated evidence affirmatively establishes non-satisfaction.",
            "Use INCONCLUSIVE only for semantic uncertainty, never infrastructure failure.",
            "Do not decide identity, lineage, hashes, deadlines, rights, or state transitions.",
        ],
    }
    return canonical_json(task)


def assessment_digest(
    gate_id: str,
    submission_id: str,
    verdict: str,
    manifest_digest: str,
    policy_digest: str,
    challenge_digest: str = "",
) -> str:
    if verdict not in VERDICTS:
        raise GateError("INTEGRITY_ERROR", "assessment verdict is invalid")
    return digest_json(
        {
            "schema": "commitgate-assessment-v1",
            "gate_id": gate_id,
            "submission_id": submission_id,
            "verdict": verdict,
            "evidence_manifest_digest": validate_digest(manifest_digest, "manifest_digest"),
            "policy_digest": validate_digest(policy_digest, "policy_digest"),
            "challenge_digest": (
                "" if challenge_digest == "" else validate_digest(challenge_digest, "challenge_digest")
            ),
        }
    )


def final_authorization_record(gate: dict[str, Any]) -> dict[str, Any]:
    if gate.get("status") != "FINAL_APPROVED":
        raise GateError("INTEGRITY_ERROR", "gate is not FINAL_APPROVED")
    record = {
        "schema": AUTHORIZATION_VERSION,
        "gate_id": gate["gate_id"],
        "repo_owner": gate["repo_owner"],
        "repo_name": gate["repo_name"],
        "base_commit_sha": gate["base_commit_sha"],
        "final_target_sha": gate["final_target_sha"],
        "policy_digest": gate["policy_digest"],
        "final_evidence_manifest_digest": gate["final_evidence_manifest_digest"],
        "final_assessment_digest": gate["final_assessment_digest"],
        "finalized_at": gate["finalized_at"],
    }
    record["final_authorization_digest"] = digest_json(record)
    return record
