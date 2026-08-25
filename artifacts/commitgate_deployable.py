# { "Depends": "py-genlayer:9b8kjyda2ycxyq4ea6g4yfpnydxhd52gqba5rb8dw7krkh5mn9p0" }
"""Pure deterministic security core for CommitGate.

This module intentionally has no GenLayer dependency.  The deployable contract is
built from this file plus ``commitgate.py`` so the same validated helpers are used
on-chain and in ordinary unit tests.
"""

import base64
import binascii
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
MAX_HTTP_BODY_BYTES = 196_608
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


def github_commit_url(owner: str, repo: str, sha: str) -> str:
    validate_repo_component(owner, "repo_owner")
    validate_repo_component(repo, "repo_name")
    validate_sha(sha)
    return f"{GITHUB_API_ORIGIN}/repos/{owner}/{repo}/commits/{sha}"


def github_compare_url(owner: str, repo: str, base_sha: str, target_sha: str) -> str:
    validate_repo_component(owner, "repo_owner")
    validate_repo_component(repo, "repo_name")
    validate_sha(base_sha, "base_commit_sha")
    validate_sha(target_sha, "target_commit_sha")
    return f"{GITHUB_API_ORIGIN}/repos/{owner}/{repo}/compare/{base_sha}...{target_sha}"


def github_content_url(owner: str, repo: str, path: str, sha: str) -> str:
    validate_repo_component(owner, "repo_owner")
    validate_repo_component(repo, "repo_name")
    path = validate_review_path(path)
    validate_sha(sha)
    return f"{GITHUB_API_ORIGIN}/repos/{owner}/{repo}/contents/{path}?ref={sha}"


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError("INTEGRITY_ERROR", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_bytes(body: bytes, *, maximum: int = MAX_HTTP_BODY_BYTES) -> Any:
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


def _fetch_json(fetch: Fetch, url: str) -> dict[str, Any]:
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
    value = parse_json_bytes(body)
    if not isinstance(value, dict):
        raise GateError("EVIDENCE_ERROR", "GitHub response must be an object")
    return value


def verify_commit(fetch: Fetch, owner: str, repo: str, sha: str) -> None:
    url = github_commit_url(owner, repo, sha)
    data = _fetch_json(fetch, url)
    html_url = f"https://github.com/{owner}/{repo}/commit/{sha}"
    if data.get("sha") != sha or data.get("url") != url or data.get("html_url") != html_url:
        raise GateError("INTEGRITY_ERROR", "commit identity or repository binding mismatch")


def verify_lineage(fetch: Fetch, owner: str, repo: str, base_sha: str, target_sha: str, *, allow_equal: bool = False) -> None:
    validate_sha(base_sha, "base_commit_sha")
    validate_sha(target_sha, "target_commit_sha")
    if base_sha == target_sha:
        if allow_equal:
            return
        raise GateError("INTEGRITY_ERROR", "base and target commits must differ")
    verify_commit(fetch, owner, repo, base_sha)
    verify_commit(fetch, owner, repo, target_sha)
    url = github_compare_url(owner, repo, base_sha, target_sha)
    data = _fetch_json(fetch, url)
    base_obj = data.get("base_commit")
    merge_obj = data.get("merge_base_commit")
    commits = data.get("commits")
    if (
        data.get("status") != "ahead"
        or data.get("behind_by") != 0
        or not isinstance(data.get("ahead_by"), int)
        or data.get("ahead_by", 0) < 1
        or not isinstance(base_obj, dict)
        or base_obj.get("sha") != base_sha
        or not isinstance(merge_obj, dict)
        or merge_obj.get("sha") != base_sha
        or not isinstance(commits, list)
        or not commits
        or not isinstance(commits[-1], dict)
        or commits[-1].get("sha") != target_sha
    ):
        raise GateError("INTEGRITY_ERROR", "target is not a descendant of the required base")


def fetch_content(fetch: Fetch, owner: str, repo: str, path: str, sha: str, *, maximum: int) -> bytes:
    url = github_content_url(owner, repo, path, sha)
    data = _fetch_json(fetch, url)
    expected_download = f"{GITHUB_RAW_ORIGIN}/{owner}/{repo}/{sha}/{path}"
    if (
        data.get("type") != "file"
        or data.get("path") != path
        or data.get("url") != url
        or data.get("download_url") != expected_download
        or data.get("encoding") != "base64"
        or not isinstance(data.get("content"), str)
        or not isinstance(data.get("size"), int)
    ):
        raise GateError("INTEGRITY_ERROR", "content identity or encoding mismatch")
    if data["size"] < 0 or data["size"] > maximum:
        raise GateError("EVIDENCE_ERROR", "content exceeds deterministic bound")
    encoded = data["content"].replace("\n", "")
    if any(char.isspace() for char in encoded):
        raise GateError("INTEGRITY_ERROR", "unexpected base64 whitespace")
    try:
        content = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error) as exc:
        raise GateError("INTEGRITY_ERROR", "invalid base64 content") from exc
    if len(content) != data["size"] or len(content) > maximum:
        raise GateError("INTEGRITY_ERROR", "content size mismatch")
    return content


def collect_review_evidence(
    fetch: Fetch,
    owner: str,
    repo: str,
    base_sha: str,
    target_sha: str,
    review_paths: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    paths = validate_review_paths(review_paths)
    verify_lineage(fetch, owner, repo, base_sha, target_sha)
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
    verify_lineage(fetch, owner, repo, target_sha, challenge_sha, allow_equal=True)
    content = fetch_content(fetch, owner, repo, path, challenge_sha, maximum=MAX_CHALLENGE_BYTES)
    try:
        text = content.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise GateError("EVIDENCE_ERROR", "challenge artifact must be UTF-8 text") from exc
    evidence = {
        "schema": "commitgate-challenge-v1",
        "repo_owner": owner,
        "repo_name": repo,
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

"""CommitGate: challenge-aware software release authorization.

This source targets the pinned current v0.3 Python runner.  The
release script in ``tools/make_deployable.py`` inlines ``commitgate_core.py`` so
the deployed artifact is a single independently reproducible file.
"""

import genlayer as gl
from genlayer.types import *
import json


class CommitGate(gl.contract.Contract):
    gates: gl.storage.TreeMap[str, str]
    submissions: gl.storage.TreeMap[str, str]
    assessments: gl.storage.TreeMap[str, str]
    challenges: gl.storage.TreeMap[str, str]
    authorizations: gl.storage.TreeMap[str, str]
    submitted_targets: gl.storage.TreeMap[str, str]
    gate_ids: gl.storage.TreeMap[str, str]
    gate_count: u256
    submission_count: u256
    assessment_count: u256
    challenge_count: u256

    def __init__(self):
        self.gate_count = 0
        self.submission_count = 0
        self.assessment_count = 0
        self.challenge_count = 0

    def _now(self) -> int:
        return int(gl.vm.get_timestamp().timestamp())

    def _sender(self) -> str:
        return validate_address(gl.message.sender_address, "caller")

    def _load_json(self, mapping, key: str, kind: str) -> dict:
        if key not in mapping:
            raise gl.vm.UserError(f"INTEGRITY_ERROR:unknown {kind}")
        # TreeMap[str, str] returns a primitive memory string. copy_to_memory is
        # reserved for storage proxy objects; parsing also produces an isolated
        # memory value before nondeterministic execution.
        raw = mapping[key]
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise gl.vm.UserError(f"INTEGRITY_ERROR:corrupt {kind}")
        return value

    def _store_gate(self, gate: dict) -> None:
        self.gates[gate["gate_id"]] = canonical_json(gate)

    def _require_caller(self, expected: str, role: str) -> None:
        if self._sender() != expected:
            raise gl.vm.UserError(f"INTEGRITY_ERROR:caller is not {role}")

    def _derive_assessment(
        self,
        gate: dict,
        submission_id: str,
        target_sha: str,
        fetch,
        challenge_context: dict | None = None,
    ) -> dict:
        manifest, semantic_inputs = collect_review_evidence(
            fetch,
            gate["repo_owner"],
            gate["repo_name"],
            gate["base_commit_sha"],
            target_sha,
            gate["review_paths"],
        )
        challenge_digest = ""
        challenge_text = ""
        prompt_challenge = None
        if challenge_context is not None:
            challenge_evidence, challenge_text = collect_challenge_evidence(
                fetch,
                gate["repo_owner"],
                gate["repo_name"],
                gate["current_target_sha"],
                challenge_context["challenge_commit_sha"],
                challenge_context["challenge_path"],
            )
            challenge_digest = digest_json(challenge_evidence)
            if challenge_digest != challenge_context["challenge_evidence_digest"]:
                raise GateError("INTEGRITY_ERROR", "challenge evidence digest changed")
            challenged_manifest, challenged_inputs = collect_review_evidence(
                fetch,
                gate["repo_owner"],
                gate["repo_name"],
                gate["base_commit_sha"],
                gate["current_target_sha"],
                gate["review_paths"],
            )
            verify_lineage(
                fetch,
                gate["repo_owner"],
                gate["repo_name"],
                gate["current_target_sha"],
                target_sha,
                allow_equal=True,
            )
            prompt_challenge = {
                "challenge_evidence": challenge_evidence,
                "challenged_evidence_manifest": challenged_manifest,
                "challenged_review_content": challenged_inputs,
                "response_target_sha": target_sha,
            }
        prompt = build_semantic_prompt(
            gate["software_policy"],
            gate["acceptance_criteria"],
            manifest,
            semantic_inputs,
            prompt_challenge,
            challenge_text,
        )
        raw = gl.nondet.exec_prompt(prompt)
        verdict = strict_parse_verdict(raw)
        manifest_digest = digest_json(manifest)
        result = {
            "verdict": verdict,
            "target_sha": target_sha,
            "evidence_manifest": manifest,
            "evidence_manifest_digest": manifest_digest,
            "assessment_digest": assessment_digest(
                gate["gate_id"],
                submission_id,
                verdict,
                manifest_digest,
                gate["policy_digest"],
                challenge_digest,
            ),
            "challenge_evidence_digest": challenge_digest,
        }
        return result

    def _consensus_assessment(
        self,
        gate: dict,
        submission_id: str,
        target_sha: str,
        challenge_context: dict | None = None,
    ) -> dict:
        gate_memory = json.loads(canonical_json(gate))
        challenge_memory = (
            None if challenge_context is None else json.loads(canonical_json(challenge_context))
        )

        def leader_fn():
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                return self._derive_assessment(
                    gate_memory, submission_id, target_sha, fetch, challenge_memory
                )
            except GateError as exc:
                raise gl.vm.UserError(str(exc))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                independent = self._derive_assessment(
                    gate_memory, submission_id, target_sha, fetch, challenge_memory
                )
                return canonical_json(leader_result.calldata) == canonical_json(independent)
            except Exception:
                return False

        return gl.vm.run_nondet(leader_fn, validator_fn)

    def _consensus_challenge(
        self, gate: dict, challenge_commit_sha: str, challenge_path: str
    ) -> dict:
        gate_memory = json.loads(canonical_json(gate))

        def derive(fetch):
            evidence, _text = collect_challenge_evidence(
                fetch,
                gate_memory["repo_owner"],
                gate_memory["repo_name"],
                gate_memory["current_target_sha"],
                challenge_commit_sha,
                challenge_path,
            )
            return {
                "challenge_evidence": evidence,
                "challenge_evidence_digest": digest_json(evidence),
            }

        def leader_fn():
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                return derive(fetch)
            except GateError as exc:
                raise gl.vm.UserError(str(exc))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
                    response = gl.nondet.web.get(
                        url,
                        headers={
                            "Accept": "application/vnd.github+json",
                            "X-GitHub-Api-Version": "2022-11-28",
                        },
                    )
                    return int(response.status), dict(response.headers), bytes(response.body)

                return canonical_json(leader_result.calldata) == canonical_json(derive(fetch))
            except Exception:
                return False

        return gl.vm.run_nondet(leader_fn, validator_fn)

    @gl.public.write
    def create_gate(
        self,
        authorized_submitter: Address,
        authorized_challenger: Address,
        repo_owner: str,
        repo_name: str,
        base_commit_sha: str,
        software_policy: str,
        acceptance_criteria: str,
        review_paths: list[str],
        challenge_window_seconds: int,
        response_window_seconds: int,
    ) -> str:
        try:
            terms = validate_gate_terms(
                repo_owner,
                repo_name,
                base_commit_sha,
                software_policy,
                acceptance_criteria,
                review_paths,
                challenge_window_seconds,
                response_window_seconds,
            )
            creator = self._sender()
            submitter = validate_address(authorized_submitter, "authorized_submitter")
            challenger = validate_address(authorized_challenger, "authorized_challenger")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        now = self._now()
        next_count = int(self.gate_count) + 1
        gate_id = digest_json(
            {
                "schema": "commitgate-id-v1",
                "creator": creator,
                "sequence": next_count,
                "created_at": now,
                "terms": terms,
            }
        )
        gate = {
            "gate_id": gate_id,
            "creator_address": creator,
            "authorized_submitter": submitter,
            "authorized_challenger": challenger,
            **terms,
            "required_ci_context": "",
            "created_at": now,
            "status": "CREATED",
            "current_target_sha": "",
            "current_submission_id": "",
            "provisional_at": 0,
            "challenge_deadline": 0,
            "active_challenge_id": "",
            "response_deadline": 0,
            "response_attempts": 0,
            "final_target_sha": "",
            "final_evidence_manifest_digest": "",
            "final_assessment_digest": "",
            "final_authorization_digest": "",
            "finalized_at": 0,
            "policy_digest": digest_json(
                {
                    "software_policy": terms["software_policy"],
                    "acceptance_criteria": terms["acceptance_criteria"],
                }
            ),
        }
        self.gate_count = next_count
        self.gate_ids[str(next_count)] = gate_id
        self._store_gate(gate)
        return gate_id

    @gl.public.write
    def activate_gate(self, gate_id: str) -> None:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["creator_address"], "creator")
        try:
            require_transition(gate["status"], "ACTIVE")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        gate["status"] = "ACTIVE"
        self._store_gate(gate)

    @gl.public.write
    def submit_target(self, gate_id: str, target_sha: str) -> str:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["authorized_submitter"], "authorized_submitter")
        try:
            target_sha = validate_sha(target_sha, "target_commit_sha")
            if target_sha == gate["base_commit_sha"]:
                raise GateError("INTEGRITY_ERROR", "base and target commits must differ")
            if gate["status"] != "ACTIVE":
                raise GateError("INTEGRITY_ERROR", "gate is not ACTIVE")
            duplicate_key = f"{gate_id}:{target_sha}"
            if duplicate_key in self.submitted_targets:
                raise GateError("INTEGRITY_ERROR", "target already submitted for gate")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        next_count = int(self.submission_count) + 1
        submission_id = digest_json(
            {
                "schema": "commitgate-submission-id-v1",
                "gate_id": gate_id,
                "target_sha": target_sha,
                "sequence": next_count,
            }
        )
        result = self._consensus_assessment(gate, submission_id, target_sha)
        now = self._now()
        verdict = result["verdict"]
        submission = {
            "submission_id": submission_id,
            "gate_id": gate_id,
            "target_sha": target_sha,
            "submitted_at": now,
            "verdict": verdict,
            "evidence_manifest_digest": result["evidence_manifest_digest"],
            "evidence_manifest": result["evidence_manifest"],
            "assessment_digest": result["assessment_digest"],
            "assessment_id": result["assessment_digest"],
            "classification": "BUSINESS_REJECT" if verdict == "REJECT" else "SEMANTIC_VERDICT",
        }
        assessment = {
            "assessment_id": result["assessment_digest"],
            "gate_id": gate_id,
            "submission_id": submission_id,
            "target_sha": target_sha,
            "verdict": verdict,
            "evidence_manifest_digest": result["evidence_manifest_digest"],
            "assessment_digest": result["assessment_digest"],
            "challenge_evidence_digest": "",
            "assessed_at": now,
        }
        gate["current_target_sha"] = target_sha
        gate["current_submission_id"] = submission_id
        if verdict == "APPROVE":
            gate["status"] = "PROVISIONAL_APPROVE"
            gate["provisional_at"] = now
            gate["challenge_deadline"] = checked_deadline(
                now, gate["challenge_window_seconds"]
            )
        else:
            gate["status"] = "ACTIVE"
        self.submission_count = next_count
        self.assessment_count = int(self.assessment_count) + 1
        self.submitted_targets[duplicate_key] = "SUBMITTED"
        self.submissions[submission_id] = canonical_json(submission)
        self.assessments[result["assessment_digest"]] = canonical_json(assessment)
        self._store_gate(gate)
        return submission_id

    @gl.public.write
    def challenge(
        self, gate_id: str, challenge_commit_sha: str, challenge_path: str
    ) -> str:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["authorized_challenger"], "authorized_challenger")
        now = self._now()
        try:
            challenge_commit_sha = validate_sha(challenge_commit_sha, "challenge_commit_sha")
            challenge_path = validate_review_path(challenge_path, challenge=True)
            if gate["status"] != "PROVISIONAL_APPROVE":
                raise GateError("INTEGRITY_ERROR", "gate is not PROVISIONAL_APPROVE")
            if now > gate["challenge_deadline"]:
                raise GateError("INTEGRITY_ERROR", "challenge deadline expired")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        result = self._consensus_challenge(gate, challenge_commit_sha, challenge_path)
        next_count = int(self.challenge_count) + 1
        challenge_id = digest_json(
            {
                "schema": "commitgate-challenge-id-v1",
                "gate_id": gate_id,
                "challenge_commit_sha": challenge_commit_sha,
                "challenge_path": challenge_path,
                "sequence": next_count,
            }
        )
        challenge = {
            "challenge_id": challenge_id,
            "gate_id": gate_id,
            "challenged_target_sha": gate["current_target_sha"],
            "challenge_commit_sha": challenge_commit_sha,
            "challenge_path": challenge_path,
            "challenge_evidence_digest": result["challenge_evidence_digest"],
            "challenge_evidence": result["challenge_evidence"],
            "challenged_at": now,
            "response_deadline": checked_deadline(now, gate["response_window_seconds"]),
            "response_target_sha": "",
            "response_evidence_manifest_digest": "",
            "response_assessment_digest": "",
        }
        gate["status"] = "CHALLENGED"
        gate["active_challenge_id"] = challenge_id
        gate["response_deadline"] = challenge["response_deadline"]
        gate["response_attempts"] = 0
        self.challenge_count = next_count
        self.challenges[challenge_id] = canonical_json(challenge)
        self._store_gate(gate)
        return challenge_id

    def _write_final_approved(self, gate: dict, target_sha: str, evidence_digest: str, assessment: str, now: int) -> None:
        gate["status"] = "FINAL_APPROVED"
        gate["final_target_sha"] = target_sha
        gate["final_evidence_manifest_digest"] = evidence_digest
        gate["final_assessment_digest"] = assessment
        gate["finalized_at"] = now
        authorization = final_authorization_record(gate)
        gate["final_authorization_digest"] = authorization["final_authorization_digest"]
        self.authorizations[gate["gate_id"]] = canonical_json(authorization)

    @gl.public.write
    def respond(self, gate_id: str, response_target_sha: str) -> str:
        gate = self._load_json(self.gates, gate_id, "gate")
        self._require_caller(gate["authorized_submitter"], "authorized_submitter")
        now = self._now()
        try:
            response_target_sha = validate_sha(response_target_sha, "response_target_sha")
            if gate["status"] != "CHALLENGED":
                raise GateError("INTEGRITY_ERROR", "gate is not CHALLENGED")
            if now > gate["response_deadline"]:
                raise GateError("INTEGRITY_ERROR", "response deadline expired")
            if gate["response_attempts"] >= MAX_RESPONSE_ATTEMPTS:
                raise GateError("INTEGRITY_ERROR", "response attempt bound reached")
        except GateError as exc:
            raise gl.vm.UserError(str(exc))
        challenge = self._load_json(
            self.challenges, gate["active_challenge_id"], "challenge"
        )
        attempt = gate["response_attempts"] + 1
        response_submission_id = digest_json(
            {
                "schema": "commitgate-response-id-v1",
                "gate_id": gate_id,
                "challenge_id": challenge["challenge_id"],
                "target_sha": response_target_sha,
                "attempt": attempt,
            }
        )
        result = self._consensus_assessment(
            gate, response_submission_id, response_target_sha, challenge
        )
        assessment_id = result["assessment_digest"]
        assessment = {
            "assessment_id": assessment_id,
            "gate_id": gate_id,
            "submission_id": response_submission_id,
            "target_sha": response_target_sha,
            "verdict": result["verdict"],
            "evidence_manifest_digest": result["evidence_manifest_digest"],
            "assessment_digest": assessment_id,
            "challenge_evidence_digest": result["challenge_evidence_digest"],
            "assessed_at": now,
        }
        challenge["response_target_sha"] = response_target_sha
        challenge["response_evidence_manifest_digest"] = result[
            "evidence_manifest_digest"
        ]
        challenge["response_assessment_digest"] = assessment_id
        gate["response_attempts"] = attempt
        if result["verdict"] == "APPROVE":
            self._write_final_approved(
                gate,
                response_target_sha,
                result["evidence_manifest_digest"],
                assessment_id,
                now,
            )
        elif result["verdict"] == "REJECT":
            gate["status"] = "FINAL_REJECTED"
            gate["final_target_sha"] = response_target_sha
            gate["final_evidence_manifest_digest"] = result[
                "evidence_manifest_digest"
            ]
            gate["final_assessment_digest"] = assessment_id
            gate["finalized_at"] = now
        else:
            gate["status"] = "CHALLENGED"
        self.assessment_count = int(self.assessment_count) + 1
        self.assessments[assessment_id] = canonical_json(assessment)
        self.challenges[challenge["challenge_id"]] = canonical_json(challenge)
        self._store_gate(gate)
        return assessment_id

    @gl.public.write
    def finalize_uncontested(self, gate_id: str) -> None:
        gate = self._load_json(self.gates, gate_id, "gate")
        now = self._now()
        if gate["status"] != "PROVISIONAL_APPROVE":
            raise gl.vm.UserError("INTEGRITY_ERROR:gate is not PROVISIONAL_APPROVE")
        if now <= gate["challenge_deadline"]:
            raise gl.vm.UserError("INTEGRITY_ERROR:challenge window remains open")
        submission = self._load_json(
            self.submissions, gate["current_submission_id"], "submission"
        )
        self._write_final_approved(
            gate,
            gate["current_target_sha"],
            submission["evidence_manifest_digest"],
            submission["assessment_digest"],
            now,
        )
        self._store_gate(gate)

    @gl.public.write
    def finalize_expired_response(self, gate_id: str) -> None:
        gate = self._load_json(self.gates, gate_id, "gate")
        now = self._now()
        if gate["status"] != "CHALLENGED":
            raise gl.vm.UserError("INTEGRITY_ERROR:gate is not CHALLENGED")
        if now <= gate["response_deadline"]:
            raise gl.vm.UserError("INTEGRITY_ERROR:response window remains open")
        gate["status"] = "FINAL_REJECTED"
        gate["final_target_sha"] = gate["current_target_sha"]
        gate["final_evidence_manifest_digest"] = ""
        gate["final_assessment_digest"] = digest_json(
            {
                "schema": "commitgate-process-consequence-v1",
                "gate_id": gate_id,
                "challenge_id": gate["active_challenge_id"],
                "consequence": "FINAL_REJECTED_NO_VALID_RESPONSE",
                "deadline": gate["response_deadline"],
            }
        )
        gate["finalized_at"] = now
        self._store_gate(gate)

    @gl.public.view
    def is_final_approved(self, gate_id: str) -> bool:
        if gate_id not in self.gates:
            return False
        gate = self._load_json(self.gates, gate_id, "gate")
        return gate["status"] == "FINAL_APPROVED"

    @gl.public.view
    def is_target_authorized(self, gate_id: str, target_sha: str) -> bool:
        if gate_id not in self.gates:
            return False
        try:
            target_sha = validate_sha(target_sha, "target_sha")
        except GateError:
            return False
        gate = self._load_json(self.gates, gate_id, "gate")
        return gate["status"] == "FINAL_APPROVED" and gate["final_target_sha"] == target_sha

    @gl.public.view
    def get_gate(self, gate_id: str) -> str:
        return canonical_json(self._load_json(self.gates, gate_id, "gate"))

    @gl.public.view
    def get_gate_count(self) -> int:
        return int(self.gate_count)

    @gl.public.view
    def get_gate_id(self, index: int) -> str:
        if index < 1 or index > int(self.gate_count):
            return ""
        return self.gate_ids[str(index)]

    @gl.public.view
    def get_submission(self, submission_id: str) -> str:
        return canonical_json(
            self._load_json(self.submissions, submission_id, "submission")
        )

    @gl.public.view
    def get_assessment(self, assessment_id: str) -> str:
        return canonical_json(
            self._load_json(self.assessments, assessment_id, "assessment")
        )

    @gl.public.view
    def get_challenge(self, challenge_id: str) -> str:
        return canonical_json(
            self._load_json(self.challenges, challenge_id, "challenge")
        )

    @gl.public.view
    def get_final_authorization(self, gate_id: str) -> str:
        if gate_id not in self.authorizations:
            return ""
        return self.authorizations[gate_id]
