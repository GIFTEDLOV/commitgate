"""Pure reference logic mirroring the on-chain CommitGate consumer checks."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Callable


class AuthorizationDenied(ValueError):
    pass


def validate_live_authorization(
    read_gate: Callable[[str], str],
    read_authorized: Callable[[str, str], bool],
    gate_id: str,
    target_sha: str,
    expected_owner: str,
    expected_repo: str,
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        raise AuthorizationDenied("invalid target SHA")
    try:
        gate = json.loads(read_gate(gate_id))
    except Exception as exc:
        raise AuthorizationDenied("malformed live gate state") from exc
    if not isinstance(gate, dict) or gate.get("gate_id") != gate_id:
        raise AuthorizationDenied("cross-gate mismatch")
    if gate.get("status") != "FINAL_APPROVED":
        raise AuthorizationDenied("gate is not FINAL_APPROVED")
    if gate.get("final_target_sha") != target_sha:
        raise AuthorizationDenied("target mismatch")
    if (gate.get("repo_owner"), gate.get("repo_name")) != (expected_owner, expected_repo):
        raise AuthorizationDenied("repository mismatch")
    if not read_authorized(gate_id, target_sha):
        raise AuthorizationDenied("CommitGate authorization view denied")
    return gate


class OneShotExecutor:
    def __init__(self) -> None:
        self.consumed: set[str] = set()

    def execute(
        self,
        read_gate: Callable[[str], str],
        read_authorized: Callable[[str, str], bool],
        gate_id: str,
        target_sha: str,
        expected_owner: str,
        expected_repo: str,
        action_name: str,
    ) -> str:
        gate = validate_live_authorization(
            read_gate,
            read_authorized,
            gate_id,
            target_sha,
            expected_owner,
            expected_repo,
        )
        if gate_id in self.consumed:
            raise AuthorizationDenied("authorization already consumed")
        record = {
            "schema": "commitgate-consumer-execution-v1",
            "gate_id": gate_id,
            "target_sha": target_sha,
            "repo_owner": expected_owner,
            "repo_name": expected_repo,
            "final_authorization_digest": gate["final_authorization_digest"],
            "action_name": action_name,
        }
        self.consumed.add(gate_id)
        return hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

