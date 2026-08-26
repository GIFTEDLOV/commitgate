# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Reference consumer that fails closed on an immediate CommitGate read."""

from genlayer import *
import hashlib
import json
import re

@gl.contract_interface
class CommitGateInterface:
    class View:
        def get_gate(self, gate_id: str) -> str: ...
        def is_target_authorized(self, gate_id: str, target_sha: str) -> bool: ...

    class Write:
        pass


class CommitGateExecutionGate(gl.Contract):
    commitgate_address: Address
    expected_repo_owner: str
    expected_repo_name: str
    one_shot: bool
    consumed: TreeMap[str, str]
    execution_records: TreeMap[str, str]

    def __init__(
        self,
        commitgate_address: Address,
        expected_repo_owner: str,
        expected_repo_name: str,
        one_shot: bool,
    ):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", expected_repo_owner):
            raise gl.vm.UserError("invalid expected repository owner")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", expected_repo_name):
            raise gl.vm.UserError("invalid expected repository name")
        self.commitgate_address = commitgate_address
        self.expected_repo_owner = expected_repo_owner
        self.expected_repo_name = expected_repo_name
        self.one_shot = one_shot

    def _read_authorization(self, gate_id: str, target_sha: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{40}", target_sha):
            raise gl.vm.UserError("authorization denied: invalid target SHA")
        gate_contract = CommitGateInterface(self.commitgate_address)
        raw_gate = gate_contract.view().get_gate(gate_id)
        try:
            gate = json.loads(raw_gate)
        except Exception:
            raise gl.vm.UserError("authorization denied: malformed CommitGate state")
        if not isinstance(gate, dict):
            raise gl.vm.UserError("authorization denied: malformed CommitGate state")
        if gate.get("gate_id") != gate_id:
            raise gl.vm.UserError("authorization denied: cross-gate mismatch")
        if gate.get("status") != "FINAL_APPROVED":
            raise gl.vm.UserError("authorization denied: gate is not FINAL_APPROVED")
        if gate.get("final_target_sha") != target_sha:
            raise gl.vm.UserError("authorization denied: target mismatch")
        if gate.get("repo_owner") != self.expected_repo_owner:
            raise gl.vm.UserError("authorization denied: repository owner mismatch")
        if gate.get("repo_name") != self.expected_repo_name:
            raise gl.vm.UserError("authorization denied: repository name mismatch")
        # A second, explicit authorization view prevents a user-supplied gate JSON
        # or frontend cache from substituting for live contract state.
        if not gate_contract.view().is_target_authorized(gate_id, target_sha):
            raise gl.vm.UserError("authorization denied by CommitGate")
        return gate

    @gl.public.view
    def can_execute(self, gate_id: str, target_sha: str) -> bool:
        try:
            self._read_authorization(gate_id, target_sha)
        except Exception:
            return False
        if self.one_shot and gate_id in self.consumed:
            return False
        return True

    @gl.public.write
    def execute_once(self, gate_id: str, target_sha: str, action_name: str) -> str:
        if not action_name or len(action_name.encode("utf-8")) > 128:
            raise gl.vm.UserError("invalid action name")
        # This read happens in the write transaction immediately before the action.
        gate = self._read_authorization(gate_id, target_sha)
        if self.one_shot and gate_id in self.consumed:
            raise gl.vm.UserError("authorization already consumed")
        record = {
            "schema": "commitgate-consumer-execution-v1",
            "gate_id": gate_id,
            "target_sha": target_sha,
            "repo_owner": self.expected_repo_owner,
            "repo_name": self.expected_repo_name,
            "final_authorization_digest": gate["final_authorization_digest"],
            "action_name": action_name,
        }
        execution_digest = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if self.one_shot:
            self.consumed[gate_id] = "CONSUMED"
        self.execution_records[execution_digest] = json.dumps(
            record, sort_keys=True, separators=(",", ":")
        )
        return execution_digest

    @gl.public.view
    def get_execution(self, execution_digest: str) -> str:
        if execution_digest not in self.execution_records:
            return ""
        return self.execution_records[execution_digest]
