import copy
import pytest

from commitgate_core import (
    GateError,
    final_authorization_record,
    require_transition,
)
from integrations.consumer_core import AuthorizationDenied, OneShotExecutor, validate_live_authorization
from tests.helpers import BASE, OWNER, REPO, TARGET


def approved_gate(gate_id="a" * 64, target=TARGET, owner=OWNER, repo=REPO):
    return {
        "gate_id": gate_id,
        "status": "FINAL_APPROVED",
        "repo_owner": owner,
        "repo_name": repo,
        "base_commit_sha": BASE,
        "final_target_sha": target,
        "policy_digest": "5" * 64,
        "final_evidence_manifest_digest": "6" * 64,
        "final_assessment_digest": "7" * 64,
        "finalized_at": 1234,
    }


def test_explicit_state_machine_and_no_early_finalization():
    require_transition("CREATED", "ACTIVE")
    require_transition("ACTIVE", "ASSESSING")
    require_transition("ASSESSING", "PROVISIONAL_APPROVE")
    require_transition("PROVISIONAL_APPROVE", "CHALLENGED")
    require_transition("PROVISIONAL_APPROVE", "FINAL_APPROVED")
    require_transition("CHALLENGED", "FINAL_REJECTED")
    for transition in [
        ("ACTIVE", "FINAL_APPROVED"),
        ("ASSESSING", "FINAL_APPROVED"),
        ("FINAL_APPROVED", "ACTIVE"),
        ("FINAL_REJECTED", "FINAL_APPROVED"),
    ]:
        with pytest.raises(GateError):
            require_transition(*transition)


def test_final_authorization_binds_all_security_fields():
    gate = approved_gate()
    record = final_authorization_record(gate)
    assert record["gate_id"] == gate["gate_id"]
    assert record["repo_owner"] == OWNER
    assert record["base_commit_sha"] == BASE
    assert record["final_target_sha"] == TARGET
    assert len(record["final_authorization_digest"]) == 64
    for key in ["repo_owner", "repo_name", "base_commit_sha", "final_target_sha", "policy_digest"]:
        changed = copy.deepcopy(gate)
        changed[key] = "changed"
        assert final_authorization_record(changed)["final_authorization_digest"] != record["final_authorization_digest"]


def test_nonfinal_gate_cannot_create_authorization():
    gate = approved_gate()
    for status in ["ACTIVE", "PROVISIONAL_APPROVE", "CHALLENGED", "FINAL_REJECTED"]:
        gate["status"] = status
        with pytest.raises(GateError):
            final_authorization_record(gate)


def live_readers(gate):
    calls = []

    def read_gate(gate_id):
        calls.append(("gate", gate_id))
        import json
        value = dict(gate)
        value["final_authorization_digest"] = "8" * 64
        return json.dumps(value)

    def read_auth(gate_id, target):
        calls.append(("auth", gate_id, target))
        return gate["status"] == "FINAL_APPROVED" and gate["final_target_sha"] == target

    return read_gate, read_auth, calls


def test_consumer_accepts_exact_live_authorization_and_rereads():
    gate = approved_gate()
    read_gate, read_auth, calls = live_readers(gate)
    result = validate_live_authorization(read_gate, read_auth, gate["gate_id"], TARGET, OWNER, REPO)
    assert result["final_target_sha"] == TARGET
    assert calls == [("gate", gate["gate_id"]), ("auth", gate["gate_id"], TARGET)]


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "PROVISIONAL_APPROVE"),
        ("status", "ACTIVE"),
        ("final_target_sha", "9" * 40),
        ("repo_owner", "evil"),
        ("repo_name", "other"),
        ("gate_id", "b" * 64),
    ],
)
def test_consumer_refuses_nonfinal_wrong_target_repo_and_cross_gate(field, value):
    gate = approved_gate()
    requested_gate = gate["gate_id"]
    gate[field] = value
    read_gate, read_auth, _ = live_readers(gate)
    with pytest.raises(AuthorizationDenied):
        validate_live_authorization(read_gate, read_auth, requested_gate, TARGET, OWNER, REPO)


def test_frontend_or_user_claim_cannot_bypass_live_authorization_view():
    gate = approved_gate()
    read_gate, _read_auth, _ = live_readers(gate)
    with pytest.raises(AuthorizationDenied):
        validate_live_authorization(read_gate, lambda *_: False, gate["gate_id"], TARGET, OWNER, REPO)


def test_one_shot_reuse_is_blocked_and_each_attempt_reads_contract():
    gate = approved_gate()
    read_gate, read_auth, calls = live_readers(gate)
    executor = OneShotExecutor()
    digest = executor.execute(read_gate, read_auth, gate["gate_id"], TARGET, OWNER, REPO, "release")
    assert len(digest) == 64
    with pytest.raises(AuthorizationDenied, match="consumed"):
        executor.execute(read_gate, read_auth, gate["gate_id"], TARGET, OWNER, REPO, "release")
    assert len(calls) == 4

