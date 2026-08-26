import json
import pytest
import re
from pathlib import Path

import gltest.direct.sdk_loader as direct_sdk_loader
from tests.v02_direct_compat import install as install_v02_direct_compat

from commitgate_core import github_git_commit_url, github_raw_url
from tests.helpers import (
    CHALLENGE,
    CHALLENGE_PATH,
    OWNER,
    PATH,
    REPO,
    RESPONSE,
    TARGET,
    commit,
    evidence_routes,
    response,
)


ARTIFACT = "artifacts/commitgate_deployable.py"
SDK_VERSION = "v0.2.12"
BASE = "1" * 40

# Reuse the official v0.2.12 bundle resolved by genvm-linter so Direct Mode
# exercises the Bradbury-shaped runner family accepted by the live RPC.
direct_sdk_loader.CACHE_DIR = Path.home() / ".cache" / "genvm-linter"
install_v02_direct_compat()


def register_evidence_mocks(direct_vm):
    for url, (status, _headers, body) in evidence_routes().items():
        direct_vm.mock_web(re.escape(url) + r"$", {"status": status, "body": body.decode()})


def response_routes():
    routes = evidence_routes()
    routes[github_git_commit_url(OWNER, REPO, CHALLENGE)] = response(
        commit(OWNER, REPO, CHALLENGE, [TARGET])
    )
    challenge_bytes = b"The guard may still allow an untrusted caller."
    routes[github_raw_url(OWNER, REPO, CHALLENGE_PATH, CHALLENGE)] = response(challenge_bytes)
    routes[github_git_commit_url(OWNER, REPO, RESPONSE)] = response(
        commit(OWNER, REPO, RESPONSE, [TARGET])
    )
    response_bytes = b"def allowed(user):\n    return user.is_admin and user.is_active\n"
    routes[github_raw_url(OWNER, REPO, PATH, RESPONSE)] = response(response_bytes)
    return routes


def register_response_mocks(direct_vm):
    for url, (status, _headers, body) in response_routes().items():
        direct_vm.mock_web(re.escape(url) + r"$", {"status": status, "body": body.decode()})


def active_gate(direct_vm, direct_deploy, submitter, challenger):
    direct_vm.sender = submitter
    contract = direct_deploy(ARTIFACT, sdk_version=SDK_VERSION)
    gate_id = contract.create_gate(
        submitter,
        challenger,
        "GIFTEDLOV",
        "commitgate-fixture",
        BASE,
        "Add an authorization check before the protected action.",
        "The target must deny non-admin callers and permit admins.",
        ["src/guard.py"],
        60,
        60,
    )
    contract.activate_gate(gate_id)
    return contract, gate_id


@pytest.mark.direct
def test_direct_create_activate_and_views(direct_vm, direct_deploy, direct_alice, direct_bob):
    direct_vm.warp("2026-08-25T12:00:00Z")
    direct_vm.sender = direct_alice
    contract = direct_deploy(ARTIFACT, sdk_version=SDK_VERSION)
    gate_id = contract.create_gate(
        direct_alice,
        direct_bob,
        "GIFTEDLOV",
        "commitgate-fixture",
        BASE,
        "Add an authorization check before the protected action.",
        "The target must deny non-admin callers and permit admins.",
        ["src/guard.py"],
        60,
        60,
    )
    created = json.loads(contract.get_gate(gate_id))
    assert created["status"] == "CREATED"
    assert created["creator_address"] == "0x" + bytes(direct_alice).hex()
    assert not contract.is_final_approved(gate_id)
    contract.activate_gate(gate_id)
    assert json.loads(contract.get_gate(gate_id))["status"] == "ACTIVE"


@pytest.mark.direct
def test_direct_rejects_wrong_activation_caller_and_bad_sha(direct_vm, direct_deploy, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    contract = direct_deploy(ARTIFACT, sdk_version=SDK_VERSION)
    gate_id = contract.create_gate(
        direct_alice,
        direct_bob,
        "GIFTEDLOV",
        "commitgate-fixture",
        BASE,
        "policy",
        "criteria",
        ["src/guard.py"],
        60,
        60,
    )
    with direct_vm.prank(direct_bob):
        with direct_vm.expect_revert("caller is not creator"):
            contract.activate_gate(gate_id)
    contract.activate_gate(gate_id)
    with direct_vm.expect_revert("exact lowercase 40-hex"):
        contract.submit_target(gate_id, "abc")


@pytest.mark.direct
def test_direct_approve_is_provisional_validator_reruns_and_finalization_is_delayed(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    direct_vm.warp("2026-08-25T12:00:00Z")
    contract, gate_id = active_gate(direct_vm, direct_deploy, direct_alice, direct_bob)
    register_evidence_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE"}')
    submission_id = contract.submit_target(gate_id, TARGET)
    gate = json.loads(contract.get_gate(gate_id))
    assert gate["status"] == "PROVISIONAL_APPROVE"
    assert not contract.is_target_authorized(gate_id, TARGET)
    assert json.loads(contract.get_submission(submission_id))["verdict"] == "APPROVE"
    assert direct_vm.run_validator() is True
    with direct_vm.expect_revert("challenge window remains open"):
        contract.finalize_uncontested(gate_id)
    direct_vm.warp("2026-08-25T12:01:01Z")
    contract.finalize_uncontested(gate_id)
    assert contract.is_final_approved(gate_id)
    assert contract.is_target_authorized(gate_id, TARGET)
    assert not contract.is_target_authorized(gate_id, "9" * 40)
    authorization = json.loads(contract.get_final_authorization(gate_id))
    assert authorization["final_target_sha"] == TARGET
    with direct_vm.expect_revert("not PROVISIONAL_APPROVE"):
        contract.finalize_uncontested(gate_id)


@pytest.mark.direct
def test_direct_validator_disagreement_and_model_failure_do_not_mutate_state(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract, gate_id = active_gate(direct_vm, direct_deploy, direct_alice, direct_bob)
    register_evidence_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE"}')
    contract.submit_target(gate_id, TARGET)
    direct_vm.clear_mocks()
    register_evidence_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"REJECT"}')
    assert direct_vm.run_validator() is False


@pytest.mark.direct
def test_direct_model_failure_does_not_mutate_state(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract2, gate2 = active_gate(direct_vm, direct_deploy, direct_alice, direct_bob)
    register_evidence_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE","extra":true}')
    with direct_vm.expect_revert("MODEL_ERROR"):
        contract2.submit_target(gate2, TARGET)
    assert json.loads(contract2.get_gate(gate2))["status"] == "ACTIVE"


@pytest.mark.direct
def test_direct_challenge_response_final_approval_for_exact_response_target(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    direct_vm.warp("2026-08-25T12:00:00Z")
    contract, gate_id = active_gate(direct_vm, direct_deploy, direct_alice, direct_bob)
    register_response_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE"}')
    contract.submit_target(gate_id, TARGET)
    direct_vm.sender = direct_bob
    challenge_id = contract.challenge(gate_id, CHALLENGE, CHALLENGE_PATH)
    challenged = json.loads(contract.get_gate(gate_id))
    assert challenged["status"] == "CHALLENGED"
    assert json.loads(contract.get_challenge(challenge_id))["challenge_evidence_digest"]
    assert direct_vm.run_validator() is True
    direct_vm.sender = direct_alice
    assessment_id = contract.respond(gate_id, RESPONSE)
    final = json.loads(contract.get_gate(gate_id))
    assert final["status"] == "FINAL_APPROVED"
    assert final["final_target_sha"] == RESPONSE
    assert final["final_assessment_digest"] == assessment_id
    assert contract.is_target_authorized(gate_id, RESPONSE)
    assert not contract.is_target_authorized(gate_id, TARGET)
    assert direct_vm.run_validator() is True


@pytest.mark.direct
def test_direct_wrong_callers_expiry_and_technical_response_failure(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    direct_vm.warp("2026-08-25T12:00:00Z")
    contract, gate_id = active_gate(direct_vm, direct_deploy, direct_alice, direct_bob)
    register_response_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE"}')
    contract.submit_target(gate_id, TARGET)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("authorized_challenger"):
        contract.challenge(gate_id, CHALLENGE, CHALLENGE_PATH)
    direct_vm.sender = direct_bob
    contract.challenge(gate_id, CHALLENGE, CHALLENGE_PATH)
    with direct_vm.expect_revert("authorized_submitter"):
        contract.respond(gate_id, RESPONSE)
    direct_vm.sender = direct_alice
    direct_vm.clear_mocks()
    routes = response_routes()
    routes[github_git_commit_url(OWNER, REPO, RESPONSE)] = response({}, 503)
    for url, (status, _headers, body) in routes.items():
            direct_vm.mock_web(re.escape(url) + r"$", {"status": status, "body": body.decode()})
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE"}')
    with direct_vm.expect_revert("EVIDENCE_ERROR"):
        contract.respond(gate_id, RESPONSE)
    assert json.loads(contract.get_gate(gate_id))["status"] == "CHALLENGED"
    direct_vm.warp("2026-08-25T12:01:01Z")
    contract.finalize_expired_response(gate_id)
    assert json.loads(contract.get_gate(gate_id))["status"] == "FINAL_REJECTED"
    assert not contract.is_final_approved(gate_id)


@pytest.mark.direct
def test_direct_inconclusive_response_is_not_rejection_and_may_retry(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    direct_vm.warp("2026-08-25T12:00:00Z")
    contract, gate_id = active_gate(direct_vm, direct_deploy, direct_alice, direct_bob)
    register_response_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"APPROVE"}')
    contract.submit_target(gate_id, TARGET)
    direct_vm.sender = direct_bob
    contract.challenge(gate_id, CHALLENGE, CHALLENGE_PATH)
    direct_vm.sender = direct_alice
    direct_vm.clear_mocks()
    register_response_mocks(direct_vm)
    direct_vm.mock_llm(r".*", '{"verdict":"INCONCLUSIVE"}')
    contract.respond(gate_id, RESPONSE)
    gate = json.loads(contract.get_gate(gate_id))
    assert gate["status"] == "CHALLENGED"
    assert gate["response_attempts"] == 1
