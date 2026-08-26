"""Production-shaped five-validator RPC test; enabled explicitly for GLSim."""

import json
import inspect
import os
from pathlib import Path
import pytest

from gltest import get_default_account, get_gl_client, get_validator_factory
from gltest.assertions import tx_execution_succeeded
from gltest.contracts.contract_factory import ContractFactory
from gltest.types import TransactionStatus
from gltest.utils import extract_contract_address
from genlayer_py.types import SimConfig
from gltest.contracts.contract import read_contract_wrapper, write_contract_wrapper

from tests.helpers import BASE, OWNER, REPO, TARGET, evidence_routes


pytestmark = [
    pytest.mark.multivalidator,
    pytest.mark.skipif(os.environ.get("COMMITGATE_GLSIM") != "1", reason="requires explicit GLSim"),
]


def context(at: str):
    web = {
        "nondet_web_request": {
            url: {
                "method": "GET",
                "status": status,
                "headers": _headers,
                "body": body.decode(),
            }
            for url, (status, _headers, body) in evidence_routes().items()
        }
    }
    llm = {"nondet_exec_prompt": {"authority_boundary": '{"verdict":"APPROVE"}'}}
    validators = get_validator_factory().batch_create_mock_validators(
        count=5, mock_llm_response=llm, mock_web_response=web
    )
    return {"validators": [validator.to_dict() for validator in validators], "genvm_datetime": at}


def deploy_exact_artifact(factory, account, transaction_context):
    """Deploy exact artifact bytes across old/new gltest client signatures."""
    client = get_gl_client()
    sim_config = SimConfig(**transaction_context)
    deploy_args = {
        "code": factory.contract_code,
        "args": [],
        "account": account,
        "consensus_max_rotations": None,
        "leader_only": False,
        "sim_config": sim_config,
    }
    deploy_signature = inspect.signature(client.deploy_contract)
    deploy_kwargs = {
        key: value
        for key, value in deploy_args.items()
        if key in deploy_signature.parameters
    }
    tx_hash = client.deploy_contract(**deploy_kwargs)

    wait_args = {"transaction_hash": tx_hash, "status": TransactionStatus.ACCEPTED}
    wait_signature = inspect.signature(client.wait_for_transaction_receipt)
    wait_kwargs = {
        key: value for key, value in wait_args.items() if key in wait_signature.parameters
    }
    receipt = client.wait_for_transaction_receipt(**wait_kwargs)
    assert tx_execution_succeeded(receipt), receipt
    address = extract_contract_address(receipt)
    return factory.build_contract(address, account=account)


def test_five_validator_rpc_lifecycle():
    first = context("2026-08-25T12:00:00Z")
    account = get_default_account()
    # Older v0.2 gltest clients only recognize the retired AST base spelling
    # when discovering a file. Build the client factory directly from the
    # exact deployable artifact so this test still exercises that artifact.
    artifact_path = Path("artifacts/commitgate_deployable.py")
    factory = ContractFactory(
        contract_name="CommitGate",
        contract_code=artifact_path.read_text(encoding="utf-8"),
    )
    contract = deploy_exact_artifact(factory, account, first)
    # Invoke exact ABI names through the low-level wrappers so this test remains
    # independent of client-side schema convenience generation.
    create_receipt = write_contract_wrapper(
        contract,
        "create_gate",
        [
            account.address,
            account.address,
            OWNER,
            REPO,
            BASE,
            "Add an authorization check before the protected action.",
            "The target must deny non-admin callers and permit admins.",
            ["src/guard.py"],
            60,
            60,
        ],
    ).transact(transaction_context=first)
    assert tx_execution_succeeded(create_receipt), create_receipt
    assert read_contract_wrapper(contract, "get_gate_count", []).call() == 1
    gate_id = read_contract_wrapper(contract, "get_gate_id", [1]).call()
    activate_receipt = write_contract_wrapper(contract, "activate_gate", [gate_id]).transact(transaction_context=first)
    assert tx_execution_succeeded(activate_receipt)
    submit_receipt = write_contract_wrapper(contract, "submit_target", [gate_id, TARGET]).transact(
        transaction_context=first, consensus_max_rotations=2
    )
    assert tx_execution_succeeded(submit_receipt), submit_receipt
    provisional = json.loads(read_contract_wrapper(contract, "get_gate", [gate_id]).call())
    assert provisional["status"] == "PROVISIONAL_APPROVE"
    assert not read_contract_wrapper(contract, "is_target_authorized", [gate_id, TARGET]).call()
    final_context = context("2026-08-25T12:01:01Z")
    final_receipt = write_contract_wrapper(contract, "finalize_uncontested", [gate_id]).transact(transaction_context=final_context)
    assert tx_execution_succeeded(final_receipt)
    assert read_contract_wrapper(contract, "is_target_authorized", [gate_id, TARGET]).call()
