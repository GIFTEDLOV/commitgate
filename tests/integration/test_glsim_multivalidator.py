"""Production-shaped five-validator RPC test; enabled explicitly for GLSim."""

import json
import inspect
import os
import pytest

from gltest import get_contract_factory, get_default_account, get_validator_factory
from gltest.assertions import tx_execution_succeeded
from gltest.contracts.contract import read_contract_wrapper, write_contract_wrapper

from tests.helpers import BASE, OWNER, REPO, TARGET, evidence_routes


def _compatible_fee_kwargs(call, fees, fee_value):
    """Bridge current testing-suite HEAD to genlayer-py 0.18 signatures."""
    parameters = inspect.signature(call).parameters
    result = {}
    if "fees" in parameters:
        result["fees"] = fees
    if "fee_value" in parameters:
        result["fee_value"] = fee_value
    return result


import gltest.contracts.contract as contract_module
import gltest.contracts.contract_factory as factory_module
from genlayer_py.client.genlayer_client import GenLayerClient
from genlayer_py.types.transactions import TransactionStatus as ClientTransactionStatus

contract_module._fee_kwargs = _compatible_fee_kwargs
factory_module._fee_kwargs = _compatible_fee_kwargs

_original_wait_for_receipt = GenLayerClient.wait_for_transaction_receipt


def _compatible_wait_for_receipt(
    self,
    transaction_hash,
    wait_until=None,
    interval=3000,
    retries=10,
    status=ClientTransactionStatus.ACCEPTED,
    **kwargs,
):
    if wait_until is not None:
        status = (
            ClientTransactionStatus.ACCEPTED
            if str(wait_until).lower() == "decided"
            else ClientTransactionStatus.FINALIZED
        )
    return _original_wait_for_receipt(
        self,
        transaction_hash,
        status=status,
        interval=interval,
        retries=retries,
        **kwargs,
    )


GenLayerClient.wait_for_transaction_receipt = _compatible_wait_for_receipt


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


def test_five_validator_rpc_lifecycle():
    first = context("2026-08-25T12:00:00Z")
    account = get_default_account()
    factory = get_contract_factory(contract_file_path="../artifacts/commitgate_deployable.py")
    contract = factory.deploy(account=account, transaction_context=first)
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
