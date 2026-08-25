from pathlib import Path
import ast


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (ROOT / "contracts" / "commitgate.py").read_text(encoding="utf-8")
CONSUMER = (ROOT / "integrations" / "commitgate_execution_gate.py").read_text(encoding="utf-8")


def function_node(source, name):
    tree = ast.parse(source)
    return next(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)


def test_independent_validator_derives_same_evidence_and_semantics():
    validator = ast.unparse(function_node(CONTRACT, "validator_fn"))
    assert "_derive_assessment" in validator
    assert "canonical_json(independent)" in validator
    assert "return True" not in validator
    assert "plausible" not in validator and "defensible" not in validator


def test_equivalence_uses_custom_v02_unsafe_pattern():
    assert CONTRACT.count("gl.vm.run_nondet(leader_fn, validator_fn)") == 2
    # JSON parsing and canonical round-tripping produce ordinary memory objects;
    # no TreeMap/storage proxy is captured by either closure.
    assert "gate_memory = json.loads(canonical_json(gate))" in CONTRACT
    assert "self.gates" not in ast.unparse(function_node(CONTRACT, "leader_fn"))


def test_nondeterministic_closures_do_not_write_storage():
    tree = ast.parse(CONTRACT)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in {"leader_fn", "validator_fn", "derive", "fetch"}:
            for inner in ast.walk(node):
                if isinstance(inner, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = inner.targets if isinstance(inner, ast.Assign) else [inner.target]
                    assert not any(
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        for target in targets
                    )


def test_approve_is_provisional_and_uncontested_deadline_is_strict():
    submit = ast.unparse(function_node(CONTRACT, "submit_target"))
    finalize = ast.unparse(function_node(CONTRACT, "finalize_uncontested"))
    assert "verdict == 'APPROVE'" in submit
    assert "gate['status'] = 'PROVISIONAL_APPROVE'" in submit
    assert "gate['status'] = 'FINAL_APPROVED'" not in submit
    assert "now <= gate['challenge_deadline']" in finalize


def test_technical_failures_are_not_mapped_to_business_rejection():
    derive = ast.unparse(function_node(CONTRACT, "_derive_assessment"))
    respond = ast.unparse(function_node(CONTRACT, "respond"))
    assert "except" not in derive
    assert "result['verdict'] == 'REJECT'" in respond
    assert "GateError" not in respond.split("result = self._consensus_assessment", 1)[1].split("if result['verdict']", 1)[0]


def test_challenge_and_response_access_deadlines_are_deterministic():
    challenge = ast.unparse(function_node(CONTRACT, "challenge"))
    respond = ast.unparse(function_node(CONTRACT, "respond"))
    expire = ast.unparse(function_node(CONTRACT, "finalize_expired_response"))
    finalize = ast.unparse(function_node(CONTRACT, "finalize_uncontested"))
    assert "authorized_challenger" in challenge and "challenge_deadline" in challenge
    assert "authorized_submitter" in respond and "response_deadline" in respond
    assert "now <= gate['response_deadline']" in expire
    for text in (challenge, respond, expire, finalize):
        assert "False and" not in text


def test_duplicate_target_and_terminal_duplicate_finalization_are_blocked():
    submit = ast.unparse(function_node(CONTRACT, "submit_target"))
    finalize = ast.unparse(function_node(CONTRACT, "finalize_uncontested"))
    assert "submitted_targets" in submit
    assert "gate['status'] != 'ACTIVE'" in submit
    assert "gate['status'] != 'PROVISIONAL_APPROVE'" in finalize


def test_consumer_rereads_exact_gate_and_authorization_before_action():
    read = ast.unparse(function_node(CONSUMER, "_read_authorization"))
    execute = ast.unparse(function_node(CONSUMER, "execute_once"))
    assert ".view().get_gate(gate_id)" in read
    assert ".view().is_target_authorized(gate_id, target_sha)" in read
    assert "gate.get('status') != 'FINAL_APPROVED'" in read
    assert "gate.get('final_target_sha') != target_sha" in read
    assert "expected_repo_owner" in read and "expected_repo_name" in read
    assert execute.index("_read_authorization") < execute.index("execution_records")
    assert "consumed" in execute
    assert "False and" not in read
