"""Run targeted, real source mutations and require every one to be killed."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "artifacts" / "mutation-report.json"


@dataclass(frozen=True)
class Mutation:
    name: str
    file: str
    old: str
    new: str
    test: str


MUTATIONS = [
    Mutation(
        "skip_repo_match",
        "contracts/commitgate_core.py",
        'or data.get("html_url") != html_url',
        'or False',
        "tests/test_evidence.py::test_wrong_repository_commit_binding_is_integrity_error",
    ),
    Mutation(
        "skip_lineage_check",
        "contracts/commitgate_core.py",
        'data.get("status") != "ahead"',
        'False',
        "tests/test_evidence.py::test_invalid_or_unrelated_lineage_rejected",
    ),
    Mutation(
        "accept_short_sha",
        "contracts/commitgate_core.py",
        're.compile(r"^[0-9a-f]{40}$")',
        're.compile(r"^[0-9a-f]{1,40}$")',
        "tests/test_core_validation.py::test_sha_must_be_exact_lowercase_40_hex",
    ),
    Mutation(
        "accept_arbitrary_challenge_path",
        "contracts/commitgate_core.py",
        'if challenge and not normalized.startswith(".commitgate/challenges/"):',
        'if False and challenge and not normalized.startswith(".commitgate/challenges/"):',
        "tests/test_core_validation.py::test_challenge_path_prefix_is_mandatory",
    ),
    Mutation(
        "trust_leader_verdict",
        "contracts/commitgate.py",
        'return canonical_json(leader_result.calldata) == canonical_json(independent)',
        'return True',
        "tests/test_contract_invariants.py::test_independent_validator_derives_same_evidence_and_semantics",
    ),
    Mutation(
        "map_evidence_failure_away_from_evidence_error",
        "contracts/commitgate_core.py",
        'raise GateError("EVIDENCE_ERROR", f"GitHub HTTP {status}")',
        'return {"verdict": "REJECT"}',
        "tests/test_evidence.py::test_missing_review_content_is_evidence_failure",
    ),
    Mutation(
        "skip_challenge_deadline",
        "contracts/commitgate.py",
        'if now > gate["challenge_deadline"]:',
        'if False and now > gate["challenge_deadline"]:',
        "tests/test_contract_invariants.py::test_challenge_and_response_access_deadlines_are_deterministic",
    ),
    Mutation(
        "finalize_provisional_early",
        "contracts/commitgate.py",
        'if now <= gate["challenge_deadline"]:',
        'if False and now <= gate["challenge_deadline"]:',
        "tests/test_contract_invariants.py::test_challenge_and_response_access_deadlines_are_deterministic",
    ),
    Mutation(
        "ignore_final_target_match",
        "integrations/commitgate_execution_gate.py",
        'if gate.get("final_target_sha") != target_sha:',
        'if False and gate.get("final_target_sha") != target_sha:',
        "tests/test_contract_invariants.py::test_consumer_rereads_exact_gate_and_authorization_before_action",
    ),
    Mutation(
        "bypass_consumer_authorization_check",
        "integrations/commitgate_execution_gate.py",
        'if not gate_contract.view().is_target_authorized(gate_id, target_sha):',
        'if False and not gate_contract.view().is_target_authorized(gate_id, target_sha):',
        "tests/test_contract_invariants.py::test_consumer_rereads_exact_gate_and_authorization_before_action",
    ),
]


def copy_workspace(destination: Path) -> None:
    ignored = shutil.ignore_patterns(".git", ".pytest_cache", "__pycache__", ".gltest-artifacts", ".venv")
    shutil.copytree(ROOT, destination, dirs_exist_ok=True, ignore=ignored)


def run() -> dict:
    results = []
    with tempfile.TemporaryDirectory(prefix="commitgate-mutations-") as temp:
        base = Path(temp)
        for index, mutation in enumerate(MUTATIONS):
            work = base / f"m{index}"
            copy_workspace(work)
            target = work / mutation.file
            source = target.read_text(encoding="utf-8")
            count = source.count(mutation.old)
            if count != 1:
                results.append({"name": mutation.name, "killed": False, "detail": f"anchor count {count}"})
                continue
            target.write_text(source.replace(mutation.old, mutation.new, 1), encoding="utf-8", newline="\n")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(work) + os.pathsep + env.get("PYTHONPATH", "")
            completed = subprocess.run(
                [sys.executable, "-m", "pytest", mutation.test, "-q"],
                cwd=work,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
            )
            results.append(
                {
                    "name": mutation.name,
                    "killed": completed.returncode != 0,
                    "test": mutation.test,
                    "returncode": completed.returncode,
                }
            )
    killed = sum(1 for result in results if result["killed"])
    return {
        "schema": "commitgate-mutation-report-v1",
        "total": len(results),
        "killed": killed,
        "survived": len(results) - killed,
        "results": results,
    }


def main() -> None:
    report = run()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, sort_keys=True))
    if report["survived"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

