"""Validate release-proof shape and cross-artifact consistency."""

from pathlib import Path
import hashlib
import json


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    proof = json.loads((ROOT / "artifacts" / "final-release-proof.json").read_text(encoding="utf-8"))
    mutation = json.loads((ROOT / "artifacts" / "mutation-report.json").read_text(encoding="utf-8"))
    assert proof["schema"] == "commitgate-final-release-proof-v1"
    assert proof["contract"]["network"] == "testnet-bradbury"
    assert proof["contract"]["chain_id"] == 4221
    assert mutation["total"] == 10 and mutation["killed"] == 10 and mutation["survived"] == 0
    actual = hashlib.sha256((ROOT / proof["contract"]["source"]).read_bytes()).hexdigest()
    recorded = proof["contract"]["source_sha256"]
    if recorded:
        assert recorded == actual, f"contract source hash mismatch: {recorded} != {actual}"
    reviewed_source = proof["contract"].get("reviewed_source_sha256", "")
    if reviewed_source:
        reviewed_actual = hashlib.sha256((ROOT / "contracts" / "commitgate.py").read_bytes()).hexdigest()
        assert reviewed_source == reviewed_actual, (
            f"reviewed source hash mismatch: {reviewed_source} != {reviewed_actual}"
        )
    generated = proof["contract"].get("generated_deployable_sha256", "")
    if generated:
        assert generated == actual, f"generated artifact hash mismatch: {generated} != {actual}"
    if proof["release_frozen"]:
        assert proof["provenance_complete"]
        assert proof["bradbury"]["status"] == "FINALIZED_SUCCESS"
        assert proof["ci"]["release_candidate_ci"]["exact_head"] is True
    print("proof artifacts: consistent")


if __name__ == "__main__":
    main()
