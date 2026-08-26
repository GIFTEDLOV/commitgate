"""Print or verify the deployable CommitGate SHA-256."""

from pathlib import Path
import argparse
import hashlib
import json
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_SOURCE = ROOT / "contracts" / "commitgate.py"
SOURCE = ROOT / "artifacts" / "commitgate_deployable.py"
PROOF = ROOT / "artifacts" / "final-release-proof.json"


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parity() -> dict[str, str | bool]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.make_deployable import build

    generated = build().encode("utf-8")
    actual = SOURCE.read_bytes()
    if generated != actual:
        raise SystemExit("deployable artifact does not match tools/make_deployable.py output")
    return {
        "contract_source_sha256": file_hash(CONTRACT_SOURCE),
        "deployable_sha256": file_hash(SOURCE),
        "generated_deployable_sha256": hashlib.sha256(generated).hexdigest(),
        "generated_matches_deployable": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = parity()
    if args.check:
        proof = json.loads(PROOF.read_text(encoding="utf-8"))
        contract = proof.get("contract", {})
        checks = {
            "source_sha256": result["deployable_sha256"],
            "reviewed_source_sha256": result["contract_source_sha256"],
            "generated_deployable_sha256": result["generated_deployable_sha256"],
        }
        for field, actual in checks.items():
            recorded = contract.get(field, "")
            if recorded and recorded != actual:
                raise SystemExit(f"{field} mismatch: recorded={recorded} actual={actual}")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
