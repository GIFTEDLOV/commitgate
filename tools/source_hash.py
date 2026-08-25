"""Print or verify the deployable CommitGate SHA-256."""

from pathlib import Path
import argparse
import hashlib
import json


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "artifacts" / "commitgate_deployable.py"
PROOF = ROOT / "artifacts" / "final-release-proof.json"


def source_hash() -> str:
    return hashlib.sha256(SOURCE.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    digest = source_hash()
    if args.check:
        proof = json.loads(PROOF.read_text(encoding="utf-8"))
        recorded = proof.get("contract", {}).get("source_sha256", "")
        if recorded and recorded != digest:
            raise SystemExit(f"source hash mismatch: recorded={recorded} actual={digest}")
    print(digest)


if __name__ == "__main__":
    main()

