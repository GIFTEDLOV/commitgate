"""Build the exact single-file deployable artifact without semantic rewrites."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "contracts" / "commitgate_core.py"
CONTRACT = ROOT / "contracts" / "commitgate.py"
OUTPUT = ROOT / "artifacts" / "commitgate_deployable.py"


def build() -> str:
    core = CORE.read_text(encoding="utf-8")
    contract = CONTRACT.read_text(encoding="utf-8")
    header, contract_body = contract.split("\n", 1)
    core = core.replace("from __future__ import annotations\n\n", "")
    contract_body = re.sub(
        r"\nfrom commitgate_core import \(\n.*?\n\)\n",
        "\n",
        contract_body,
        count=1,
        flags=re.DOTALL,
    )
    return header + "\n" + core.rstrip() + "\n\n" + contract_body.lstrip()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    content = build()
    if not content.endswith("\n"):
        content += "\n"
    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    print(OUTPUT.relative_to(ROOT))


if __name__ == "__main__":
    main()

