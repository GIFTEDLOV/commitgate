"""Validate a v0.2.12 contract with the exact SDK pinned in its header.

The Bradbury-compatible v0.2.12 standard library exposes schema generation at
``genlayer.py.get_schema``. This narrow validator uses the linter's artifact
resolver and the exact v0.2.12 bundle selected for the contract.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import numpy  # noqa: F401 - required before importing the SDK storage types

from genvm_linter.validate.artifacts import download_artifacts
from genvm_linter.validate.sdk_loader import (
    extract_sdk_paths,
    find_contract_class,
    load_contract_module,
    parse_contract_header,
    setup_wasi_mocks,
)


GENVM_VERSION = "v0.2.12"


def validate(contract_path: Path) -> dict:
    setup_wasi_mocks()
    dependencies = parse_contract_header(contract_path)
    tarball = download_artifacts(GENVM_VERSION)
    sdk_paths, notes = extract_sdk_paths(tarball, dependencies)
    for path in reversed(sdk_paths):
        source = path / "src" if (path / "src").exists() else path
        sys.path.insert(0, str(source))

    from genlayer.py.get_schema import get_schema

    module = load_contract_module(contract_path)
    contract_class = find_contract_class(module)
    if contract_class is None:
        raise RuntimeError("no contract class found")
    schema = get_schema(contract_class)
    methods = schema.get("methods", {})
    return {
        "ok": True,
        "contract": contract_class.__name__,
        "methods": len(methods),
        "view_methods": sum(
            1 for method in methods.values() if method.get("readonly", False)
        ),
        "write_methods": sum(
            1 for method in methods.values() if not method.get("readonly", False)
        ),
        "runner": dependencies.get("py-genlayer", ""),
        "notes": notes,
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tools/genvm_v03_validate.py CONTRACT")
    result = validate(Path(sys.argv[1]).resolve())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
