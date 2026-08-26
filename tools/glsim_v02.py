"""Launch GLSim against the exact Bradbury-shaped v0.2.12 runner bundle."""

from pathlib import Path
import sys

import gltest.direct.sdk_loader as sdk_loader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.v02_direct_compat import install


sdk_loader.CACHE_DIR = Path.home() / ".cache" / "genvm-linter"
sdk_loader.setup_sdk_paths(
    ROOT / "artifacts" / "commitgate_deployable.py",
    "v0.2.12",
)
_setup_sdk_paths = sdk_loader.setup_sdk_paths


def _setup_bradbury_sdk(contract_path=None, version=None):
    return _setup_sdk_paths(contract_path, version or "v0.2.12")


sdk_loader.setup_sdk_paths = _setup_bradbury_sdk
install()

from glsim.engine import SimEngine

# Upstream glsim currently asks the Direct Mode loader to patch run_nondet
# before the v0.2 loader has injected gl.message into fd 0. Importing the
# v0.2 SDK at that point consumes empty stdin. deploy_contract applies the
# same patch at the correct point immediately after loading the contract.
SimEngine._ensure_direct_mode_runtime_patches = lambda self: None

from glsim.__main__ import main


if __name__ == "__main__":
    main()
