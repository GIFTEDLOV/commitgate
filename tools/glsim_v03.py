"""Launch GLSim with the exact current v0.3 runner cache and Direct adapter."""

from pathlib import Path
import sys

import gltest.direct.sdk_loader as sdk_loader
from gltest.direct import wasi_mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.v03_direct_compat import install


sdk_loader.CACHE_DIR = Path.home() / ".cache" / "genvm-linter"
sdk_loader.setup_sdk_paths(
    ROOT / "artifacts" / "commitgate_deployable.py",
    "genlayerlabs-genvm-manager-v0.6.0-rc2",
)
# The current SDK decides its VM import surface on first import. GLSim creates
# deterministic addresses during engine construction, so install the WASI
# module before importing GLSim and therefore before that first SDK import.
sys.modules["_genlayer_wasi"] = wasi_mock
install()

from glsim.__main__ import main


if __name__ == "__main__":
    main()
