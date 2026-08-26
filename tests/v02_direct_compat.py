"""Narrow Windows file-descriptor adapter for released v0.2 Direct Mode."""

from __future__ import annotations

import atexit
import os
import tempfile


def install() -> None:
    import gltest.direct.loader as loader
    original_load_module = loader._load_module

    def load_module(contract_path):
        import genlayer.gl.genvm_contracts as contract_module

        contract_module.__known_contract__ = None
        module = original_load_module(contract_path)

        # Production creates a fresh message mapping for each VM invocation.
        # Released Direct Mode keeps the imported mapping while tests reuse one
        # in-process VM, so expose only its transaction datetime dynamically.
        import genlayer.gl as gl_module
        from gltest.direct import wasi_mock

        class _DynamicMessageRaw(dict):
            def __getitem__(self, key):
                if key == "datetime":
                    return wasi_mock.get_vm()._datetime
                return super().__getitem__(key)

        gl_module.message_raw = _DynamicMessageRaw(gl_module.message_raw)
        return module

    def inject_message_to_fd0(vm) -> None:
        from genlayer.py import calldata
        from genlayer.py.types import Address

        def address(value):
            return Address(value) if isinstance(value, bytes) else value

        message_data = {
            "contract_address": address(vm._contract_address),
            "sender_address": address(vm.sender),
            "origin_address": address(vm.origin),
            "stack": [],
            "value": vm._value,
            "datetime": vm._datetime,
            "is_init": False,
            "chain_id": vm._chain_id,
            "entry_kind": 0,
            "entry_data": b"",
            "entry_stage_data": None,
        }
        encoded = calldata.encode(message_data)
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, encoded)
            os.lseek(fd, 0, os.SEEK_SET)
            vm._original_stdin_fd = os.dup(0)
            os.dup2(fd, 0)
        finally:
            os.close(fd)
            try:
                os.unlink(path)
            except PermissionError:
                def cleanup(pending=path):
                    try:
                        if os.path.exists(pending):
                            os.unlink(pending)
                    except OSError:
                        pass

                atexit.register(cleanup)

    loader._inject_message_to_fd0 = inject_message_to_fd0
    loader._load_module = load_module
