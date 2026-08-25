"""Narrow Windows/v0.3 adapter for unreleased Direct Mode support."""

from __future__ import annotations

import atexit
import datetime
import os
import tempfile


def install() -> None:
    import gltest.direct.loader as loader

    original_patch_run_nondet = loader._patch_run_nondet_for_direct_mode
    original_load_module = loader._load_module

    def load_module(contract_path):
        # Each Direct test emulates a fresh VM process. The v0.3 SDK keeps its
        # single-contract registration in module state, so reset that process
        # global before reloading the same artifact in the pytest process.
        import genlayer.contract as contract_module

        contract_module.__known_contract__ = None
        return original_load_module(contract_path)

    def patch_runtime_for_direct_mode() -> None:
        original_patch_run_nondet()
        import genlayer.vm as gl_vm
        from gltest.direct import wasi_mock

        def get_timestamp():
            raw = wasi_mock.get_vm()._datetime
            return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))

        gl_vm.get_timestamp = get_timestamp

    def inject_message_to_fd0(vm) -> None:
        calldata = loader.import_calldata()
        Address = loader.import_address()

        def address(value):
            return Address(value) if isinstance(value, bytes) else value

        origin = address(vm.origin)
        message_data = {
            "contract_address": address(vm._contract_address),
            "sender_address": address(vm.sender),
            "origin_address": origin,
            "signer_address": origin,
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
    loader._patch_run_nondet_for_direct_mode = patch_runtime_for_direct_mode
    loader._load_module = load_module
