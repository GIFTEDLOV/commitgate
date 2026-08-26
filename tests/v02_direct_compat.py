"""Narrow Windows file-descriptor adapter for released v0.2 Direct Mode."""

from __future__ import annotations

import atexit
import os
import sys
import tempfile


def install() -> None:
    import gltest.direct.loader as loader
    from gltest.direct.vm import VMContext
    original_load_module = loader._load_module
    original_patch_run_nondet = loader._patch_run_nondet_for_direct_mode
    original_refresh_gl_message = VMContext._refresh_gl_message

    def patch_runtime_for_direct_mode() -> None:
        # The pinned v0.2 Direct harness can leave the SDK's production WASI
        # run_nondet path installed. Reuse its normal Direct patch first, then
        # enforce the same leader/captured-validator behavior when that patch
        # is unavailable or was marked complete too early during SDK loading.
        original_patch_run_nondet()
        import genlayer.gl.vm as gl_vm
        from gltest.direct import wasi_mock
        from genlayer.py.types import Lazy

        def direct_run_nondet(leader_fn, validator_fn, /, **_kwargs):
            vm = wasi_mock.get_vm()
            vm._in_nondet = True
            try:
                result = leader_fn()
            finally:
                vm._in_nondet = False
            vm._captured_validators.append((result, leader_fn, validator_fn))
            return result

        def direct_run_nondet_unsafe(leader_fn, validator_fn, /):
            return direct_run_nondet(leader_fn, validator_fn)

        def lazy_run_nondet(leader_fn, validator_fn, /, **kwargs):
            return Lazy(lambda: direct_run_nondet(leader_fn, validator_fn, **kwargs))

        def lazy_run_nondet_unsafe(leader_fn, validator_fn, /):
            return Lazy(lambda: direct_run_nondet_unsafe(leader_fn, validator_fn))

        direct_run_nondet.lazy = lazy_run_nondet
        direct_run_nondet_unsafe.lazy = lazy_run_nondet_unsafe
        gl_vm.run_nondet = direct_run_nondet
        gl_vm.run_nondet_unsafe = direct_run_nondet_unsafe
        gl_vm._direct_mode_patched = True
        gl_vm._direct_mode_unsafe_patched = True

    def refresh_gl_message(vm):
        # Some released v0.2 Direct builds refresh message_raw but leave the
        # cached gl.message sender unchanged. Keep caller checks aligned with
        # the VM's active sender for assignment and prank alike.
        original_refresh_gl_message(vm)
        gl_module = sys.modules.get("genlayer.gl")
        if gl_module is None or getattr(gl_module, "message", None) is None:
            return

        from genlayer.py.types import Address, u256

        sender = vm.sender
        if isinstance(sender, bytes):
            sender = Address(sender)
        elif hasattr(sender, "as_bytes") and not isinstance(sender, Address):
            sender = Address(sender.as_bytes)

        origin = vm.origin
        if isinstance(origin, bytes):
            origin = Address(origin)
        elif hasattr(origin, "as_bytes") and not isinstance(origin, Address):
            origin = Address(origin.as_bytes)

        gl_module.message = gl_module.MessageType(
            contract_address=gl_module.message.contract_address,
            sender_address=sender,
            origin_address=origin,
            value=u256(vm._value),
            chain_id=u256(vm._chain_id),
        )

    def allocate_contract(contract_cls, vm, *args, **kwargs):
        # The released loader's fallback constructor is reached on CPython
        # 3.12 because it does not recognize the v0.2 contract storage shape.
        # Allocate through the v0.2 descriptor directly so field setters retain
        # the same storage-backed behavior as GenVM.
        from genlayer.py.storage import ROOT_SLOT_ID
        from genlayer.py.storage._internal.generate import (
            ORIGINAL_INIT_ATTR,
            Lit,
            _storage_build,
        )

        descriptor = _storage_build(contract_cls, {})
        assert not isinstance(descriptor, Lit)
        slot = vm._storage.get_store_slot(ROOT_SLOT_ID)
        instance = descriptor.get(slot, 0)
        init = getattr(descriptor.cls, "__init__", contract_cls.__init__)
        if hasattr(init, ORIGINAL_INIT_ATTR):
            init = getattr(init, ORIGINAL_INIT_ATTR)
        init(instance, *args, **kwargs)
        return instance

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

        import genlayer.gl.nondet.web as web_module
        original_web_get = getattr(web_module.get, "_commitgate_v02_original", web_module.get)

        def direct_web_get(url, *, headers=None):
            vm = wasi_mock.get_vm()
            mock = vm._match_web_mock(url, "GET")
            if mock is None:
                return original_web_get(url, headers=headers or {})

            response = mock.get("response", mock)
            body = response.get("body", b"")
            if isinstance(body, str):
                body = body.encode("utf-8")
            response_headers = {
                key: value.encode("utf-8") if isinstance(value, str) else value
                for key, value in response.get("headers", {}).items()
            }
            return web_module.Response(
                status=int(response.get("status", 200)),
                headers=response_headers,
                body=body,
            )

        direct_web_get._commitgate_v02_original = original_web_get
        web_module.get = direct_web_get

        import genlayer.gl.nondet as nondet_module
        original_exec_prompt = getattr(
            nondet_module.exec_prompt,
            "_commitgate_v02_original",
            nondet_module.exec_prompt,
        )

        def direct_exec_prompt(prompt, **config):
            vm = wasi_mock.get_vm()
            mock = vm._match_llm_mock(prompt)
            if mock is None:
                return original_exec_prompt(prompt, **config)
            if isinstance(mock, str):
                import json

                try:
                    return json.loads(mock)
                except (TypeError, ValueError):
                    return mock
            return mock

        direct_exec_prompt._commitgate_v02_original = original_exec_prompt
        nondet_module.exec_prompt = direct_exec_prompt
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
    loader._allocate_contract = allocate_contract
    loader._patch_run_nondet_for_direct_mode = patch_runtime_for_direct_mode
    VMContext._refresh_gl_message = refresh_gl_message
