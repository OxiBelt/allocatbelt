#!/usr/bin/env python3
"""Focused lifecycle regressions for the private SourceA C3a H context association."""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE_PATH = Path(__file__).with_name("application-campaign-chronology.py")


def _load_sourcea_module():
    name = f"sourcea_c3a_lifecycle_{os.getpid()}"
    previous = sys.modules.get(name)
    spec = importlib.util.spec_from_file_location(name, SOURCE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SOURCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous is None:
            if sys.modules.get(name) is module:
                sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return name, previous, module


class _CloseResource:
    def __init__(self) -> None:
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


class _InheritedLock:
    def __enter__(self):
        raise AssertionError("fork child tried to acquire an inherited mutex")

    def __exit__(self, *_args):
        raise AssertionError("fork child tried to release an inherited mutex")


class SourceAOwnedHContextLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module_name, cls.previous_module, cls.module = _load_sourcea_module()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.previous_module is None:
            if sys.modules.get(cls.module_name) is cls.module:
                sys.modules.pop(cls.module_name, None)
        else:
            sys.modules[cls.module_name] = cls.previous_module

    def _scope(self):
        module = self.module
        return module._Source5OwnedOperationScope(
            module._SOURCE5_OWNED_OPERATION_SCOPE_SECRET,
        )

    def test_registry_rejects_other_scope_foreign_thread_and_fork_copy(self) -> None:
        module = self.module
        scope = self._scope()
        lock = object()
        session = SimpleNamespace(lock=lock, operation_scope=scope)
        entry = {
            "scope": scope,
            "creator_pid": os.getpid(),
            "sourcea_module": module,
            "session": session,
            "lock": lock,
            "thread_id": threading.get_ident() + 1,
        }
        module._SOURCE5_OWNED_OPERATION_SCOPES[scope] = entry
        try:
            with self.assertRaisesRegex(
                    module.ChronologyError, "another scope, session, lock, process or thread"):
                module._source5_owned_h_context_registry_entry(
                    session, scope, object(),
                )

            entry["thread_id"] = threading.get_ident()
            session.operation_scope = self._scope()
            with self.assertRaisesRegex(
                    module.ChronologyError, "another scope, session, lock, process or thread"):
                module._source5_owned_h_context_registry_entry(
                    session, scope, object(),
                )

            session.operation_scope = scope
            scope._creator_pid = os.getpid() - 1
            with self.assertRaisesRegex(
                    module.ChronologyError, "inherited SourceA operation scope"):
                module._source5_owned_h_context_registry_entry(
                    session, scope, object(),
                )
        finally:
            module._SOURCE5_OWNED_OPERATION_SCOPES.pop(scope, None)

    def test_scope_expiry_detaches_before_unique_independent_cleanup(self) -> None:
        module = self.module
        scope = self._scope()
        context = object()
        first_module = types.ModuleType("sourcea_c3a_first_owned_context_module")
        second_module = types.ModuleType("sourcea_c3a_second_owned_context_module")
        first_resource = _CloseResource()
        second_resource = _CloseResource()
        binding = {
            "context": context,
            "owned_modules": (first_module, first_module, second_module),
            "owned_resources": (first_resource, first_resource, second_resource),
        }
        entry = {
            "scope": scope,
            "creator_pid": os.getpid(),
            "state": module._Source5OwnedScopeState.REPLAY_COMPLETE,
            "current_h_binding": binding,
            "current_h_context_construction_marker": object(),
            "current_h_context_pending": object(),
            "h_binding": object(),
            "old_owner_binding": object(),
            "plan_binding": object(),
        }
        session = SimpleNamespace(operation_scope=scope)
        context_id = id(context)
        with module._SOURCE5_OWNED_OPERATION_SCOPE_LOCK:
            module._SOURCE5_OWNED_OPERATION_SCOPES[scope] = entry
        with module._SOURCE5_OWNED_H_CONTEXT_LOCK:
            module._SOURCE5_OWNED_H_CONTEXTS[context_id] = binding

        first_error = RuntimeError("first module close failed")
        attempted = []
        original_runner = module._source5_run_cleanups_independently
        original_close = module._close_module

        def close_module(candidate):
            attempted.append(candidate)
            if candidate is first_module:
                raise first_error
            original_close(candidate)

        def observe_detached(actions):
            self.assertNotIn(context_id, module._SOURCE5_OWNED_H_CONTEXTS)
            self.assertNotIn(scope, module._SOURCE5_OWNED_OPERATION_SCOPES)
            return original_runner(actions)

        try:
            with patch.object(module, "_close_module", side_effect=close_module), \
                    patch.object(module, "_source5_run_cleanups_independently",
                                 side_effect=observe_detached):
                with self.assertRaises(RuntimeError) as caught:
                    module._source5_owned_scope_expire(scope, session, entry)
            self.assertIs(caught.exception, first_error)
            self.assertEqual(attempted, [first_module, second_module])
            self.assertEqual(first_resource.close_count, 1)
            self.assertEqual(second_resource.close_count, 1)
            self.assertIsNone(session.operation_scope)
            self.assertEqual(binding, {})
            self.assertIsNone(entry["current_h_binding"])
        finally:
            module._SOURCE5_OWNED_OPERATION_SCOPES.pop(scope, None)
            module._SOURCE5_OWNED_H_CONTEXTS.pop(context_id, None)

    def test_fork_child_expiry_drops_copied_registry_without_mutex(self) -> None:
        module = self.module
        scope = self._scope()
        parent_pid = os.getpid()
        scope._creator_pid = parent_pid - 1
        lock = object()
        context = object()
        binding = {"context": context, "owned_modules": (), "owned_resources": ()}
        entry = {
            "scope": scope,
            "creator_pid": parent_pid,
            "lock": lock,
            "session": None,
            "state": module._Source5OwnedScopeState.REPLAY_COMPLETE,
            "current_h_binding": binding,
            "current_h_context_construction_marker": object(),
            "current_h_context_pending": object(),
            "h_binding": object(),
            "old_owner_binding": object(),
            "plan_binding": object(),
        }
        session = object.__new__(module._Source5PreparedExplorationRegistrationSession)
        session.lock = lock
        session.operation_scope = scope
        entry["session"] = session
        context_id = id(context)
        module._SOURCE5_OWNED_OPERATION_SCOPES[scope] = entry
        module._SOURCE5_OWNED_H_CONTEXTS[context_id] = binding
        try:
            with patch.object(module, "_SOURCE5_OWNED_OPERATION_SCOPE_LOCK",
                              _InheritedLock()), \
                    patch.object(module, "_SOURCE5_OWNED_H_CONTEXT_LOCK",
                                 _InheritedLock()):
                self.assertIsNone(
                    module._source5_invalidate_copied_lock_authority(lock),
                )
            self.assertIsNone(session.operation_scope)
            self.assertNotIn(scope, module._SOURCE5_OWNED_OPERATION_SCOPES)
            self.assertNotIn(context_id, module._SOURCE5_OWNED_H_CONTEXTS)
            self.assertEqual(binding, {})
        finally:
            module._SOURCE5_OWNED_OPERATION_SCOPES.pop(scope, None)
            module._SOURCE5_OWNED_H_CONTEXTS.pop(context_id, None)


if __name__ == "__main__":
    unittest.main()
