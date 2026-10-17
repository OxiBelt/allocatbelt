#!/usr/bin/env python3
"""Static regressions for SourceA C2 fresh replay scopes and route boundaries."""
from __future__ import annotations

import ast
import builtins
import symtable
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_PATH = SCRIPT_DIR / "application-campaign-chronology.py"


class SourceAC2ScopeStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text()
        cls.tree = ast.parse(cls.source, filename=str(SOURCE_PATH))
        compile(cls.source, str(SOURCE_PATH), "exec")
        cls.functions = {
            node.name: node for node in cls.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        cls.classes = {
            node.name: node for node in cls.tree.body
            if isinstance(node, ast.ClassDef)
        }

    def _calls(self, name: str) -> list[str]:
        result = []
        for node in ast.walk(self.functions[name]):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                result.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                result.append(node.func.attr)
        return result

    def test_core_and_scope_are_private_top_level_types(self) -> None:
        for name in (
            "_source5_owned_input_generation_replay_held",
            "_source5_owned_registration_append_held",
            "_source5_owned_operation_scope_held",
            "_source5_owned_scope_require",
            "_source5_owned_scope_advance_frontier",
            "_source5_owned_scope_bind_old_owner_state",
            "_source5_owned_scope_bind_plan",
        ):
            self.assertIn(name, self.functions)
        self.assertIn("_Source5OwnedOperationScope", self.classes)
        self.assertIn("_Source5OwnedReplayRoute", self.classes)
        self.assertIn("_Source5OwnedOperationSink", self.classes)

    def test_replay_core_keeps_the_full_fresh_owner_sequence(self) -> None:
        core = ast.get_source_segment(
            self.source, self.functions["_source5_owned_input_generation_replay_held"],
        )
        self.assertIsNotNone(core)
        for required in (
            "_source5_verify_captured_prepared_ack_cohort_held",
            "_source5_recorded_numeric_ancestor_context_held",
            "_source5_owned_scope_bind_old_owner_state",
            "_source5_owned_scope_bind_plan",
            "_source5_owned_scope_bind_h_client",
            "_source5_owned_registration_build_plan",
            "source5_recorded_preparation_read_client_v1",
            "verify_prepared_inputs_completion_closed_recorded_v2",
            "session.global_cursor == 720",
            "session.numeric_replay_count == 720",
            "session.require_complete()",
            "_source5_owned_scope_mark_replay_complete",
        ):
            self.assertIn(required, core)
        self.assertNotIn("_locked(", core)
        self.assertNotIn("captured_read_context", core)
        self.assertNotIn("artifact_reader:", core)
        core_calls = [node for node in ast.walk(
            self.functions["_source5_owned_input_generation_replay_held"],
        ) if isinstance(node, ast.Call)]
        line_for = lambda name: min(node.lineno for node in core_calls
                                    if isinstance(node.func, ast.Name) and
                                    node.func.id == name)
        gpg = line_for("_source5_verify_captured_prepared_ack_cohort_held")
        numeric = line_for("_source5_recorded_numeric_ancestor_context_held")
        bind_old = line_for("_source5_owned_scope_bind_old_owner_state")
        build_plan = line_for("_source5_owned_registration_build_plan")
        bind_plan = line_for("_source5_owned_scope_bind_plan")
        bind_h = line_for("_source5_owned_scope_bind_h_client")
        inputprep = next(node.lineno for node in ast.walk(
            self.functions["_source5_owned_input_generation_replay_held"],
        ) if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == "verified_completion"
                for target in node.targets) and
            isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and
            node.value.func.id == "verifier")
        h_client_assignment = min(node.lineno for node in ast.walk(
            self.functions["_source5_owned_input_generation_replay_held"],
        ) if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Attribute) and target.attr == "h_client"
                for target in node.targets))
        self.assertLess(gpg, numeric)
        self.assertLess(numeric, bind_old)
        self.assertLess(bind_old, build_plan)
        self.assertLess(build_plan, bind_plan)
        self.assertLess(bind_plan, h_client_assignment)
        self.assertLess(h_client_assignment, bind_h)
        self.assertLess(bind_h, inputprep)

    def test_route_basis_distinguishes_registration_from_sealed_refresh(self) -> None:
        builder = ast.get_source_segment(
            self.source, self.functions["_source5_owned_registration_build_plan"],
        )
        self.assertIn('"registration_replay"', builder)
        self.assertIn('"refresh_replay"', builder)
        self.assertIn("session.frontier", builder)
        self.assertIn("session.execution_manifest_pin", builder)
        self.assertIn("session.registration_head", builder)
        self.assertIn("session.frontier == {", builder)
        self.assertIn('"head_sha256": "0" * 64', builder)
        self.assertIn('"record_count": 0', builder)
        self.assertIn('basis["execution_manifest_pin"]', builder)
        self.assertIn('basis["registration_head"]', builder)
        self.assertIn("nonce = os.urandom(16).hex()", builder)
        nonce_calls = [
            node for node in ast.walk(self.functions["_source5_owned_registration_build_plan"])
            if isinstance(node, ast.Call) and any(
                keyword.arg == "session_nonce" and
                isinstance(keyword.value, ast.Name) and keyword.value.id == "nonce"
                for keyword in node.keywords
            )
        ]
        self.assertGreaterEqual(len(nonce_calls), 2)

    def test_width_and_lineage_are_validated_in_outer_setup_before_scope(self) -> None:
        outer = self.functions["register_source5_prepared_exploration_owned_locked"]
        calls = [
            node for node in ast.walk(outer)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        width = next(node for node in calls
                     if node.func.id == "_source5_prepared_exploration_width_projection")
        scope = next(node for node in calls
                     if node.func.id == "_source5_owned_operation_scope_held")
        replay = next(node for node in calls
                      if node.func.id == "_source5_owned_input_generation_replay_held")
        self.assertLess(width.lineno, scope.lineno)
        self.assertLess(scope.lineno, replay.lineno)
        ancestor = next(keyword.value for keyword in width.keywords
                        if keyword.arg == "ancestor")
        self.assertEqual(
            ast.dump(ancestor, include_attributes=False),
            ast.dump(ast.parse('lineage_proofs[host_id]["ancestor"]', mode="eval").body,
                     include_attributes=False),
        )
        core = self.functions["_source5_owned_input_generation_replay_held"]
        self.assertTrue(any(
            isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == "checked_width_pin"
                for target in node.targets) and
            isinstance(node.value, ast.Attribute) and node.value.attr == "width_pin"
            for node in ast.walk(core)
        ))

    def test_scope_binds_source_lock_inputs_frontier_deadline_and_h_client(self) -> None:
        binding = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_binding_value"],
        )
        self.assertIsNotNone(binding)
        for field in (
            '"creator_pid"', '"sourcea_module"', '"device"', '"inode"', '"mode"', '"owner"',
            '"source_module_pins"', '"profile_pin"', '"width_pin"',
            '"completion_pin"', '"provenance_sha256"', '"execution_manifest_pin"',
            '"manifest_value_sha256"', '"deadline_ns"',
            '"allowed_sink_names"',
        ):
            self.assertIn(field, binding)
        scope_lifetime = ast.get_source_segment(
            self.source, self.functions["_source5_owned_operation_scope_held"],
        )
        self.assertIn('"frontier"', scope_lifetime)
        self.assertIn("_read_journal(session.lock, prepared)", scope_lifetime)
        self.assertIn('current_state.get("file_stat") == session.journal_file_key',
                      scope_lifetime)
        self.assertIn("current_manifest == manifest", scope_lifetime)
        self.assertIn("session.input_snapshots.append(manifest_snapshot)",
                      scope_lifetime)
        scope_require = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_require"],
        )
        self.assertIn("threading.get_ident()", scope_require)
        self.assertIn("_check_lock", scope_require)
        self.assertIn("h_binding", scope_require)
        self.assertIn("_source5_owned_scope_numeric_binding", scope_require)
        self.assertIn('"context_sha256"', scope_require)
        self.assertIn('"plan_id"', scope_require)
        self.assertIn('entry.get("allowed_sinks") is route_sinks', scope_require)

    def test_scope_replay_completion_checks_exact_numeric_cohort_counts(self) -> None:
        complete = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_mark_replay_complete"],
        )
        self.assertIn("session.require_complete()", complete)
        self.assertIn(
            'entry["old_owner_binding"]["numeric_binding"]["rows_per_host"] ==',
            complete,
        )
        self.assertIn('entry["plan_binding"]["window_count"] == 720', complete)
        self.assertNotIn("_source5_owned_scope_bind_old_owner_state(", complete)
        self.assertNotIn("_source5_owned_scope_bind_plan(", complete)
        self.assertNotIn("_source5_owned_scope_bind_h_client(", complete)

    def test_scope_lifecycle_unregisters_on_every_exit(self) -> None:
        node = self.functions["_source5_owned_operation_scope_held"]
        decorators = [
            ast.unparse(item) for item in node.decorator_list
        ]
        self.assertIn("contextlib.contextmanager", decorators)
        try_nodes = [item for item in ast.walk(node) if isinstance(item, ast.Try)]
        self.assertTrue(any(item.finalbody for item in try_nodes))
        body = ast.get_source_segment(self.source, node)
        self.assertIn("_SOURCE5_OWNED_OPERATION_SCOPES", body)
        self.assertIn("_source5_owned_scope_expire(scope, session, entry)", body)
        expire = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_expire"],
        )
        self.assertIn('getattr(scope, "_creator_pid"', expire)
        self.assertIn("with _SOURCE5_OWNED_OPERATION_SCOPE_LOCK", expire)
        self.assertIn("session.operation_scope = None", expire)
        outer = ast.get_source_segment(
            self.source, self.functions["register_source5_prepared_exploration_owned_locked"],
        )
        self.assertIn("_source5_run_cleanups_independently(cleanup_actions)", outer)
        for close_call in (
            "close_optional_reader(reader)",
            "close_module_once(module)",
            "_source5_construction_close_prepared(prepared)",
        ):
            self.assertIn(close_call, outer)
        self.assertIn("lambda reader=bootstrap_reader", outer)
        self.assertIn("lambda reader=capture_reader", outer)
        self.assertIn("if cleanup_error is not None and primary_error is None", outer)
        self.assertIn("raise cleanup_error", outer)
        prepared_close = ast.get_source_segment(
            self.source, self.functions["_source5_construction_close_prepared"],
        )
        self.assertIn("_source5_run_cleanups_independently(close_actions)", prepared_close)
        self.assertIn("lambda module=module", prepared_close)
        self.assertIn("if close_error is not None", prepared_close)
        self.assertIn("raise close_error", prepared_close)


    def test_c3a_h_context_foundation_is_private_and_nongranting(self) -> None:
        create = self.functions["_source5_owned_create_h_context_held"]
        bind = self.functions["_source5_owned_bind_h_context_held"]
        require_context = self.functions["_source5_owned_require_h_context_held"]
        for node, expected_args in (
            (create, ["session", "scope"]),
            (bind, ["session", "scope", "h_context"]),
            (require_context, ["session", "scope", "h_context"]),
        ):
            self.assertEqual([arg.arg for arg in node.args.args], expected_args)
            self.assertFalse(any(
                isinstance(item, ast.Name) and item.id == "_serialize_locked_api"
                for item in node.decorator_list
            ))
        create_text = ast.get_source_segment(self.source, create)
        bind_text = ast.get_source_segment(self.source, bind)
        require_text = ast.get_source_segment(self.source, require_context)
        self.assertIn("_Source5OwnedReplayRoute.SEALED_REFRESH", create_text)
        self.assertIn("_Source5OwnedScopeState.REPLAY_COMPLETE", create_text)
        self.assertIn("session.require_complete()", create_text)
        self.assertIn("session.global_cursor == 720", create_text)
        self.assertIn("session.numeric_replay_count == 720", create_text)
        self.assertIn("_source5_load_context_with_active_sourcea_held", create_text)
        self.assertIn("_source5_owned_bind_h_context_held", create_text)
        self.assertIn("current_h_context_construction_marker", create_text)
        self.assertIn("current_h_context_pending", bind_text)
        registry = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_registry_entry"],
        )
        self.assertIn('type(h_context) is binding.get("context_type")', registry)
        self.assertIn("_SOURCE5_OWNED_H_CONTEXTS", registry)
        self.assertIn("context_id not in _SOURCE5_OWNED_H_CONTEXTS", bind_text)
        self.assertIn('pending.get("context") is h_context', bind_text)
        self.assertIn("current_h_binding", require_text)
        for field in ('"manifest": current["manifest"]',
                      '"prepared": current["prepared"]',
                      '"state": current["state"]',
                      '"manifest_pin": current["manifest_pin"]'):
            self.assertIn(field, require_text)
        self.assertNotIn('state.get("pending") is None', require_text)
        self.assertNotIn('state.get("source5_pending") is None', require_text)
        old_h3 = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_require"],
        )
        self.assertIn('h_binding = entry.get("h_binding")', old_h3)
        entry_factory = ast.get_source_segment(
            self.source, self.functions["_source5_owned_operation_scope_held"],
        )
        self.assertIn('"current_h_binding": None', entry_factory)
        outer = ast.get_source_segment(
            self.source,
            self.functions["register_source5_prepared_exploration_owned_locked"],
        )
        self.assertNotIn("_source5_owned_create_h_context_held(", outer)
        expire = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_expire"],
        )
        self.assertLess(expire.index("_source5_owned_h_context_detach"),
                        expire.index("_source5_owned_h_context_cleanup"))
        cleanup = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_cleanup"],
        )
        self.assertIn("_source5_run_cleanups_independently(actions)", cleanup)
        self.assertIn("binding.clear()", cleanup)

    def test_c3a_registry_rechecks_pid_thread_frontier_and_mutation(self) -> None:
        registry = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_registry_entry"],
        )
        require_context = ast.get_source_segment(
            self.source, self.functions["_source5_owned_require_h_context_held"],
        )
        validate_candidate = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_validate_candidate"],
        )
        copied_invalidation = ast.get_source_segment(
            self.source, self.functions["_source5_invalidate_copied_lock_authority"],
        )
        current = ast.get_source_segment(
            self.source,
            self.functions["_source5_owned_h_context_current_operation_data"],
        )
        input_body = ast.get_source_segment(
            self.source,
            self.functions["_source5_owned_h_context_verified_input_body_binding"],
        )
        validate_bodies = ast.get_source_segment(
            self.source,
            self.functions["_source5_owned_h_context_validate_input_bodies"],
        )
        for required in (
            'scope_entry.get("creator_pid") == current_pid',
            'scope_entry.get("thread_id") == threading.get_ident()',
            'session.operation_scope is scope',
            'type(session.lock) is lock_type',
            'binding.get("lock_fd") == session.lock.fd',
            'binding.get("lock_fd_key") == session.lock._fd_key',
            'binding.get("frontier")',
            'session.journal_file_key == scope_entry["frontier"]["file_stat"]',
            'binding.get("manifest_pin")',
            'binding.get("source_module_pins") == session.source_module_pins',
            'registered.get("context") is h_context',
            'getattr(active_sourcea, name, None) is function',
            'getattr(h_module, name, None) is function',
        ):
            self.assertIn(required, registry)
        self.assertIn("context.artifact_root == Path(current[\"manifest\"][\"artifact_root\"])",
                      validate_candidate)
        self.assertIn("context.journal_width_contract == width_contract",
                      validate_candidate)
        self.assertIn("context.journal_width_contract_pin == expected_width_pin ==",
                      validate_candidate)
        self.assertIn('_source5_owned_h_context_current_operation_data', require_context)
        self.assertIn('_source5_owned_h_context_validate_candidate', require_context)
        self.assertIn('session.operation_scope = None', copied_invalidation)
        self.assertLess(copied_invalidation.index('session.operation_scope = None'),
                        copied_invalidation.index('_source5_owned_h_context_cleanup'))
        self.assertIn('_source5_construction_recheck_file(snapshot', require_context)
        self.assertIn('_read_source5_v5_journal_structural(session.lock, prepared)', current)
        self.assertIn('state.get("head") == frontier["head_sha256"]', current)
        self.assertIn('state.get("file_stat") == frontier["file_stat"]', current)
        self.assertIn('manifest == prepared["source5_execution_manifest"]', current)
        self.assertEqual(current.count('session.check_deadline('), 1)
        self.assertLess(current.index('session.check_deadline('),
                        current.index('_source5_owned_h_context_verified_input_body_binding('))
        self.assertLess(current.index('_source5_owned_h_context_verified_input_body_binding('),
                        current.index('_read_source5_v5_journal_structural('))
        self.assertGreater(current.rindex('time.monotonic_ns()'),
                           current.index('_read_source5_v5_journal_structural('))
        for body_field in ('"source_manifest_pins"', '"input_snapshot_sha256"',
                           '"plan_sha256"',
                           'getattr(session, "input_snapshots"'):
            self.assertIn(body_field, input_body)
        self.assertIn('spec_raw == canonical_bytes(spec)', input_body)
        self.assertIn('plan_raw == canonical_bytes(plan)', input_body)
        for body_field in ('"spec_raw"', '"plan_raw"'):
            self.assertIn(body_field, validate_bodies)
        for body_name in ('spec', 'plan', 'source', 'sources'):
            self.assertIn(body_name, validate_bodies)
        self.assertIn('canonical_bytes(value)', validate_bodies)
        self.assertIn('sha256_bytes(raw)', validate_bodies)
        self.assertIn('_source5_owned_h_context_validate_input_bodies(',
                      validate_candidate)

    def test_c3a_binding_policy_has_one_actual_nongranting_producer_consumer_shape(self) -> None:
        policy = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_action_policy"],
        )
        consumer = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_require_action_policy"],
        )
        producer = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_validate_candidate"],
        )
        registry = ast.get_source_segment(
            self.source, self.functions["_source5_owned_h_context_registry_entry"],
        )
        self.assertIn('"allowed_actions": frozenset()', policy)
        self.assertIn('"allowed_sink_names": ()', policy)
        self.assertIn('_source5_owned_h_context_action_policy(entry)', producer)
        self.assertIn('_source5_owned_h_context_require_action_policy(binding, scope_entry)', registry)
        self.assertIn('binding.get("allowed_actions") == policy["allowed_actions"]', consumer)
        self.assertIn('binding.get("allowed_sink_names") == policy["allowed_sink_names"]', consumer)

    def test_registration_proof_is_bound_to_a_separate_live_scope(self) -> None:
        issue = ast.get_source_segment(
            self.source, self.functions["_source5_issue_prepared_registration_proof"],
        )
        check = ast.get_source_segment(
            self.source, self.functions["_source5_prepared_registration_proof_check"],
        )
        self.assertIn('"scope": scope', issue)
        self.assertIn('entry.get("scope")', check)
        self.assertIn("_source5_owned_scope_require", check)
        self.assertIn("_source5_owned_scope_precheck_sink", check)
        self.assertIn("_source5_prepared_registration_finalize_consume", check)
        final_guard = ast.get_source_segment(
            self.source, self.functions["_source5_prepared_registration_finalize_consume"],
        )
        self.assertIn("_source5_owned_scope_consume_sink", final_guard)

    def test_registration_scope_is_one_outer_lock_and_no_sink_routes_are_public(self) -> None:
        api = self.functions["register_source5_prepared_exploration_owned_locked"]
        decorators = {
            item.id for item in api.decorator_list if isinstance(item, ast.Name)
        } | {
            item.func.id for item in api.decorator_list
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
        }
        self.assertIn("_serialize_locked_api", decorators)
        parameters = {
            argument.arg for argument in
            api.args.posonlyargs + api.args.args + api.args.kwonlyargs
        }
        for forbidden in ("route", "scope", "allowed_sinks", "provider", "proof"):
            self.assertNotIn(forbidden, parameters)
        core_decorators = self.functions["_source5_owned_input_generation_replay_held"].decorator_list
        self.assertFalse(any(
            isinstance(item, ast.Name) and item.id == "_serialize_locked_api"
            for item in core_decorators
        ))

    def test_scope_lock_and_proof_reject_inherited_pid_before_registry_locks(self) -> None:
        lock_live = ast.get_source_segment(
            self.source, self.functions["_lock_token_is_live"],
        )
        self.assertLess(lock_live.index("os.getpid()"),
                        lock_live.index("_LIVE_LOCK_TOKENS.get"))
        serializer = ast.get_source_segment(
            self.source, self.functions["_serialize_locked_api"],
        )
        self.assertLess(serializer.index("_lock_token_is_live(lock)"),
                        serializer.index("with token[4]"))
        scope_entry = ast.get_source_segment(
            self.source, self.functions["_source5_owned_scope_entry"],
        )
        self.assertLess(scope_entry.index('getattr(scope, "_creator_pid"'),
                        scope_entry.index("with _SOURCE5_OWNED_OPERATION_SCOPE_LOCK"))
        proof_check = ast.get_source_segment(
            self.source, self.functions["_source5_prepared_registration_proof_check"],
        )
        self.assertLess(proof_check.index('getattr(proof, "_creator_pid"'),
                        proof_check.index("with _SOURCE5_PREPARED_REGISTRATION_PROOF_LOCK"))
        lock_class = self.classes["CampaignHostLock"]
        exit_method = next(node for node in lock_class.body
                           if isinstance(node, ast.FunctionDef) and node.name == "__exit__")
        child_branch = next(node for node in ast.walk(exit_method)
                            if isinstance(node, ast.If) and
                            "_creator_pid" in ast.get_source_segment(self.source, node.test))
        child_source = ast.get_source_segment(self.source, child_branch)
        self.assertIn("os.close(descriptor)", child_source)
        self.assertIn("self.fd = -1", child_source)
        child_calls = [node for node in ast.walk(child_branch)
                       if isinstance(node, ast.Call)]
        call_names = [ast.unparse(node.func) for node in child_calls]
        self.assertNotIn("fcntl.flock", call_names)
        self.assertFalse(any(name.endswith(".acquire") or name.endswith(".release")
                             for name in call_names))
        invalidator = ast.get_source_segment(
            self.source, self.functions["_source5_invalidate_copied_lock_authority"],
        )
        self.assertNotIn("with ", invalidator)
        self.assertIn('entry.get("lock") is lock', invalidator)
        self.assertIn("_SOURCE5_PREPARED_REGISTRATION_PROOFS.pop", invalidator)
        self.assertIn("_SOURCE5_OWNED_OPERATION_SCOPES.pop", invalidator)

    def test_held_journal_recheck_follows_last_callbacks_and_precedes_consume_write(self) -> None:
        final_guard = self.functions["_source5_prepared_registration_finalize_consume"]
        guard_calls = [node for node in ast.walk(final_guard)
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        line = {name: min(node.lineno for node in guard_calls if node.func.id == name)
                for name in (
                    "_source5_prepared_registration_recheck_inputs_callback_free",
                    "_source5_owned_scope_recheck_callback_free",
                    "_source5_prepared_registration_recheck_empty_frontier_held",
                    "_source5_owned_scope_consume_sink",
                )}
        clock_line = min(node.lineno for node in ast.walk(final_guard)
                         if isinstance(node, ast.Call) and
                         isinstance(node.func, ast.Attribute) and
                         node.func.attr == "monotonic_ns")
        self.assertLess(line["_source5_prepared_registration_recheck_inputs_callback_free"],
                        line["_source5_owned_scope_recheck_callback_free"])
        self.assertLess(line["_source5_owned_scope_recheck_callback_free"],
                        line["_source5_prepared_registration_recheck_empty_frontier_held"])
        self.assertLess(line["_source5_prepared_registration_recheck_empty_frontier_held"],
                        clock_line)
        self.assertLess(clock_line, line["_source5_owned_scope_consume_sink"])
        proof = ast.get_source_segment(
            self.source, self.functions["_source5_prepared_registration_proof_check"],
        )
        self.assertIn("_source5_prepared_registration_finalize_consume(", proof)
        self.assertLess(proof.index("_source5_prepared_registration_finalize_consume("),
                        proof.index('entry["state"] = "consumed"'))
        append = self.functions["_append_event_impl"]
        append_calls = [node for node in ast.walk(append)
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        write_lines = [node.lineno for node in append_calls if node.func.attr == "write"]
        consume_line = next(node.lineno for node in ast.walk(append)
                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "_source5_prepared_registration_proof_check"
                            and any(k.arg == "mode" and isinstance(k.value, ast.Constant)
                                    and k.value.value == "consume" for k in node.keywords))
        self.assertTrue(write_lines)
        self.assertLess(consume_line, min(write_lines))
        held = ast.get_source_segment(
            self.source,
            self.functions["_source5_prepared_registration_recheck_empty_frontier_held"],
        )
        self.assertIn("os.fstat(journal_fd)", held)
        self.assertIn("journal_path.lstat()", held)
        self.assertIn("os.pread(journal_fd, 1, 0)", held)
        self.assertIn('state.get("record_count") == 0', held)

    def test_structural_bootstrap_cannot_issue_or_restore_a_scope(self) -> None:
        structural = ast.get_source_segment(
            self.source, self.functions["_prepare_source5_v5_structural_context_held"],
        )
        self.assertIsNotNone(structural)
        self.assertNotIn("_source5_owned_operation_scope_held", structural)
        self.assertNotIn("_source5_owned_input_generation_replay_held", structural)
        self.assertNotIn("_SOURCE5_OWNED_OPERATION_SCOPES", structural)

    def test_all_seven_v5_sink_refusals_remain(self) -> None:
        gate_calls: dict[str, int] = {}
        for node in self.tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            count = sum(
                isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and
                item.func.id == "_source5_require_v5_replay_authority"
                for item in ast.walk(node)
            )
            if count:
                gate_calls[node.name] = count
        self.assertEqual(gate_calls, {
            "_source5_analysis_identity": 1,
            "refresh_source5_analysis_gate_locked": 1,
            "_validate_source5_authorization": 1,
            "authorize_source5_job_locked": 1,
            "record_source5_analysis_locked": 1,
            "verify_source5_capacity_ancestor_locked": 1,
            "source5_authorization_context_locked": 1,
        })

    def test_new_private_helpers_have_no_unbound_global_names(self) -> None:
        module = symtable.symtable(self.source, str(SOURCE_PATH), "exec")
        module_names = set(module.get_identifiers())
        builtin_names = set(dir(builtins))
        helper_names = (
            "_source5_run_cleanups_independently",
            "_source5_invalidate_copied_lock_authority",
            "_source5_prepared_registration_finalize_consume",
            "_source5_prepared_registration_recheck_empty_frontier_held",
            "_source5_owned_scope_expire",
            "_source5_owned_scope_digest",
            "_source5_owned_scope_binding_value",
            "_source5_owned_scope_entry",
            "_source5_owned_scope_require",
            "_source5_owned_scope_check_live",
            "_source5_owned_scope_recheck_callback_free",
            "_source5_owned_scope_bind_h_client",
            "_source5_owned_scope_numeric_binding",
            "_source5_owned_scope_bind_old_owner_state",
            "_source5_owned_scope_bind_plan",
            "_source5_owned_scope_mark_replay_complete",
            "_source5_owned_scope_precheck_sink",
            "_source5_owned_scope_consume_sink",
            "_source5_owned_scope_advance_frontier",
            "_source5_owned_operation_scope_held",
            "_source5_owned_input_generation_replay_held",
            "_source5_owned_registration_append_held",
            "_source5_owned_h_context_detach",
            "_source5_owned_h_context_cleanup",
            "_source5_owned_h_context_current_operation_data",
            "_source5_owned_h_context_module_inventory",
            "_source5_owned_h_context_source_functions",
            "_source5_owned_h_context_h_functions",
            "_source5_owned_h_context_validate_candidate",
            "_source5_owned_h_context_registry_entry",
            "_source5_owned_create_h_context_held",
            "_source5_owned_h_context_close_unbound_candidate",
            "_source5_owned_bind_h_context_held",
            "_source5_owned_require_h_context_held",
            "_source5_owned_h_context_verified_input_body_binding",
            "_source5_owned_h_context_validate_input_bodies",
            "_source5_owned_h_context_action_policy",
            "_source5_owned_h_context_require_action_policy",
        )
        tables = {
            (child.get_name(), child.get_lineno()): child
            for child in module.get_children()
        }
        for name in helper_names:
            function = self.functions[name]
            table = tables[(name, function.lineno)]
            for symbol in table.get_symbols():
                if symbol.is_global() and symbol.is_referenced():
                    self.assertIn(
                        symbol.get_name(), module_names | builtin_names,
                        f"{name} references unbound global {symbol.get_name()}",
                    )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
