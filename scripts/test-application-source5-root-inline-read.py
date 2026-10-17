#!/usr/bin/env python3
"""Focused Root inline current-input and guest-path isolation tests.

The actual-H6 fixture below exercises only Source's pure 720-row plan and
chunk validators. It does not run GPG, serve an authenticated window, or
claim full Root/SourceA qualification.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent


def load_sibling(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test dependency {path.name}")
    import sys
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


archive = load_sibling(
    SCRIPT_DIR / "application-source5-evidence-archive.py",
    "source5_root_inline_archive_tests",
)
read_plan_tests = load_sibling(
    SCRIPT_DIR / "test-application-source5-recorded-preparation-read.py",
    "source5_root_inline_actual_plan_tests",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sealed_resource(operation_kind: str, role_raws: dict[str, bytes],
                    window_chunk_raws: list[bytes]) -> dict[str, object]:
    body = {
        "schema": archive.ROOT_INLINE_CURRENT_INPUT_RESOURCE_SCHEMA_V1,
        "operation_kind": operation_kind,
        "maximum_buffered_bytes": (
            sum(len(raw) for raw in role_raws.values()) +
            sum(len(raw) for raw in window_chunk_raws)
        ),
        "document_count": len(role_raws) + len(window_chunk_raws),
        "role_byte_counts": {
            role: len(raw) for role, raw in role_raws.items()
        },
        "window_chunk_byte_counts": [len(raw) for raw in window_chunk_raws],
    }
    return {**body, "resource_sha256": hashlib.sha256(canonical(body)).hexdigest()}


class RootInlineResourceGrammarTests(unittest.TestCase):
    def test_fixed_role_sets_exclude_old_capture_and_future_completion(self) -> None:
        construction = archive._root_inline_current_input_role_caps(
            archive.ROOT_INLINE_OPERATION_CONSTRUCTION_SERVE,
        )
        ordinary = archive._root_inline_current_input_role_caps(
            archive.ROOT_INLINE_OPERATION_ORDINARY_SERVE,
        )
        construction_release = archive._root_inline_current_input_role_caps(
            archive.ROOT_INLINE_OPERATION_CONSTRUCTION_RELEASE,
        )
        ordinary_release = archive._root_inline_current_input_role_caps(
            archive.ROOT_INLINE_OPERATION_ORDINARY_RELEASE,
        )
        self.assertEqual(set(construction), {
            "basis", "read_plan", "session_descriptor",
            "selected_source_manifest", "final_spec", "final_plan", "request",
        })
        self.assertEqual(set(ordinary), set(construction) | {"current_width"})
        self.assertEqual(set(construction_release), {
            "basis", "read_plan", "session_descriptor",
            "selected_source_manifest",
        })
        self.assertEqual(ordinary_release, construction_release)
        self.assertNotIn("lineage_capture_manifest", construction)
        self.assertNotIn("completion", construction)

    def test_serve_rejects_bad_accounting_before_any_document_parse(self) -> None:
        route = archive.ROOT_INLINE_OPERATION_CONSTRUCTION_SERVE
        roles = {
            name: b"x"
            for name in archive._root_inline_current_input_role_caps(route)
        }
        chunks = [b"c"]
        resource = sealed_resource(route, roles, chunks)
        resource["document_count"] += 1
        body = {key: value for key, value in resource.items()
                if key != "resource_sha256"}
        resource["resource_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
        with patch.object(
                archive, "_parse_canonical",
                side_effect=AssertionError("parsed before current-input admission")):
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._serve_source5_preparation_read_window_inline(
                    roles["request"], basis_raw=roles["basis"],
                    read_plan_raw=roles["read_plan"],
                    session_descriptor_raw=roles["session_descriptor"],
                    window_chunk_raws=chunks,
                    final_spec_raw=roles["final_spec"],
                    final_plan_raw=roles["final_plan"],
                    current_width_raw=None, source_root="/unused",
                    selected_source_manifest_raw=roles["selected_source_manifest"],
                    lineage_capture_manifest_raw=b"old-capture",
                    lineage_capture_stage_root="/unused",
                    archive_source5_root="/unused",
                    response_output_path="/unused/response.json.incoming",
                    bundle_output_path="/unused/response.tar.incoming",
                    root_current_input_resource_declaration=resource,
                    root_resource_declaration={},
                    root_output_resource_declaration={}, route=route,
                )

    def test_release_rejects_bad_accounting_before_any_document_parse(self) -> None:
        route = archive.ROOT_INLINE_OPERATION_CONSTRUCTION_RELEASE
        roles = {
            name: b"x"
            for name in archive._root_inline_current_input_role_caps(route)
        }
        chunks = [b"c"]
        resource = sealed_resource(route, roles, chunks)
        resource["maximum_buffered_bytes"] += 1
        body = {key: value for key, value in resource.items()
                if key != "resource_sha256"}
        resource["resource_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
        with patch.object(
                archive, "_parse_canonical",
                side_effect=AssertionError("parsed before current-input admission")):
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._release_source5_preparation_read_root_output_inline(
                    roles["basis"], roles["read_plan"],
                    roles["session_descriptor"], chunks, "/unused",
                    roles["selected_source_manifest"], resource, {}, 0, {}, {},
                    route=route,
                )

    def test_route_kind_and_chunk_hashes_are_exact(self) -> None:
        roles = {"basis": b"b", "read_plan": b"p",
                 "session_descriptor": b"s", "selected_source_manifest": b"m"}
        chunks = [b"chunk"]
        declaration = sealed_resource(
            archive.ROOT_INLINE_OPERATION_ORDINARY_RELEASE, roles, chunks,
        )
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._validate_root_inline_current_input_resource_v1(
                declaration, archive.ROOT_INLINE_OPERATION_CONSTRUCTION_RELEASE,
                roles, chunks,
            )

    def test_boolean_values_are_not_accepted_as_byte_or_document_counts(self) -> None:
        route = archive.ROOT_INLINE_OPERATION_CONSTRUCTION_RELEASE
        roles = {name: b"x" for name in
                 archive._root_inline_current_input_role_caps(route)}
        chunks = [b"c"]
        valid = sealed_resource(route, roles, chunks)
        for field in ("maximum_buffered_bytes", "document_count"):
            declaration = dict(valid)
            declaration[field] = True
            body = {key: value for key, value in declaration.items()
                    if key != "resource_sha256"}
            declaration["resource_sha256"] = hashlib.sha256(
                canonical(body),
            ).hexdigest()
            with self.subTest(field=field), self.assertRaises(
                    archive.EvidenceArchiveError):
                archive._validate_root_inline_current_input_resource_v1(
                    declaration, route, roles, chunks,
                )
        declaration = dict(valid)
        declaration["role_byte_counts"] = dict(valid["role_byte_counts"])
        declaration["role_byte_counts"]["basis"] = True
        body = {key: value for key, value in declaration.items()
                if key != "resource_sha256"}
        declaration["resource_sha256"] = hashlib.sha256(
            canonical(body),
        ).hexdigest()
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._validate_root_inline_current_input_resource_v1(
                declaration, route, roles, chunks,
            )
        declaration = dict(valid)
        declaration["window_chunk_byte_counts"] = [True]
        body = {key: value for key, value in declaration.items()
                if key != "resource_sha256"}
        declaration["resource_sha256"] = hashlib.sha256(
            canonical(body),
        ).hexdigest()
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._validate_root_inline_current_input_resource_v1(
                declaration, route, roles, [b"c"],
            )

    def test_unbounded_shape_rejected_before_hash(self) -> None:
        route = archive.ROOT_INLINE_OPERATION_CONSTRUCTION_RELEASE
        roles = {name: b"x" for name in
                 archive._root_inline_current_input_role_caps(route)}
        chunks = [b"c"] * (archive.ROOT_INLINE_MAX_WINDOW_CHUNKS + 1)
        oversized = sealed_resource(route, roles, chunks)
        with patch.object(
                archive, "_canonical",
                side_effect=AssertionError("hashed unbounded declaration")):
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_root_inline_current_input_resource_v1(
                    oversized, route, roles, chunks,
                )

        valid = sealed_resource(route, roles, [b"c"])
        extra_role = dict(valid)
        extra_role["role_byte_counts"] = dict(valid["role_byte_counts"])
        extra_role["role_byte_counts"]["unbounded"] = 1
        body = {key: value for key, value in extra_role.items()
                if key != "resource_sha256"}
        extra_role["resource_sha256"] = hashlib.sha256(
            canonical(body),
        ).hexdigest()
        with patch.object(
                archive, "_canonical",
                side_effect=AssertionError("hashed malformed role map")):
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_root_inline_current_input_resource_v1(
                    extra_role, route, roles, [b"c"],
                )


class RootInlineActualPlanChunkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.fixture_class = read_plan_tests.ActualH6RecordedReadPlanTests
        cls.fixture_class.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.fixture_class.tearDownClass()
        finally:
            super().tearDownClass()

    def test_selected_inline_chunk_avoids_all_h_path_io(self) -> None:
        _basis, _basis_pin, plan, chunks, plan_pin = \
            self.fixture_class.construction_fixture()
        raw_chunks = [read_plan_tests.canonical(chunk) for chunk in chunks]
        archive._validate_root_inline_window_chunk_sequence(plan, raw_chunks)
        with patch.object(
                archive, "_read_absolute_private_file",
                side_effect=AssertionError("Root opened an H logical path")), \
             patch.object(
                archive.os, "statvfs",
                side_effect=AssertionError("Root applied an H device check")):
            _chunk, row = archive._recorded_read_window_chunk(
                plan, plan_pin, read_plan_tests.read_plan, 0,
                construction=True, inline_window_chunk_raws=raw_chunks,
            )
        self.assertEqual(row["read_ordinal"], 0)

    def test_pure_session_projection_is_bound_to_construction_plan(self) -> None:
        basis, basis_pin, plan, _chunks, plan_pin = \
            self.fixture_class.construction_fixture()
        _descriptor, session_raw, _session_pin = \
            archive._recorded_read_plan_member(
                read_plan_tests.read_plan, "build_session_descriptor",
                construction=True,
            )(plan, plan_pin)
        session, checked_basis_pin, checked_plan_pin = \
            archive._validate_root_inline_plan_session(
                read_plan_tests.read_plan, basis, plan, session_raw,
                construction=True,
            )
        self.assertEqual(session["operation_kind"], "completion_construction")
        self.assertEqual(checked_basis_pin, basis_pin)
        self.assertEqual(checked_plan_pin, plan_pin)
        altered = json.loads(session_raw)
        altered["session_nonce"] = "b" * 32
        body = {key: value for key, value in altered.items()
                if key != "session_sha256"}
        altered["session_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._validate_root_inline_plan_session(
                read_plan_tests.read_plan, basis, plan, canonical(altered),
                construction=True,
            )

    def test_inline_chunk_requires_the_actual_raw3_pin_grammar(self) -> None:
        _basis, _basis_pin, plan, chunks, _plan_pin = \
            self.fixture_class.construction_fixture()
        raw_chunks = [read_plan_tests.canonical(chunk) for chunk in chunks]
        self.assertEqual(set(plan["window_chunks"][0]["pin"]), {
            "path", "raw_sha256", "semantic_sha256",
        })
        for mutation in ("missing_semantic", "boolean_semantic", "extra_field"):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(plan))
                pin = changed["window_chunks"][0]["pin"]
                if mutation == "missing_semantic":
                    del pin["semantic_sha256"]
                elif mutation == "boolean_semantic":
                    pin["semantic_sha256"] = True
                else:
                    pin["proof"] = True
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._validate_root_inline_window_chunk_sequence(changed, raw_chunks)

    def test_unselected_bad_hash_fails_complete_sequence(self) -> None:
        _basis, _basis_pin, plan, chunks, _plan_pin = \
            self.fixture_class.construction_fixture()
        raw_chunks = [read_plan_tests.canonical(chunk) for chunk in chunks]
        raw_chunks[-1] += b" "
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._validate_root_inline_window_chunk_sequence(plan, raw_chunks)


if __name__ == "__main__":
    unittest.main()
