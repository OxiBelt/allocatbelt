"""Resident Source-manifest handoff tests; no archive authority is issued."""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

path = Path(__file__).with_name("application-campaign-chronology.py")
spec = importlib.util.spec_from_file_location("source5_archive_source_context_tests", path)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class ArchiveSourceContextTests(unittest.TestCase):
    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="source5-archive-source-context-") as temporary:
            root = Path(temporary).resolve()
            p = root / "resident-source.json"
            body = {"schema": m.SOURCE_SCHEMA,
                    "source": {"source_tree_sha256": "a" * 64},
                    "fixture": "already verified Source context boundary"}
            value = {**body, "manifest_sha256": hashlib.sha256(m.canonical_bytes(body)).hexdigest()}
            # The real Source producer emits canonical JSON including its
            # self digest; its raw digest differs from the semantic body hash.
            raw = m.canonical_bytes(value)
            p.write_bytes(raw)
            p.chmod(0o600)
            ref = {"host_id": "host", "path": str(p),
                   "raw_sha256": hashlib.sha256(raw).hexdigest(),
                   "semantic_sha256": value["manifest_sha256"],
                   "source_tree_sha256": body["source"]["source_tree_sha256"]}
            prepared = {"host_id": "host", "source": value,
                        "source_manifest_raw_refs": {"host": ref}}
            yield p, raw, prepared, ref

    def kwargs(self, prepared):
        return m._source5_archive_budget_source_kwargs(
            prepared, {"schema": m.SOURCE5_HOST_BUDGET_SCHEMA_V3},
        )

    def test_v3_preserves_full_pinned_document_including_self_digest(self):
        with self.case() as (_path, raw, prepared, ref):
            self.assertNotEqual(hashlib.sha256(raw).hexdigest(), ref["semantic_sha256"])
            self.assertEqual(self.kwargs(prepared), {"source_manifest_raw": raw})

    def test_legacy_v2_does_not_read_or_add_a_new_archive_keyword(self):
        with mock.patch.object(m, "_read_stable", side_effect=AssertionError("legacy Source read")):
            self.assertEqual(m._source5_archive_budget_source_kwargs(
                {}, {"schema": m.SOURCE5_HOST_BUDGET_SCHEMA_V2}), {})

    def test_changed_resident_raw_bytes_cannot_use_old_pin(self):
        with self.case() as (p, raw, prepared, _ref):
            p.write_bytes(raw + b" ")
            with self.assertRaisesRegex(m.ChronologyError, "exact raw pin"):
                self.kwargs(prepared)

    def test_repinned_raw_cannot_change_selected_semantic_source(self):
        with self.case() as (p, _raw, prepared, ref):
            changed = copy.deepcopy(prepared["source"])
            changed["fixture"] = "foreign source"
            raw = m.canonical_bytes(changed)
            p.write_bytes(raw)
            ref["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            with self.assertRaisesRegex(m.ChronologyError, "raw/semantic/tree closure"):
                self.kwargs(prepared)

    def test_different_selected_host_pin_is_rejected_before_read(self):
        with self.case() as (_p, _raw, prepared, ref):
            ref["host_id"] = "foreign-host"
            with mock.patch.object(m, "_read_stable", side_effect=AssertionError("foreign Source read")):
                with self.assertRaisesRegex(m.ChronologyError, "original host"):
                    self.kwargs(prepared)

    def test_source_tree_pin_is_bound_to_the_selected_document(self):
        with self.case() as (_p, _raw, prepared, ref):
            ref["source_tree_sha256"] = "f" * 64
            with self.assertRaisesRegex(m.ChronologyError, "raw/semantic/tree closure"):
                self.kwargs(prepared)


if __name__ == "__main__":
    unittest.main()
