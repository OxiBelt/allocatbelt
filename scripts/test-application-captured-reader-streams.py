#!/usr/bin/env python3
"""Captured byte/stream plumbing; synthetic data, no APP or host-proof claim."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


FIXED = load("captured_stream_fixed", SCRIPTS / "application-fixed-pair.py")
FEEDBACK = load("captured_stream_feedback", SCRIPTS / "application-feedback-readback.py")
PRESSURE = load("captured_stream_pressure", SCRIPTS / "application-pressure-readback.py")
FIXTURES = load("captured_stream_feedback_fixtures", SCRIPTS / "test-application-feedback-readback.py")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stage_files(root, payloads):
    stage = root / "stage"
    stage.mkdir(mode=0o700)
    refs = {}
    for index, (origin, raw) in enumerate(sorted(payloads.items())):
        local = stage / f"{index:06d}"
        local.write_bytes(raw)
        local.chmod(0o400)
        refs[str(origin)] = {"origin_path": str(origin), "path": str(local),
                            "role": "opaque_trace", "host_id": "host-1",
                            "raw_sha256": sha(raw), "semantic_sha256": None,
                            "byte_count": len(raw), "maximum_bytes": len(raw)}
    return stage, refs


class CapturedReaderStreamsTests(unittest.TestCase):
    @contextmanager
    def case(self, raw=b'{"value":1}\n', name="feedback-events.jsonl"):
        with tempfile.TemporaryDirectory(prefix="captured-reader-streams-") as directory:
            root = Path(directory).resolve()
            origin = root / "absent-origins" / name
            stage, refs = stage_files(root, {origin: raw})
            view = FIXED.CapturedFixedPairArtifactsV1(refs, stage)
            yield root, origin, stage, refs, view

    def test_both_raw_and_json_readers_use_real0400_captures(self):
        with self.case() as (_root, origin, _stage, _refs, view):
            raw, digest = FEEDBACK.read_stable(origin, "feedback", 128, artifact_view=view)
            self.assertEqual((raw, digest), (b'{"value":1}\n', sha(b'{"value":1}\n')))
            value, observed = FEEDBACK.read_canonical(origin, "feedback", 128, digest, artifact_view=view)
            self.assertEqual((value, observed), ({"value": 1}, digest))
            value, copied, observed = PRESSURE.read_canonical(origin, "pressure", 128, artifact_view=view)
            self.assertEqual((value, copied, observed), ({"value": 1}, raw, digest))
            self.assertFalse(origin.exists())

    def test_missing_capture_never_uses_an_existing_origin(self):
        with self.case() as (root, origin, stage, refs, _view):
            other = root / "other.json"
            other_refs = {str(other): {**refs[str(origin)], "origin_path": str(other)}}
            view = FIXED.CapturedFixedPairArtifactsV1(other_refs, stage)
            origin.parent.mkdir(mode=0o700)
            origin.write_bytes(b'{"value":1}\n')
            for module, error in ((FEEDBACK, FEEDBACK.ValidationError), (PRESSURE, PRESSURE.ReadbackError)):
                with self.subTest(reader=module.__name__), patch.object(FIXED.os, "open", side_effect=AssertionError("missing ref attempted IO")):
                    with self.assertRaisesRegex(error, "absent from the exact captured refs"):
                        module.read_stable(origin, "missing", 128, artifact_view=view)

    def test_reader_ceiling_rejects_before_physical_open(self):
        with self.case() as (_root, origin, _stage, _refs, view):
            for module in (FEEDBACK, PRESSURE):
                with self.subTest(reader=module.__name__), patch.object(FIXED.os, "open", side_effect=AssertionError("oversize attempted IO")):
                    with self.assertRaisesRegex(FIXED.FixedPairError, "original reader byte ceiling"):
                        module.read_stable(origin, "oversized", 1, artifact_view=view)

    def test_reader_independently_checks_callback_raw_digest(self):
        with self.case() as (_root, origin, _stage, _refs, view):
            class WrongDigest:
                has_file = view.has_file
                def read(self, path, label, maximum):
                    raw, _sha = view.read(path, label, maximum)
                    return raw, "0" * 64
            for module, error in ((FEEDBACK, FEEDBACK.ValidationError), (PRESSURE, PRESSURE.ReadbackError)):
                with self.subTest(reader=module.__name__):
                    with self.assertRaisesRegex(error, "captured bytes differ"):
                        module.read_stable(origin, "wrong-digest", 128, artifact_view=WrongDigest())

    def test_repinned_json_still_obeys_strict_canonical_parser(self):
        raw = b'{"value":1,"value":2}\n'
        with self.case(raw) as (_root, origin, _stage, _refs, view):
            for module, error in ((FEEDBACK, FEEDBACK.ValidationError), (PRESSURE, PRESSURE.ReadbackError)):
                with self.subTest(reader=module.__name__):
                    with self.assertRaises(error):
                        module.read_canonical(origin, "duplicate", len(raw), artifact_view=view)

    def test_feedback_lines_have_actual_byte_count_and_no_origin_stat(self):
        raw = b"first\nsecond\n"
        with self.case(raw) as (_root, origin, _stage, _refs, view):
            with FEEDBACK.CapturedBoundedLines(origin, "lines", len(raw), 32, view) as lines:
                self.assertEqual(lines.byte_count, len(raw))
                self.assertFalse(hasattr(lines, "before"))
                self.assertEqual(list(lines), [b"first", b"second"])
                self.assertEqual(lines.finish(), sha(raw))
            self.assertFalse(origin.exists())

    def test_feedback_partial_consumption_cannot_finish(self):
        raw = b"first\nsecond\n"
        with self.case(raw) as (_root, origin, _stage, _refs, view):
            with FEEDBACK.CapturedBoundedLines(origin, "partial", len(raw), 32, view) as lines:
                self.assertEqual(next(iter(lines)), b"first")
                with self.assertRaisesRegex(FEEDBACK.ValidationError, "size differs from bytes consumed"):
                    lines.finish()

    def test_feedback_framing_and_line_limits_are_unchanged(self):
        for raw, maximum_line, message in ((b"long-line\n", 2, "oversized line"),
                                           (b"partial", 64, "partial final record"),
                                           (b"line\r\n", 64, "invalid framing"),
                                           (b"line\0\n", 64, "invalid framing")):
            with self.subTest(raw=raw), self.case(raw) as (_root, origin, _stage, _refs, view):
                with FEEDBACK.CapturedBoundedLines(origin, "framing", len(raw), maximum_line, view) as lines:
                    with self.assertRaisesRegex(FEEDBACK.ValidationError, message):
                        list(lines)

    def test_capture_replacement_and_mutation_are_not_origin_facts(self):
        for variant in ("replacement", "mutation"):
            raw = b"first\nsecond\n"
            with self.subTest(variant=variant), self.case(raw) as (_root, origin, stage, refs, view):
                local = Path(refs[str(origin)]["path"])
                with self.assertRaisesRegex(FIXED.FixedPairError, "changed during replay"):
                    with FEEDBACK.CapturedBoundedLines(origin, "stable", len(raw), 32, view) as lines:
                        self.assertEqual(list(lines), [b"first", b"second"])
                        self.assertEqual(lines.finish(), sha(raw))
                        if variant == "replacement":
                            replacement = stage / "new"
                            replacement.write_bytes(raw)
                            replacement.chmod(0o400)
                            os.replace(replacement, local)
                        else:
                            local.chmod(0o600)

    def test_pressure_event_stream_matches_live_parser_after_reclaim(self):
        raw = PRESSURE.canonical_bytes({"sequence": 0}) + PRESSURE.canonical_bytes({"sequence": 1})
        with self.case(raw, "events.jsonl") as (_root, origin, _stage, _refs, view):
            origin.parent.mkdir(mode=0o700)
            origin.write_bytes(raw)
            before = {}
            legacy = list(PRESSURE._iter_events(origin, sha(raw), len(raw), 1024, before))
            origin.unlink()
            state = {}
            captured = list(PRESSURE._iter_events(origin, sha(raw), len(raw), 1024, state, artifact_view=view))
            self.assertEqual((captured, state), (legacy, before))
            self.assertEqual(state["event_count"], 2)
            self.assertEqual(state["events_sha256"], sha(raw))
            self.assertFalse(origin.exists())

    def test_repinned_pressure_events_must_still_be_canonical(self):
        raw = b'{"sequence": 0}\n'
        with self.case(raw, "events.jsonl") as (_root, origin, _stage, _refs, view):
            with self.assertRaisesRegex(PRESSURE.ReadbackError, "pressure event line 0 is not canonical"):
                list(PRESSURE._iter_events(origin, sha(raw), len(raw), 1024, {}, artifact_view=view))

    def test_pressure_event_snapshot_must_match_original_receipt_size(self):
        raw = PRESSURE.canonical_bytes({"sequence": 0})
        with self.case(raw, "events.jsonl") as (_root, origin, _stage, _refs, view):
            with self.assertRaisesRegex(PRESSURE.ReadbackError, "size/raw pin differs"):
                list(PRESSURE._iter_events(origin, sha(raw), len(raw) - 1, 1024, {}, artifact_view=view))

    def test_pressure_partial_consumption_never_sets_completed_digest(self):
        raw = PRESSURE.canonical_bytes({"sequence": 0}) + PRESSURE.canonical_bytes({"sequence": 1})
        with self.case(raw, "events.jsonl") as (_root, origin, _stage, _refs, view):
            state = {}
            stream = PRESSURE._iter_events(origin, sha(raw), len(raw), 1024, state, artifact_view=view)
            self.assertEqual(next(stream), {"sequence": 0})
            stream.close()
            self.assertEqual(state["event_count"], 1)
            self.assertNotIn("events_sha256", state)
            self.assertNotIn("events_bytes", state)

    def test_complete_feedback_event_and_sample_models_accept_captured_streams(self):
        with tempfile.TemporaryDirectory(prefix="captured-feedback-model-") as directory:
            root = Path(directory).resolve()
            fixture = FIXTURES.Fixture(root / "fixture", "mixed", profile="oversubscribed", capacity_trace=True)
            fixture.install_v4_source_v5()
            baseline_result = fixture.verify()
            self.assertFalse(baseline_result["qualification_eligible"])
            recipe = FEEDBACK._validate_expectation_body({key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"})
            paths = {name: fixture.trace / name for name in FEEDBACK.TRACE_FILES}
            def replay(factory, directory_fd):
                with factory("feedback-trace-manifest.tsv", FEEDBACK.MAX_MANIFEST_BYTES, FEEDBACK.MAX_MANIFEST_BYTES) as manifest_lines:
                    manifest = FEEDBACK._parse_manifest(list(manifest_lines), recipe)
                    manifest_sha = manifest_lines.finish(directory_fd)
                with factory("feedback-events.jsonl", FEEDBACK.MAX_EVENT_FILE_BYTES, FEEDBACK.MAX_EVENT_LINE_BYTES) as events:
                    self.assertEqual(events.byte_count, manifest["artifacts"]["feedback-events.jsonl"]["bytes"])
                    events_sha, model, event_info = FEEDBACK._validate_event_stream(events, directory_fd, recipe, manifest, fixture.hashes["events"])
                with factory("resource-samples.tsv", FEEDBACK.MAX_SAMPLE_FILE_BYTES, FEEDBACK.MAX_SAMPLE_LINE_BYTES) as samples:
                    self.assertEqual(samples.byte_count, manifest["artifacts"]["resource-samples.tsv"]["bytes"])
                    samples_sha = FEEDBACK._validate_resource_sample_rows(samples, directory_fd, recipe, manifest, fixture.hashes["samples"], model, event_info)
                return manifest_sha, events_sha, samples_sha, model.sample_count, event_info
            descriptor = FEEDBACK._open_trace_directory(fixture.trace)
            try:
                before = replay(lambda name, maximum, line: FEEDBACK.BoundedLines(descriptor, name, name, maximum, line), descriptor)
            finally:
                os.close(descriptor)
            stage, refs = stage_files(root, {path: path.read_bytes() for path in paths.values()})
            for path in paths.values():
                path.unlink()
            view = FIXED.CapturedFixedPairArtifactsV1(refs, stage)
            after = replay(lambda name, maximum, line: FEEDBACK.CapturedBoundedLines(paths[name], name, maximum, line, view), None)
            self.assertEqual(after, before)
            self.assertEqual(after[:3], tuple(fixture.hashes[key] for key in ("manifest", "events", "samples")))
            self.assertTrue(all(not path.exists() for path in paths.values()))


if __name__ == "__main__":
    unittest.main()
