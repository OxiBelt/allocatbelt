#!/usr/bin/env python3
"""Offline unit witnesses for bounded application-byte calibration production."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("application-byte-capacity.py")
SPEC = importlib.util.spec_from_file_location("byte_capacity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
capacity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capacity)

CAMPAIGN_TEST_PATH = Path(__file__).with_name("test-application-campaign.py")
CAMPAIGN_TEST_SPEC = importlib.util.spec_from_file_location("capacity_campaign_fixtures", CAMPAIGN_TEST_PATH)
assert CAMPAIGN_TEST_SPEC is not None and CAMPAIGN_TEST_SPEC.loader is not None
campaign_fixtures = importlib.util.module_from_spec(CAMPAIGN_TEST_SPEC)
CAMPAIGN_TEST_SPEC.loader.exec_module(campaign_fixtures)


class Fixture:
    def __init__(self, root: Path, workload: str = "mixed"):
        self.root = root
        self.trace = root / "trace"
        self.trace.mkdir(mode=0o700)
        self.identity = {"host_id": "synthetic-host", "run_id": "calibration",
                         "report_nonce": "a" * 32, "process_id": 123,
                         "allocator": "allocatbelt", "executor": "allocatbelt",
                         "workload": workload, "profile": "steady", "mode": "capacity",
                         "source_sha256": "b" * 64, "binary_sha256": "c" * 64,
                         "pressure_qualification": False}
        self.base = 100_000_000_000
        self.interval = 100_000_000
        self.header = ["sample_sequence", "window_lower_ns", "window_upper_ns"]
        suffixes = ("measured_lower_ns", "measured_upper_ns", "committed_bytes", "completions",
                    "generation", "counter_overflow", "invalid_io", "source_count_overflow", "generation_overflow")
        self.header += [f"{name}_meter_{suffix}" for name in ("disk", "download") for suffix in suffixes]
        rows = []
        for index in range(301):
            at = self.base + index * self.interval
            row = [str(index + 1), str(at), str(at + 10)]
            for name, step in (("disk", 1000), ("download", 2000)):
                applicable = workload in (("disk", "mixed") if name == "disk" else ("http", "mixed"))
                row += [str(at), str(at + 10), str(index * step if applicable else 0),
                        str(index if applicable else 0), "1", "false", "false", "false", "false"]
            rows.append(row)
        self.rows = rows
        self.write_samples()
        self.manifest = self.trace / "feedback-trace-manifest.tsv"
        self.manifest.write_bytes(("schema\tallocatbelt.application-feedback-trace-manifest.v1\n"
                                   f"clock_anchor\t{self.base}\t{self.base + 10}\n"
                                   "completion\tcomplete\ttrue\n").encode())
        self.events = self.trace / "feedback-events.jsonl"
        self.events.write_bytes(capacity.canonical({"schema": "allocatbelt.application-feedback-event.v1",
                                                   "sequence": 1, "kind": "worker_joined", "panicked": False}))
        self.source = campaign_fixtures.source_for(self.identity["host_id"])
        campaign_path = Path(__file__).with_name("application-campaign.py")
        self.source["source"]["files"].append({
            "path": "scripts/application-campaign.py", "kind": "file",
            "mode": f"100{stat.S_IMODE(campaign_path.stat().st_mode):03o}",
            "sha256": hashlib.sha256(campaign_path.read_bytes()).hexdigest(),
            "size": campaign_path.stat().st_size,
        })
        feedback_path = Path(__file__).with_name("application-feedback-readback.py")
        self.feedback_validator_sha = hashlib.sha256(feedback_path.read_bytes()).hexdigest()
        self.source["source"]["files"].append({
            "path": "scripts/application-feedback-readback.py", "kind": "file", "mode": "100644",
            "sha256": self.feedback_validator_sha, "size": feedback_path.stat().st_size,
        })
        self.source["source"]["files"].sort(key=lambda item: item["path"].encode("utf-8"))
        inventory = campaign_fixtures.campaign.source_inventory_module()
        self.identity["source_sha256"] = inventory.digest_records(self.source["source"]["files"])
        self.source["source"]["source_tree_sha256"] = self.identity["source_sha256"]
        self.source["artifacts"]["allocatbelt"]["sha256"] = self.identity["binary_sha256"]
        self.source["resource_domain_calibration"]["source"]["source_tree_sha256"] = self.identity["source_sha256"]
        self.source["manifest_sha256"] = campaign_fixtures.campaign.digest_object(
            {key: value for key, value in self.source.items() if key != "manifest_sha256"})
        self.validator_sha = self.feedback_validator_sha
        assert self.validator_sha != self.source["runtime_readback_validator"]["sha256"]
        self.source_pin = self.pin_json("source.json", self.source)
        self.context = {"schema": "allocatbelt.application-capacity-context.v1", "identity": self.identity,
                        "stage": "pre_confirmation", "storage": {"scope": "synthetic_fixture"},
                        "network": {"scope": "synthetic_fixture"}}
        self.expectation = self.make_expectation()
        self.expectation_pin = self.pin_json("expectation.json", self.expectation)
        self.request = {"schema": capacity.REQUEST_SCHEMA, "calibration_id": "before-confirmation",
                        "identity": self.identity, "source_manifest": self.source_pin,
                        "expectation": self.expectation_pin,
                        "context": self.pin_json("context.json", self.context),
                        "expectation_sha256": self.expectation_pin["sha256"], "validator_sha256": self.validator_sha,
                        "trace_directory": str(self.trace), "minimum_interval_seconds": 10}
        self.refresh_validation()

    @staticmethod
    def pin(path: Path) -> dict[str, str]:
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def pin_json(self, name: str, value: object) -> dict[str, str]:
        path = self.root / name
        path.write_bytes(capacity.canonical(value))
        return self.pin(path)

    def make_expectation(self) -> dict:
        body = {"schema": "allocatbelt.application-feedback-expectation.v1",
                "mode": "capacity_calibration", "identity": self.identity,
                "policy": {}, "app_capacity_artifact_sha256": None,
                "host_binding": {"path": self.source_pin["path"], "raw_sha256": self.source_pin["sha256"]},
                "external_pressure_proof": None, "final_runtime_binding": None,
                "minimum_production_seconds": 30, "minimum_pressure_overlap_seconds": 0}
        body["recipe_sha256"] = hashlib.sha256(capacity.canonical(body)).hexdigest()
        return body

    def repin_expectation(self) -> None:
        self.expectation = self.make_expectation()
        self.expectation_pin = self.pin_json("expectation.json", self.expectation)
        self.request["expectation"] = self.expectation_pin
        self.request["expectation_sha256"] = self.expectation_pin["sha256"]

    def repin_source(self) -> None:
        self.source["manifest_sha256"] = campaign_fixtures.campaign.digest_object(
            {key: value for key, value in self.source.items() if key != "manifest_sha256"})
        self.source_pin = self.pin_json("source.json", self.source)
        self.request["source_manifest"] = self.source_pin
        self.repin_expectation()

    def write_samples(self) -> None:
        raw = "schema\tallocatbelt.application-feedback-resource-sample.v1\n"
        raw += "\t".join(self.header) + "\n"
        raw += "".join("\t".join(row) + "\n" for row in self.rows)
        (self.trace / "resource-samples.tsv").write_text(raw)

    def refresh_validation(self) -> None:
        lower = 30_000_000_000 - 10
        report = {"schema": capacity.VALIDATION_SCHEMA, "mode": "capacity_calibration",
                  "validated": True, "qualification_eligible": False,
                  "identity": self.identity, "expectation_raw_sha256": self.expectation_pin["sha256"],
                  "validator_sha256": self.validator_sha,
                  "raw_artifact_sha256": {"manifest": self.pin(self.manifest)["sha256"],
                                           "events": self.pin(self.events)["sha256"],
                                           "samples": self.pin(self.trace / "resource-samples.tsv")["sha256"]},
                  "production_window": {"start_monotonic_ns": [self.base, self.base + 10],
                                        "end_monotonic_ns": [self.base + 30_000_000_000,
                                                             self.base + 30_000_000_010],
                                        "duration_lower_bound_ns": lower,
                                        "duration_upper_bound_ns": 30_000_000_010},
                  "final_runtime_binding": {"raw_sha256": None, "validated": False}}
        self.request["validation"] = self.pin_json("validation.json", report)

    def produce(self):
        raw_sha = hashlib.sha256(capacity.canonical(self.request)).hexdigest()
        return capacity.produce(self.request, raw_sha)


class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="byte-capacity-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))

    def test_exact_application_rates_and_transitive_provenance(self):
        artifact, receipt = self.fixture.produce()
        values = dict(line.split("\t") for line in artifact.decode().splitlines())
        self.assertEqual(values["disk.bytes_per_second"], "10000")
        self.assertEqual(values["download.bytes_per_second"], "20000")
        self.assertLessEqual(len(artifact), 4096)
        self.assertFalse(receipt["qualification_eligible"])
        self.assertNotEqual(self.fixture.validator_sha,
                            self.fixture.source["runtime_readback_validator"]["sha256"])
        material = dict(receipt)
        proof = material.pop("provenance_material_sha256")
        material.pop("capacity_artifact_raw_sha256")
        self.assertEqual(hashlib.sha256(capacity.canonical(material)).hexdigest(), proof)
        self.assertEqual(values["disk.provenance"], "application-trace:" + proof)

    def test_non_io_workloads_keep_missing_denominators(self):
        root = Path(self.temp.name) / "cpu"
        root.mkdir()
        fixture = Fixture(root, "cpu")
        artifact, _ = fixture.produce()
        values = dict(line.split("\t") for line in artifact.decode().splitlines())
        self.assertEqual(values["disk.bytes_per_second"], "missing")
        self.assertEqual(values["download.units"], "missing")

    def test_counter_reset_and_generation_change_reject_even_with_new_digests(self):
        index = self.fixture.header.index("disk_meter_generation")
        self.fixture.rows[150][index] = "2"
        self.fixture.write_samples()
        self.fixture.refresh_validation()
        with self.assertRaises(capacity.CapacityError):
            self.fixture.produce()

    def test_latched_diagnostics_and_applied_control_reject(self):
        index = self.fixture.header.index("disk_meter_invalid_io")
        self.fixture.rows[100][index] = "true"
        self.fixture.write_samples()
        self.fixture.refresh_validation()
        with self.assertRaises(capacity.CapacityError):
            self.fixture.produce()
        self.fixture.rows[100][index] = "false"
        self.fixture.write_samples()
        event = {"schema": "allocatbelt.application-feedback-event.v1", "sequence": 1, "kind": "apply"}
        self.fixture.events.write_bytes(capacity.canonical(event))
        self.fixture.refresh_validation()
        with self.assertRaises(capacity.CapacityError):
            self.fixture.produce()

    def test_meter_bracket_must_fit_enclosing_capture_window(self):
        lower_index = self.fixture.header.index("disk_meter_measured_lower_ns")
        upper_index = self.fixture.header.index("disk_meter_measured_upper_ns")
        self.fixture.rows[120][lower_index] = str(int(self.fixture.rows[120][lower_index]) - 1)
        self.fixture.rows[120][upper_index] = str(int(self.fixture.rows[120][upper_index]) - 1)
        self.fixture.write_samples()
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "outside its resource capture window"):
            self.fixture.produce()

    def test_dense_resource_rows_reject_stale_meter_observation(self):
        lower_index = self.fixture.header.index("window_lower_ns")
        upper_index = self.fixture.header.index("window_upper_ns")
        disk_lower = self.fixture.header.index("disk_meter_measured_lower_ns")
        disk_upper = self.fixture.header.index("disk_meter_measured_upper_ns")
        for index, lo, hi in ((150, 15_000_000_000, 15_200_000_000),
                              (151, 15_100_000_000, 15_300_000_000)):
            row = self.fixture.rows[index]
            row[lower_index] = str(self.fixture.base + lo)
            row[upper_index] = str(self.fixture.base + hi)
            row[disk_lower] = str(self.fixture.base + 15_100_000_000)
            row[disk_upper] = str(self.fixture.base + 15_100_000_010)
        self.fixture.write_samples()
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "duplicated, stale, or sparse"):
            self.fixture.produce()

    def test_meter_jump_over_two_hundred_milliseconds_rejects(self):
        lower_index = self.fixture.header.index("window_lower_ns")
        upper_index = self.fixture.header.index("window_upper_ns")
        disk_lower = self.fixture.header.index("disk_meter_measured_lower_ns")
        disk_upper = self.fixture.header.index("disk_meter_measured_upper_ns")
        row150 = self.fixture.rows[150]
        row150[lower_index] = str(self.fixture.base + 15_000_000_000)
        row150[upper_index] = str(self.fixture.base + 15_200_000_000)
        row150[disk_lower] = str(self.fixture.base + 15_000_000_000)
        row150[disk_upper] = str(self.fixture.base + 15_000_000_010)
        row151 = self.fixture.rows[151]
        row151[lower_index] = str(self.fixture.base + 15_100_000_000)
        row151[upper_index] = str(self.fixture.base + 15_300_000_000)
        row151[disk_lower] = str(self.fixture.base + 15_201_000_000)
        row151[disk_upper] = str(self.fixture.base + 15_201_000_010)
        self.fixture.write_samples()
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "duplicated, stale, or sparse"):
            self.fixture.produce()

    def test_expectation_must_bind_exact_source_manifest_and_v4_contract(self):
        self.fixture.expectation["host_binding"]["raw_sha256"] = "f" * 64
        self.fixture.expectation.pop("recipe_sha256")
        self.fixture.expectation["recipe_sha256"] = hashlib.sha256(
            capacity.canonical(self.fixture.expectation)).hexdigest()
        self.fixture.expectation_pin = self.fixture.pin_json("expectation.json", self.fixture.expectation)
        self.fixture.request["expectation"] = self.fixture.expectation_pin
        self.fixture.request["expectation_sha256"] = self.fixture.expectation_pin["sha256"]
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "does not pin this source manifest"):
            self.fixture.produce()

    def test_feedback_validator_hash_is_distinct_from_fixed_runtime_validator(self):
        self.fixture.request["validator_sha256"] = self.fixture.source["runtime_readback_validator"]["sha256"]
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "source-inventoried feedback validator"):
            self.fixture.produce()

    def test_future_source_schema_label_is_not_supported(self):
        self.fixture.source["schema"] = "allocatbelt.application-source-manifest.v5"
        self.fixture.repin_source()
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "unsupported source manifest schema"):
            self.fixture.produce()

    def test_full_controller_rejects_pinned_manifest_with_bad_selfdigest(self):
        self.fixture.source["build"]["host_id"] = "different-host"
        self.fixture.source_pin = self.fixture.pin_json("source.json", self.fixture.source)
        self.fixture.request["source_manifest"] = self.fixture.source_pin
        self.fixture.repin_expectation()
        self.fixture.refresh_validation()
        with self.assertRaisesRegex(capacity.CapacityError, "source-manifest digest mismatch"):
            self.fixture.produce()

    def test_tampered_samples_and_unvalidated_receipt_reject(self):
        with (self.fixture.trace / "resource-samples.tsv").open("ab") as out:
            out.write(b"bad\n")
        with self.assertRaises(capacity.CapacityError):
            self.fixture.produce()
        root = Path(self.temp.name) / "unvalidated"
        root.mkdir()
        fixture = Fixture(root)
        path = Path(fixture.request["validation"]["path"])
        report = json.loads(path.read_bytes())
        report["validated"] = False
        fixture.request["validation"] = fixture.pin_json("validation.json", report)
        with self.assertRaises(capacity.CapacityError):
            fixture.produce()

    def test_symlink_and_replaced_file_are_not_accepted(self):
        path = Path(self.temp.name) / "file"
        path.write_bytes(b"abc\n")
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        link = Path(self.temp.name) / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            capacity.PinnedFile(link, sha, 100)
        reader = capacity.PinnedFile(path, sha, 100)
        self.addCleanup(reader.close)
        self.assertEqual(reader.line(), b"abc\n")
        path.rename(path.with_name("old"))
        path.write_bytes(b"abc\n")
        with self.assertRaises(capacity.CapacityError):
            reader.finish()

    def test_bundle_publication_is_atomic_no_replace_and_private(self):
        parent = Path(self.temp.name) / "publish"
        parent.mkdir(mode=0o700)
        final = parent / "bundle"
        artifact, receipt = b"capacity\n", b"receipt\n"
        capacity.publish_bundle(final, artifact, receipt)
        self.assertEqual((final / "application-byte-capacity.tsv").read_bytes(), artifact)
        self.assertEqual((final / "capacity-receipt.json").read_bytes(), receipt)
        self.assertEqual(stat.S_IMODE(final.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((final / "application-byte-capacity.tsv").stat().st_mode), 0o600)

    def test_bundle_publication_refuses_existing_directory_or_symlink(self):
        parent = Path(self.temp.name) / "no-replace"
        parent.mkdir(mode=0o700)
        final = parent / "existing"
        final.mkdir(mode=0o700)
        marker = final / "kept"
        marker.write_text("preserve")
        with self.assertRaises(OSError):
            capacity.publish_bundle(final, b"new", b"receipt")
        self.assertEqual(marker.read_text(), "preserve")
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        link = parent / "linked"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            capacity.publish_bundle(link, b"new", b"receipt")
        self.assertEqual(list(outside.iterdir()), [])
        parent_link = Path(self.temp.name) / "parent-link"
        parent_link.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(OSError):
            capacity.publish_bundle(parent_link / "through-link", b"new", b"receipt")

    def test_second_file_failure_retains_only_private_staging_directory(self):
        parent = Path(self.temp.name) / "injected-failure"
        parent.mkdir(mode=0o700)
        final = parent / "bundle"
        original = capacity._write_staged_file

        def fail_second(directory_fd, name, raw):
            if name == "capacity-receipt.json":
                raise OSError("injected second-file failure")
            original(directory_fd, name, raw)

        with mock.patch.object(capacity, "_write_staged_file", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "injected second-file failure"):
                capacity.publish_bundle(final, b"capacity", b"receipt")
        self.assertFalse(final.exists())
        stages = list(parent.glob(".capacity-stage-*"))
        self.assertEqual(len(stages), 1)
        self.assertEqual([path.name for path in stages[0].iterdir()], ["application-byte-capacity.tsv"])
        self.assertEqual(stat.S_IMODE(stages[0].stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((stages[0] / "application-byte-capacity.tsv").stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
