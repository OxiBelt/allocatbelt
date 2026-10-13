#!/usr/bin/env python3
"""Freeze application-byte capacities from a separately validated native trace.

This producer consumes a before-confirmation capacity run. It measures committed
application bytes, not device or wire capacity, and never qualifies performance.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import types
from pathlib import Path
from typing import Any

REQUEST_SCHEMA = "allocatbelt.application-byte-capacity-request.v1"
RECEIPT_SCHEMA = "allocatbelt.application-byte-capacity-receipt.v1"
VALIDATION_SCHEMA = "allocatbelt.application-feedback-validation.v1"
CAPACITY_SCHEMA = "allocatbelt.app-byte-capacity.v1"
UNITS = "application_bytes_per_second"
U64_MAX = (1 << 64) - 1
MAX_METADATA = 16 * 1024 * 1024
MAX_STREAM = 1024 * 1024 * 1024
MAX_ROW = 8192
MAX_ROWS = 120_002


class CapacityError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CapacityError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"invalid {label} fields")
    return value


def digest(value: object) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "invalid SHA-256")
    return value


def integer(value: object, label: str, maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"invalid {label}")
    return value


def decimal(value: str, label: str) -> int:
    require(re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None, f"invalid {label}")
    return integer(int(value), label)


def token(value: object, label: str) -> str:
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", value)
            is not None, f"invalid {label}")
    return value


class PinnedFile:
    """Bounded anchored regular-file reader, checked again after EOF."""
    def __init__(self, path: Path, expected: str, maximum: int):
        require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
                "artifact path must be normalized and absolute")
        require(len(os.fsencode(path)) <= 4096, "artifact path exceeds bound")
        self.path = path
        self.expected = digest(expected)
        self.maximum = maximum
        self.count = 0
        self.hasher = hashlib.sha256()
        fd = self.open_anchored(path)
        try:
            self.before = os.fstat(fd)
            require(stat.S_ISREG(self.before.st_mode) and self.before.st_size <= maximum,
                    "artifact is not a bounded regular file")
            self.stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def open_anchored(path: Path) -> int:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in path.parts[1:-1]:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                os.close(directory)
                directory = next_fd
            return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                           os.O_CLOEXEC, dir_fd=directory)
        finally:
            os.close(directory)

    def line(self) -> bytes:
        raw = self.stream.readline(MAX_ROW + 1)
        self._add(raw)
        require(len(raw) <= MAX_ROW, "artifact row exceeds bound")
        require(not raw or (raw.endswith(b"\n") and b"\r" not in raw),
                "artifact row is not LF framed")
        return raw

    def _add(self, raw: bytes) -> None:
        self.count += len(raw)
        require(self.count <= self.maximum, "artifact exceeds byte bound")
        self.hasher.update(raw)

    def finish(self) -> None:
        after = os.fstat(self.stream.fileno())
        path_fd = self.open_anchored(self.path)
        try:
            current_path = os.fstat(path_fd)
        finally:
            os.close(path_fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(self.before, name) == getattr(after, name) ==
                    getattr(current_path, name) for name in fields),
                "artifact changed while read")
        require(self.count == after.st_size and self.hasher.hexdigest() == self.expected,
                "artifact size or SHA mismatch")

    def close(self) -> None:
        self.stream.close()


def metadata(pin: dict[str, Any], maximum: int = MAX_METADATA) -> tuple[dict[str, Any], bytes]:
    exact(pin, {"path", "sha256"}, "artifact pin")
    reader = PinnedFile(Path(pin["path"]), pin["sha256"], maximum)
    try:
        raw = reader.stream.read(maximum + 1)
        reader._add(raw)
        reader.finish()
    finally:
        reader.close()
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(CapacityError("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CapacityError("invalid JSON artifact") from error
    require(type(value) is dict and canonical(value) == raw, "metadata is not canonical JSON")
    return value, raw


def verify_validation(request: dict[str, Any]) -> dict[str, Any]:
    validation, _ = metadata(request["validation"])
    exact(validation, {"schema", "mode", "validated", "qualification_eligible",
                       "expectation_raw_sha256", "validator_sha256", "identity",
                       "raw_artifact_sha256", "production_window", "final_runtime_binding"},
          "feedback validation")
    require(validation["schema"] == VALIDATION_SCHEMA and
            validation["mode"] == "capacity_calibration" and
            validation["validated"] is True and validation["qualification_eligible"] is False,
            "capacity run lacks calibration-mode validation")
    require(validation["identity"] == request["identity"], "validation identity mismatch")
    require(validation["expectation_raw_sha256"] == request["expectation"]["sha256"] and
            validation["validator_sha256"] == digest(request["validator_sha256"]),
            "validator/expectation pin mismatch")
    hashes = exact(validation["raw_artifact_sha256"], {"manifest", "events", "samples"}, "trace digests")
    for value in hashes.values():
        digest(value)
    window = exact(validation["production_window"], {"start_monotonic_ns", "end_monotonic_ns",
                    "duration_lower_bound_ns", "duration_upper_bound_ns"}, "production window")
    start_lower, start_upper = bracket(window["start_monotonic_ns"])
    end_lower, end_upper = bracket(window["end_monotonic_ns"])
    lower_duration = integer(window["duration_lower_bound_ns"], "lower duration")
    upper_duration = integer(window["duration_upper_bound_ns"], "upper duration")
    require(end_lower > start_upper and lower_duration == end_lower - start_upper and
            upper_duration == end_upper - start_lower and
            29_000_000_000 <= lower_duration <= upper_duration <= 31_000_000_000,
            "capacity validation has an invalid thirty-second production window")
    exact(validation["final_runtime_binding"], {"raw_sha256", "validated"}, "final runtime binding")
    require(validation["final_runtime_binding"] == {"raw_sha256": None, "validated": False},
            "calibration receipt has an unexpected final proof")
    return validation


def bracket(value: object) -> tuple[int, int]:
    require(type(value) is list and len(value) == 2, "invalid clock bracket")
    lower, upper = (integer(item, "clock timestamp") for item in value)
    require(0 < lower <= upper and upper - lower <= 50_000_000, "invalid clock uncertainty")
    return lower, upper


def measure_samples(path: Path, expected: str, manifest_expected: str, start: int, end: int,
                    workload: str, minimum_ns: int) -> tuple[dict[str, Any], int]:
    reader = PinnedFile(path, expected, MAX_STREAM)
    try:
        require(reader.line() == b"schema\tallocatbelt.application-feedback-resource-sample.v1\n",
                "unknown resource sample schema")
        header = reader.line().decode("ascii").rstrip("\n").split("\t")
        require(len(header) == len(set(header)), "duplicate sample columns")
        needed = {"sample_sequence", "window_lower_ns", "window_upper_ns"}
        suffixes = ("measured_lower_ns", "measured_upper_ns", "committed_bytes", "completions",
                    "generation", "counter_overflow", "invalid_io", "source_count_overflow", "generation_overflow")
        needed |= {f"{direction}_meter_{suffix}" for direction in ("disk", "download") for suffix in suffixes}
        require(needed <= set(header), "sample meter columns missing")
        anchor_width = read_trace_clock_width(path.parent / "feedback-trace-manifest.tsv", manifest_expected)
        selected: dict[str, list[dict[str, int]]] = {"disk": [], "download": []}
        previous: dict[str, dict[str, int]] = {}
        previous_capture_lower: int | None = None
        previous_selected_lower: int | None = None
        count = 0
        while raw := reader.line():
            count += 1
            require(count <= MAX_ROWS, "too many sample rows")
            values = raw.decode("ascii").rstrip("\n").split("\t")
            require(len(values) == len(header), "sample column count mismatch")
            row = dict(zip(header, values))
            require(decimal(row["sample_sequence"], "sample sequence") == count, "sample sequence gap")
            capture_lower = decimal(row["window_lower_ns"], "capture window lower")
            capture_upper = decimal(row["window_upper_ns"], "capture window upper")
            require(0 < capture_lower <= capture_upper and capture_upper - capture_lower <= 200_000_000,
                    "invalid resource capture window")
            if previous_capture_lower is not None:
                capture_gap = capture_lower - previous_capture_lower
                require(0 < capture_gap <= 200_000_000,
                        "resource capture windows are duplicated, out of order, or sparse")
            previous_capture_lower = capture_lower
            in_production = capture_lower >= start and capture_upper <= end
            if in_production:
                if previous_selected_lower is not None:
                    capture_gap = capture_lower - previous_selected_lower
                    require(0 < capture_gap <= 200_000_000,
                            "selected production resource windows are duplicated, out of order, or sparse")
                previous_selected_lower = capture_lower
            for direction in selected:
                prefix = f"{direction}_meter_"
                for suffix in suffixes[5:]:
                    require(row[prefix + suffix] == "false", "meter diagnostics are latched")
                point = {key: decimal(row[prefix + key], key) for key in suffixes[:5]}
                lower, upper = point["measured_lower_ns"], point["measured_upper_ns"]
                require(0 < lower <= upper and upper - lower == anchor_width,
                        "meter timestamp bracket differs from the fixed trace clock")
                require(capture_lower <= lower <= upper <= capture_upper,
                        "meter observation falls outside its resource capture window")
                if direction in previous:
                    old = previous[direction]
                    require(point["generation"] == old["generation"] and
                            point["committed_bytes"] >= old["committed_bytes"] and
                            point["completions"] >= old["completions"] and
                            lower >= old["measured_lower_ns"], "meter reset or counter/time regression")
                previous[direction] = point
                if in_production:
                    if selected[direction]:
                        delta_ns = lower - selected[direction][-1]["measured_lower_ns"]
                        require(0 < delta_ns <= 200_000_000,
                                f"selected {direction} meter observations are duplicated, stale, or sparse")
                    if not selected[direction]:
                        selected[direction].append(point)
                    elif len(selected[direction]) == 1:
                        selected[direction].append(point)
                    else:
                        selected[direction][1] = point
        reader.finish()
    finally:
        reader.close()
    result: dict[str, Any] = {}
    for direction, endpoints in selected.items():
        require(len(endpoints) == 2, "production lacks meter interval endpoints")
        first, last = endpoints
        duration = last["measured_lower_ns"] - first["measured_lower_ns"]
        require(duration >= minimum_ns, "measured production interval is too short")
        delta = last["committed_bytes"] - first["committed_bytes"]
        completed = last["completions"] - first["completions"]
        applicable = workload in (("disk", "mixed") if direction == "disk" else ("http", "mixed"))
        if applicable:
            rate = delta * 1_000_000_000 // duration
            require(0 < rate <= U64_MAX and completed > 0, "applicable meter has no committed progress")
        else:
            require(delta == completed == 0, "unexpected IO progress in non-IO workload")
            rate = None
        result[direction] = {"bytes_per_second": rate, "units": UNITS if applicable else "missing",
                             "first": first, "last": last, "interval_ns": duration,
                             "committed_bytes_delta": delta, "completions_delta": completed}
    return result, count


def read_trace_clock_width(path: Path, expected: str) -> int:
    reader = PinnedFile(path, expected, 64 * 1024)
    lower: int | None = None
    upper: int | None = None
    try:
        require(reader.line() == b"schema\tallocatbelt.application-feedback-trace-manifest.v1\n",
                "unknown trace manifest schema")
        while raw := reader.line():
            if raw.startswith(b"clock_anchor\t"):
                require(lower is None, "duplicate trace clock anchor")
                parts = raw[:-1].decode("ascii").split("\t")
                require(len(parts) == 3, "malformed trace clock anchor")
                lower, upper = decimal(parts[1], "trace clock lower"), decimal(parts[2], "trace clock upper")
        reader.finish()
    finally:
        reader.close()
    require(lower is not None and upper is not None and 0 < lower <= upper and upper - lower <= 50_000_000,
            "trace manifest has no valid fixed clock anchor")
    return upper - lower


def _verify_expectation(request: dict[str, Any]) -> dict[str, Any]:
    expectation, raw = metadata(request["expectation"])
    require(hashlib.sha256(raw).hexdigest() == digest(request["expectation_sha256"]) ==
            request["expectation"]["sha256"], "caller-pinned expectation SHA mismatch")
    schema = expectation.get("schema")
    require(schema in ("allocatbelt.application-feedback-expectation.v1",
                       "allocatbelt.application-feedback-expectation.v2") and
            expectation.get("mode") == "capacity_calibration", "unsupported capacity expectation")
    keys = {"schema", "mode", "identity", "policy", "app_capacity_artifact_sha256",
            "host_binding", "external_pressure_proof", "final_runtime_binding",
            "minimum_production_seconds", "minimum_pressure_overlap_seconds", "recipe_sha256"}
    if schema == "allocatbelt.application-feedback-expectation.v2":
        keys.add("construction_probe")
    exact(expectation, keys, "caller-pinned feedback expectation")
    body = {key: value for key, value in expectation.items() if key != "recipe_sha256"}
    require(digest(expectation.get("recipe_sha256")) == hashlib.sha256(canonical(body)).hexdigest(),
            "expectation self digest mismatch")
    require(expectation.get("identity") == request["identity"], "caller-pinned expectation identity mismatch")
    require(expectation["app_capacity_artifact_sha256"] is None and
            expectation["external_pressure_proof"] is None and
            expectation["final_runtime_binding"] is None and
            expectation["identity"]["pressure_qualification"] is False and
            expectation["minimum_pressure_overlap_seconds"] == 0,
            "caller-pinned expectation is not a non-qualifying calibration")
    host_binding = exact(expectation.get("host_binding"), {"path", "raw_sha256"}, "expectation host binding")
    source_pin = exact(request["source_manifest"], {"path", "sha256"}, "source manifest pin")
    digest(source_pin["sha256"])
    require(host_binding["path"] == source_pin["path"] and
            digest(host_binding["raw_sha256"]) == source_pin["sha256"],
            "expectation host binding does not pin this source manifest")
    return expectation


def _campaign_module(source: dict[str, Any]) -> types.ModuleType:
    files = source.get("source", {}).get("files")
    require(type(files) is list, "source manifest inventory is malformed")
    records = [item for item in files if type(item) is dict and item.get("path") == "scripts/application-campaign.py"]
    require(len(records) == 1, "source inventory does not contain one campaign controller")
    record = exact(records[0], {"path", "kind", "mode", "sha256", "size"}, "campaign controller inventory record")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"),
            "campaign controller must be a regular tracked source file")
    expected_sha = digest(record["sha256"])
    expected_size = integer(record["size"], "campaign controller size", MAX_METADATA)
    path = Path(os.path.abspath(__file__)).with_name("application-campaign.py")
    reader = PinnedFile(path, expected_sha, MAX_METADATA)
    try:
        declared_mode = int(record["mode"], 8) & 0o777
        require(stat.S_IMODE(reader.before.st_mode) == declared_mode,
                "captured campaign controller mode differs from its regular source record")
        raw = reader.stream.read(MAX_METADATA + 1)
        reader._add(raw)
        reader.finish()
    finally:
        reader.close()
    require(len(raw) == expected_size, "captured campaign controller size differs from source inventory")
    module = types.ModuleType("allocatbelt_capacity_pinned_campaign")
    module.__file__ = str(path)
    try:
        code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception as error:
        raise CapacityError("pinned campaign controller cannot be loaded") from error
    require(getattr(module, "SOURCE_SCHEMA", None) == "allocatbelt.application-source-manifest.v4",
            "pinned campaign controller contract is unsupported")
    return module


def _verify_feedback_validator(source: dict[str, Any], expected_sha256: str) -> bytes:
    files = source.get("source", {}).get("files")
    require(type(files) is list, "source manifest inventory is malformed")
    records = [item for item in files if type(item) is dict and
               item.get("path") == "scripts/application-feedback-readback.py"]
    require(len(records) == 1, "source inventory does not contain one feedback validator")
    record = exact(records[0], {"path", "kind", "mode", "sha256", "size"},
                   "feedback validator inventory record")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"),
            "feedback validator must be a regular tracked source file")
    source_sha = digest(record["sha256"])
    require(source_sha == digest(expected_sha256),
            "caller-pinned SHA differs from the source-inventoried feedback validator")
    expected_size = integer(record["size"], "feedback validator size", MAX_METADATA)
    path = Path(os.path.abspath(__file__)).with_name("application-feedback-readback.py")
    reader = PinnedFile(path, source_sha, MAX_METADATA)
    try:
        raw = reader.stream.read(MAX_METADATA + 1)
        reader._add(raw)
        reader.finish()
    finally:
        reader.close()
    require(len(raw) == expected_size, "captured feedback validator size differs from source inventory")
    return raw


def verify_source(source: dict[str, Any], expectation: dict[str, Any], validator_sha256: str) -> None:
    require(source.get("schema") == "allocatbelt.application-source-manifest.v4",
            "unsupported source manifest schema")
    controller = _campaign_module(source)
    try:
        controller.verify_source_manifest(source, source_root=None, verify_artifacts=False)
    except controller.CampaignError as error:
        raise CapacityError(f"source manifest verification failed: {error}") from error
    identity = expectation["identity"]
    require(source["build"]["host_id"] == identity["host_id"] and
            source["source"]["source_tree_sha256"] == identity["source_sha256"] and
            source["artifacts"][identity["allocator"]]["sha256"] == identity["binary_sha256"],
            "source/host/binary binding mismatch")
    validator_raw = _verify_feedback_validator(source, validator_sha256)
    if expectation["schema"] == "allocatbelt.application-feedback-expectation.v2":
        _validate_construction_probe(source, expectation, validator_raw)


def _validate_construction_probe(
    source: dict[str, Any], expectation: dict[str, Any], validator_raw: bytes,
) -> None:
    """Reuse only captured, source-pinned reader code for the v2 projection."""
    path = Path(os.path.abspath(__file__)).with_name("application-feedback-readback.py")
    module = types.ModuleType("allocatbelt_capacity_pinned_feedback")
    module.__file__ = str(path)
    try:
        exec(compile(validator_raw, str(path), "exec", dont_inherit=True), module.__dict__)
        body = {key: value for key, value in expectation.items() if key != "recipe_sha256"}
        encoded, _ = module.build_pressure_expectation_recipe(body)
        require(encoded == canonical(expectation), "v2 expectation differs from its typed reader contract")
        module.validate_construction_probe(expectation, source)
    except CapacityError:
        raise
    except Exception as error:
        raise CapacityError(f"construction policy probe validation failed: {error}") from error


def verify_no_actuation(path: Path, expected: str) -> int:
    reader = PinnedFile(path, expected, MAX_STREAM)
    count = 0
    last: dict[str, Any] | None = None
    try:
        while raw := reader.line():
            count += 1
            require(count <= 500_000, "event count exceeds bound")
            try:
                last = json.loads(raw, object_pairs_hook=unique)
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise CapacityError("invalid event JSON") from error
            require(type(last) is dict and last.get("sequence") == count and
                    last.get("schema") == "allocatbelt.application-feedback-event.v1", "event sequence/schema mismatch")
            require(last.get("kind") not in ("apply", "worker_failure"), "calibration controls were not fixed")
        reader.finish()
    finally:
        reader.close()
    require(last is not None and last.get("kind") == "worker_joined" and last.get("panicked") is False,
            "calibration history lacks successful joined shutdown")
    return count


def produce(request: dict[str, Any], request_sha: str) -> tuple[bytes, dict[str, Any]]:
    exact(request, {"schema", "calibration_id", "identity", "source_manifest", "validation",
                    "expectation", "expectation_sha256", "validator_sha256", "trace_directory", "context",
                    "minimum_interval_seconds"}, "capacity request")
    require(request["schema"] == REQUEST_SCHEMA, "unknown capacity request schema")
    calibration_id = token(request["calibration_id"], "calibration id")
    identity = exact(request["identity"], {"host_id", "run_id", "report_nonce", "process_id",
                     "allocator", "executor", "workload", "profile", "mode", "source_sha256",
                     "binary_sha256", "pressure_qualification"}, "capacity identity")
    require(identity.get("mode") == "capacity" and
            identity.get("pressure_qualification") is False, "calibration is not a pre-confirmation capacity run")
    require(integer(identity["process_id"], "process id") > 0 and
            type(identity["report_nonce"]) is str and
            re.fullmatch(r"[0-9a-f]{32}", identity["report_nonce"]) is not None,
            "invalid process/nonce identity")
    for name in ("host_id", "run_id", "allocator", "executor", "workload", "profile"):
        token(identity.get(name), name)
    require(identity["workload"] in ("cpu", "memory", "disk", "http", "mixed"), "unknown workload")
    expectation = _verify_expectation(request)
    source, source_raw = metadata(request["source_manifest"])
    verify_source(source, expectation, request["validator_sha256"])
    validation = verify_validation(request)
    context, context_raw = metadata(request["context"])
    exact(context, {"schema", "identity", "stage", "storage", "network"}, "capacity context")
    require(context.get("schema") == "allocatbelt.application-capacity-context.v1" and
            context.get("identity") == identity and context.get("stage") == "pre_confirmation",
            "context is not bound to this pre-confirmation process")
    hashes = validation["raw_artifact_sha256"]
    directory = Path(request["trace_directory"])
    manifest = PinnedFile(directory / "feedback-trace-manifest.tsv", hashes["manifest"], 64 * 1024)
    try:
        require(manifest.line() == b"schema\tallocatbelt.application-feedback-trace-manifest.v1\n", "unknown trace manifest")
        complete = False
        while raw := manifest.line():
            if raw == b"completion\tcomplete\ttrue\n":
                require(not complete, "duplicate completion marker")
                complete = True
        manifest.finish()
        require(complete, "trace is incomplete")
    finally:
        manifest.close()
    window = exact(validation["production_window"], {"start_monotonic_ns", "end_monotonic_ns",
                    "duration_lower_bound_ns", "duration_upper_bound_ns"}, "production window")
    start_lower, start_upper = bracket(window["start_monotonic_ns"])
    end_lower, end_upper = bracket(window["end_monotonic_ns"])
    require(end_lower > start_upper and window["duration_lower_bound_ns"] == end_lower - start_upper and
            window["duration_upper_bound_ns"] == end_upper - start_lower, "production window does not reconcile")
    require(29_000_000_000 <= window["duration_lower_bound_ns"] <=
            window["duration_upper_bound_ns"] <= 31_000_000_000,
            "capacity production must cover the separate thirty-second lane")
    minimum = integer(request["minimum_interval_seconds"], "minimum interval", 30)
    require(minimum >= 10, "calibration interval must be at least ten seconds")
    measurements, rows = measure_samples(directory / "resource-samples.tsv", hashes["samples"],
                                         hashes["manifest"],
                                         start_upper, end_lower, identity["workload"], minimum * 1_000_000_000)
    events = verify_no_actuation(directory / "feedback-events.jsonl", hashes["events"])
    producer = Path(__file__).absolute()
    producer_raw_sha = hashlib.sha256(producer.read_bytes()).hexdigest()
    receipt: dict[str, Any] = {"schema": RECEIPT_SCHEMA, "request_raw_sha256": digest(request_sha),
        "producer_sha256": producer_raw_sha, "calibration_id": calibration_id,
        "identity": identity, "source_manifest_raw_sha256": hashlib.sha256(source_raw).hexdigest(),
        "validation_raw_sha256": request["validation"]["sha256"],
        "validator_sha256": request["validator_sha256"], "expectation_raw_sha256": request["expectation_sha256"],
        "context_raw_sha256": hashlib.sha256(context_raw).hexdigest(), "raw_trace_sha256": hashes,
        "measurements": measurements, "sample_rows": rows, "event_rows": events,
        "qualification_eligible": False, "claim": "committed_application_bytes_only"}
    provenance_sha = hashlib.sha256(canonical(receipt)).hexdigest()
    fields = {"schema": CAPACITY_SCHEMA, "calibration_id": calibration_id,
              "host_id": identity["host_id"], "profile": identity["profile"],
              "workload": identity["workload"], "source_sha256": identity["source_sha256"]}
    for direction, measurement in measurements.items():
        fields[direction + ".bytes_per_second"] = str(measurement["bytes_per_second"]) if measurement["bytes_per_second"] else "missing"
        fields[direction + ".units"] = measurement["units"]
        fields[direction + ".provenance"] = "application-trace:" + provenance_sha
    artifact = "".join(name + "\t" + fields[name] + "\n" for name in sorted(fields)).encode("ascii")
    require(len(artifact) <= 4096, "capacity artifact exceeds runtime bound")
    receipt["provenance_material_sha256"] = provenance_sha
    receipt["capacity_artifact_raw_sha256"] = hashlib.sha256(artifact).hexdigest()
    return artifact, receipt


def _open_absolute_directory(path: Path) -> int:
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
            "directory path must be normalized and absolute")
    require(len(os.fsencode(path)) <= 4096, "directory path exceeds bound")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            require(component not in ("", ".", ".."), "directory path has an unsafe component")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        require(stat.S_ISDIR(os.fstat(fd).st_mode), "directory descriptor is not a directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_staged_file(directory_fd: int, name: str, raw: bytes) -> None:
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            require(written > 0, "short write while staging capacity bundle")
            offset += written
        os.fsync(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_size == len(raw), "staged capacity file metadata mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
        check = bytearray()
        while len(check) <= len(raw):
            block = os.read(fd, min(64 * 1024, len(raw) + 1 - len(check)))
            if not block:
                break
            check.extend(block)
        require(bytes(check) == raw and hashlib.sha256(check).digest() == hashlib.sha256(raw).digest(),
                "staged capacity file readback mismatch")
    finally:
        os.close(fd)


def _rename_noreplace(directory_fd: int, old_name: str, new_name: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable; refusing non-atomic publication") from error
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(directory_fd, os.fsencode(old_name), directory_fd,
                       os.fsencode(new_name), 1)  # RENAME_NOREPLACE
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), new_name)


def _verify_bundle(directory_fd: int, expected_files: dict[str, bytes]) -> None:
    directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=directory_fd)
    try:
        directory_stat = os.fstat(directory)
        require(stat.S_ISDIR(directory_stat.st_mode) and stat.S_IMODE(directory_stat.st_mode) == 0o700,
                "capacity bundle directory mode changed")
        require(set(os.listdir(directory)) == set(expected_files),
                "published capacity bundle has an unexpected file set")
        for name, expected in expected_files.items():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600 and
                        before.st_size == len(expected), "published capacity file metadata mismatch")
                observed = bytearray()
                while len(observed) <= len(expected):
                    block = os.read(fd, min(64 * 1024, len(expected) + 1 - len(observed)))
                    if not block:
                        break
                    observed.extend(block)
                after = os.fstat(fd)
                require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                        bytes(observed) == expected, "published capacity file changed during readback")
            finally:
                os.close(fd)
    finally:
        os.close(directory)


def publish_bundle(output_directory: Path, artifact: bytes, receipt_raw: bytes) -> None:
    require(output_directory.is_absolute() and str(output_directory) == os.path.normpath(str(output_directory)),
            "output directory must be normalized and absolute")
    final_name = output_directory.name
    require(final_name not in ("", ".", "..") and "/" not in final_name and "\x00" not in final_name and
            len(os.fsencode(final_name)) <= 255, "output bundle name is invalid")
    parent_path = output_directory.parent
    parent_fd = _open_absolute_directory(parent_path)
    stage_fd = -1
    stage_name = ""
    expected_files = {
        "application-byte-capacity.tsv": artifact,
        "capacity-receipt.json": receipt_raw,
    }
    try:
        parent_identity = os.fstat(parent_fd)
        for _ in range(8):
            candidate = ".capacity-stage-" + secrets.token_hex(16)
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_fd)
                stage_name = candidate
                break
            except FileExistsError:
                continue
        require(bool(stage_name), "could not allocate a unique capacity staging directory")
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent_fd)
        os.fchmod(stage_fd, 0o700)
        stage_stat = os.fstat(stage_fd)
        require(stat.S_ISDIR(stage_stat.st_mode) and stat.S_IMODE(stage_stat.st_mode) == 0o700 and
                stage_stat.st_uid == os.getuid(), "capacity staging directory is not private")
        for name, raw in expected_files.items():
            _write_staged_file(stage_fd, name, raw)
        os.fsync(stage_fd)
        _verify_bundle(stage_fd, expected_files)
        named_stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
        require((stage_stat.st_dev, stage_stat.st_ino) == (named_stage.st_dev, named_stage.st_ino) and
                stat.S_ISDIR(named_stage.st_mode), "capacity staging directory was replaced")
        check_parent_fd = _open_absolute_directory(parent_path)
        try:
            checked_parent = os.fstat(check_parent_fd)
        finally:
            os.close(check_parent_fd)
        require((parent_identity.st_dev, parent_identity.st_ino) ==
                (checked_parent.st_dev, checked_parent.st_ino), "capacity output parent changed while staging")
        _rename_noreplace(parent_fd, stage_name, final_name)
        os.fsync(parent_fd)
        check_parent_fd = _open_absolute_directory(parent_path)
        try:
            checked_parent = os.fstat(check_parent_fd)
        finally:
            os.close(check_parent_fd)
        require((parent_identity.st_dev, parent_identity.st_ino) ==
                (checked_parent.st_dev, checked_parent.st_ino), "capacity output parent changed during publication")
        final_fd = os.open(final_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent_fd)
        try:
            final_stat = os.fstat(final_fd)
            require((stage_stat.st_dev, stage_stat.st_ino) == (final_stat.st_dev, final_stat.st_ino),
                    "published capacity bundle is not the staged directory")
            _verify_bundle(final_fd, expected_files)
        finally:
            os.close(final_fd)
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        request, _ = metadata({"path": str(args.request), "sha256": args.request_sha256})
        artifact, receipt = produce(request, args.request_sha256)
        publish_bundle(args.output_directory, artifact, canonical(receipt))
        print(json.dumps({"capacity_artifact_raw_sha256": receipt["capacity_artifact_raw_sha256"],
                          "qualification_eligible": False}, sort_keys=True))
        return 0
    except (OSError, CapacityError, KeyError, TypeError, UnicodeError) as error:
        print(f"application byte capacity refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
