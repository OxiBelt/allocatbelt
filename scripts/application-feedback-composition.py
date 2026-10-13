#!/usr/bin/env python3
"""Compose prelaunch calibrated feedback policy and post-Popen expectations.

This module consumes source-pinned SourceV5, application-byte capacity, and
construction-probe inputs. It resolves policy numerics without launching a
workload and always emits ineligible preparation receipts. A separate
finalization step requires the caller's actual positive application PID.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any


REQUEST_SCHEMA = "allocatbelt.application-feedback-composition-request.v1"
POLICY_SCHEMA = "allocatbelt.application-feedback-resolved-policy.v1"
RECEIPT_SCHEMA = "allocatbelt.application-feedback-composition-receipt.v1"
FINALIZE_SCHEMA = "allocatbelt.application-feedback-expectation-finalization.v1"
FINALIZE_RECEIPT_SCHEMA = "allocatbelt.application-feedback-expectation-finalization-receipt.v1"
EXPECTATION_SCHEMA_V5 = "allocatbelt.application-feedback-expectation.v5"
SOURCE_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
CAPACITY_REQUEST_SCHEMA = "allocatbelt.application-byte-capacity-request.v1"
CAPACITY_RECEIPT_SCHEMA = "allocatbelt.application-byte-capacity-receipt.v1"
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_PROBE_BYTES = 512 * 1024
MAX_SMALL_ARTIFACT_BYTES = 4096
SOURCE_ROOT = Path(__file__).resolve().parent.parent
FEEDBACK_READER = "scripts/application-feedback-readback.py"
CAPACITY_PRODUCER = "scripts/application-byte-capacity.py"


class CompositionError(ValueError):
    """A pinned SourceV5 composition input fails its exact contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompositionError(message)


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise CompositionError(f"value is not canonical JSON: {error}") from error


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value: object, label: str = "SHA-256") -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"{label} is malformed")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected key set")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = (1 << 64) - 1) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be an unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def absolute_path(value: object, label: str) -> Path:
    require(type(value) is str and 0 < len(value) <= 4096, f"{label} must be a bounded absolute path")
    path = Path(value)
    require(path.is_absolute() and str(path) == value and ".." not in PurePosixPath(value).parts, f"{label} must be normalized and absolute")
    return path


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    try:
        require(path.resolve(strict=True) == path, f"{label} traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise CompositionError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its byte bound")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - len(raw)))
            require(block, f"{label} was truncated while reading")
            raw.extend(block)
        after_fd, after_path = os.fstat(fd), path.lstat()
        require(key(before) == key(after_fd) == key(after_path), f"{label} changed during read")
        return bytes(raw), sha256(raw)
    finally:
        os.close(fd)


def _read_canonical(path: Path, label: str, expected_sha: object, maximum: int = MAX_METADATA_BYTES) -> tuple[dict[str, Any], bytes, str]:
    expected = digest(expected_sha, f"{label} raw SHA-256")
    raw, actual = _read_stable(path, label, maximum)
    require(actual == expected, f"{label} raw SHA-256 differs from its pin")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=lambda item: (_ for _ in ()).throw(CompositionError(f"non-finite JSON number: {item}")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CompositionError(f"{label} is not bounded JSON: {error}") from error
    require(type(value) is dict and canonical(value) == raw, f"{label} is not canonical JSON")
    return value, raw, actual


def _record(source: dict[str, Any], relative: str, label: str) -> dict[str, Any]:
    records = source.get("source", {}).get("files")
    require(type(records) is list, "SourceV5 typed inventory is missing")
    matches = [item for item in records if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 inventory must contain one {label} record")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"), f"SourceV5 {label} is not a canonical regular-file entry")
    digest(record["sha256"], f"SourceV5 {label} SHA-256")
    uint(record["size"], f"SourceV5 {label} size")
    return record


def _pinned_source_module(source: dict[str, Any], key: str, relative: str, label: str, maximum: int) -> types.ModuleType:
    harness = source.get("qualification_harness")
    require(type(harness) is dict and key in harness, f"SourceV5 harness omits {label}")
    pin = exact(harness[key], {"path", "sha256"}, f"SourceV5 {label} pin")
    record = _record(source, relative, label)
    require(pin == {"path": relative, "sha256": record["sha256"]}, f"SourceV5 {label} harness pin differs from its regular inventory entry")
    path = SOURCE_ROOT.joinpath(*PurePosixPath(relative).parts)
    raw, actual = _read_stable(path, f"pinned {label}", maximum)
    info = path.stat(follow_symlinks=False)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == record["sha256"] and len(raw) == record["size"] and mode == record["mode"], f"installed {label} differs from SourceV5 inventory bytes")
    module = types.ModuleType(f"source5_{key}_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise CompositionError(f"pinned {label} cannot be compiled: {error}") from error
    return module


def _load_verified_inputs(request: dict[str, Any]) -> tuple[Any, Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_pin = exact(request["source_manifest"], {"path", "raw_sha256"}, "SourceV5 manifest pin")
    source_path = absolute_path(source_pin["path"], "SourceV5 manifest path")
    source, source_raw, source_raw_sha = _read_canonical(source_path, "SourceV5 manifest", source_pin["raw_sha256"])
    require(source.get("schema") == SOURCE_SCHEMA_V5, "composition requires a SourceV5 manifest")
    source_root = absolute_path(request["source_root"], "SourceV5 source root")
    require(source_root == SOURCE_ROOT, "composition source root must be the root containing its pinned harness siblings")
    context = exact(request["context"], {"host_id", "workload", "profile", "calibration_id"}, "composition context")
    require(all(type(context[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", context[key]) for key in context), "composition context has an invalid token")
    reader = _pinned_source_module(source, "feedback_validator", FEEDBACK_READER, "feedback validator", MAX_METADATA_BYTES)
    probe_pin = exact(request["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "construction probe pin")
    require(probe_pin["allocator"] in reader.APPLICATION_ALLOCATOR_LABELS, "construction probe allocator is outside the original application artifact set")
    identity = {
        "host_id": context["host_id"], "workload": context["workload"], "profile": context["profile"],
        "allocator": probe_pin["allocator"], "source_sha256": source["source"]["source_tree_sha256"],
        "binary_sha256": digest(probe_pin["binary_sha256"], "construction probe binary SHA-256"),
    }
    require(source["build"]["host_id"] == context["host_id"], "composition host differs from SourceV5 build host")
    minimal = {"schema": EXPECTATION_SCHEMA_V5, "mode": "pressure_validation", "identity": identity}
    try:
        reader._verify_source_manifest_v5(source, minimal)
    except Exception as error:
        raise CompositionError(f"pinned SourceV5 full verifier rejected the source: {error}") from error
    producer = _pinned_source_module(source, "byte_capacity_producer", CAPACITY_PRODUCER, "byte-capacity producer", MAX_METADATA_BYTES)
    return reader, producer, source, context, identity


def _verify_capacity_request_binding(
    reader: Any, producer: Any, source: dict[str, Any], context: dict[str, Any], identity: dict[str, Any],
    source_pin: dict[str, Any], bundle: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    request_pin = exact(bundle["request"], {"path", "raw_sha256"}, "capacity request pin")
    artifact_pin = exact(bundle["artifact"], {"path", "raw_sha256"}, "capacity artifact pin")
    receipt_pin = exact(bundle["receipt"], {"path", "raw_sha256"}, "capacity receipt pin")
    request_path = absolute_path(request_pin["path"], "capacity request path")
    request, request_raw, request_sha = _read_canonical(request_path, "capacity request", request_pin["raw_sha256"])
    require(request.get("schema") == "allocatbelt.application-byte-capacity-request.v1", "unsupported capacity request schema")
    request_identity = exact(request.get("identity"), {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor", "workload", "profile",
        "mode", "source_sha256", "binary_sha256", "pressure_qualification",
    }, "capacity request identity")
    require(request_identity["host_id"] == context["host_id"] and request_identity["workload"] == context["workload"] and request_identity["profile"] == context["profile"], "capacity request context differs from the selected SourceV5 cell")
    require(request_identity["source_sha256"] == identity["source_sha256"] and request_identity["allocator"] in reader.APPLICATION_ALLOCATOR_LABELS, "capacity request source or allocator differs from SourceV5")
    calibrator_artifact = exact(source["artifacts"].get(request_identity["allocator"]), {"path", "sha256"}, "SourceV5 capacity calibrator artifact")
    require(request_identity["binary_sha256"] == calibrator_artifact["sha256"], "capacity request binary differs from its SourceV5 calibrator artifact")
    require(request_identity["executor"] in reader.V5_EXECUTOR_LABELS, "capacity request executor is outside the original native/Tokio role set")
    require(request_identity["mode"] == "capacity" and request_identity["pressure_qualification"] is False, "capacity request is not an ineligible calibration run")
    uint(request_identity["process_id"], "capacity request process ID", positive=True, maximum=(1 << 31) - 1)
    require(request.get("calibration_id") == context["calibration_id"], "capacity request calibration ID differs from the composition context")
    embedded_source_pin = exact(request.get("source_manifest"), {"path", "sha256"}, "capacity request SourceV5 manifest pin")
    require(embedded_source_pin == {"path": source_pin["path"], "sha256": source_pin["raw_sha256"]}, "capacity request does not pin the exact SourceV5 manifest bytes")
    expectation_pin = exact(request.get("expectation"), {"path", "sha256"}, "capacity expectation pin")
    expectation_path = absolute_path(expectation_pin["path"], "capacity expectation path")
    capacity_expectation, _expectation_raw, _ = _read_canonical(expectation_path, "capacity expectation", expectation_pin["sha256"])
    require(capacity_expectation.get("schema") == "allocatbelt.application-feedback-expectation.v4" and capacity_expectation.get("mode") == "capacity_calibration", "capacity request does not carry the SourceV5 V4 calibration expectation")
    require(capacity_expectation.get("identity") == request_identity, "capacity expectation identity differs from its producer request")
    capacity_host_pin = exact(capacity_expectation.get("host_binding"), {"path", "raw_sha256"}, "capacity expectation SourceV5 host binding")
    require(capacity_host_pin["path"] == embedded_source_pin["path"], "capacity expectation path differs from its SourceV5 request pin")
    require(digest(capacity_host_pin["raw_sha256"], "capacity expectation SourceV5 raw SHA-256") == digest(embedded_source_pin["sha256"], "capacity request SourceV5 SHA-256"), "capacity expectation does not pin the exact SourceV5 manifest bytes")
    artifact_sha = digest(artifact_pin["raw_sha256"], "capacity artifact raw SHA-256")
    producer_pin = {"path": request_pin["path"], "sha256": request_sha}
    producer_artifact_pin = {"path": artifact_pin["path"], "sha256": artifact_sha}
    producer_receipt_pin = {"path": receipt_pin["path"], "sha256": digest(receipt_pin["raw_sha256"], "capacity receipt raw SHA-256")}
    try:
        require(producer.verify_capacity_bundle(producer_pin, producer_artifact_pin, producer_receipt_pin) is True,
                "pinned byte-capacity producer did not accept its complete evidence bundle")
    except Exception as error:
        raise CompositionError(f"pinned byte-capacity producer bundle replay failed: {error}") from error
    receipt_path = absolute_path(receipt_pin["path"], "capacity receipt path")
    capacity_receipt, _receipt_raw, receipt_sha = _read_canonical(receipt_path, "capacity receipt", producer_receipt_pin["sha256"])
    require(capacity_receipt.get("schema") == CAPACITY_RECEIPT_SCHEMA and capacity_receipt.get("qualification_eligible") is False, "capacity receipt schema or eligibility is invalid")
    require(capacity_receipt.get("identity") == request_identity and capacity_receipt.get("calibration_id") == context["calibration_id"], "capacity receipt identity/calibration differs from the producer request")
    require(capacity_receipt.get("source_manifest_raw_sha256") == source_pin["raw_sha256"], "capacity receipt SourceV5 manifest digest differs")
    require(capacity_receipt.get("capacity_artifact_raw_sha256") == artifact_sha, "capacity receipt artifact digest differs")
    return request, capacity_receipt, {
        "request": request_sha, "artifact": artifact_sha, "receipt": receipt_sha,
    }


def _source_policy_context(source: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    feedback = exact(source.get("feedback_policy"), {"schema", "policy", "policy_sha256"}, "SourceV5 feedback policy artifact")
    feedback_body = exact(feedback["policy"], {"schema", "version", "reader_contract", "algorithm", "contexts", "source_pins"}, "SourceV5 feedback policy body")
    context_key = f"{context['workload']}/{context['profile']}"
    contexts = feedback_body["contexts"]
    require(type(contexts) is dict and context_key in contexts, "SourceV5 feedback policy omits the selected context")
    value = exact(contexts[context_key], {"workers", "minimum_dense_observations", "controls"}, "SourceV5 feedback policy context")
    return value


def _make_policy_document(
    request: dict[str, Any], request_raw_sha: str, reader: Any, source: dict[str, Any], context: dict[str, Any],
    identity: dict[str, Any], probe_pin: dict[str, Any], bundle: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    probe_path = absolute_path(probe_pin["path"], "construction probe path")
    probe, _probe_raw, probe_sha = _read_canonical(probe_path, "calibrated construction probe", probe_pin["raw_sha256"], MAX_PROBE_BYTES)
    artifact_pin = {"path": bundle["artifact"]["path"], "raw_sha256": bundle["artifact"]["raw_sha256"]}
    try:
        observed_probe_sha = reader.validate_calibrated_construction_probe_v2(
            probe_pin, source, artifact_pin, identity,
        )
        require(observed_probe_sha == probe_sha, "captured feedback reader returned a different construction probe digest")
        policy = reader.resolve_calibrated_feedback_policy_v5(source, probe, artifact_pin, identity)
    except Exception as error:
        raise CompositionError(f"captured calibrated feedback validator rejected the probe: {error}") from error
    feedback_artifact = source["feedback_policy"]
    static_context = _source_policy_context(source, context)
    static_policy, _algorithm, _workers = reader._static_policy_from_source_v5(
        source, identity, probe["collector"], probe["rust_control_context"]["algorithm"],
    )
    for direction in ("disk", "upload", "download"):
        static_policy["rate_buckets"][direction] = {
            "initial_bytes_per_second": static_policy["rate_buckets"][direction]["ceiling_bytes_per_second"],
            **static_policy["rate_buckets"][direction],
        }
    source_raw_sha = digest(request["source_manifest"]["raw_sha256"], "SourceV5 manifest raw SHA-256")
    semantic_sha = digest(source["manifest_sha256"], "SourceV5 semantic manifest SHA-256")
    source_tree_sha = digest(source["source"]["source_tree_sha256"], "SourceV5 source tree SHA-256")
    build_sha = reader.digest_object(source["build"])
    app_sha = digest(probe_pin["binary_sha256"], "SourceV5 APP artifact SHA-256")
    capacity_sha = digest(bundle["artifact"]["raw_sha256"], "capacity artifact SHA-256")
    base_policy_sha = reader.digest_object(static_policy)
    base_context_sha = reader.digest_object(static_context)
    policy_body = {
        "schema": POLICY_SCHEMA,
        "context": {**context, "allocator": identity["allocator"]},
        "policy": policy,
        "source_manifest_raw_sha256": source_raw_sha,
        "source_manifest_sha256": semantic_sha,
        "source_tree_sha256": source_tree_sha,
        "build_sha256": build_sha,
        "app_binary_sha256": app_sha,
        "probe_raw_sha256": probe_sha,
        "capacity_request_raw_sha256": digest(request.get("capacity_bundle", {}).get("request", {}).get("raw_sha256"), "capacity request raw SHA-256"),
        "capacity_artifact_raw_sha256": capacity_sha,
        "capacity_receipt_raw_sha256": digest(request.get("capacity_bundle", {}).get("receipt", {}).get("raw_sha256"), "capacity receipt raw SHA-256"),
        "base_policy_artifact_sha256": digest(feedback_artifact["policy_sha256"], "SourceV5 feedback policy artifact SHA-256"),
        "base_policy_sha256": base_policy_sha,
        "base_context_sha256": base_context_sha,
        "resolution_rule_version": reader.CAPACITY_RESOLUTION_VERSION,
    }
    policy_body["policy_sha256"] = reader.digest_object(policy_body)
    policy_raw = canonical(policy_body)
    receipt_body = {
        "schema": RECEIPT_SCHEMA,
        "validated": True,
        "execution_ready": False,
        "qualification_eligible": False,
        "controller_chronology_proven": False,
        "request_raw_sha256": request_raw_sha,
        "source_manifest_raw_sha256": source_raw_sha,
        "source_manifest_sha256": semantic_sha,
        "source_tree_sha256": source_tree_sha,
        "build_sha256": build_sha,
        "app_binary_sha256": app_sha,
        "probe_raw_sha256": probe_sha,
        "capacity_request_raw_sha256": policy_body["capacity_request_raw_sha256"],
        "capacity_artifact_raw_sha256": capacity_sha,
        "capacity_receipt_raw_sha256": policy_body["capacity_receipt_raw_sha256"],
        "base_policy_artifact_sha256": policy_body["base_policy_artifact_sha256"],
        "base_policy_sha256": base_policy_sha,
        "base_context_sha256": base_context_sha,
        "resolved_policy_raw_sha256": sha256(policy_raw),
        "resolved_policy_sha256": policy_body["policy_sha256"],
        "resolution_rule_version": reader.CAPACITY_RESOLUTION_VERSION,
        "validator_sha256": _self_sha256(),
        "context": policy_body["context"],
    }
    receipt_body["receipt_sha256"] = sha256(canonical(receipt_body))
    return policy_body, receipt_body


def _validate_resolve_request(value: object) -> dict[str, Any]:
    request = exact(value, {
        "schema", "source_root", "source_manifest", "context", "construction_probe", "capacity_bundle",
    }, "feedback composition request")
    require(request["schema"] == REQUEST_SCHEMA, "unsupported feedback composition request schema")
    absolute_path(request["source_root"], "SourceV5 source root")
    source = exact(request["source_manifest"], {"path", "raw_sha256"}, "SourceV5 manifest pin")
    absolute_path(source["path"], "SourceV5 manifest path")
    digest(source["raw_sha256"], "SourceV5 manifest raw SHA-256")
    context = exact(request["context"], {"host_id", "workload", "profile", "calibration_id"}, "composition context")
    for key in context:
        require(type(context[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", context[key]) is not None, f"composition context {key} is malformed")
    probe = exact(request["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "construction probe pin")
    absolute_path(probe["path"], "construction probe path")
    digest(probe["raw_sha256"], "construction probe raw SHA-256")
    digest(probe["binary_sha256"], "construction probe binary SHA-256")
    require(probe["allocator"] in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"), "composition allocator is outside the original application artifact set")
    bundle = exact(request["capacity_bundle"], {"request", "artifact", "receipt"}, "complete capacity producer bundle")
    for name in bundle:
        pin = exact(bundle[name], {"path", "raw_sha256"}, f"capacity bundle {name} pin")
        absolute_path(pin["path"], f"capacity bundle {name} path")
        digest(pin["raw_sha256"], f"capacity bundle {name} raw SHA-256")
    require(len({bundle[name]["path"] for name in bundle}) == 3, "capacity request, artifact, and receipt paths must be distinct")
    return request


def _self_sha256() -> str:
    raw, actual = _read_stable(Path(__file__).resolve(), "feedback composition validator", MAX_METADATA_BYTES)
    require(len(raw) <= MAX_METADATA_BYTES, "feedback composition validator exceeds its bound")
    return actual


def compose_calibrated_policy_v5(request: object, request_raw_sha256: object) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replay the pinned producer bundle and resolve a prelaunch V5 policy."""
    value = _validate_resolve_request(request)
    raw_sha = digest(request_raw_sha256, "composition request raw SHA-256")
    reader, producer, source, context, identity = _load_verified_inputs(value)
    source_pin = value["source_manifest"]
    bundle = value["capacity_bundle"]
    _verify_capacity_request_binding(reader, producer, source, context, identity, source_pin, bundle)
    return _make_policy_document(value, raw_sha, reader, source, context, identity, value["construction_probe"], bundle)


def build_calibrated_feedback_expectation_v5(request: object) -> dict[str, Any]:
    """Finalize a V5 expectation only after the caller supplies its actual PID."""
    value = exact(request, {
        "schema", "source_root", "source_manifest", "resolved_policy", "composition_receipt",
        "construction_probe", "capacity_bundle", "expectation_header",
    }, "V5 expectation finalization request")
    require(value["schema"] == FINALIZE_SCHEMA, "unsupported V5 expectation finalization schema")
    source_root = absolute_path(value["source_root"], "SourceV5 source root")
    require(source_root == SOURCE_ROOT, "finalization source root differs from pinned harness root")
    source_pin = exact(value["source_manifest"], {"path", "raw_sha256"}, "SourceV5 manifest pin")
    source_path = absolute_path(source_pin["path"], "SourceV5 manifest path")
    source, _source_raw, source_raw_sha = _read_canonical(source_path, "SourceV5 manifest", source_pin["raw_sha256"])
    policy_pin = exact(value["resolved_policy"], {"path", "raw_sha256"}, "resolved policy pin")
    policy_path = absolute_path(policy_pin["path"], "resolved policy path")
    policy, _policy_raw, policy_raw_sha = _read_canonical(policy_path, "resolved calibrated policy", policy_pin["raw_sha256"])
    receipt_pin = exact(value["composition_receipt"], {"path", "raw_sha256"}, "composition receipt pin")
    receipt_path = absolute_path(receipt_pin["path"], "composition receipt path")
    receipt, _receipt_raw, receipt_raw_sha = _read_canonical(receipt_path, "calibrated policy composition receipt", receipt_pin["raw_sha256"])
    _verify_policy_and_receipt(source, source_raw_sha, policy, policy_raw_sha, receipt, receipt_raw_sha)
    probe_pin = exact(value["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "construction probe pin")
    capacity_bundle = exact(value["capacity_bundle"], {"request", "artifact", "receipt"}, "capacity bundle pins")
    bundle_context = {key: policy["context"][key] for key in ("host_id", "workload", "profile", "calibration_id")}
    reader, producer, verified_source, context, probe_identity = _load_verified_inputs({
        "source_root": str(source_root),
        "source_manifest": source_pin,
        "context": bundle_context,
        "construction_probe": probe_pin,
        "capacity_bundle": capacity_bundle,
    })
    require(verified_source["manifest_sha256"] == source["manifest_sha256"], "finalization SourceV5 semantic digest changed after policy composition")
    _verify_capacity_request_binding(reader, producer, verified_source, context, probe_identity, source_pin, capacity_bundle)
    identity = exact(value["expectation_header"].get("identity"), {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor", "workload", "profile",
        "mode", "source_sha256", "binary_sha256", "pressure_qualification",
    }, "post-Popen V5 identity")
    require(identity["allocator"] in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system") and identity["executor"] in ("allocatbelt", "tokio-1.53.1"), "V5 expectation role is outside the original APP artifact/executor set")
    require(identity["allocator"] == policy["context"]["allocator"], "actual APP allocator differs from the prelaunch selected artifact")
    require(identity["host_id"] == policy["context"]["host_id"] and identity["workload"] == policy["context"]["workload"] and identity["profile"] == policy["context"]["profile"], "actual APP identity differs from the prelaunch calibrated context")
    require(identity["source_sha256"] == policy["source_tree_sha256"] and identity["binary_sha256"] == policy["app_binary_sha256"], "actual APP source or binary differs from the prelaunch composition")
    require(identity["pressure_qualification"] is True, "V5 expectation identity does not request pressure validation")
    uint(identity["process_id"], "actual APP process ID", positive=True, maximum=(1 << 31) - 1)
    require(re.fullmatch(r"[0-9a-f]{32}", identity["report_nonce"]) is not None, "actual APP report nonce is malformed")
    header = exact(value["expectation_header"], {
        "identity", "external_pressure_proof", "final_runtime_binding", "minimum_production_seconds",
        "minimum_pressure_overlap_seconds",
    }, "caller-frozen V5 expectation header")
    artifact_pin = exact(capacity_bundle["artifact"], {"path", "raw_sha256"}, "capacity artifact pin")
    require(probe_pin["allocator"] == identity["allocator"] and probe_pin["binary_sha256"] == policy["app_binary_sha256"] and probe_pin["raw_sha256"] == policy["probe_raw_sha256"], "construction probe differs from the prelaunch policy composition")
    require(artifact_pin["raw_sha256"] == policy["capacity_artifact_raw_sha256"], "capacity artifact differs from the prelaunch policy composition")
    for name in ("request", "artifact", "receipt"):
        exact(capacity_bundle[name], {"path", "raw_sha256"}, f"capacity bundle {name} pin")
        absolute_path(capacity_bundle[name]["path"], f"capacity bundle {name} path")
        digest(capacity_bundle[name]["raw_sha256"], f"capacity bundle {name} raw SHA-256")
    require(capacity_bundle["request"]["raw_sha256"] == policy["capacity_request_raw_sha256"] and capacity_bundle["receipt"]["raw_sha256"] == policy["capacity_receipt_raw_sha256"], "capacity producer bundle differs from the prelaunch policy composition")
    body = {
        "schema": EXPECTATION_SCHEMA_V5,
        "mode": "pressure_validation",
        "identity": identity,
        "policy": policy["policy"],
        "app_capacity_artifact_sha256": artifact_pin["raw_sha256"],
        "app_capacity_artifact": artifact_pin,
        "host_binding": {"path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"]},
        "construction_probe": probe_pin,
        "external_pressure_proof": header["external_pressure_proof"],
        "final_runtime_binding": header["final_runtime_binding"],
        "minimum_production_seconds": header["minimum_production_seconds"],
        "minimum_pressure_overlap_seconds": header["minimum_pressure_overlap_seconds"],
    }
    reader._validate_expectation_body(body)
    reader.validate_calibrated_construction_probe_v2(probe_pin, verified_source, artifact_pin, identity, policy["policy"])
    return body


def _verify_policy_and_receipt(
    source: dict[str, Any], source_raw_sha: str, policy: dict[str, Any], policy_raw_sha: str,
    receipt: dict[str, Any], receipt_raw_sha: str,
) -> None:
    exact(policy, {
        "schema", "context", "policy", "source_manifest_raw_sha256", "source_manifest_sha256",
        "source_tree_sha256", "build_sha256", "app_binary_sha256", "probe_raw_sha256",
        "capacity_request_raw_sha256", "capacity_artifact_raw_sha256", "capacity_receipt_raw_sha256",
        "base_policy_artifact_sha256", "base_policy_sha256", "base_context_sha256",
        "resolution_rule_version", "policy_sha256",
    }, "resolved calibrated policy")
    body = {key: item for key, item in policy.items() if key != "policy_sha256"}
    require(policy["schema"] == POLICY_SCHEMA and digest(policy["policy_sha256"], "resolved policy digest") == sha256(canonical(body)), "resolved calibrated policy self digest is invalid")
    exact(receipt, {
        "schema", "validated", "execution_ready", "qualification_eligible", "controller_chronology_proven",
        "request_raw_sha256", "source_manifest_raw_sha256", "source_manifest_sha256", "source_tree_sha256",
        "build_sha256", "app_binary_sha256", "probe_raw_sha256", "capacity_request_raw_sha256",
        "capacity_artifact_raw_sha256", "capacity_receipt_raw_sha256", "base_policy_artifact_sha256",
        "base_policy_sha256", "base_context_sha256", "resolved_policy_raw_sha256",
        "resolved_policy_sha256", "resolution_rule_version", "validator_sha256", "context", "receipt_sha256",
    }, "calibrated policy composition receipt")
    receipt_body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    require(receipt["schema"] == RECEIPT_SCHEMA and digest(receipt["receipt_sha256"], "composition receipt digest") == sha256(canonical(receipt_body)), "composition receipt self digest is invalid")
    for flag in ("validated", "execution_ready", "qualification_eligible", "controller_chronology_proven"):
        require(type(receipt[flag]) is bool, f"composition receipt {flag} flag is not boolean")
    require(receipt["validated"] is True and receipt["execution_ready"] is False and receipt["qualification_eligible"] is False and receipt["controller_chronology_proven"] is False, "composition receipt has an invalid readiness or qualification claim")
    require(digest(receipt["validator_sha256"], "composition validator SHA-256") == _self_sha256(), "composition receipt was produced by different validator bytes")
    digest(receipt["request_raw_sha256"], "composition request raw SHA-256")
    links = (
        ("source_manifest_raw_sha256", source_raw_sha),
        ("source_manifest_sha256", source["manifest_sha256"]),
        ("source_tree_sha256", source["source"]["source_tree_sha256"]),
        ("build_sha256", policy["build_sha256"]),
        ("app_binary_sha256", policy["app_binary_sha256"]),
        ("probe_raw_sha256", policy["probe_raw_sha256"]),
        ("capacity_request_raw_sha256", policy["capacity_request_raw_sha256"]),
        ("capacity_artifact_raw_sha256", policy["capacity_artifact_raw_sha256"]),
        ("capacity_receipt_raw_sha256", policy["capacity_receipt_raw_sha256"]),
        ("base_policy_artifact_sha256", policy["base_policy_artifact_sha256"]),
        ("base_policy_sha256", policy["base_policy_sha256"]),
        ("base_context_sha256", policy["base_context_sha256"]),
        ("resolution_rule_version", policy["resolution_rule_version"]),
        ("resolved_policy_sha256", policy["policy_sha256"]),
        ("resolved_policy_raw_sha256", policy_raw_sha),
    )
    for field, expected in links:
        require(receipt[field] == expected, f"composition receipt differs from resolved policy at {field}")
    require(receipt["context"] == policy["context"], "composition receipt context differs from the resolved policy")
    require(policy["source_manifest_raw_sha256"] == source_raw_sha and policy["source_manifest_sha256"] == source["manifest_sha256"] and policy["source_tree_sha256"] == source["source"]["source_tree_sha256"], "resolved policy is bound to a different SourceV5 manifest")
    require(receipt_raw_sha == sha256(canonical(receipt)), "composition receipt canonical digest differs")


def _finish_expectation(request: dict[str, Any], raw_sha: str) -> tuple[bytes, dict[str, Any]]:
    body = build_calibrated_feedback_expectation_v5(request)
    source_root = absolute_path(request["source_root"], "SourceV5 source root")
    reader_path = source_root / FEEDBACK_READER
    reader_raw, reader_sha = _read_stable(reader_path, "pinned feedback reader", MAX_METADATA_BYTES)
    source_value, _source_raw, _source_sha = _read_canonical(
        absolute_path(request["source_manifest"]["path"], "SourceV5 manifest path"),
        "SourceV5 manifest", request["source_manifest"]["raw_sha256"],
    )
    reader_record = _record(source_value, FEEDBACK_READER, "feedback validator")
    reader_pin = exact(source_value["qualification_harness"].get("feedback_validator"), {"path", "sha256"}, "SourceV5 feedback validator pin")
    require(reader_pin == {"path": FEEDBACK_READER, "sha256": reader_sha} and reader_record["sha256"] == reader_sha, "finalization feedback reader differs from the SourceV5 pin")
    reader = types.ModuleType(f"finalize_feedback_reader_{reader_sha}")
    reader.__file__ = str(reader_path)
    reader.__package__ = ""
    exec(compile(reader_raw, str(reader_path), "exec", dont_inherit=True), reader.__dict__)
    final_bytes, final_sha = reader.build_pressure_expectation_recipe(body)
    receipt = {
        "schema": FINALIZE_RECEIPT_SCHEMA,
        "validated": True,
        "execution_ready": False,
        "qualification_eligible": False,
        "controller_chronology_proven": False,
        "finalization_request_raw_sha256": raw_sha,
        "composition_receipt_raw_sha256": request["composition_receipt"]["raw_sha256"],
        "expectation_header_sha256": reader.digest_object(request["expectation_header"]),
        "expectation_raw_sha256": final_sha,
        "validator_sha256": _self_sha256(),
    }
    receipt["receipt_sha256"] = sha256(canonical(receipt))
    return final_bytes, receipt


def _write_exclusive(path: Path, raw: bytes) -> None:
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), "output path must be normalized and absolute")
    try:
        require(path.parent.resolve(strict=True) == path.parent, "output parent traverses a symlink or alias")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    except OSError as error:
        raise CompositionError(f"cannot create fresh composition output: {error}") from error
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            require(written > 0, "composition output write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve", help="verify capacity evidence and resolve the prelaunch numeric policy")
    resolve.add_argument("--request", type=Path, required=True)
    resolve.add_argument("--policy-output", type=Path, required=True)
    resolve.add_argument("--receipt-output", type=Path, required=True)
    finalize = commands.add_parser("finalize", help="freeze a V5 expectation after the actual APP PID is known")
    finalize.add_argument("--request", type=Path, required=True)
    finalize.add_argument("--expectation-output", type=Path, required=True)
    finalize.add_argument("--receipt-output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request_path = absolute_path(str(args.request), "composition request path")
        request_raw, request_sha = _read_stable(request_path, "composition request", MAX_METADATA_BYTES)
        try:
            request = json.loads(request_raw.decode("utf-8"), object_pairs_hook=_unique)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise CompositionError(f"composition request is invalid JSON: {error}") from error
        require(type(request) is dict and canonical(request) == request_raw, "composition request is not canonical JSON")
        if args.command == "resolve":
            policy, receipt = compose_calibrated_policy_v5(request, request_sha)
            _write_exclusive(absolute_path(str(args.policy_output), "resolved policy output"), canonical(policy))
            _write_exclusive(absolute_path(str(args.receipt_output), "composition receipt output"), canonical(receipt))
            sys.stdout.buffer.write(canonical({"validated": True, "execution_ready": False, "qualification_eligible": False, "controller_chronology_proven": False, "policy_sha256": policy["policy_sha256"], "receipt_sha256": receipt["receipt_sha256"]}))
            return 0
        require(request.get("schema") == FINALIZE_SCHEMA, "unsupported V5 finalization request schema")
        final, receipt = _finish_expectation(request, request_sha)
        _write_exclusive(absolute_path(str(args.expectation_output), "V5 expectation output"), final)
        _write_exclusive(absolute_path(str(args.receipt_output), "V5 finalization receipt output"), canonical(receipt))
        sys.stdout.buffer.write(canonical({"validated": True, "execution_ready": False, "qualification_eligible": False, "controller_chronology_proven": False, "expectation_raw_sha256": sha256(final), "receipt_sha256": receipt["receipt_sha256"]}))
        return 0
    except (CompositionError, OSError, ValueError, TypeError) as error:
        print(f"application-feedback-composition: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
