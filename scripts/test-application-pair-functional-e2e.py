#!/usr/bin/env python3
"""Run bounded functional-only native pair receipts from an explicitly pinned build.

This helper never creates qualification evidence. It checks out one signed
source revision, freezes a functional-only build/calibration overlay, and writes
its logs and output outside the source checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path
from typing import Any


SIGNED_SOURCE_COMMIT = "9290a2b194a667aba8816020214230d111ab80a3"
SIGNED_CONTROLLER_SHA256 = "1947fe29efa932bf4b8a3bc30a7390151f2f21cb940b18204c8da5225bc157e4"
SOURCE_INVENTORY_MODULE_SHA256 = "09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950"
FUNCTIONAL_LIMITS = {
    "max_arrivals": 1000,
    "max_rate_per_second": 1000,
    "max_trace_deadline_seconds": 30,
    "max_drain_deadline_seconds": 30,
    "max_shutdown_deadline_seconds": 15,
    "max_process_deadline_seconds": 300,
}
WORKLOAD = "cpu"
PROFILE = "steady"
MODE = "open_loop"
_CAMPAIGN: Any | None = None
_SOURCE_INVENTORY: Any | None = None
MAX_SMALL_ARTIFACT_BYTES = 128 * 1024
MAX_CAMPAIGN_SOURCE_BYTES = 4 * 1024 * 1024


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
        require(before.st_size <= maximum, f"{label} exceeds its finite size bound")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(descriptor, min(64 * 1024, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= maximum, f"{label} exceeds its finite size bound")
            chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and count == before.st_size
            and stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
            f"{label} changed while taking its bounded snapshot",
        )
    finally:
        os.close(descriptor)
    return b"".join(chunks), digest.hexdigest()


def hash_stable(path: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    count = 0
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"hash input is not a regular file: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            count += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and count == before.st_size
            and stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
            f"hash input changed while streaming: {path}",
        )
    finally:
        os.close(descriptor)
    return digest.hexdigest(), count


def fail(message: str) -> None:
    raise RuntimeError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_campaign_module(source_root: Path) -> Any:
    path = source_root / "scripts" / "application-campaign.py"
    source, source_sha256 = read_stable(path, "signed campaign controller source", MAX_CAMPAIGN_SOURCE_BYTES)
    require(source_sha256 == SIGNED_CONTROLLER_SHA256, "campaign controller differs from the pinned signed source")
    module = types.ModuleType("functional_e2e_application_campaign")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def load_source_inventory_module() -> Any:
    path = Path(__file__).with_name("application-source-inventory.py")
    source, source_sha256 = read_stable(path, "shared source inventory module", MAX_CAMPAIGN_SOURCE_BYTES)
    require(source_sha256 == SOURCE_INVENTORY_MODULE_SHA256, "shared source inventory module differs from its frozen SHA-256")
    module = types.ModuleType("functional_e2e_source_inventory")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise RuntimeError(f"shared source inventory module cannot be compiled: {error}") from error
    require(module.SCHEMA == "allocatbelt.application-source-inventory.v1", "shared source inventory module has an unexpected schema")
    return module


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


class BytesArtifactPath:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def open(self, mode: str = "rb") -> io.BytesIO:
        require(mode == "rb", "receipt adapter only supports read-only binary access")
        return io.BytesIO(self.raw)


def read_metadata(path: Path) -> dict[str, str]:
    _header, rows = _CAMPAIGN.read_tsv(path)
    result: dict[str, str] = {}
    for row in rows:
        key = row["key"]
        require(key not in result, f"metadata repeats key {key}")
        result[key] = row["value"]
    return result


def run_bounded(argv: list[str], cwd: Path, stdout_path: Path, stderr_path: Path, timeout_seconds: int) -> int:
    require(0 < timeout_seconds <= 600, "child timeout exceeds the functional envelope")
    process: subprocess.Popen[bytes] | None = None
    received_signal: int | None = None
    stop_started: float | None = None
    timed_out = False
    grace_seconds = 1.5
    old_handlers: dict[int, Any] = {}

    def send_to_group(signum: int) -> None:
        if process is not None:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    def request_stop(signum: int, _frame: Any) -> None:
        nonlocal received_signal, stop_started
        if stop_started is None:
            received_signal = signum
            stop_started = time.monotonic()
            send_to_group(signal.SIGTERM)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, request_stop)
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
            if received_signal is not None:
                return 128 + received_signal
            process = subprocess.Popen(
                argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                close_fds=True, start_new_session=True,
            )
            if stop_started is not None:
                send_to_group(signal.SIGTERM)
            deadline = time.monotonic() + timeout_seconds
            while True:
                now = time.monotonic()
                if now >= deadline and stop_started is None:
                    timed_out = True
                    request_stop(signal.SIGTERM, None)
                if stop_started is not None and now >= stop_started + grace_seconds:
                    send_to_group(signal.SIGKILL)
                    require(now < stop_started + 2 * grace_seconds, "child did not exit after bounded group termination")
                try:
                    code = process.wait(timeout=0.1)
                    return 124 if timed_out else (128 + received_signal if received_signal is not None else code)
                except subprocess.TimeoutExpired:
                    continue
    finally:
        if process is not None:
            if process.poll() is None:
                send_to_group(signal.SIGTERM)
                try:
                    process.wait(timeout=grace_seconds)
                except subprocess.TimeoutExpired:
                    send_to_group(signal.SIGKILL)
                    process.wait(timeout=grace_seconds)
            # A reaped leader can still leave descendants in its original group.
            send_to_group(signal.SIGKILL)
        for signum, old_handler in old_handlers.items():
            signal.signal(signum, old_handler)


def hash_path(path: Path) -> str:
    return hash_stable(path)[0]


def safe_source_file(source_root: Path, relative: str, label: str) -> tuple[Path, str, int]:
    require(type(relative) is str and relative and "\\" not in relative, f"{label} path is malformed")
    rel = Path(relative)
    require(not rel.is_absolute() and ".." not in rel.parts and rel.as_posix() == relative, f"{label} path is not portable")
    cursor = source_root
    for part in rel.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), f"{label} path traverses a symlink: {relative}")
    resolved = cursor.resolve(strict=True)
    require(resolved.is_file(), f"{label} is not a regular file: {relative}")
    sha256, size = hash_stable(resolved)
    return resolved, sha256, size


def run_checked(argv: list[str], cwd: Path, timeout_seconds: int = 60) -> bytes:
    try:
        result = subprocess.run(
            argv, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"functional E2E command failed: {argv[0]}: {error}") from error
    return result.stdout


def functional_source_overlay(
    source_root: Path,
    output_root: Path,
    logs: Path,
    attempt_id: str,
    host_id: str,
    candidate_relative: str,
    baseline_relative: str,
    calibration_relative: str,
    calibration_output_relative: str,
) -> tuple[dict[str, Any], dict[str, tuple[Path, str]], dict[str, Any]]:
    commit = run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii").strip()
    require(commit == SIGNED_SOURCE_COMMIT, "functional E2E source is not the signed immutable 9290 commit")
    status = run_checked(["git", "status", "--porcelain", "--untracked-files=no"], source_root)
    require(status == b"", "tracked signed source changed before functional E2E")
    require(_SOURCE_INVENTORY is not None, "shared source inventory module was not loaded")
    typed_inventory = _SOURCE_INVENTORY.inventory(source_root)
    tree_sha256 = _SOURCE_INVENTORY.digest_inventory(typed_inventory)
    source_files = typed_inventory["entries"]
    cargo_lock_path, cargo_lock_sha256, _cargo_lock_size = safe_source_file(source_root, "Cargo.lock", "Cargo.lock")
    require(tree_sha256 == _SOURCE_INVENTORY.digest_records(source_files), "functional source inventory digest does not reconcile")

    calibration_path, calibration_binary_sha256, _ = safe_source_file(
        source_root, calibration_relative, "resource-domain calibration binary"
    )
    candidate_path, candidate_sha256, _ = safe_source_file(source_root, candidate_relative, "allocatbelt benchmark binary")
    baseline_path, baseline_sha256, _ = safe_source_file(source_root, baseline_relative, "secure mimalloc benchmark binary")
    require(os.access(candidate_path, os.X_OK) and os.access(baseline_path, os.X_OK) and os.access(calibration_path, os.X_OK), "one or more pinned functional binaries are not executable")
    calibration_output_path = source_root / calibration_output_relative
    require(not calibration_output_path.exists() and not calibration_output_path.is_symlink(), "calibration output path must be fresh")
    calibration_output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not calibration_output_path.parent.is_symlink(), "calibration output directory may not be a symlink")
    calibration_status = run_bounded(
        [str(calibration_path)], source_root, calibration_output_path,
        logs / "calibration.stderr.log", 60,
    )
    (logs / "calibration.exit").write_text(f"{calibration_status}\n", encoding="ascii")
    require(calibration_status == 0, "independent native resource-domain calibration failed")
    calibration_raw, calibration_output_sha256 = read_stable(
        calibration_output_path, "independent calibration output", MAX_SMALL_ARTIFACT_BYTES
    )
    calibration_record = _CAMPAIGN.validate_calibration_record(
        _CAMPAIGN.parse_json_object_bytes(calibration_raw, "independent calibration output", MAX_SMALL_ARTIFACT_BYTES)
    )
    validator_path, validator_sha256, _ = safe_source_file(
        source_root, "scripts/application-runtime-readback.py", "runtime readback validator"
    )
    validator_module = _CAMPAIGN.runtime_readback_module(validator_sha256)
    fixed_policy = _CAMPAIGN.fixed_runtime_policy_artifact(validator_sha256)
    cargo_version = run_checked(["cargo", "-V"], source_root).decode("utf-8").strip()
    rustc_verbose = run_checked(["rustc", "-Vv"], source_root).decode("utf-8").splitlines()
    rustc_release = next(
        (line.removeprefix("release: ") for line in rustc_verbose if line.startswith("release: ")),
        "",
    )
    require(rustc_release == "1.99.0", "functional E2E requires Rust 1.99.0")
    target_triple = "x86_64-unknown-linux-gnu"
    target_cpu = "x86-64-v3"
    require("x86-64-v3" in (source_root / ".cargo" / "config.toml").read_text(encoding="utf-8"), "signed Cargo config does not pin x86-64-v3")

    feature_tree_path = output_root / "cargo-features.tree.txt"
    features_status = run_bounded(
        ["cargo", "tree", "--locked", "--target", target_triple, "--edges", "features", "-p", "allocatbelt-bench", "-p", "allocatbelt-qualification-tools"],
        source_root, feature_tree_path, logs / "cargo-features.stderr.log", 90,
    )
    (logs / "cargo-features.exit").write_text(f"{features_status}\n", encoding="ascii")
    require(features_status == 0, "cannot freeze exact release dependency feature tree")
    feature_tree_sha256, feature_tree_size = hash_stable(feature_tree_path)
    feature_manifest = {
        "schema": "allocatbelt.functional-build-features.v1",
        "cargo_tree_path": feature_tree_path.name,
        "cargo_tree_sha256": feature_tree_sha256,
        "cargo_tree_bytes": feature_tree_size,
        "packages": ["allocatbelt-bench", "allocatbelt-qualification-tools"],
        "profile": "release",
        "locked": True,
    }
    feature_manifest_path = output_root / "build-features.json"
    write_canonical(feature_manifest_path, feature_manifest)
    features_sha256 = hashlib.sha256(_CAMPAIGN.canonical_bytes(feature_manifest)).hexdigest()

    build_command = [
        "cargo", "build", "--release", "--locked", "-p", "allocatbelt-bench",
        "--bin", "bench-application-allocatbelt", "--bin", "bench-application-mimalloc",
        "--bin", "bench-resource-domain-calibration", "-p", "allocatbelt-qualification-tools",
        "--bin", "application-analyze",
    ]
    build_inputs = {
        "schema": "allocatbelt.functional-build-inputs.v1",
        "build_provenance": "externally_built_signed_source",
        "helper_executed_build": False,
        "build_command": build_command,
        "target_triple": target_triple,
        "target_cpu": target_cpu,
        "profile": "release",
        "cargo_lock_sha256": cargo_lock_sha256,
        "cargo_config_sha256": hash_path(source_root / ".cargo" / "config.toml"),
        "workspace_manifest_sha256": hash_path(source_root / "Cargo.toml"),
        "features_manifest_sha256": features_sha256,
        "rustc_verbose": rustc_verbose,
        "cargo_version": cargo_version,
        "environment": {
            key: os.environ.get(key, "")
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS")
        },
    }
    build_inputs_path = output_root / "build-inputs.json"
    write_canonical(build_inputs_path, build_inputs)
    build_inputs_sha256 = hashlib.sha256(_CAMPAIGN.canonical_bytes(build_inputs)).hexdigest()
    source_identity = {
        "git_commit": commit,
        "source_tree_sha256": tree_sha256,
        "cargo_lock_sha256": cargo_lock_sha256,
        "files": source_files,
    }
    build_identity = {
        "host_id": host_id,
        "rustc_release": rustc_release,
        "rustc_verbose": rustc_verbose,
        "cargo_version": cargo_version,
        "target_triple": target_triple,
        "target_cpu": target_cpu,
        "profile": "release",
        "features_sha256": features_sha256,
        "build_inputs_sha256": build_inputs_sha256,
    }
    calibration = {
        "binary": {"path": calibration_relative, "sha256": calibration_binary_sha256},
        "output": {"path": calibration_output_relative, "sha256": calibration_output_sha256},
        "record": calibration_record,
        "source": {key: source_identity[key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")},
        "build": build_identity,
        "build_sha256": _CAMPAIGN.digest_object(build_identity),
    }
    source: dict[str, Any] = {
        "schema": "allocatbelt.application-functional-source-overlay.v2",
        "execution_scope": "functional_only",
        "source_inventory_module_sha256": SOURCE_INVENTORY_MODULE_SHA256,
        "source_inventory": typed_inventory,
        "source": source_identity,
        "build": build_identity,
        "artifacts": {
            "allocatbelt": {"path": candidate_relative, "sha256": candidate_sha256},
            "mimalloc-secure": {"path": baseline_relative, "sha256": baseline_sha256},
        },
        "fixed_runtime_policy": fixed_policy,
        "runtime_readback_validator": {"path": "scripts/application-runtime-readback.py", "sha256": validator_sha256},
        "resource_domain_calibration": calibration,
        "build_evidence": {
            "features": {"path": feature_manifest_path.name, "sha256": hash_path(feature_manifest_path)},
            "feature_tree": {"path": feature_tree_path.name, "sha256": feature_tree_sha256},
            "build_inputs": {"path": build_inputs_path.name, "sha256": hash_path(build_inputs_path)},
        },
    }
    source["manifest_sha256"] = _CAMPAIGN.digest_object(source)
    source_path = output_root / "functional-source-overlay.json"
    source_raw = write_canonical(source_path, source)
    require(source_raw and hashlib.sha256(source_raw).hexdigest() == hash_path(source_path), "functional source overlay did not persist canonically")
    _CAMPAIGN.validate_fixed_runtime_policy_artifact(source["fixed_runtime_policy"], validator_sha256)
    require(calibration_path.resolve(strict=True) == (source_root / calibration_relative).resolve(strict=True), "calibration binary path changed during source overlay construction")
    require(validator_module is not None, "runtime validator module did not load from its pinned source bytes")
    artifacts = {
        "candidate_binary": (candidate_path, candidate_sha256),
        "secure_baseline_binary": (baseline_path, baseline_sha256),
        "calibration_binary": (calibration_path, calibration_binary_sha256),
        "calibration_output": (calibration_output_path, calibration_output_sha256),
        "runtime_validator": (validator_path, validator_sha256),
        "cargo_lock": (cargo_lock_path, cargo_lock_sha256),
    }
    build_info = {
        "build_provenance": "externally_built_signed_source",
        "helper_executed_build": False,
        "features_manifest_sha256": features_sha256,
        "build_inputs_sha256": build_inputs_sha256,
        "feature_tree_sha256": feature_tree_sha256,
        "build_command": build_command,
        "output_path": source_path,
        "output_sha256": hash_path(source_path),
    }
    return source, artifacts, build_info

def write_canonical(path: Path, value: Any) -> bytes:
    raw = _CAMPAIGN.canonical_bytes(value)
    require(not path.exists() and not path.is_symlink(), f"refusing to replace E2E artifact: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    os.chmod(path, 0o600, follow_symlinks=False)
    return raw


def write_report(path: Path, value: Any) -> None:
    require(not path.is_symlink(), "functional E2E report path may not be a symlink")
    raw = _CAMPAIGN.canonical_bytes(value)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".functional-report-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def emit_oracle(
    source_root: Path,
    binary: Path,
    binary_sha256: str,
    source_sha256: str,
    oracle_path: Path,
    rate: int,
    arrivals: int,
    logs: Path,
    name: str,
) -> str:
    command = [
        str(binary), "--emit-oracle-only", str(oracle_path),
        "--source-sha256", source_sha256,
        "--binary-sha256", binary_sha256,
        "--workload", WORKLOAD,
        "--profile", PROFILE,
        "--rate", str(rate),
        "--arrivals", str(arrivals),
        "--trace-deadline-seconds", str(FUNCTIONAL_LIMITS["max_trace_deadline_seconds"]),
    ]
    status = run_bounded(
        command, source_root, logs / f"oracle-{name}.stdout.log",
        logs / f"oracle-{name}.stderr.log", 60,
    )
    (logs / f"oracle-{name}.exit").write_text(f"{status}\n", encoding="ascii")
    require(status == 0 and oracle_path.is_file() and not oracle_path.is_symlink(), f"oracle producer failed for {name}; see captured native log")
    oracle_sha256 = hash_path(oracle_path)
    _CAMPAIGN.validate_oracle(
        oracle_path, source_sha256, binary_sha256, WORKLOAD, PROFILE, rate, arrivals,
    )
    return oracle_sha256


def bindings_for_case(
    source: dict[str, Any], spec: dict[str, Any], run_id: str, pair_kind: str,
    rate: int, arrivals: int,
) -> dict[str, Any]:
    host_id = source["build"]["host_id"]
    job: dict[str, Any] = {
        "host_id": host_id,
        "phase": "confirmation",
        "comparison_family": "fixed_policy",
        "run_id": run_id,
        "family": WORKLOAD,
        "workload": WORKLOAD,
        "profile": PROFILE,
        "mode": MODE,
        "rate_per_second": rate,
        "arrivals": arrivals,
        "ordinal": 1,
        "pair_kind": pair_kind,
        "allocator": "allocatbelt",
        "comparison_kind": "executor",
    }
    if pair_kind in ("aa-bounded", "aa-tokio"):
        executor = "bounded" if pair_kind == "aa-bounded" else "tokio"
        job.update({
            "phase": "aa", "executor": executor, "control_id": f"functional-{executor}-aa",
            "comparison_kind": None,
        })
        job.pop("comparison_kind")
    elif pair_kind == "allocator-match":
        job.update({
            "comparison_kind": "allocator", "baseline_allocator": "mimalloc-secure",
        })
    bindings = _CAMPAIGN.build_runtime_process_bindings(job, spec, source)
    return {"job": job, "bindings": bindings}


def process_overlay(
    source: dict[str, Any], run_id: str, pair_kind: str, rate: int, arrivals: int,
    runner_sha256: str, runtime_bindings_sha256: str, bindings: list[dict[str, Any]],
    candidate_binary_sha256: str, baseline_binary_sha256: str | None,
    oracle_sha256: str, baseline_oracle_sha256: str | None,
) -> dict[str, Any]:
    calibration = source["resource_domain_calibration"]
    first = bindings[0]
    require(all(item["resource_ceiling_sha256"] == first["resource_ceiling_sha256"] for item in bindings), "functional pair recipes changed resource ceiling within the process set")
    require(all(item["policy_sha256"] == first["policy_sha256"] for item in bindings), "functional pair recipes changed policy within the process set")
    require(all(item["fixed_global_control_baseline"] == first["fixed_global_control_baseline"] for item in bindings), "functional pair recipes changed the numeric Control baseline")
    return {
        "schema": "allocatbelt.application-functional-pair-overlay.v2",
        "execution_scope": "functional_only",
        "run_id": run_id,
        "source_head": source["source"]["git_commit"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
        "source_inventory_module_sha256": source["source_inventory_module_sha256"],
        "source_manifest_sha256": source["manifest_sha256"],
        "pair_runner_sha256": runner_sha256,
        "runtime_bindings_sha256": runtime_bindings_sha256,
        "runtime_validator_sha256": source["runtime_readback_validator"]["sha256"],
        "candidate_binary_sha256": candidate_binary_sha256,
        "baseline_binary_sha256": baseline_binary_sha256,
        "oracle_sha256": oracle_sha256,
        "baseline_oracle_sha256": baseline_oracle_sha256,
        "workload": WORKLOAD,
        "profile": PROFILE,
        "mode": MODE,
        "rate_per_second": rate,
        "arrivals": arrivals,
        "pair_kind": pair_kind,
        "resource_ceiling_sha256": first["resource_ceiling_sha256"],
        "policy_sha256": first["policy_sha256"],
        "fixed_global_control_baseline": first["fixed_global_control_baseline"],
        "calibration_binary_sha256": calibration["binary"]["sha256"],
        "calibration_output_sha256": calibration["output"]["sha256"],
        "processes": [
            {name: item[name] for name in ("pair", "executor", "allocator")}
            for item in bindings
        ],
        "functional_limits": FUNCTIONAL_LIMITS,
    }


def parse_canonical_object(raw: bytes, label: str, maximum: int = 1024 * 1024) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its functional receipt size bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} is not duplicate-free UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    return value


def validate_functional_pair(
    pair_dir: Path, source: dict[str, Any], spec: dict[str, Any], job: dict[str, Any],
    bindings: list[dict[str, Any]], overlay_sha256: str, runner_sha256: str,
    runtime_bindings_sha256: str, oracle_sha256: str,
    baseline_binary_sha256: str | None, baseline_oracle_sha256: str | None,
) -> dict[str, Any]:
    require(pair_dir.is_dir() and not pair_dir.is_symlink(), "functional pair output directory is missing or symlinked")
    complete = {}
    for line in (pair_dir / "pair.complete").read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("\t")
        require(separator and key not in complete, "functional completion record is malformed or repeats a key")
        complete[key] = value
    require(complete == {"pair_status": "functional_only", "execution_scope": "functional_only"}, "functional pair completion record promoted or changed scope")
    metadata = read_metadata(pair_dir / "metadata.tsv")
    require(metadata.get("execution_scope") == "functional_only" and metadata.get("execution_scope_after") == "functional_only", "functional metadata scope is missing or changed")
    require(metadata.get("functional_overlay_sha256_before") == overlay_sha256 == metadata.get("functional_overlay_sha256_after"), "functional overlay hash changed across native pair")
    require(metadata.get("pair_runner_sha256_before") == runner_sha256 == metadata.get("pair_runner_sha256_after"), "functional runner hash changed across native pair")
    require(metadata.get("source_tree_sha256_before") == source["source"]["source_tree_sha256"] == metadata.get("source_tree_sha256_after"), "signed source tree changed across functional pair")
    require(metadata.get("source_inventory_schema") == "allocatbelt.application-source-inventory.v1", "functional metadata has the wrong source inventory schema")
    require(
        metadata.get("source_inventory_module_sha256") == SOURCE_INVENTORY_MODULE_SHA256
        == metadata.get("source_inventory_module_sha256_before") == metadata.get("source_inventory_module_sha256_after"),
        "shared source inventory module changed across native pair",
    )
    require(metadata.get("binary_sha256_before") == source["artifacts"]["allocatbelt"]["sha256"] == metadata.get("binary_sha256_after"), "candidate binary hash changed across functional pair")
    require(metadata.get("runtime_bindings_sha256_before") == runtime_bindings_sha256 == metadata.get("runtime_bindings_sha256_after"), "runtime binding hash changed across functional pair")
    require(metadata.get("runtime_validator_sha256_before") == source["runtime_readback_validator"]["sha256"] == metadata.get("runtime_validator_sha256_after"), "runtime validator hash changed across functional pair")
    require(metadata.get("oracle_sha256_before") == oracle_sha256 == metadata.get("oracle_sha256_after"), "candidate oracle hash changed across functional pair")
    require(metadata.get("baseline_binary_sha256_before") == (baseline_binary_sha256 or "") == metadata.get("baseline_binary_sha256_after"), "baseline binary hash changed across functional pair")
    require(metadata.get("baseline_oracle_sha256_before") == (baseline_oracle_sha256 or "") == metadata.get("baseline_oracle_sha256_after"), "baseline oracle hash changed across functional pair")
    require(metadata.get("fixed_global_control_baseline") == str(source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"]), "functional metadata changed the independent Control baseline")

    header, rows = _CAMPAIGN.read_tsv(pair_dir / "processes.tsv", 2)
    require(header == _CAMPAIGN.PAIR_PROCESS_HEADER, "functional process ledger header differs from the current runtime schema")
    _CAMPAIGN.require_exact_pair_process_rows(rows, job)
    expected_by_descriptor = {
        (item["pair"], item["executor"], item["allocator"]): item for item in bindings
    }
    require(len(expected_by_descriptor) == 2, "functional runtime bindings do not have two unique descriptors")
    module = _CAMPAIGN.runtime_readback_module(source["runtime_readback_validator"]["sha256"])
    process_results = []
    for row in rows:
        descriptor = (row["pair"], row["executor"], row["allocator"])
        binding = expected_by_descriptor[descriptor]
        require(row["exit_code"] == "0" and row["row_validation"] == "valid", "native functional process did not pass the row and sidecar validators")
        require(row["p99_qualification"] == "functional_only", "functional process acquired a qualification p99 label")
        require(row["runtime_recipe_sha256"] == binding["recipe_sha256"], "functional process recipe hash differs from its frozen binding")
        require(row["resource_ceiling_sha256"] == binding["resource_ceiling_sha256"], "functional process ceiling hash differs from its frozen recipe")
        require(row["policy_sha256"] == binding["policy_sha256"], "functional process policy hash differs from its frozen source")
        require(row["fixed_global_control_baseline"] == str(binding["fixed_global_control_baseline"]), "functional process baseline differs from its independent calibration")
        require(row["validator_sha256"] == source["runtime_readback_validator"]["sha256"], "functional process validator pin differs")
        require(row["source_manifest_sha256"] == source["manifest_sha256"], "functional process source-manifest pin differs")
        require(row["calibration_binary_sha256"] == source["resource_domain_calibration"]["binary"]["sha256"], "functional process calibration binary pin differs")
        require(row["calibration_output_sha256"] == source["resource_domain_calibration"]["output"]["sha256"], "functional process calibration output pin differs")

        output_path, output_raw, output_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "stdout", "stdout_sha256")
        output_header, output_rows = _CAMPAIGN.read_tsv_bytes(output_raw, str(output_path), 1)
        require(len(output_header) == 53, "functional benchmark stdout has the wrong output schema width")
        output = output_rows[0]
        runtime_name = "allocatbelt" if row["executor"] == "bounded" else "tokio-1.53.1"
        require((output["allocator"], output["executor"], output["workload"], output["mode"]) == (row["allocator"], runtime_name, WORKLOAD, MODE), "functional benchmark row identity differs")
        require(int(output["attempted"]) == job["arrivals"] and int(output["admitted"]) == job["arrivals"], "functional benchmark did not admit its full bounded trace")
        require(int(output["completed_on_time"]) + int(output["completed_late"]) == job["arrivals"], "functional benchmark completion count differs")
        require(int(output["errors"]) == int(output["cancellations"]) == int(output["unresolved"]) == int(output["lost"]) == 0, "functional benchmark reported errors or lost work")
        require(output["result_digest"] == output["expected_digest"], "functional benchmark aggregate digest differs")
        require(all(int(output[field]) == 0 for field in ("final_managed_bytes", "final_disk_ops", "final_network_ops")), "functional benchmark retained final resource charges")

        _receipt_path, receipt_raw, receipt_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_readback", "runtime_readback_sha256")
        _expectation_path, expectation_raw, expectation_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_expectation", "runtime_expectation_sha256")
        _validation_path, validation_raw, validation_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_validation", "runtime_validation_sha256")
        expected = module.build_fixed_expectation(binding["recipe"])
        require(expectation_sha == binding["expectation_sha256"] and expectation_raw == module.canonical_bytes(expected), "functional expectation differs from the controller recipe")
        fields = module.read_receipt(BytesArtifactPath(receipt_raw))
        validation = module.validate_runtime_readback(fields, expected)
        stored_validation = _CAMPAIGN.parse_json_object_bytes(validation_raw, "functional runtime validation output", _CAMPAIGN.MAX_READBACK_ARTIFACT_BYTES)
        require(_CAMPAIGN.canonical_bytes(stored_validation) == _CAMPAIGN.canonical_bytes(validation), "functional CLI validation output differs from independent receipt validation")
        require(validation["validated"] is True and validation["expectation_sha256"] == binding["expectation_sha256"], "functional receipt was not independently validated")
        require(validation["field_count"] == len(fields), "functional receipt field count differs")
        process_results.append({
            "pair": row["pair"], "executor": row["executor"], "allocator": row["allocator"],
            "output_sha256": output_sha, "runtime_readback_sha256": receipt_sha,
            "runtime_expectation_sha256": expectation_sha, "runtime_validation_sha256": validation_sha,
            "validated": True, "p99_qualification": row["p99_qualification"],
        })
    return {"execution_scope": "functional_only", "pair_status": complete["pair_status"], "processes": process_results}


def main(argv: list[str] | None = None) -> int:
    global _CAMPAIGN, _SOURCE_INVENTORY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--pair-runner", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--cpu-set", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--host-id", default="agent-9700x-baremetal")
    parser.add_argument("--candidate-binary", default="target/release/bench-application-allocatbelt")
    parser.add_argument("--secure-baseline-binary", default="target/release/bench-application-mimalloc")
    parser.add_argument("--calibration-binary", default="target/release/bench-resource-domain-calibration")
    parser.add_argument("--arrivals", type=int, default=1000)
    parser.add_argument("--rate-per-second", type=int, default=1000)
    parser.add_argument("--trace-deadline-seconds", type=int, default=10)
    parser.add_argument("--drain-deadline-seconds", type=int, default=10)
    parser.add_argument("--shutdown-deadline-seconds", type=int, default=5)
    parser.add_argument("--process-deadline-seconds", type=int, default=150)
    parser.add_argument("--pair-deadline-seconds", type=int, default=360)
    args = parser.parse_args(argv)

    source_root = args.source_root.resolve(strict=True)
    _CAMPAIGN = load_campaign_module(source_root)
    _SOURCE_INVENTORY = load_source_inventory_module()
    pair_runner = args.pair_runner.resolve(strict=True)
    output_root = args.output_root.expanduser().absolute()
    cursor = Path(output_root.anchor)
    for part in output_root.parts[1:-1]:
        cursor /= part
        require(not cursor.is_symlink(), f"functional E2E output path traverses a symlink: {cursor}")
    output_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not output_root.exists() and not output_root.is_symlink(), "functional E2E output root must be a fresh nonsymlink path")
    require(not _CAMPAIGN.within(source_root, output_root), "functional E2E output root must remain outside signed source")
    require(not _CAMPAIGN.within(source_root, pair_runner), "pair runner overlay must remain outside signed source")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.attempt_id) is not None, "attempt ID is not a safe bounded token")
    require(re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", args.cpu_set) is not None, "CPU set is not a portable taskset list")
    require(args.arrivals == 1000 and args.rate_per_second == 1000, "functional E2E pins the exact bounded 1000-arrival/second CPU smoke")
    require(
        1 <= args.trace_deadline_seconds <= 30
        and 1 <= args.drain_deadline_seconds <= 30
        and 1 <= args.shutdown_deadline_seconds <= 15
        and 1 <= args.process_deadline_seconds <= 300
        and 1 <= args.pair_deadline_seconds <= 600,
        "functional E2E deadline exceeds its finite envelope",
    )
    require(pair_runner.is_file() and not pair_runner.is_symlink() and os.access(pair_runner, os.X_OK), "pair runner overlay must be an executable regular file")
    pair_runner_sha256 = hash_path(pair_runner)

    output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    logs = output_root / "logs"
    raw_root = output_root / "raw"
    functional_inputs = raw_root / ".functional-inputs"
    oracles_dir = raw_root / ".functional-oracles"
    logs.mkdir(mode=0o700)
    raw_root.mkdir(mode=0o700)
    functional_inputs.mkdir(mode=0o700)
    oracles_dir.mkdir(mode=0o700)
    report_path = output_root / "functional-e2e-report.json"
    report: dict[str, Any] = {
        "schema": "allocatbelt.application-functional-pair-e2e-report.v1",
        "execution_scope": "functional_only",
        "attempt_id": args.attempt_id,
        "signed_source_commit": SIGNED_SOURCE_COMMIT,
        "pair_runner_sha256": pair_runner_sha256,
        "functional_source_overlay_schema": "allocatbelt.application-functional-source-overlay.v2",
        "functional_limits": FUNCTIONAL_LIMITS,
        "cases": [],
    }
    write_report(report_path, report)

    try:
        calibration_output_relative = f"target/functional-e2e-calibration/{args.attempt_id}/calibration-output.json"
        source, pinned_artifacts, build_info = functional_source_overlay(
            source_root,
            output_root,
            logs,
            args.attempt_id,
            args.host_id,
            args.candidate_binary,
            args.secure_baseline_binary,
            args.calibration_binary,
            calibration_output_relative,
        )
        source_tree_sha256 = source["source"]["source_tree_sha256"]
        calibration = source["resource_domain_calibration"]
        baseline = calibration["record"]["fixed_global_control_baseline"]
        validator = source["runtime_readback_validator"]
        validator_path = source_root / validator["path"]
        candidate_binary = source_root / source["artifacts"]["allocatbelt"]["path"]
        secure_binary = source_root / source["artifacts"]["mimalloc-secure"]["path"]
        candidate_sha = source["artifacts"]["allocatbelt"]["sha256"]
        secure_sha = source["artifacts"]["mimalloc-secure"]["sha256"]
        source_overlay_path = output_root / "functional-source-overlay.json"
        source_overlay_sha256 = hash_path(source_overlay_path)
        report.update({
            "source_tree_sha256": source_tree_sha256,
            "functional_source_overlay_sha256": source_overlay_sha256,
            "functional_source_overlay_manifest_sha256": source["manifest_sha256"],
            "runtime_validator_sha256": validator["sha256"],
            "candidate_binary_sha256": candidate_sha,
            "secure_baseline_binary_sha256": secure_sha,
            "calibration_binary_sha256": calibration["binary"]["sha256"],
            "calibration_output_sha256": calibration["output"]["sha256"],
            "fixed_global_control_baseline": baseline,
            "build_features_sha256": build_info["features_manifest_sha256"],
            "build_inputs_sha256": build_info["build_inputs_sha256"],
            "build_command": build_info["build_command"],
            "feature_tree_sha256": build_info["feature_tree_sha256"],
        })
        write_report(report_path, report)

        rate = args.rate_per_second
        arrivals = args.arrivals
        oracle_paths: dict[str, Path] = {}
        oracle_hashes: dict[str, str] = {}
        for allocator, binary, binary_sha in (
            ("allocatbelt", candidate_binary, candidate_sha),
            ("mimalloc-secure", secure_binary, secure_sha),
        ):
            oracle_path = oracles_dir / f"{allocator}.oracle.tsv"
            oracle_hashes[allocator] = emit_oracle(
                source_root, binary, binary_sha, source_tree_sha256, oracle_path,
                rate, arrivals, logs, allocator,
            )
            oracle_paths[allocator] = oracle_path

        cell_limits = _CAMPAIGN.fixed_resource_limits_for_cell(WORKLOAD, PROFILE, validator["sha256"])
        cell = {
            "family": WORKLOAD,
            "workload": WORKLOAD,
            "profile": PROFILE,
            "arrivals": arrivals,
            "async_workers": 4,
            "resource_limits": cell_limits,
            "resource_ceiling_sha256": hashlib.sha256(_CAMPAIGN.canonical_bytes(cell_limits)).hexdigest(),
            "capacity_horizon_seconds": 30,
        }
        spec = {"campaign_id": f"functional-e2e-{args.attempt_id}", "cells": [cell]}
        cases = (("matched", "matched"), ("aa-bounded", "aa-bounded"), ("aa-tokio", "aa-tokio"), ("allocator-match", "allocator-match"))
        for case_name, pair_kind in cases:
            run_id = f"functional-{case_name}-{args.attempt_id}-01"
            job_data = bindings_for_case(source, spec, run_id, pair_kind, rate, arrivals)
            job = job_data["job"]
            bindings = job_data["bindings"]
            binding_path = functional_inputs / f"{run_id}.runtime-bindings.json"
            binding_sha256 = _CAMPAIGN.write_runtime_binding_manifest(binding_path, bindings, job, spec, source)
            baseline_binary_sha = secure_sha if pair_kind == "allocator-match" else None
            baseline_oracle_sha = oracle_hashes["mimalloc-secure"] if pair_kind == "allocator-match" else None
            overlay = process_overlay(
                source, run_id, pair_kind, rate, arrivals, pair_runner_sha256, binding_sha256,
                bindings, candidate_sha, baseline_binary_sha, oracle_hashes["allocatbelt"], baseline_oracle_sha,
            )
            overlay_path = functional_inputs / f"{run_id}.functional-overlay.json"
            overlay_raw = write_canonical(overlay_path, overlay)
            overlay_sha256 = hashlib.sha256(overlay_raw).hexdigest()
            baseline_args = (
                [str(secure_binary), "mimalloc-secure", str(oracle_paths["mimalloc-secure"]), baseline_oracle_sha]
                if pair_kind == "allocator-match" else ["", "", "", ""]
            )
            command = [
                str(pair_runner), "--functional-only", str(candidate_binary), "allocatbelt",
                WORKLOAD, MODE, str(rate), args.cpu_set, run_id, str(raw_root),
                str(arrivals), str(args.trace_deadline_seconds), str(args.drain_deadline_seconds),
                str(args.shutdown_deadline_seconds), str(args.process_deadline_seconds),
                str(oracle_paths["allocatbelt"]), oracle_hashes["allocatbelt"], PROFILE, pair_kind,
                *baseline_args,
                "--runtime-bindings", str(binding_path),
                "--runtime-bindings-sha256", binding_sha256,
                "--runtime-validator", str(validator_path),
                "--runtime-validator-sha256", validator["sha256"],
                "--fixed-global-control-baseline", str(baseline),
                "--functional-overlay", str(overlay_path),
                "--functional-overlay-sha256", overlay_sha256,
            ]
            case_logs = logs / case_name
            case_logs.mkdir(mode=0o700)
            exit_code = run_bounded(
                command, source_root, case_logs / "runner.stdout.log",
                case_logs / "runner.stderr.log", args.pair_deadline_seconds,
            )
            (case_logs / "runner.exit").write_text(f"{exit_code}\n", encoding="ascii")
            case_result: dict[str, Any] = {
                "run_id": run_id,
                "pair_kind": pair_kind,
                "execution_scope": "functional_only",
                "pair_runner_sha256": pair_runner_sha256,
                "runtime_bindings_path": str(binding_path),
                "runtime_bindings_sha256": binding_sha256,
                "functional_overlay_path": str(overlay_path),
                "functional_overlay_sha256": overlay_sha256,
                "oracle_sha256": oracle_hashes["allocatbelt"],
                "baseline_oracle_sha256": baseline_oracle_sha,
                "exit_code": exit_code,
            }
            report["cases"].append(case_result)
            if exit_code != 0:
                report["passed_functional_checks"] = False
                write_report(report_path, report)
                fail(f"native functional pair failed for {case_name}; see {case_logs}")
            pair_dir = raw_root / run_id
            case_result["validation"] = validate_functional_pair(
                pair_dir, source, spec, job, bindings, overlay_sha256,
                pair_runner_sha256, binding_sha256, oracle_hashes["allocatbelt"],
                baseline_binary_sha, baseline_oracle_sha,
            )
            case_result["validated_processes"] = len(case_result["validation"]["processes"])
            write_report(report_path, report)

        current_commit = run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii").strip()
        require(current_commit == source["source"]["git_commit"], "signed source commit changed across functional E2E")
        current_status = run_checked(["git", "status", "--porcelain", "--untracked-files=no"], source_root)
        require(current_status == b"", "tracked signed source changed across functional E2E")
        require(_SOURCE_INVENTORY is not None, "shared source inventory module was not loaded")
        current_inventory = _SOURCE_INVENTORY.inventory(source_root)
        current_tree_sha256 = _SOURCE_INVENTORY.digest_inventory(current_inventory)
        current_source_files = current_inventory["entries"]
        require(
            current_tree_sha256 == source_tree_sha256 and current_source_files == source["source"]["files"],
            "signed source inventory changed across functional E2E",
        )
        source_inventory_module_path = Path(__file__).with_name("application-source-inventory.py")
        require(hash_path(source_inventory_module_path) == SOURCE_INVENTORY_MODULE_SHA256, "shared source inventory module changed across functional E2E")
        require(hash_path(pair_runner) == pair_runner_sha256, "functional runner draft changed across E2E runs")
        require(hash_path(source_overlay_path) == source_overlay_sha256, "functional source overlay changed during E2E")
        for allocator, oracle_path in oracle_paths.items():
            require(hash_path(oracle_path) == oracle_hashes[allocator], f"frozen oracle changed during E2E: {allocator}")
        for artifact_name, (artifact_path, artifact_sha256) in pinned_artifacts.items():
            require(hash_path(artifact_path) == artifact_sha256, f"frozen input changed during functional E2E: {artifact_name}")
        for artifact_name, evidence in source["build_evidence"].items():
            evidence_path = output_root / evidence["path"]
            require(hash_path(evidence_path) == evidence["sha256"], f"build evidence changed during functional E2E: {artifact_name}")
        for item in report["cases"]:
            require(hash_path(Path(item["runtime_bindings_path"])) == item["runtime_bindings_sha256"], "runtime binding manifest changed during E2E")
            require(hash_path(Path(item["functional_overlay_path"])) == item["functional_overlay_sha256"], "functional pair overlay changed during E2E")
        report["passed_functional_checks"] = True
        write_report(report_path, report)
        return 0
    except Exception as error:
        report["passed_functional_checks"] = False
        report["error"] = str(error)
        try:
            write_report(report_path, report)
        except Exception:
            pass
        print(f"functional E2E stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
