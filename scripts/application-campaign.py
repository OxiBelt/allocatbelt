#!/usr/bin/env python3
"""Preregister, validate, and fail-retain application campaign cells.

This controller does not choose rates or controls. It consumes their frozen
digests and emits a deterministic schedule. Preparation can be completed while
the benchmark contract is still incomplete; execution is refused until the
owning global/tenant resource domain and matched feedback binding are pinned.
Raw run artifacts belong under an external private output root.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import heapq
import hashlib
import json
import math
import os
import re
import signal
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from fractions import Fraction
from pathlib import Path
from typing import Any


SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v2"
SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v2"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v1"
LEDGER_SCHEMA = "allocatbelt.application-campaign-ledger.v1"
ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
STANDALONE = ("cpu", "memory", "http", "disk")
FAMILIES = (*STANDALONE, "mixed")
LOADS = (70, 90)
MAX_ARRIVALS = 1_000_000
# Qualification stays hard-disabled until the production binary emits and the
# controller verifies its owning-domain, policy, ceiling, and live-usage
# readback. Manifest labels alone cannot enable native execution or pass gates.
RUNTIME_QUALIFICATION_READBACK_SUPPORTED = False
EXTERNAL_PRESSURE_DRIVER_SUPPORTED = False
ANALYZER_INPUT_MAGIC = b"ABQST01\0"
ANALYZER_OUTPUT_MAGIC = b"ABQSO01\0"
ANALYZER_INPUT_LIMIT_BYTES = 32 * 1024**3
ANALYZER_RESIDENT_BUDGET_BYTES = 2 * 1024**3
ANALYZER_PRIMARY_ENDPOINTS_PER_HOST = 486
ANALYZER_SUITE_ENDPOINTS_PER_HOST = 9
ANALYZER_PAIR_GROUPS_PER_HOST = 135
COMPARISON_FAMILY_ORDER = ["fixed_policy", "external_pressure"]
PRESSURE_PREDECESSOR_CONTRACT = "fixed_policy_successful_pair_receipt_same_host_workload_profile_allocator_executor_load_ordinal"
CONTROL_KEYS = {
    "cpu_model",
    "microcode_sha256",
    "kernel_release",
    "governor",
    "frequency_policy",
    "boost_policy",
    "cpu_set",
    "numa_policy",
    "cgroup_policy_sha256",
    "background_load_policy_sha256",
    "x86_64_v3_capability_sha256",
    "target_triple",
    "target_cpu",
}


class CampaignError(Exception):
    pass


@contextmanager
def hard_wall_deadline(seconds: float, message: str):
    require(math.isfinite(seconds) and seconds > 0, "hard wall deadline must be positive and finite")

    def expired(_signum: int, _frame: Any) -> None:
        raise CampaignError(message)

    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if previous_timer[0] > 0:
            remaining = max(0.0, previous_timer[0] - (time.monotonic() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])
        signal.signal(signal.SIGALRM, previous_handler)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignError(message)


def exact_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{name} must be an object")
    missing = expected - value.keys()
    extra = value.keys() - expected
    require(not missing, f"{name} is missing keys: {sorted(missing)}")
    require(not extra, f"{name} has unknown keys: {sorted(extra)}")
    return value


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CampaignError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"cannot read JSON input {path}: {error}") from error
    require(isinstance(value, dict), f"JSON input {path} must contain an object")
    return value


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise CampaignError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def digest_object(value: dict[str, Any], field: str = "manifest_sha256") -> str:
    payload = dict(value)
    payload.pop(field, None)
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def token(value: Any, name: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", value), f"invalid {name}")
    return value


def positive_int(value: Any, name: str, maximum: int | None = None) -> int:
    require(type(value) is int and value > 0, f"{name} must be a positive integer")
    if maximum is not None:
        require(value <= maximum, f"{name} exceeds its finite bound {maximum}")
    return value


def run_checked(args: list[str], cwd: Path | None = None, timeout_seconds: float = 120.0) -> bytes:
    require(math.isfinite(timeout_seconds) and timeout_seconds > 0, "command timeout must be positive and finite")
    try:
        result = subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise CampaignError(f"command failed: {args[0]} ({error})") from error
    return result.stdout


def source_inventory(root: Path, timeout_seconds: float = 120.0) -> tuple[str, list[dict[str, Any]]]:
    root = root.resolve(strict=True)
    git_root = Path(run_checked(["git", "rev-parse", "--show-toplevel"], root, timeout_seconds).decode().strip()).resolve()
    require(git_root == root, "source root must be the git worktree root")
    files = run_checked(["git", "ls-files", "-co", "--exclude-standard", "-z"], root, timeout_seconds)
    relpaths = sorted(path for path in files.split(b"\0") if path)
    require(relpaths, "source tree contains no files")
    records: list[dict[str, Any]] = []
    checksum_input = bytearray()
    for raw_path in relpaths:
        require(b"\n" not in raw_path and b"\\" not in raw_path, "source paths with newline or backslash are not supported by the runner hash format")
        rel = raw_path.decode("utf-8")
        candidate = root / rel
        require(not candidate.is_symlink(), f"source inventory refuses symlink: {rel}")
        try:
            data = candidate.read_bytes()
        except OSError as error:
            raise CampaignError(f"source file is unreadable: {rel}: {error}") from error
        sha = hashlib.sha256(data).hexdigest()
        records.append({"path": rel, "sha256": sha, "size": len(data)})
        checksum_input.extend(f"{sha}  {rel}\n".encode("utf-8"))
    return hashlib.sha256(checksum_input).hexdigest(), records


def source_manifest(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.source_root).resolve(strict=True)
    require(args.target_triple == "x86_64-unknown-linux-gnu", "campaign target must be x86_64-unknown-linux-gnu")
    require(args.target_cpu == "x86-64-v3", "campaign build must pin x86-64-v3")
    commit = run_checked(["git", "rev-parse", "HEAD"], root).decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None, "invalid git commit id")
    tree_sha, source_files = source_inventory(root)
    cargo_lock = root / "Cargo.lock"
    require(cargo_lock.is_file(), "source root lacks Cargo.lock")
    rustc = run_checked(["rustc", "-Vv"], root).decode().splitlines()
    cargo = run_checked(["cargo", "-V"], root).decode().strip()
    rustc_release = next((line.removeprefix("release: ") for line in rustc if line.startswith("release: ")), "")
    require(rustc_release == "1.99.0", f"expected Rust 1.99.0, found {rustc_release or 'unknown'}")
    artifacts: dict[str, dict[str, Any]] = {}
    for assignment in args.allocator_binary:
        label, separator, path = assignment.partition("=")
        require(separator and label in ALLOCATORS, f"invalid allocator binary binding: {assignment}")
        require(label not in artifacts, f"duplicate allocator binary binding: {label}")
        artifact_rel = Path(path)
        require(not artifact_rel.is_absolute() and ".." not in artifact_rel.parts, "binary path must be relative to source root")
        artifact = root / artifact_rel
        require(artifact.is_file() and not artifact.is_symlink(), f"binary artifact missing or symlinked: {artifact_rel}")
        artifacts[label] = {"path": artifact_rel.as_posix(), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
    require(set(artifacts) == set(ALLOCATORS), f"all four allocator binaries required; got {sorted(artifacts)}")
    require(len({item["path"] for item in artifacts.values()}) == len(ALLOCATORS), "allocator binaries must have distinct frozen paths")
    soak_artifacts: dict[str, dict[str, Any]] = {}
    for assignment in args.soak_binary:
        label, separator, path = assignment.partition("=")
        require(separator and label in ALLOCATORS, f"invalid soak binary binding: {assignment}")
        require(label not in soak_artifacts, f"duplicate soak binary binding: {label}")
        artifact_rel = Path(path)
        require(not artifact_rel.is_absolute() and ".." not in artifact_rel.parts, "soak binary path must be relative to source root")
        artifact = root / artifact_rel
        require(artifact.is_file() and not artifact.is_symlink(), f"soak binary artifact missing or symlinked: {artifact_rel}")
        soak_artifacts[label] = {"path": artifact_rel.as_posix(), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
    require(set(soak_artifacts) == set(ALLOCATORS), f"all four dedicated soak binaries required; got {sorted(soak_artifacts)}")
    require(len({item["path"] for item in soak_artifacts.values()}) == len(ALLOCATORS), "dedicated soak binaries must have distinct frozen paths")
    analyzer_relative = Path(args.analysis_binary)
    require(not analyzer_relative.is_absolute() and ".." not in analyzer_relative.parts, "analyzer binary path must be relative to source root")
    require(analyzer_relative.as_posix() not in {item["path"] for item in artifacts.values()} | {item["path"] for item in soak_artifacts.values()}, "analysis binary must be a distinct pinned build artifact")
    analyzer_path = root / analyzer_relative
    require(analyzer_path.is_file() and not analyzer_path.is_symlink(), "pinned analyzer binary is missing or symlinked")
    manifest: dict[str, Any] = {
        "schema": SOURCE_SCHEMA,
        "source": {
            "git_commit": commit,
            "source_tree_sha256": tree_sha,
            "cargo_lock_sha256": hashlib.sha256(cargo_lock.read_bytes()).hexdigest(),
            "files": source_files,
        },
        "build": {
            "host_id": token(args.host_id, "host id"),
            "rustc_release": rustc_release,
            "rustc_verbose": rustc,
            "cargo_version": cargo,
            "target_triple": args.target_triple,
            "target_cpu": args.target_cpu,
            "profile": "release",
            "features_sha256": args.features_sha256,
            "build_inputs_sha256": args.build_inputs_sha256,
        },
        "artifacts": artifacts,
        "soak_artifacts": soak_artifacts,
        "analysis_artifact": {
            "path": analyzer_relative.as_posix(),
            "sha256": hashlib.sha256(analyzer_path.read_bytes()).hexdigest(),
        },
    }
    require(is_sha256(args.features_sha256), "features manifest SHA-256 is required")
    require(is_sha256(args.build_inputs_sha256), "build inputs SHA-256 is required")
    manifest["manifest_sha256"] = digest_object(manifest)
    return manifest


def verify_source_manifest(
    manifest: dict[str, Any], source_root: Path | None = None, verify_artifacts: bool = True,
    timeout_seconds: float = 120.0,
) -> None:
    exact_keys(manifest, {"schema", "source", "build", "artifacts", "soak_artifacts", "analysis_artifact", "manifest_sha256"}, "source manifest")
    require(manifest["schema"] == SOURCE_SCHEMA, "unsupported source-manifest schema")
    require(is_sha256(manifest["manifest_sha256"]) and digest_object(manifest) == manifest["manifest_sha256"], "source-manifest digest mismatch")
    source = exact_keys(manifest["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "source manifest source")
    build = exact_keys(manifest["build"], {"host_id", "rustc_release", "rustc_verbose", "cargo_version", "target_triple", "target_cpu", "profile", "features_sha256", "build_inputs_sha256"}, "source manifest build")
    require(source["git_commit"] and is_sha256(source["source_tree_sha256"]) and is_sha256(source["cargo_lock_sha256"]), "source identity is incomplete")
    require(build["rustc_release"] == "1.99.0" and build["target_triple"] == "x86_64-unknown-linux-gnu" and build["target_cpu"] == "x86-64-v3" and build["profile"] == "release", "amd64-v3 build identity is unfrozen")
    require(is_sha256(build["features_sha256"]) and is_sha256(build["build_inputs_sha256"]), "build controls are not pinned")
    exact_keys(manifest["artifacts"], set(ALLOCATORS), "source manifest artifacts")
    exact_keys(manifest["soak_artifacts"], set(ALLOCATORS), "source manifest soak artifacts")
    exact_keys(manifest["analysis_artifact"], {"path", "sha256"}, "source manifest analyzer artifact")
    analysis_path = Path(manifest["analysis_artifact"]["path"])
    require(not analysis_path.is_absolute() and ".." not in analysis_path.parts and is_sha256(manifest["analysis_artifact"]["sha256"]), "source manifest analyzer path/digest is malformed")
    require(len({item.get("path") for item in manifest["artifacts"].values()}) == len(ALLOCATORS), "source manifest aliases allocator binary paths")
    require(len({item.get("path") for item in manifest["soak_artifacts"].values()}) == len(ALLOCATORS), "source manifest aliases dedicated soak binary paths")
    require(manifest["analysis_artifact"].get("path") not in {item.get("path") for item in manifest["artifacts"].values()} | {item.get("path") for item in manifest["soak_artifacts"].values()}, "source manifest reuses a treatment binary for analysis")
    require(isinstance(source["files"], list) and source["files"], "source file inventory is missing")
    inventory_hash = hashlib.sha256("".join(f"{entry['sha256']}  {entry['path']}\n" for entry in source["files"]).encode()).hexdigest()
    require(inventory_hash == source["source_tree_sha256"], "source file inventory digest is invalid")
    if source_root is not None:
        root = source_root.resolve(strict=True)
        tree_sha, files = source_inventory(root, timeout_seconds)
        current_commit = run_checked(["git", "rev-parse", "HEAD"], root, timeout_seconds).decode().strip()
        require(current_commit == source["git_commit"] and tree_sha == source["source_tree_sha256"] and files == source["files"], "source tree differs from the frozen manifest")
        current_rustc = run_checked(["rustc", "-Vv"], root, timeout_seconds).decode().splitlines()
        current_cargo = run_checked(["cargo", "-V"], root, timeout_seconds).decode().strip()
        require(current_rustc == build["rustc_verbose"] and current_cargo == build["cargo_version"], "toolchain differs from the frozen build manifest")
    if verify_artifacts:
        require(source_root is not None, "source root required to verify live artifacts")
        root = source_root.resolve(strict=True)
        all_artifacts = {
            **manifest["artifacts"],
            **{f"soak-{name}": value for name, value in manifest["soak_artifacts"].items()},
            "analysis-engine": manifest["analysis_artifact"],
        }
        for label, artifact in all_artifacts.items():
            exact_keys(artifact, {"path", "sha256"}, f"artifact {label}")
            rel = Path(artifact["path"])
            require(not rel.is_absolute() and ".." not in rel.parts, f"artifact path for {label} is not portable")
            binary = root / rel
            require(binary.is_file() and not binary.is_symlink() and hashlib.sha256(binary.read_bytes()).hexdigest() == artifact["sha256"], f"frozen binary mismatch: {label}")


def load_source_manifests(spec: dict[str, Any], spec_path: Path, source_root: Path | None, selected_host: str | None = None) -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for ref in spec.get("source_manifests", []):
        exact_keys(ref, {"host_id", "relative_path", "sha256"}, "source manifest reference")
        host_id = ref["host_id"]
        path = Path(ref["relative_path"])
        require(not path.is_absolute() and ".." not in path.parts and is_sha256(ref["sha256"]), f"invalid host source manifest reference: {host_id}")
        manifest_path = spec_path.resolve().parent / path
        source = read_json(manifest_path)
        require(source.get("manifest_sha256") == ref["sha256"], f"host source manifest digest mismatch: {host_id}")
        verify_source_manifest(source, source_root, selected_host == host_id)
        sources[host_id] = source
    return sources


def expected_profile_cells() -> set[tuple[str, str, str]]:
    result = {(family, family, profile) for family in STANDALONE for profile in ("steady", "burst", "oversubscribed")}
    result.update(("mixed", "mixed", profile) for profile in ("mixed", "burst", "oversubscribed"))
    return result


def preregistration_digest(spec: dict[str, Any]) -> str:
    core = dict(spec)
    core.pop("rates", None)
    core.pop("oracles", None)
    return digest_object(core)


def validate_spec(spec: dict[str, Any], sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    expected = {"schema", "campaign_id", "source_manifests", "runner_sha256", "hosts", "cells", "rates", "oracles", "protocol", "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines"}
    exact_keys(spec, expected, "campaign spec")
    require(spec["schema"] == SPEC_SCHEMA, "unsupported campaign-spec schema")
    campaign_id = token(spec["campaign_id"], "campaign_id")
    require(is_sha256(spec["runner_sha256"]), "pair runner implementation is not pinned")
    hosts = spec["hosts"]
    require(isinstance(hosts, list) and len(hosts) == 3, "campaign requires exactly three pinned hosts")
    seen_hosts: set[str] = set()
    venues: list[str] = []
    for index, host in enumerate(hosts):
        exact_keys(host, {"host_id", "venue", "host_fingerprint_sha256", "controls"}, f"host[{index}]")
        host_id = token(host["host_id"], "host id")
        require(host_id not in seen_hosts, f"duplicate host id: {host_id}")
        seen_hosts.add(host_id)
        venues.append(host["venue"])
        require(host["venue"] in ("bare_metal", "kvm_guest"), f"unknown venue for {host_id}")
        require(is_sha256(host["host_fingerprint_sha256"]), f"host fingerprint is not pinned: {host_id}")
        controls = exact_keys(host["controls"], CONTROL_KEYS, f"host controls {host_id}")
        require(controls["target_triple"] == "x86_64-unknown-linux-gnu" and controls["target_cpu"] == "x86-64-v3", f"host {host_id} is not an amd64-v3 target")
        for field in ("microcode_sha256", "cgroup_policy_sha256", "background_load_policy_sha256", "x86_64_v3_capability_sha256"):
            require(is_sha256(controls[field]), f"host {host_id} has unfrozen control {field}")
        for field in ("cpu_model", "kernel_release", "governor", "frequency_policy", "boost_policy", "cpu_set", "numa_policy"):
            require(isinstance(controls[field], str) and controls[field], f"host {host_id} has unknown control {field}")
        require(hashlib.sha256(canonical_bytes(controls)).hexdigest() == host["host_fingerprint_sha256"], f"host {host_id} fingerprint does not match its controls")
    source_refs = spec["source_manifests"]
    require(isinstance(source_refs, list) and len(source_refs) == 3, "one source/build manifest per host is required")
    refs_by_host: dict[str, dict[str, Any]] = {}
    for index, ref in enumerate(source_refs):
        exact_keys(ref, {"host_id", "relative_path", "sha256"}, f"source manifest reference[{index}]")
        host_id = token(ref["host_id"], "source manifest host id")
        require(host_id in seen_hosts and host_id not in refs_by_host, f"source manifest has unknown or duplicate host: {host_id}")
        path = Path(ref["relative_path"])
        require(not path.is_absolute() and ".." not in path.parts, f"source manifest path must be portable: {host_id}")
        require(is_sha256(ref["sha256"]) and sources[host_id]["manifest_sha256"] == ref["sha256"], f"source manifest hash mismatch: {host_id}")
        require(sources[host_id]["build"]["host_id"] == host_id, f"build manifest host identity mismatch: {host_id}")
        refs_by_host[host_id] = ref
    require(set(refs_by_host) == seen_hosts and set(sources) == seen_hosts, "source manifests do not cover the exact host matrix")
    identities = {
        (source["source"]["git_commit"], source["source"]["source_tree_sha256"], source["source"]["cargo_lock_sha256"], source["build"]["rustc_release"], tuple(source["build"]["rustc_verbose"]), source["build"]["cargo_version"], source["build"]["target_triple"], source["build"]["target_cpu"], source["build"]["features_sha256"], source["build"]["build_inputs_sha256"], source["analysis_artifact"]["path"], source["analysis_artifact"]["sha256"])
        for source in sources.values()
    }
    require(len(identities) == 1, "host builds do not share the frozen source/toolchain/amd64-v3 contract")
    require(venues.count("bare_metal") == 1 and venues.count("kvm_guest") == 2, "host matrix must contain one bare-metal host and two KVM guests")

    binding = exact_keys(spec["runtime_binding"], {"resource_domain", "resource_policy_sha256", "feedback_policy_sha256", "feedback_match", "source_state"}, "runtime binding")
    require(binding["source_state"] in ("pending", "complete"), "unknown runtime-source state")
    require(binding["resource_domain"] in ("pending", "owning_global_tenant"), "unknown resource-domain execution binding")
    require(binding["feedback_match"] in ("pending", "fixed_same_policy", "external_same_policy"), "unknown matched feedback-policy binding")
    for field in ("resource_policy_sha256", "feedback_policy_sha256"):
        require(is_sha256(binding[field]), f"runtime binding lacks frozen {field}")
    require(binding["feedback_match"] in ("fixed_same_policy", "external_same_policy"), "allocatbelt and Tokio feedback policy must be explicitly matched")

    phase_adapters = exact_keys(spec["phase_adapters"], {"same_executor_aa_sha256", "three_hour_soak_sha256", "simultaneous_analysis_sha256"}, "phase adapters")
    for name, value in phase_adapters.items():
        require(value is None or is_sha256(value), f"phase adapter pin is malformed: {name}")

    cells = spec["cells"]
    require(isinstance(cells, list), "cells must be a list")
    actual_cells: set[tuple[str, str, str]] = set()
    cell_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, cell in enumerate(cells):
        exact_keys(cell, {"family", "workload", "profile", "arrivals", "async_workers", "resource_limits", "resource_ceiling_sha256", "capacity_horizon_seconds"}, f"cell[{index}]")
        key = (cell["family"], cell["workload"], cell["profile"])
        require(key not in actual_cells, f"duplicate family/profile cell: {key}")
        actual_cells.add(key)
        cell_map[key] = cell
        require(cell["family"] in FAMILIES and cell["workload"] in FAMILIES, f"unknown family/workload in {key}")
        require(isinstance(cell["arrivals"], int) and 1 <= cell["arrivals"] <= MAX_ARRIVALS, f"arrival count outside finite bound in {key}")
        minimum = 400_000 if cell["workload"] == "mixed" else 100_000
        require(cell["arrivals"] >= minimum, f"confirmation trace too small for {key}")
        require(cell["async_workers"] == (2 if cell["profile"] == "oversubscribed" else 4), f"worker count mismatches profile: {key}")
        limits = exact_keys(cell["resource_limits"], {"managed_bytes", "disk_ops", "network_ops", "tasks", "cpu_charges"}, f"resource limits {key}")
        for field, value in limits.items():
            require(type(value) is int and 0 <= value <= (1 << 64) - 1, f"resource limit is not a finite u64: {key}/{field}")
        require(limits["tasks"] > 0 and limits["cpu_charges"] > 0, f"task/CPU ceilings must be positive: {key}")
        require(hashlib.sha256(canonical_bytes(limits)).hexdigest() == cell["resource_ceiling_sha256"], f"resource ceiling digest does not bind the numeric limits: {key}")
        require(is_sha256(cell["resource_ceiling_sha256"]), f"resource ceiling is not frozen for {key}")
        require(cell["capacity_horizon_seconds"] == 30, f"capacity horizon must be 30s for {key}")
    require(actual_cells == expected_profile_cells(), f"family/profile matrix differs from required set; missing={sorted(expected_profile_cells() - actual_cells)} extra={sorted(actual_cells - expected_profile_cells())}")

    protocol = exact_keys(spec["protocol"], {"exploration_pairs", "confirmation_pairs", "standalone_min_successes", "mixed_min_successes", "family_min_successes", "bootstrap_draws", "bootstrap_block_arrivals", "bootstrap_seed", "bootstrap_prng", "comparison_family_order", "external_pressure_predecessor", "confidence", "simultaneous_adjustment", "bootstrap_hierarchy", "weighting", "gate_scope", "safety_overload_gate_eligible", "soak_seconds", "soak_rss_growth_percent", "schedule_seed", "allocator_min_capacity_ratio", "allocator_max_p99_ratio", "executor_min_capacity_ratio", "executor_max_p99_ratio", "max_workload_throughput_ratio", "max_workload_cpu_ratio", "max_workload_p99_ratio", "max_retained_rss_ratio"}, "protocol")
    require(protocol["exploration_pairs"] == 6 and protocol["confirmation_pairs"] == 36, "exploration/confirmation pair counts are fixed at six and 36")
    require(protocol["standalone_min_successes"] == 100_000 and protocol["mixed_min_successes"] == 400_000 and protocol["family_min_successes"] == 100_000, "observation minima differ from the frozen qualification contract")
    require(protocol["bootstrap_draws"] == 50_000 and protocol["bootstrap_block_arrivals"] == 1000 and protocol["confidence"] == 0.95, "bootstrap contract differs from the frozen qualification contract")
    require(protocol["simultaneous_adjustment"] == "paired_contiguous_block_max_standardized_deviation", "unknown simultaneous interval method")
    require(protocol["bootstrap_hierarchy"] == "independent_pair_jobs_with_shared_indices_within_job_then_full_contiguous_block_pseudotraces", "unknown paired-job bootstrap hierarchy")
    require(protocol["bootstrap_prng"] == "splitmix64_v1_fnv1a_group_seed_rejection_uniform", "bootstrap PRNG/group seed schedule is not frozen to analyzer protocol v1")
    require(protocol["comparison_family_order"] == COMPARISON_FAMILY_ORDER, "fixed-policy then external-pressure family order is not frozen")
    require(protocol["external_pressure_predecessor"] == PRESSURE_PREDECESSOR_CONTRACT, "external-pressure predecessor contract differs from the frozen comparison family schema")
    require(protocol["weighting"] == "equal_profile_then_family_then_equal_eligible_contexts", "profile/family/context weights must be frozen")
    require(protocol["gate_scope"] == "independent_per_host_no_pooling" and protocol["safety_overload_gate_eligible"] is False, "host pooling or safety-profile promotion is forbidden")
    gates = {
        "allocator_min_capacity_ratio": 1.05,
        "allocator_max_p99_ratio": 0.95,
        "executor_min_capacity_ratio": 1.05,
        "executor_max_p99_ratio": 0.95,
        "max_workload_throughput_ratio": 0.98,
        "max_workload_cpu_ratio": 1.02,
        "max_workload_p99_ratio": 1.05,
        "max_retained_rss_ratio": 1.05,
    }
    require(all(protocol[key] == value for key, value in gates.items()), "numeric gates differ from the restored qualification plan")
    positive_int(protocol["soak_seconds"], "soak duration")
    require(protocol["soak_seconds"] == 10_800 and protocol["soak_rss_growth_percent"] == 5, "soak contract must be three hours with five-percent RSS bound")
    positive_int(protocol["bootstrap_seed"], "bootstrap seed")
    positive_int(protocol["schedule_seed"], "schedule seed")

    deadlines = exact_keys(spec["deadlines"], {"setup_seconds", "trace_seconds", "drain_seconds", "shutdown_seconds", "process_seconds", "pair_validation_seconds", "outer_seconds", "soak_outer_seconds"}, "deadlines")
    for name, value in deadlines.items():
        positive_int(value, f"deadline {name}")
    require(deadlines["setup_seconds"] == 120 and deadlines["trace_seconds"] <= 3600 and deadlines["drain_seconds"] <= 3600 and deadlines["shutdown_seconds"] <= 600 and deadlines["process_seconds"] <= 7200 and deadlines["pair_validation_seconds"] <= 3600 and deadlines["outer_seconds"] >= 3 * deadlines["process_seconds"] + deadlines["setup_seconds"] + deadlines["pair_validation_seconds"] and deadlines["outer_seconds"] <= 25_320, "outer watchdog does not cover oracle generation, both pair processes, setup, and validation")
    require(deadlines["soak_outer_seconds"] >= protocol["soak_seconds"] + 1200 + deadlines["pair_validation_seconds"] and deadlines["soak_outer_seconds"] <= 14_400, "soak outer watchdog does not cover its full continuous horizon and receipt validation")
    shutdown_units = max(4 if cell["workload"] == "mixed" else 3 if cell["workload"] == "http" else 2 if cell["workload"] == "disk" else 1 for cell in cells)
    minimum_process = deadlines["setup_seconds"] + deadlines["trace_seconds"] + deadlines["drain_seconds"] + deadlines["shutdown_seconds"] * shutdown_units
    require(deadlines["process_seconds"] >= minimum_process, "whole-process deadline does not cover setup, configured trace, drain, and all driver shutdown budgets")

    rates = spec["rates"]
    require(isinstance(rates, list), "rates must be a list")
    rate_keys: set[tuple[str, str, str, int]] = set()
    for index, rate in enumerate(rates):
        exact_keys(rate, {"host_id", "family", "profile", "load_percent", "arrivals_per_second", "pilot_manifest_sha256"}, f"rate[{index}]")
        key = (rate["host_id"], rate["family"], rate["profile"], rate["load_percent"])
        require(key not in rate_keys, f"duplicate rate key: {key}")
        rate_keys.add(key)
        require(rate["host_id"] in seen_hosts and (rate["family"], cell_map.get((rate["family"], "mixed" if rate["family"] == "mixed" else rate["family"], rate["profile"]), {}).get("workload"), rate["profile"]) in actual_cells, f"rate references unknown cell: {key}")
        require(rate["load_percent"] in LOADS, f"unknown open-loop load fraction: {key}")
        positive_int(rate["arrivals_per_second"], f"arrival rate {key}", 1_000_000_000)
        require(is_sha256(rate["pilot_manifest_sha256"]), f"rate lacks frozen pilot provenance: {key}")
        cell = next((c for c in cells if c["family"] == rate["family"] and c["profile"] == rate["profile"]), None)
        require(cell is not None, f"rate has no corresponding cell: {key}")
        rate_seconds = (cell["arrivals"] + rate["arrivals_per_second"] - 1) // rate["arrivals_per_second"]
        require(rate_seconds <= deadlines["trace_seconds"], f"rate/count exceeds trace deadline: {key}")
    expected_rates = {(host_id, cell["family"], cell["profile"], load) for host_id in seen_hosts for cell in cells for load in LOADS}
    require(not rate_keys or rate_keys == expected_rates, f"frozen 70/90 rate matrix incomplete: missing={len(expected_rates - rate_keys)} extra={len(rate_keys - expected_rates)}")

    oracles = spec["oracles"]
    require(isinstance(oracles, list), "oracles must be a list")
    oracle_keys: set[tuple[str, str, str, str, int]] = set()
    for index, oracle in enumerate(oracles):
        exact_keys(oracle, {"host_id", "allocator", "family", "profile", "load_percent", "relative_path", "sha256"}, f"oracle[{index}]")
        key = (oracle["host_id"], oracle["allocator"], oracle["family"], oracle["profile"], oracle["load_percent"])
        require(key not in oracle_keys, f"duplicate oracle key: {key}")
        oracle_keys.add(key)
        require(oracle["host_id"] in seen_hosts and oracle["allocator"] in ALLOCATORS and oracle["load_percent"] in LOADS, f"oracle references unknown cell: {key}")
        require(isinstance(oracle["relative_path"], str) and not Path(oracle["relative_path"]).is_absolute() and ".." not in Path(oracle["relative_path"]).parts, f"oracle path must be relative: {key}")
        require(is_sha256(oracle["sha256"]), f"oracle digest is not frozen: {key}")
    expected_oracles = {(host_id, allocator, cell["family"], cell["profile"], load) for host_id in seen_hosts for allocator in ALLOCATORS for cell in cells for load in LOADS}
    require(not oracle_keys or oracle_keys == expected_oracles, f"trusted oracle matrix incomplete: missing={len(expected_oracles - oracle_keys)} extra={len(oracle_keys - expected_oracles)}")
    require(not oracle_keys or bool(rate_keys), "trusted oracles require frozen 70/90 rates")
    oracles_frozen = oracle_keys == expected_oracles
    confirmation_ready = bool(rate_keys) and oracles_frozen

    aa = spec["aa_controls"]
    require(isinstance(aa, list) and aa, "A/A controls must be explicitly preregistered")
    aa_ids: set[str] = set()
    for index, item in enumerate(aa):
        exact_keys(item, {"control_id", "allocator", "family", "profile", "mode", "load_percent", "executor", "pairs", "purpose"}, f"A/A control[{index}]")
        aa_id = token(item["control_id"], "A/A control id")
        require(aa_id not in aa_ids, f"duplicate A/A control id: {aa_id}")
        aa_ids.add(aa_id)
        require(item["allocator"] in ALLOCATORS and item["family"] in FAMILIES and item["profile"] in ("steady", "mixed", "burst", "oversubscribed"), f"unknown A/A control scope: {aa_id}")
        require(item["mode"] in ("capacity", "open_loop") and item["executor"] in ("bounded", "tokio"), f"unknown A/A control mode: {aa_id}")
        require((item["mode"] == "capacity" and item["load_percent"] is None) or (item["mode"] == "open_loop" and item["load_percent"] in LOADS), f"A/A control load is not frozen: {aa_id}")
        require((item["family"], "mixed" if item["family"] == "mixed" else item["family"], item["profile"]) in actual_cells, f"A/A control references an unknown profile cell: {aa_id}")
        require(item["mode"] != "open_loop" or confirmation_ready, f"open-loop A/A control requires frozen rates and trusted oracles: {aa_id}")
        positive_int(item["pairs"], f"A/A control pairs {aa_id}", 36)
        require(isinstance(item["purpose"], str) and item["purpose"], f"A/A control purpose missing: {aa_id}")

    soak = exact_keys(spec["soak"], {"workload", "profile", "allocator", "executor", "driver_relative_path", "driver_sha256", "interval_ms"}, "soak")
    require(soak["workload"] == "mixed" and soak["profile"] in ("mixed", "burst", "oversubscribed") and soak["allocator"] in ALLOCATORS and soak["executor"] in ("bounded", "tokio"), "soak treatment must be an explicit mixed-load cell")
    require(is_sha256(soak["driver_sha256"]), "three-hour soak driver is not pinned")
    soak_path = Path(soak["driver_relative_path"])
    require(not soak_path.is_absolute() and ".." not in soak_path.parts and soak_path.suffix == ".sh", "soak driver path must be a portable source-relative shell script")
    for host_id, source in sources.items():
        source_files = {item["path"]: item["sha256"] for item in source["source"]["files"]}
        require(source_files.get(soak_path.as_posix()) == soak["driver_sha256"], f"host {host_id} source manifest does not bind the continuous soak runner")
    require(soak["interval_ms"] == 100, "soak resource sampling interval must remain 100ms")

    require(campaign_id, "campaign id is invalid")
    binding_ready = binding["resource_domain"] == "owning_global_tenant" and binding["source_state"] == "complete" and binding["feedback_match"] in ("fixed_same_policy", "external_same_policy")
    aa_runner_ready = phase_adapters["same_executor_aa_sha256"] == spec["runner_sha256"]
    soak_ready = is_sha256(phase_adapters["three_hour_soak_sha256"]) and phase_adapters["three_hour_soak_sha256"] == soak["driver_sha256"]
    analysis_script_sha = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
    analysis_ready = is_sha256(phase_adapters["simultaneous_analysis_sha256"]) and phase_adapters["simultaneous_analysis_sha256"] == analysis_script_sha
    rates_frozen = bool(rate_keys)
    gaps = []
    if not binding_ready:
        gaps.append("owning global/tenant ResourceDomain and matched feedback policy are not bound")
    if not RUNTIME_QUALIFICATION_READBACK_SUPPORTED:
        gaps.append("production binary runtime-domain/policy/ceiling readback is not implemented and independently validated")
    if not EXTERNAL_PRESSURE_DRIVER_SUPPORTED:
        gaps.append("external-pressure pair driver/readbacks are not implemented; fixed-policy predecessor receipts cannot qualify pressure")
    if not rates_frozen:
        gaps.append("six-pair exploration rates are not frozen")
    elif not oracles_frozen:
        gaps.append("canonical per-ID oracle generation and manifest binding are pending")
    if not aa_runner_ready:
        gaps.append("same-executor A/A driver hash is not bound to the frozen pair runner")
    if not soak_ready:
        gaps.append("three-hour continuous mixed-soak driver is not bound and validated")
    if not analysis_ready:
        gaps.append("simultaneous paired hierarchical bootstrap analyzer hash is not bound to this implementation")
    if not confirmation_ready:
        gaps.append("confirmation cannot launch before frozen rates and trusted per-ID oracles exist")
    execution_ready = binding_ready and RUNTIME_QUALIFICATION_READBACK_SUPPORTED
    full_gate_ready = execution_ready and EXTERNAL_PRESSURE_DRIVER_SUPPORTED and rates_frozen and confirmation_ready and aa_runner_ready and soak_ready and analysis_ready
    return {"campaign_id": campaign_id, "host_ids": sorted(seen_hosts), "cell_count": len(cells), "rate_count": len(rates), "oracle_count": len(oracles), "rates_frozen": rates_frozen, "oracles_frozen": oracles_frozen, "confirmation_ready": confirmation_ready, "execution_binding_complete": binding_ready, "runtime_readback_supported": RUNTIME_QUALIFICATION_READBACK_SUPPORTED, "pressure_family_ready": EXTERNAL_PRESSURE_DRIVER_SUPPORTED, "execution_ready": execution_ready, "full_gate_ready": full_gate_ready, "full_gate_gaps": gaps}


def load_rate_map(spec: dict[str, Any]) -> dict[tuple[str, str, str, int], int]:
    return {(item["host_id"], item["family"], item["profile"], item["load_percent"]): item["arrivals_per_second"] for item in spec["rates"]}


def freeze_rates(spec: dict[str, Any], pilot: dict[str, Any], pilot_sha256: str) -> dict[str, Any]:
    exact_keys(pilot, {"schema", "spec_sha256", "host_id", "cells"}, "pilot evidence")
    require(pilot["schema"] == "allocatbelt.application-capacity-pilot.v1", "unsupported pilot evidence schema")
    require(pilot["spec_sha256"] == preregistration_digest(spec), "pilot evidence belongs to a different preregistration")
    hosts = {item["host_id"] for item in spec["hosts"]}
    require(pilot["host_id"] in hosts, "pilot evidence host is not preregistered")
    expected_cells = {(cell["family"], cell["profile"]) for cell in spec["cells"]}
    expected_keys = {(family, profile, allocator) for family, profile in expected_cells for allocator in ALLOCATORS}
    observed: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    require(isinstance(pilot["cells"], list), "pilot cells must be a list")
    for index, group in enumerate(pilot["cells"]):
        exact_keys(group, {"family", "profile", "allocator", "pairs"}, f"pilot cell[{index}]")
        key = (group["family"], group["profile"], group["allocator"])
        require(key not in observed and key in expected_keys, f"unknown or duplicate pilot cell: {key}")
        require(isinstance(group["pairs"], list) and len(group["pairs"]) == 6, f"pilot cell must contain six original pairs: {key}")
        pairs: list[dict[str, Any]] = []
        for pair_index, pair in enumerate(group["pairs"]):
            exact_keys(pair, {"ordinal", "bounded_status", "tokio_status", "bounded_on_time", "bounded_late", "bounded_attempted", "bounded_admitted", "bounded_rejected", "tokio_on_time", "tokio_late", "tokio_attempted", "tokio_admitted", "tokio_rejected", "raw_pair_sha256"}, f"pilot pair[{pair_index}] {key}")
            require(pair["ordinal"] == pair_index + 1 and pair["bounded_status"] == "valid" and pair["tokio_status"] == "valid", f"pilot pair is missing, reordered, or invalid: {key}")
            require(is_sha256(pair["raw_pair_sha256"]), f"pilot pair lacks raw evidence digest: {key}")
            for executor in ("bounded", "tokio"):
                on_time = positive_int(pair[f"{executor}_on_time"], f"{executor} on-time pilot completions", 10_000_000)
                late = pair[f"{executor}_late"]
                attempted = pair[f"{executor}_attempted"]
                admitted = pair[f"{executor}_admitted"]
                rejected = pair[f"{executor}_rejected"]
                require(type(late) is int and 0 <= late <= 10_000_000 and type(attempted) is int and 0 < attempted <= 10_000_000 and type(admitted) is int and type(rejected) is int, f"invalid pilot counts: {key}")
                require(attempted == admitted == on_time + late and rejected == 0, f"pilot accounting is not complete: {key}")
            pairs.append(pair)
        observed[key] = pairs
    require(set(observed) == expected_keys, f"pilot matrix incomplete: missing={len(expected_keys - set(observed))}")

    cells: list[dict[str, Any]] = []
    for family, profile in sorted(expected_cells):
        treatment_medians: list[Fraction] = []
        for allocator in ALLOCATORS:
            pairs = observed[(family, profile, allocator)]
            for executor in ("bounded", "tokio"):
                rates = sorted(Fraction(pair[f"{executor}_on_time"], 30) for pair in pairs)
                treatment_medians.append((rates[2] + rates[3]) / 2)
        weakest_capacity = min(treatment_medians)
        for load in LOADS:
            rate = (weakest_capacity * load).__floor__() // 100
            require(rate > 0, f"frozen {load}% rate floors to zero for {family}/{profile}")
            require(rate <= 250_000_000 if profile == "burst" else rate <= 1_000_000_000, f"frozen {load}% rate exceeds profile bound for {family}/{profile}")
            cells.append({"family": family, "profile": profile, "load_percent": load, "arrivals_per_second": rate})
    result = {
        "schema": "allocatbelt.application-frozen-rates.v1",
        "spec_sha256": preregistration_digest(spec),
        "pilot_manifest_sha256": pilot_sha256,
        "host_id": pilot["host_id"],
        "rate_basis": "floor(load_percent * min(six-pair median on-time capacity across all allocators and both executors))",
        "rates": cells,
    }
    result["manifest_sha256"] = digest_object(result)
    return result


def splitmix64_next(state: int) -> tuple[int, int]:
    state = (state + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
    value = state
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
    return state, value ^ (value >> 31)


def splitmix64_below(state: int, upper_bound: int) -> tuple[int, int]:
    require(upper_bound > 0, "random bound must be positive")
    modulus = 1 << 64
    acceptance_limit = modulus - modulus % upper_bound
    while True:
        state, value = splitmix64_next(state)
        if value < acceptance_limit:
            return state, value % upper_bound


def bootstrap_group_seed(seed: int, group_name: str, group_id: int) -> int:
    value = 0xCBF29CE484222325
    for byte in group_name.encode("utf-8"):
        value = ((value ^ byte) * 0x00000100000001B3) & ((1 << 64) - 1)
    return (seed ^ value ^ ((group_id * 0xD6E8FEB86659FD93) & ((1 << 64) - 1))) & ((1 << 64) - 1)


def splitmix64_below_v1(state: int, upper_bound: int) -> tuple[int, int]:
    require(upper_bound > 0, "random bound must be positive")
    threshold = ((-upper_bound) & ((1 << 64) - 1)) % upper_bound
    while True:
        state, value = splitmix64_next(state)
        if value >= threshold:
            return state, value % upper_bound


def nearest_rank(values: list[int], percentile: int) -> int:
    require(values and 0 < percentile <= 100, "nearest-rank quantile requires samples and percentile in 1..100")
    ordered = sorted(values)
    rank = (percentile * len(ordered) + 99) // 100
    return ordered[max(0, rank - 1)]


def bootstrap_ratio_interval(
    pair_samples: list[list[float]], draws: int, seed: int, alpha: float, two_sided: bool = True,
) -> tuple[float, float, float]:
    """Paired cluster/block bootstrap of positive candidate/control ratios.

    Each outer draw resamples matched run pairs. Each selected pair then
    contributes one paired 1,000-arrival block ratio, preserving both the
    allocator/executor match and contiguous arrival locality.
    """
    require(pair_samples and all(samples and all(value > 0 for value in samples) for samples in pair_samples), "bootstrap requires positive matched pair/block ratios")
    require(draws > 0 and 0 < alpha < 1, "invalid bootstrap draw count or tail probability")
    state = seed & ((1 << 64) - 1)
    estimates: list[float] = []
    for _ in range(draws):
        total = 0.0
        for _ in pair_samples:
            state, pair_index = splitmix64_below(state, len(pair_samples))
            blocks = pair_samples[pair_index]
            state, block_index = splitmix64_below(state, len(blocks))
            total += math.log(blocks[block_index])
        estimates.append(math.exp(total / len(pair_samples)))
    estimates.sort()
    tail = alpha / 2 if two_sided else alpha
    low_rank = max(0, math.floor(tail * draws))
    high_rank = min(draws - 1, math.ceil((1 - tail) * draws) - 1)
    point = math.exp(sum(math.log(value) for samples in pair_samples for value in samples) / sum(len(samples) for samples in pair_samples))
    return point, estimates[low_rank], estimates[high_rank]


def bootstrap_pair_interval(pair_ratios: list[float], draws: int, seed: int, alpha: float) -> tuple[float, float, float]:
    require(pair_ratios and all(value > 0 for value in pair_ratios), "paired bootstrap requires positive ratios")
    return bootstrap_ratio_interval([[value] for value in pair_ratios], draws, seed, alpha)


def joint_simultaneous_bootstrap(
    tests: list[dict[str, Any]], draws: int, seed: int, confidence: float = 0.95,
) -> tuple[list[dict[str, float]], dict[str, Any]]:
    """Shared-pair and shared-arrival-block max-standardized bootstrap.

    This is an unstudentized max-standardized-deviation bootstrap: each
    endpoint scale is the standard deviation of its joint bootstrap draws.
    Ratios are resampled on log scale. Each independent pair job gets an
    independent outer pair-index vector; endpoints derived from the same job
    share it. Each sampled trace resamples its complete contiguous block set,
    shared by both treatments and all mixed source families.
    """
    require(tests and draws > 0 and 0 < confidence < 1, "joint bootstrap contract is incomplete")
    measured_tests = [test for test in tests if test.get("suite_components") is None]
    require(measured_tests, "joint bootstrap has no process-pair endpoints")
    pair_count = len(measured_tests[0]["ratios"])
    require(pair_count > 0 and all(len(test["ratios"]) == pair_count for test in measured_tests), "joint bootstrap pair horizons differ")
    pair_groups = sorted({test["pair_group"] for test in measured_tests})
    block_groups = sorted({test["block_group"] for test in tests if test.get("traces") is not None})
    block_counts: dict[Any, list[int]] = {}
    for group in block_groups:
        group_tests = [test for test in tests if test.get("traces") is not None and test["block_group"] == group]
        first = group_tests[0]
        first_family = first["traces"][0]["family"]
        counts = [len(first["traces"][pair_index]["candidate"][first_family]) for pair_index in range(pair_count)]
        require(all(count > 0 for count in counts), f"paired arrival blocks are missing for {group}")
        for test in group_tests:
            family = test["traces"][0]["family"]
            require([len(test["traces"][pair_index]["candidate"][family]) for pair_index in range(pair_count)] == counts, f"paired arrival block horizons differ for {group}")
            require(all(len(test["traces"][pair_index]["control"][family]) == counts[pair_index] for pair_index in range(pair_count)), f"paired treatment block horizons differ for {group}")
        block_counts[group] = counts
    stable_group_names = {group: json.dumps(group, sort_keys=True, separators=(",", ":")) for group in pair_groups}
    group_states = {
        group: bootstrap_group_seed(seed, stable_group_names[group], group_id)
        for group_id, group in enumerate(sorted(pair_groups, key=lambda item: stable_group_names[item]))
    }

    def draw() -> tuple[dict[Any, list[int]], dict[tuple[Any, int], list[int]]]:
        pairs_by_group: dict[Any, list[int]] = {}
        indices: dict[tuple[Any, int], list[int]] = {}
        for group in pair_groups:
            state = group_states[group]
            pairs = []
            for slot in range(pair_count):
                state, selected = splitmix64_below_v1(state, pair_count)
                pairs.append(selected)
                if group in block_counts:
                    block_count = block_counts[group][selected]
                    selected_blocks = []
                    for _ in range(block_count):
                        state, block = splitmix64_below_v1(state, block_count)
                        selected_blocks.append(block)
                    indices[(group, slot)] = selected_blocks
            pairs_by_group[group] = pairs
            group_states[group] = state
        return pairs_by_group, indices

    centers: list[float] = []
    for test in tests:
        components = test.get("suite_components")
        if components is None:
            centers.append(sum(math.log(value) for value in test["ratios"]) / pair_count)
        else:
            weights = test["suite_weights"]
            require(len(weights) == len(components) and abs(sum(weights) - 1.0) < 1e-12, "suite component weights are malformed")
            centers.append(sum(weight * centers[index] for index, weight in zip(components, weights, strict=True)))

    def endpoint_draw(test: dict[str, Any], pairs_by_group: dict[Any, list[int]], blocks: dict[tuple[Any, int], list[int]]) -> float:
        components = test.get("suite_components")
        if components is not None:
            return sum(weight * endpoint_draw(tests[index], pairs_by_group, blocks) for index, weight in zip(components, test["suite_weights"], strict=True))
        pairs = pairs_by_group[test["pair_group"]]
        traces = test.get("traces")
        if traces is None:
            return sum(math.log(test["ratios"][pair_index]) for pair_index in pairs) / pair_count
        group = test["block_group"]
        total = 0.0
        for slot_index, pair_index in enumerate(pairs):
            trace = traces[pair_index]
            family = trace["family"]
            selected_blocks = blocks[(group, slot_index)]
            candidate = exact_pseudotrace_p99(trace["candidate"][family], selected_blocks)
            control = exact_pseudotrace_p99(trace["control"][family], selected_blocks)
            total += math.log(candidate / control)
        return total / pair_count

    means = [0.0] * len(tests)
    m2 = [0.0] * len(tests)
    observations = 0
    for draw_index in range(draws):
        pairs_by_group, block_indices = draw()
        observations += 1
        for endpoint, test in enumerate(tests):
            value = endpoint_draw(test, pairs_by_group, block_indices)
            delta = value - means[endpoint]
            means[endpoint] += delta / observations
            m2[endpoint] += delta * (value - means[endpoint])
    scales = [math.sqrt(value / (draws - 1)) for value in m2]
    for index, scale in enumerate(scales):
        if scale == 0.0:
            require(means[index] == centers[index], f"zero-scale endpoint is not exactly centered: {tests[index]['name']}")

    max_statistics: list[float] = []
    group_states = {
        group: bootstrap_group_seed(seed, stable_group_names[group], group_id)
        for group_id, group in enumerate(sorted(pair_groups, key=lambda item: stable_group_names[item]))
    }
    for _draw_index in range(draws):
        pairs_by_group, block_indices = draw()
        maximum = 0.0
        for endpoint, test in enumerate(tests):
            value = endpoint_draw(test, pairs_by_group, block_indices)
            if scales[endpoint] == 0.0:
                require(value == centers[endpoint], f"constant endpoint replicate differs from point: {test['name']}")
                continue
            maximum = max(maximum, abs(value - centers[endpoint]) / scales[endpoint])
        max_statistics.append(maximum)
    max_statistics.sort()
    critical_rank = min(draws - 1, math.ceil(confidence * draws) - 1)
    critical = max_statistics[critical_rank]
    intervals = []
    for center, scale in zip(centers, scales, strict=True):
        intervals.append({"point": math.exp(center), "lower": math.exp(center - critical * scale), "upper": math.exp(center + critical * scale), "scale_log": scale})
    metadata = {
        "schema": "allocatbelt.application-joint-bootstrap.v1",
        "method": "paired_contiguous_block_max_standardized_deviation",
        "prng": "splitmix64_v1_fnv1a_group_seed_rejection_uniform",
        "draws": draws,
        "seed": seed,
        "confidence": confidence,
        "endpoint_count": len(tests),
        "critical_value": critical,
        "critical_order_statistic_rank": critical_rank + 1,
        "critical_rank_mc_standard_error_draws": math.sqrt(draws * confidence * (1 - confidence)),
        "endpoint_order_sha256": hashlib.sha256("\n".join(test["name"] for test in tests).encode()).hexdigest(),
        "scale_definition": "sample_sd_of_shared_joint_log_ratio_bootstrap_draws",
        "point_definition": "geometric_mean_of_36_matched_process_ratios; suite endpoints are equal-weight geometric means",
    }
    return intervals, metadata


def ratio_gate(lower: float, upper: float, threshold: float, direction: str) -> bool:
    require(0 < lower <= upper and threshold > 0 and direction in ("lower", "upper"), "malformed ratio gate")
    return lower >= threshold if direction == "lower" else upper <= threshold


def equal_profile_family_context_weights(keys: list[tuple[str, str, str]]) -> list[float]:
    profiles = ("steady", "mixed", "burst", "oversubscribed")
    require(keys and {profile for profile, _, _ in keys} == set(profiles), "suite weighting requires all four frozen profiles")
    contexts: dict[tuple[str, str], set[str]] = {}
    families_by_profile: dict[str, set[str]] = {}
    for profile, family, context in keys:
        require(profile in profiles and family in STANDALONE and context in (*STANDALONE, "mixed"), "suite component has an unknown profile/family/context")
        contexts.setdefault((profile, family), set()).add(context)
        families_by_profile.setdefault(profile, set()).add(family)
    require(all(families_by_profile.get(profile) == set(STANDALONE) for profile in profiles), "each suite profile must represent all four workload families")
    require(all(contexts[(profile, family)] for profile in profiles for family in STANDALONE), "suite profile/family context is incomplete")
    return [1.0 / 4 / 4 / len(contexts[(profile, family)]) for profile, family, _context in keys]


def validate_phase_ledger(records: list[dict[str, Any]], expected_jobs: list[dict[str, Any]], phase: str, host_id: str) -> None:
    require(len(records) == len(expected_jobs), f"{phase} ledger is incomplete for host {host_id}")
    require(all(record.get("state") == "valid_pair" for record in records), f"{phase} contains a failed, interrupted, or invalid pair")
    actual: dict[str, dict[str, Any]] = {}
    for record in records:
        job = record.get("job")
        require(isinstance(job, dict) and job.get("phase") == phase and job.get("host_id") == host_id, f"{phase} ledger contains a foreign or malformed host record")
        run_id = job.get("run_id")
        require(isinstance(run_id, str) and run_id not in actual, f"{phase} ledger repeats a run id")
        actual[run_id] = job
    wanted = {job["run_id"]: job for job in expected_jobs}
    require(len(wanted) == len(expected_jobs) and set(actual) == set(wanted), f"{phase} ledger does not cover the exact frozen pair horizon")
    require(all(actual[run_id] == job for run_id, job in wanted.items()), f"{phase} ledger job metadata differs from its frozen plan")


def fixed_pressure_predecessor_receipt(
    pressure_job: dict[str, Any], fixed_record: dict[str, Any], spec: dict[str, Any],
) -> dict[str, Any]:
    fixed_job = fixed_record.get("job")
    require(
        fixed_record.get("state") == "valid_pair"
        and isinstance(fixed_job, dict)
        and fixed_job.get("comparison_family") == "fixed_policy",
        "external-pressure predecessor is not a successful fixed-policy pair receipt",
    )
    pressure_pair_kind = pressure_job["pair_kind"].removeprefix("pressure-")
    expected_key = (
        pressure_job["host_id"], pressure_job["family"], pressure_job["profile"], pressure_job["mode"],
        pressure_job["load_percent"], pressure_job["comparison_kind"],
        pressure_job.get("baseline_allocator", pressure_job["allocator"]), pressure_pair_kind, pressure_job["ordinal"],
    )
    fixed_key = (
        fixed_job["host_id"], fixed_job["family"], fixed_job["profile"], fixed_job["mode"],
        fixed_job["load_percent"], fixed_job["comparison_kind"],
        fixed_job.get("baseline_allocator", fixed_job["allocator"]), fixed_job["pair_kind"], fixed_job["ordinal"],
    )
    require(fixed_key == expected_key, "pressure predecessor ID does not match host/workload/profile/allocator/executor/load/ordinal")
    expected_cell = next(cell for cell in spec["cells"] if cell["family"] == fixed_job["family"] and cell["profile"] == fixed_job["profile"])
    metrics = fixed_record.get("process_metrics")
    require(isinstance(metrics, list) and len(metrics) == 2, "fixed predecessor receipt lacks its two validated process observations")
    readback_receipts = []
    for metric in metrics:
        readback = exact_keys(metric.get("runtime_readback"), {
            "schema", "comparison_family", "resource_domain", "feedback_policy_sha256",
            "resource_ceiling_sha256", "live_usage_sha256", "readback_sha256", "receipt_sha256",
        }, "fixed predecessor runtime readback")
        require(
            readback["schema"] == "allocatbelt.application-runtime-readback.v1"
            and readback["comparison_family"] == "fixed_policy"
            and readback["resource_domain"] == "owning_global_tenant"
            and readback["feedback_policy_sha256"] == spec["runtime_binding"]["feedback_policy_sha256"]
            and readback["resource_ceiling_sha256"] == expected_cell["resource_ceiling_sha256"]
            and is_sha256(readback["live_usage_sha256"])
            and is_sha256(readback["readback_sha256"])
            and is_sha256(readback["receipt_sha256"]),
            "fixed predecessor runtime readback differs from its source/policy/ceiling receipt",
        )
        readback_receipts.append(readback["receipt_sha256"])
    material = {
        "run_id": fixed_job["run_id"],
        "record_sha256": digest_object(fixed_record),
        "readback_receipt_sha256s": readback_receipts,
    }
    return {**material, "receipt_sha256": digest_object(material)}


def validate_pressure_predecessor_receipts(
    pressure_records: list[dict[str, Any]], fixed_records: list[dict[str, Any]], spec: dict[str, Any],
) -> None:
    fixed_by_id = {record["job"]["run_id"]: record for record in fixed_records}
    require(len(fixed_by_id) == len(fixed_records), "fixed predecessor ledger repeats a run ID")
    for record in pressure_records:
        job = record["job"]
        predecessors = job.get("predecessor_run_ids")
        require(isinstance(predecessors, list) and len(predecessors) == 1, "pressure job must name exactly one fixed-policy predecessor ID")
        fixed = fixed_by_id.get(predecessors[0])
        require(fixed is not None, "pressure job references a missing fixed-policy predecessor receipt")
        expected = fixed_pressure_predecessor_receipt(job, fixed, spec)
        require(record.get("predecessor_receipts") == [expected], "pressure ledger does not bind the validated successful fixed-policy readback receipt")


def revalidate_pair_records(
    records: list[dict[str, Any]], phase: str, ledger_root: Path, source: dict[str, Any], spec: dict[str, Any], campaign_artifacts: Path,
) -> None:
    for record in records:
        require(record.get("runner_sha256_before") == spec["runner_sha256"] and record.get("runner_sha256_after") == spec["runner_sha256"], "recorded pair runner is not bound to the frozen runner hash")
        job = record["job"]
        relative = Path(record.get("pair_directory", ""))
        require(not relative.is_absolute() and ".." not in relative.parts, "pair directory path is unsafe")
        pair_dir = ledger_root / relative
        require(within(ledger_root, pair_dir) and pair_dir.is_dir(), "pair directory is missing or escaped its phase root")
        header, process_rows = read_tsv(pair_dir / "processes.tsv", 2)
        expected_header = ("pair executor allocator exit_code row_validation p99_qualification argv stdout time_report ids_sha256 shutdown_sha256 capacity_family_sha256").split()
        require(header == expected_header and all(row["exit_code"] == "0" and row["row_validation"] == "valid" for row in process_rows), "raw process ledger is invalid during independent revalidation")
        actual = [extract_process_metrics(pair_dir, row, job, source, spec, campaign_artifacts) for row in process_rows]
        require(record.get("process_metrics") == actual, "stored process metrics differ from independently revalidated raw evidence")


def latency_blocks_by_family(pair_dir: Path, metric: dict[str, Any], families: tuple[str, ...], block_size: int) -> dict[str, list[list[tuple[int, int]]]]:
    ids_path = pair_dir / metric["ids_path"]
    require(sha256_file(ids_path) == metric["ids_sha256"], "arrival sidecar changed before block analysis")
    result: dict[str, list[list[tuple[int, int]]]] = {family: [] for family in families}

    def finish_block(block: dict[str, list[int]]) -> None:
        for family in families:
            values = sorted(block[family], reverse=True)
            grouped: list[tuple[int, int]] = []
            for latency in values:
                if grouped and grouped[-1][0] == latency:
                    grouped[-1] = (latency, grouped[-1][1] + 1)
                else:
                    grouped.append((latency, 1))
            # Preserve the same original-ID block index for every family,
            # including empty-family blocks at the final partial horizon.
            result[family].append(grouped)
            block[family].clear()
    try:
        with ids_path.open("r", encoding="utf-8") as stream:
            require(stream.readline().rstrip("\n") == "schema\tallocatbelt-app-arrivals-v3", "arrival sidecar schema changed before block analysis")
            identity = stream.readline().rstrip("\n").split("\t")
            require(len(identity) == 9, "arrival sidecar identity changed before block analysis")
            require(stream.readline().rstrip("\n") == "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum", "arrival sidecar header changed before block analysis")
            block: dict[str, list[int]] = {family: [] for family in families}
            in_block = 0
            for expected_id, line in enumerate(stream):
                fields = line.rstrip("\n").split("\t")
                require(len(fields) == 7 and fields[0] == str(expected_id) and fields[1] in families and fields[4] == "completed", "arrival terminal is invalid during block analysis")
                scheduled, completion = parse_uint(fields[2], "scheduled_ns"), parse_uint(fields[3], "completion_ns")
                require(completion >= scheduled, "negative latency during block analysis")
                block[fields[1]].append(completion - scheduled)
                in_block += 1
                if in_block == block_size:
                    finish_block(block)
                    in_block = 0
            if in_block:
                finish_block(block)
    except (OSError, UnicodeError) as error:
        raise CampaignError(f"cannot read arrival blocks for analysis: {error}") from error
    require(all(any(block for block in result[family]) for family in families), "one source family has no successful latency observations")
    return result


def exact_pseudotrace_p99(blocks: list[list[tuple[int, int]]], selected_blocks: list[int]) -> int:
    """Return exact nearest-rank p99 of the full block-resampled trace."""
    require(blocks and selected_blocks, "pseudotrace requires blocks and a sampled horizon")
    multiplicities: dict[int, int] = {}
    for block_id in selected_blocks:
        require(0 <= block_id < len(blocks), "pseudotrace block index is outside the fixed trace")
        multiplicities[block_id] = multiplicities.get(block_id, 0) + 1
    sample_count = sum(multiplicities[block_id] * sum(count for _, count in blocks[block_id]) for block_id in multiplicities)
    require(sample_count > 0, "pseudotrace contains no successful family arrivals")
    ascending_rank = (99 * sample_count + 99) // 100
    descending_rank = sample_count - ascending_rank + 1
    heap: list[tuple[int, int, int]] = []
    for block_id in multiplicities:
        if blocks[block_id]:
            latency, _ = blocks[block_id][0]
            heapq.heappush(heap, (-latency, block_id, 0))
    observed = 0
    while heap:
        negative_latency, block_id, value_index = heapq.heappop(heap)
        latency, count = blocks[block_id][value_index]
        observed += multiplicities[block_id] * count
        if observed >= descending_rank:
            return latency
        next_index = value_index + 1
        if next_index < len(blocks[block_id]):
            next_latency, _ = blocks[block_id][next_index]
            heapq.heappush(heap, (-next_latency, block_id, next_index))
    raise CampaignError("pseudotrace weighted order statistic fell short of the exact rank")


def _wire_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    require(0 < len(encoded) <= 512, "analysis wire string exceeds its finite byte bound")
    return struct.pack("<H", len(encoded)) + encoded


def _write_frame(destination: Any, frame_payload: bytes) -> None:
    require(destination.tell() + 8 + len(frame_payload) <= ANALYZER_INPUT_LIMIT_BYTES, "analysis stream exceeds its declared byte ceiling")
    destination.write(struct.pack("<Q", len(frame_payload)))
    destination.write(frame_payload)


def _write_trace_frame_to_spools(
    ids_path: Path,
    expected_sha256: str,
    families: tuple[str, ...],
    block_size: int,
    scratch_directory: Path,
) -> dict[str, Any]:
    require(is_sha256(expected_sha256) and sha256_file(ids_path) == expected_sha256, "trace source sidecar hash changed before analyzer serialization")
    spools = {family: tempfile.TemporaryFile(mode="w+b", dir=scratch_directory) for family in families}
    for spool in spools.values():
        spool.write(b"\0\0\0\0")
    block_values = {family: [] for family in families}
    block_counts = {family: 0 for family in families}
    observed_ids = 0

    def finish_global_block() -> None:
        for family in families:
            values = sorted(block_values[family], reverse=True)
            grouped: list[tuple[int, int]] = []
            for latency in values:
                if grouped and grouped[-1][0] == latency:
                    grouped[-1] = (latency, grouped[-1][1] + 1)
                else:
                    grouped.append((latency, 1))
            spool = spools[family]
            spool.write(struct.pack("<II", len(values), len(grouped)))
            for latency, frequency in grouped:
                spool.write(struct.pack("<QI", latency, frequency))
            block_counts[family] += 1
            block_values[family].clear()

    try:
        with ids_path.open("r", encoding="utf-8") as stream:
            require(stream.readline().rstrip("\n") == "schema\tallocatbelt-app-arrivals-v3", "analyzer trace has an unsupported per-ID schema")
            identity = stream.readline().rstrip("\n").split("\t")
            require(len(identity) == 9 and identity[0] == "identity", "analyzer trace process identity is malformed")
            require(stream.readline().rstrip("\n") == "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum", "analyzer trace header is malformed")
            in_block = 0
            for expected_id, line in enumerate(stream):
                require(expected_id < MAX_ARRIVALS, "analyzer trace exceeds the per-process arrival bound")
                fields = line.rstrip("\n").split("\t")
                require(len(fields) == 7 and fields[0] == str(expected_id), f"analyzer trace ID is malformed at {expected_id}")
                family = fields[1]
                require(family in block_values and fields[4] == "completed", f"analyzer trace has an invalid terminal/family at {expected_id}")
                scheduled = parse_uint(fields[2], "analyzer trace schedule")
                completion = parse_uint(fields[3], "analyzer trace completion")
                checksum = parse_uint(fields[5], "analyzer trace checksum")
                expected_checksum = parse_uint(fields[6], "analyzer trace expected checksum")
                require(completion >= scheduled and checksum == expected_checksum, f"analyzer trace timestamp/checksum differs at {expected_id}")
                block_values[family].append(completion - scheduled)
                observed_ids += 1
                in_block += 1
                if in_block == block_size:
                    finish_global_block()
                    in_block = 0
            if in_block:
                finish_global_block()
    except (OSError, UnicodeError) as error:
        for spool in spools.values():
            spool.close()
        raise CampaignError(f"cannot stream compact analyzer trace: {error}") from error
    require(observed_ids > 0 and all(block_counts[family] > 0 for family in families), "analyzer trace has no IDs or no global arrival blocks")
    require(len(set(block_counts.values())) == 1, "mixed source-family global block horizons differ")
    for spool in spools.values():
        spool.seek(0)
        spool.write(struct.pack("<I", block_counts[families[0]]))
        spool.seek(0)
    require(sha256_file(ids_path) == expected_sha256, "trace sidecar changed while serializing analyzer input")
    return {"spools": spools, "blocks": block_counts[families[0]], "observed_ids": observed_ids}


def _copy_spool(destination: Any, spool: Any) -> None:
    spool.seek(0)
    shutil.copyfileobj(spool, destination, length=1024 * 1024)


def _write_analysis_group(
    destination: Any,
    group_id: int,
    group_name: str,
    pair_count: int,
    family_tests: dict[str, dict[str, Any]],
    scratch_directory: Path,
    block_size: int,
) -> None:
    families = tuple(sorted(family_tests))
    with tempfile.TemporaryFile(mode="w+b", dir=scratch_directory) as frame:
        frame.write(struct.pack("<BH", 4, group_id))
        frame.write(_wire_string(group_name))
        frame.write(struct.pack("<H", len(families)))
        for family in families:
            frame.write(_wire_string(family))
        frame.write(struct.pack("<H", pair_count))
        for pair_index in range(pair_count):
            if not families:
                continue
            references = [family_tests[family]["traces"][pair_index] for family in families]
            first = references[0]
            candidate_ref = first["candidate"]["__trace_source__"]
            control_ref = first["control"]["__trace_source__"]
            for other in references[1:]:
                require(
                    other["candidate"]["__trace_source__"] == candidate_ref
                    and other["control"]["__trace_source__"] == control_ref,
                    "mixed family endpoints do not share the same paired process traces",
                )
            candidate_path = Path(candidate_ref["path"])
            control_path = Path(control_ref["path"])
            candidate = _write_trace_frame_to_spools(candidate_path, candidate_ref["sha256"], families, block_size, scratch_directory)
            control = _write_trace_frame_to_spools(control_path, control_ref["sha256"], families, block_size, scratch_directory)
            try:
                require(candidate["observed_ids"] == control["observed_ids"] and candidate["blocks"] == control["blocks"], "paired trace IDs/block horizons differ")
                for family in families:
                    _copy_spool(frame, candidate["spools"][family])
                    _copy_spool(frame, control["spools"][family])
            finally:
                for spool in (*candidate["spools"].values(), *control["spools"].values()):
                    spool.close()
        frame_length = frame.tell()
        require(frame_length <= 8 * 1024**3, "one analyzer pair-group frame exceeds its finite byte bound")
        require(destination.tell() + 8 + frame_length <= ANALYZER_INPUT_LIMIT_BYTES, "analysis stream exceeds its declared byte ceiling")
        frame.seek(0)
        destination.write(struct.pack("<Q", frame_length))
        shutil.copyfileobj(frame, destination, length=1024 * 1024)


def _binary_analysis_input(
    tests: list[dict[str, Any]], protocol: dict[str, Any], output_path: Path, scratch_directory: Path,
) -> tuple[list[dict[str, Any]], dict[str, int], str, int]:
    primary = [test for test in tests if test.get("suite_components") is None]
    suites = [test for test in tests if test.get("suite_components") is not None]
    require(primary and len(tests) <= 1024, "analysis endpoint count is outside its frozen bound")
    group_names = sorted({json.dumps(test["pair_group"], sort_keys=True, separators=(",", ":")) for test in primary})
    require(group_names and len(group_names) <= 512, "analysis pair-group count is outside its frozen bound")
    group_ids = {name: index for index, name in enumerate(group_names)}
    primary_index = {id(test): index for index, test in enumerate(primary)}
    pair_count = protocol["confirmation_pairs"]
    block_size = protocol["bootstrap_block_arrivals"]

    with output_path.open("xb") as output:
        output.write(ANALYZER_INPUT_MAGIC)
        header_fields = struct.pack(
            "<IHHHHQdIQQ",
            protocol["bootstrap_draws"], pair_count, len(group_names), len(primary), len(suites),
            protocol["bootstrap_seed"], protocol["confidence"], block_size,
            ANALYZER_INPUT_LIMIT_BYTES, ANALYZER_RESIDENT_BUDGET_BYTES,
        )
        _write_frame(output, bytes([1]) + header_fields)
        for endpoint_id, test in enumerate(primary):
            traced = test.get("traces") is not None
            group_id = group_ids[json.dumps(test["pair_group"], sort_keys=True, separators=(",", ":"))]
            endpoint = bytearray([1 if traced else 0])
            endpoint.extend(struct.pack("<H", group_id))
            endpoint.extend(_wire_string(test["name"]))
            if traced:
                trace_pairs = test["traces"]
                family = trace_pairs[0]["family"]
                require(all(pair["family"] == family for pair in trace_pairs), "p99 endpoint changes family within its paired trace")
                endpoint.extend(_wire_string(family))
                require(len(trace_pairs) == pair_count, "p99 endpoint trace horizon differs from the confirmation pair count")
                for pair_index, pair in enumerate(trace_pairs):
                    candidate_p99 = parse_uint(str(pair["candidate_p99"]), "candidate observed p99")
                    control_p99 = parse_uint(str(pair["control_p99"]), "control observed p99")
                    require(candidate_p99 > 0 and control_p99 > 0, "p99 endpoint contains a zero denominator")
                    require(math.isclose(test["ratios"][pair_index], candidate_p99 / control_p99, rel_tol=1e-12, abs_tol=0.0), "p99 process ratios differ from their independent observed endpoints")
                    endpoint.extend(struct.pack("<QQ", candidate_p99, control_p99))
            else:
                require(len(test["ratios"]) == pair_count, "counter endpoint pair horizon differs")
                for ratio in test["ratios"]:
                    require(math.isfinite(ratio) and ratio > 0, "counter endpoint ratio is non-finite or non-positive")
                    endpoint.extend(struct.pack("<d", ratio))
            _write_frame(output, bytes([2]) + endpoint)
        for suite_index, suite in enumerate(suites):
            suite_frame = bytearray([3])
            suite_frame.extend(_wire_string(suite["name"]))
            suite_frame.extend(struct.pack("<H", len(suite["suite_components"])))
            for component_index, weight in zip(suite["suite_components"], suite["suite_weights"], strict=True):
                require(0 <= component_index < len(tests) and tests[component_index].get("suite_components") is None, "suite references a non-primary endpoint")
                numerator, denominator = Fraction(weight).limit_denominator(4096).as_integer_ratio()
                require(math.isclose(float(Fraction(numerator, denominator)), weight, rel_tol=0.0, abs_tol=1e-15), "suite weight cannot be represented by the frozen rational protocol")
                suite_frame.extend(struct.pack("<HII", primary_index[id(tests[component_index])], numerator, denominator))
            _write_frame(output, bytes(suite_frame))
        for group_name, group_id in group_ids.items():
            p99_group_tests = [
                test for test in primary
                if test["traces"] is not None
                and json.dumps(test["pair_group"], sort_keys=True, separators=(",", ":")) == group_name
            ]
            group_tests = {
                test["traces"][0]["family"]: test
                for test in p99_group_tests
            }
            require(len(group_tests) == len(p99_group_tests), "paired group repeats a p99 source-family endpoint")
            _write_analysis_group(output, group_id, group_name, pair_count, group_tests, scratch_directory, block_size)
        _write_frame(output, b"\x05")
        output.flush()
        os.fsync(output.fileno())
    output_path.chmod(0o600)
    input_sha256 = sha256_file(output_path)
    input_bytes = output_path.stat().st_size
    require(input_bytes <= ANALYZER_INPUT_LIMIT_BYTES, "serialized analysis input exceeds its finite byte bound")
    return tests, group_ids, input_sha256, input_bytes


def _run_rust_analysis(
    tests: list[dict[str, Any]], protocol: dict[str, Any], binary: Path,
    expected_binary_sha256: str, scratch_directory: Path, timeout_seconds: int,
) -> tuple[list[dict[str, float]], dict[str, Any]]:
    require(sha256_file(binary) == expected_binary_sha256, "analysis binary differs from its host source manifest before invocation")
    input_path = scratch_directory / f".analysis-input-{os.getpid()}-{time.monotonic_ns()}.bin"
    output_path = scratch_directory / f".analysis-output-{os.getpid()}-{time.monotonic_ns()}.bin"
    try:
        _, input_group_ids, input_sha256, input_size = _binary_analysis_input(tests, protocol, input_path, scratch_directory)
        input_sha256_before = sha256_file(input_path)
        require(input_sha256_before == input_sha256 and input_path.stat().st_size == input_size, "analyzer input hash/length differs after serialization")
        started = time.monotonic()
        try:
            result = subprocess.run([str(binary), str(input_path), str(output_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CampaignError(f"pinned Rust analyzer did not finish within its finite budget: {error}") from error
        elapsed_seconds = time.monotonic() - started
        require(result.returncode == 0 and output_path.is_file(), f"pinned Rust analyzer rejected its canonical stream: {result.stderr.decode(errors='replace')[:512]}")
        require(sha256_file(binary) == expected_binary_sha256, "analysis binary changed during invocation")
        require(sha256_file(input_path) == input_sha256_before and input_path.stat().st_size == input_size, "analyzer input changed during invocation")
        output_bytes = output_path.read_bytes()
        output_sha256 = hashlib.sha256(output_bytes).hexdigest()
        require(len(output_bytes) <= 2 * 1024 * 1024 and output_bytes.startswith(ANALYZER_OUTPUT_MAGIC), "Rust analyzer response is malformed or exceeds its finite bound")
        offset = 8

        def take(format_string: str) -> tuple[Any, ...]:
            nonlocal offset
            size = struct.calcsize(format_string)
            require(offset + size <= len(output_bytes), "Rust analyzer response is truncated")
            values = struct.unpack_from(format_string, output_bytes, offset)
            offset += size
            return values

        draws, endpoint_count, group_count = take("<IHH")
        seed, consumed_bytes, resident_peak, critical = take("<QQQd")
        ordered = [test for test in tests if test.get("suite_components") is None] + [test for test in tests if test.get("suite_components") is not None]
        require(draws == protocol["bootstrap_draws"] and seed == protocol["bootstrap_seed"] and endpoint_count == len(ordered), "Rust analyzer response identity differs from the frozen draw/endpoints")
        require(group_count == len(input_group_ids), "Rust analyzer pair-group count differs from its frozen input")
        require(consumed_bytes == input_size and resident_peak <= ANALYZER_RESIDENT_BUDGET_BYTES, "Rust analyzer byte or resident-memory accounting differs")
        require(math.isfinite(critical) and critical >= 0.0, "Rust analyzer critical value is invalid")
        expected_names = [test["name"] for test in ordered]
        tests_by_name = {test["name"]: test for test in tests}

        def input_center(test: dict[str, Any]) -> float:
            if test.get("suite_components") is None:
                return math.fsum(math.log(value) for value in test["ratios"]) / protocol["confirmation_pairs"]
            return math.fsum(
                weight * input_center(tests[component])
                for component, weight in zip(test["suite_components"], test["suite_weights"], strict=True)
            )

        intervals_by_name = {}
        for expected_id, expected_name in enumerate(expected_names):
            endpoint_id, name_length = take("<HH")
            require(endpoint_id == expected_id and name_length > 0 and offset + name_length <= len(output_bytes), "Rust analyzer endpoint ID/name frame is malformed")
            name = output_bytes[offset : offset + name_length].decode("utf-8")
            offset += name_length
            point, center_log, scale_log, lower, upper = take("<ddddd")
            require(name == expected_name, "Rust analyzer endpoint order differs from its frozen plan")
            require(all(math.isfinite(value) for value in (point, center_log, scale_log, lower, upper)) and point > 0 and lower > 0 and lower <= point <= upper and scale_log >= 0, f"Rust analyzer interval is invalid for {name}")
            expected_center = input_center(tests_by_name[name])
            require(math.isclose(point, math.exp(expected_center), rel_tol=1e-10, abs_tol=0.0), f"Rust analyzer point estimate differs from the independently recomputed input center for {name}")
            require(math.isclose(center_log, expected_center, rel_tol=1e-10, abs_tol=1e-12), f"Rust analyzer log center differs from the independent input center for {name}")
            intervals_by_name[name] = {"point": point, "lower": lower, "upper": upper, "scale_log": scale_log}
        require(offset == len(output_bytes), "Rust analyzer response has trailing bytes")
        require(sha256_file(output_path) == output_sha256, "Rust analyzer output changed while it was being validated")
        require(sha256_file(binary) == expected_binary_sha256, "analysis binary changed before validation completed")
        require(sha256_file(input_path) == input_sha256_before, "analyzer input changed before validation completed")
        intervals = [intervals_by_name[test["name"]] for test in tests]
        metadata = {
            "schema": "allocatbelt.application-rust-bootstrap.v1",
            "method": "paired_contiguous_block_max_standardized_deviation",
            "prng": "splitmix64_v1_fnv1a_group_seed_rejection_uniform",
            "draws": draws,
            "seed": seed,
            "confidence": protocol["confidence"],
            "endpoint_count": endpoint_count,
            "group_count": group_count,
            "critical_value": critical,
            "critical_rank_mc_standard_error_draws": math.sqrt(draws * protocol["confidence"] * (1 - protocol["confidence"])),
            "endpoint_order_sha256": hashlib.sha256("\n".join(test["name"] for test in ordered).encode()).hexdigest(),
            "scale_definition": "sample_sd_of_joint_log_ratio_draw_matrix",
            "point_definition": "geometric_mean_of_matched_process_ratios; suite endpoints use rational equal profile-family-context weights",
            "analyzer_binary_sha256": expected_binary_sha256,
            "input_sha256": input_sha256_before,
            "input_bytes": input_size,
            "resident_peak_bytes": resident_peak,
            "output_sha256": output_sha256,
            "analyzer_wall_seconds": elapsed_seconds,
        }
        return intervals, metadata
    finally:
        for path in (input_path, output_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def pair_record_map(records: list[dict[str, Any]], phase: str, host_id: str) -> dict[tuple[str, str, str, int, str, int], dict[str, Any]]:
    mapped: dict[tuple[str, str, str, int, str, int], dict[str, Any]] = {}
    for record in records:
        job = record.get("job")
        require(isinstance(job, dict) and job.get("phase") == phase and job.get("host_id") == host_id, "phase ledger contains a foreign or malformed job")
        key = (job["family"], job["profile"], job["mode"], job.get("load_percent") or 0, job["allocator"], job["ordinal"])
        require(key not in mapped, f"phase ledger repeats scheduled treatment: {key}")
        mapped[key] = record
    return mapped


def validate_aa_records(records: list[dict[str, Any]], expected_jobs: list[dict[str, Any]], host_id: str, draws: int, seed: int) -> dict[str, Any]:
    validate_phase_ledger(records, expected_jobs, "aa", host_id)
    by_control: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        require(record.get("state") == "valid_pair", "A/A phase contains a failed, interrupted, or invalid pair")
        job = record.get("job")
        require(isinstance(job, dict) and job.get("host_id") == host_id and job.get("phase") == "aa", "A/A ledger contains a foreign job")
        metrics = record.get("process_metrics")
        require(isinstance(metrics, list) and len(metrics) == 2 and metrics[0]["executor"] == metrics[1]["executor"], "A/A pair did not run the same executor twice")
        by_control.setdefault(job["control_id"], []).append(record)
    results = []
    for control_id, pairs in sorted(by_control.items()):
        ordinals = sorted(item["job"]["ordinal"] for item in pairs)
        require(ordinals == list(range(1, len(pairs) + 1)), f"A/A control has missing or duplicated ordinals: {control_id}")
        comparisons = {}
        for field in ("capacity_per_second", "response_p99_ns", "cpu_ns_per_completion", "rss_after_drain_kib"):
            if field == "capacity_per_second" and pairs[0]["job"]["mode"] != "capacity":
                continue
            if field == "response_p99_ns" and pairs[0]["job"]["mode"] != "open_loop":
                continue
            ratios = []
            for item in pairs:
                left, right = item["process_metrics"]
                a, b = left[field], right[field]
                if a is not None and b is not None:
                    require(a > 0 and b > 0, f"A/A has a zero denominator for {field}")
                    ratios.append(b / a)
            if ratios:
                point, low, high = bootstrap_pair_interval(ratios, draws, seed + len(results), 0.05 / max(1, len(by_control) * 4))
                comparisons[field] = {"ratio": point, "lower": low, "upper": high, "interval_contains_one": low <= 1.0 <= high}
        results.append({"control_id": control_id, "pair_count": len(pairs), "comparisons": comparisons, "passed": all(value["interval_contains_one"] for value in comparisons.values())})
    require(results and all(item["passed"] for item in results), "A/A control detected a statistically resolved same-executor shift")
    return {"schema": "allocatbelt.application-aa-analysis.v1", "host_id": host_id, "controls": results, "passed": True}


def analyze_confirmation_host_gated(
    spec: dict[str, Any], host_id: str, records: list[dict[str, Any]], ledger_root: Path,
    analysis_binary: Path | None = None, analysis_binary_sha256: str | None = None,
    phase: str = "confirmation",
) -> dict[str, Any]:
    """Analyze only explicitly matched two-process treatment jobs."""
    protocol = spec["protocol"]
    require(phase in ("confirmation", "pressure"), "host analyzer requires a fixed or pressure comparison phase")
    expected = build_jobs(spec, phase, host_id)
    validate_phase_ledger(records, expected, phase, host_id)
    jobs: dict[tuple[str, str, str, int, str, str, int], dict[str, Any]] = {}
    metric_cache: dict[tuple[str, str, str, int, str, str, int, str, str], tuple[dict[str, Any], Path]] = {}
    for record in records:
        job = record["job"]
        kind = job["comparison_kind"]
        contrast = job["baseline_allocator"] if kind == "allocator" else job["allocator"]
        key = (job["family"], job["profile"], job["mode"], job.get("load_percent") or 0, kind, contrast, job["ordinal"])
        require(key not in jobs, f"confirmation repeats explicitly matched pair job {key}")
        process_metrics = record.get("process_metrics")
        require(isinstance(process_metrics, list) and len(process_metrics) == 2, "comparison job needs exactly two fresh processes")
        if kind == "allocator":
            require({item["allocator"] for item in process_metrics} == {"allocatbelt", job["baseline_allocator"]} and {item["executor"] for item in process_metrics} == {"bounded"}, "allocator comparison is not a matched bounded candidate/baseline pair")
        else:
            require(kind == "executor" and {item["allocator"] for item in process_metrics} == {job["allocator"]} and {item["executor"] for item in process_metrics} == {"bounded", "tokio"}, "executor comparison is not a matched same-allocator bounded/Tokio pair")
        jobs[key] = record
        pair_dir = ledger_root / record["pair_directory"]
        for item in process_metrics:
            metric_cache[(*key, item["allocator"], item["executor"])] = (item, pair_dir)
    expected_keys = set()
    for job in expected:
        kind = job["comparison_kind"]
        contrast = job["baseline_allocator"] if kind == "allocator" else job["allocator"]
        expected_keys.add((job["family"], job["profile"], job["mode"], job.get("load_percent") or 0, kind, contrast, job["ordinal"]))
    require(set(jobs) == expected_keys, "comparison jobs do not cover the preregistered paired horizon")

    def pair_key(cell: dict[str, Any], mode: str, load: int, kind: str, contrast: str, ordinal: int) -> tuple[str, str, str, int, str, str, int]:
        return (cell["family"], cell["profile"], mode, load, kind, contrast, ordinal)

    def metric(cell: dict[str, Any], mode: str, load: int, kind: str, contrast: str, ordinal: int, allocator: str, executor: str) -> tuple[dict[str, Any], Path]:
        return metric_cache[(*pair_key(cell, mode, load, kind, contrast, ordinal), allocator, executor)]

    cells = sorted(spec["cells"], key=lambda cell: (cell["family"], cell["profile"]))
    trace_cache: dict[tuple[Any, ...], dict[str, list[list[tuple[int, int]]]]] = {}

    def traces(cell: dict[str, Any], load: int, kind: str, contrast: str, ordinal: int, allocator: str, executor: str) -> dict[str, Any]:
        cache_key = (*pair_key(cell, "open_loop", load, kind, contrast, ordinal), allocator, executor)
        if analysis_binary is not None:
            process_metric, pair_dir = metric(cell, "open_loop", load, kind, contrast, ordinal, allocator, executor)
            require(isinstance(process_metric.get("ids_path"), str) and is_sha256(process_metric.get("ids_sha256")), "Rust analyzer process is missing its trusted per-ID sidecar reference")
            return {"__trace_source__": {"path": str(pair_dir / process_metric["ids_path"]), "sha256": process_metric["ids_sha256"]}}
        if cache_key not in trace_cache:
            process_metric, pair_dir = metric(cell, "open_loop", load, kind, contrast, ordinal, allocator, executor)
            families = STANDALONE if cell["family"] == "mixed" else (cell["family"],)
            trace_cache[cache_key] = latency_blocks_by_family(pair_dir, process_metric, families, protocol["bootstrap_block_arrivals"])
        return trace_cache[cache_key]

    tests: list[dict[str, Any]] = []

    def add(
        name: str, ratios: list[float], threshold: float, direction: str, pair_group: tuple[Any, ...],
        *, traces_by_pair: list[dict[str, Any]] | None = None, suite_key: tuple[str, str, str] | None = None,
        suite_components: list[int] | None = None, suite_weights: list[float] | None = None,
    ) -> int:
        require(len(ratios) == protocol["confirmation_pairs"] and all(math.isfinite(value) and value > 0 for value in ratios), f"{name}: incomplete or zero-denominator matched comparison")
        if suite_components is None:
            require(traces_by_pair is None or suite_key is not None, f"{name}: latency component lacks its frozen suite key")
        else:
            require(traces_by_pair is None and suite_key is None and suite_weights is not None, f"{name}: suite endpoint has component-only fields")
        tests.append({"name": name, "ratios": ratios, "threshold": threshold, "direction": direction, "pair_group": pair_group, "traces": traces_by_pair, "block_group": pair_group if traces_by_pair is not None else None, "suite_key": suite_key, "suite_components": suite_components, "suite_weights": suite_weights})
        return len(tests) - 1

    def add_suite(name: str, components: list[int], threshold: float, direction: str) -> None:
        keys = [tests[index]["suite_key"] for index in components]
        weights = equal_profile_family_context_weights(keys)
        require(abs(sum(weights) - 1.0) < 1e-12, f"{name}: suite family/profile weights do not sum to one")
        ratios = [math.exp(sum(weight * math.log(tests[index]["ratios"][pair]) for index, weight in zip(components, weights, strict=True))) for pair in range(protocol["confirmation_pairs"])]
        add(name, ratios, threshold, direction, ("suite", name), suite_components=components, suite_weights=weights)

    for baseline in ("mimalloc-secure", "mimalloc-standard"):
        throughput_components = []
        for cell in cells:
            families = STANDALONE if cell["family"] == "mixed" else (cell["family"],)
            for family in families:
                ratios = []
                for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                    candidate, _ = metric(cell, "capacity", 0, "allocator", baseline, ordinal, "allocatbelt", "bounded")
                    control, _ = metric(cell, "capacity", 0, "allocator", baseline, ordinal, baseline, "bounded")
                    if cell["family"] == "mixed":
                        ratios.append(candidate["capacity_throughput_by_family"][family] / control["capacity_throughput_by_family"][family])
                    else:
                        ratios.append(candidate["capacity_per_second"] / control["capacity_per_second"])
                group = (cell["family"], cell["profile"], "capacity", 0, "allocator", baseline)
                endpoint = add(f"allocator-throughput-cell:{cell['family']}:{cell['profile']}:{family}:{baseline}", ratios, protocol["max_workload_throughput_ratio"], "lower", group, suite_key=(cell["profile"], family, cell["family"]))
                throughput_components.append(endpoint)
            group = (cell["family"], cell["profile"], "capacity", 0, "allocator", baseline)
            cpu_ratios = []
            rss_ratios = []
            for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                candidate, _ = metric(cell, "capacity", 0, "allocator", baseline, ordinal, "allocatbelt", "bounded")
                control, _ = metric(cell, "capacity", 0, "allocator", baseline, ordinal, baseline, "bounded")
                cpu_ratios.append(candidate["cpu_ns_per_completion"] / control["cpu_ns_per_completion"])
                rss_ratios.append(candidate["rss_after_drain_kib"] / control["rss_after_drain_kib"])
            add(f"allocator-cpu-cell:{cell['family']}:{cell['profile']}:{baseline}", cpu_ratios, protocol["max_workload_cpu_ratio"], "upper", group)
            add(f"allocator-rss-cell:{cell['family']}:{cell['profile']}:{baseline}", rss_ratios, protocol["max_retained_rss_ratio"], "upper", group)
        add_suite(f"allocator-throughput-suite:{baseline}", throughput_components, protocol["allocator_min_capacity_ratio"], "lower")

        for load in LOADS:
            p99_components = []
            for cell in cells:
                group = (cell["family"], cell["profile"], "open_loop", load, "allocator", baseline)
                cpu_ratios = []
                rss_ratios = []
                for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                    candidate, _ = metric(cell, "open_loop", load, "allocator", baseline, ordinal, "allocatbelt", "bounded")
                    control, _ = metric(cell, "open_loop", load, "allocator", baseline, ordinal, baseline, "bounded")
                    cpu_ratios.append(candidate["cpu_ns_per_completion"] / control["cpu_ns_per_completion"])
                    rss_ratios.append(candidate["rss_after_drain_kib"] / control["rss_after_drain_kib"])
                add(f"allocator-cpu-cell:{cell['family']}:{cell['profile']}:open{load}:{baseline}", cpu_ratios, protocol["max_workload_cpu_ratio"], "upper", group)
                add(f"allocator-rss-cell:{cell['family']}:{cell['profile']}:open{load}:{baseline}", rss_ratios, protocol["max_retained_rss_ratio"], "upper", group)
                families = STANDALONE if cell["family"] == "mixed" else (cell["family"],)
                for family in families:
                    ratios = []
                    trace_pairs = []
                    for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                        candidate, _ = metric(cell, "open_loop", load, "allocator", baseline, ordinal, "allocatbelt", "bounded")
                        control, _ = metric(cell, "open_loop", load, "allocator", baseline, ordinal, baseline, "bounded")
                        ratios.append(candidate["latency_p99_by_family_ns"][family] / control["latency_p99_by_family_ns"][family])
                        trace_pairs.append({
                            "candidate": traces(cell, load, "allocator", baseline, ordinal, "allocatbelt", "bounded"),
                            "control": traces(cell, load, "allocator", baseline, ordinal, baseline, "bounded"),
                            "family": family,
                            "candidate_p99": candidate["latency_p99_by_family_ns"][family],
                            "control_p99": control["latency_p99_by_family_ns"][family],
                        })
                    endpoint = add(f"allocator-p99-cell:{cell['family']}:{cell['profile']}:{family}:{load}:{baseline}", ratios, protocol["max_workload_p99_ratio"], "upper", group, traces_by_pair=trace_pairs, suite_key=(cell["profile"], family, cell["family"]))
                    p99_components.append(endpoint)
            add_suite(f"allocator-p99-suite:{load}:{baseline}", p99_components, protocol["allocator_max_p99_ratio"], "upper")

    throughput_components = []
    for cell in cells:
        families = STANDALONE if cell["family"] == "mixed" else (cell["family"],)
        group = (cell["family"], cell["profile"], "capacity", 0, "executor", "allocatbelt")
        for family in families:
            ratios = []
            for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                bounded, _ = metric(cell, "capacity", 0, "executor", "allocatbelt", ordinal, "allocatbelt", "bounded")
                tokio, _ = metric(cell, "capacity", 0, "executor", "allocatbelt", ordinal, "allocatbelt", "tokio")
                if cell["family"] == "mixed":
                    ratios.append(bounded["capacity_throughput_by_family"][family] / tokio["capacity_throughput_by_family"][family])
                else:
                    ratios.append(bounded["capacity_per_second"] / tokio["capacity_per_second"])
            endpoint = add(f"executor-throughput-cell:{cell['family']}:{cell['profile']}:{family}", ratios, protocol["max_workload_throughput_ratio"], "lower", group, suite_key=(cell["profile"], family, cell["family"]))
            throughput_components.append(endpoint)
        cpu_ratios = []
        rss_ratios = []
        for ordinal in range(1, protocol["confirmation_pairs"] + 1):
            bounded, _ = metric(cell, "capacity", 0, "executor", "allocatbelt", ordinal, "allocatbelt", "bounded")
            tokio, _ = metric(cell, "capacity", 0, "executor", "allocatbelt", ordinal, "allocatbelt", "tokio")
            cpu_ratios.append(bounded["cpu_ns_per_completion"] / tokio["cpu_ns_per_completion"])
            rss_ratios.append(bounded["rss_after_drain_kib"] / tokio["rss_after_drain_kib"])
        add(f"executor-cpu-cell:{cell['family']}:{cell['profile']}", cpu_ratios, protocol["max_workload_cpu_ratio"], "upper", group)
        add(f"executor-rss-cell:{cell['family']}:{cell['profile']}", rss_ratios, protocol["max_retained_rss_ratio"], "upper", group)
    add_suite("executor-throughput-suite", throughput_components, protocol["executor_min_capacity_ratio"], "lower")

    for load in LOADS:
        p99_components = []
        for cell in cells:
            group = (cell["family"], cell["profile"], "open_loop", load, "executor", "allocatbelt")
            cpu_ratios = []
            rss_ratios = []
            for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                bounded, _ = metric(cell, "open_loop", load, "executor", "allocatbelt", ordinal, "allocatbelt", "bounded")
                tokio, _ = metric(cell, "open_loop", load, "executor", "allocatbelt", ordinal, "allocatbelt", "tokio")
                cpu_ratios.append(bounded["cpu_ns_per_completion"] / tokio["cpu_ns_per_completion"])
                rss_ratios.append(bounded["rss_after_drain_kib"] / tokio["rss_after_drain_kib"])
            add(f"executor-cpu-cell:{cell['family']}:{cell['profile']}:open{load}", cpu_ratios, protocol["max_workload_cpu_ratio"], "upper", group)
            add(f"executor-rss-cell:{cell['family']}:{cell['profile']}:open{load}", rss_ratios, protocol["max_retained_rss_ratio"], "upper", group)
            families = STANDALONE if cell["family"] == "mixed" else (cell["family"],)
            for family in families:
                ratios = []
                trace_pairs = []
                for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                    bounded, _ = metric(cell, "open_loop", load, "executor", "allocatbelt", ordinal, "allocatbelt", "bounded")
                    tokio, _ = metric(cell, "open_loop", load, "executor", "allocatbelt", ordinal, "allocatbelt", "tokio")
                    ratios.append(bounded["latency_p99_by_family_ns"][family] / tokio["latency_p99_by_family_ns"][family])
                    trace_pairs.append({
                        "candidate": traces(cell, load, "executor", "allocatbelt", ordinal, "allocatbelt", "bounded"),
                        "control": traces(cell, load, "executor", "allocatbelt", ordinal, "allocatbelt", "tokio"),
                        "family": family,
                        "candidate_p99": bounded["latency_p99_by_family_ns"][family],
                        "control_p99": tokio["latency_p99_by_family_ns"][family],
                    })
                endpoint = add(f"executor-p99-cell:{cell['family']}:{cell['profile']}:{family}:{load}", ratios, protocol["max_workload_p99_ratio"], "upper", group, traces_by_pair=trace_pairs, suite_key=(cell["profile"], family, cell["family"]))
                p99_components.append(endpoint)
        add_suite(f"executor-p99-suite:{load}", p99_components, protocol["executor_max_p99_ratio"], "upper")

    if analysis_binary is None:
        require(analysis_binary_sha256 is None, "Python reference analysis must not accept an analyzer binary pin")
        intervals, bootstrap_metadata = joint_simultaneous_bootstrap(tests, protocol["bootstrap_draws"], protocol["bootstrap_seed"], protocol["confidence"])
    else:
        primary_endpoint_count = sum(test.get("suite_components") is None for test in tests)
        suite_endpoint_count = len(tests) - primary_endpoint_count
        pair_group_count = len({test["pair_group"] for test in tests if test.get("suite_components") is None})
        require(
            (primary_endpoint_count, suite_endpoint_count, pair_group_count)
            == (ANALYZER_PRIMARY_ENDPOINTS_PER_HOST, ANALYZER_SUITE_ENDPOINTS_PER_HOST, ANALYZER_PAIR_GROUPS_PER_HOST),
            "Rust analyzer input does not cover the complete frozen per-host fixed/pressure metric family",
        )
        require(is_sha256(analysis_binary_sha256), "Rust analyzer is missing its source-manifest binary hash")
        intervals, bootstrap_metadata = _run_rust_analysis(
            tests,
            protocol,
            analysis_binary,
            analysis_binary_sha256,
            ledger_root,
            spec["deadlines"]["outer_seconds"],
        )
    result_tests = []
    passed = True
    for index, test in enumerate(tests):
        interval = intervals[index]
        gate = ratio_gate(interval["lower"], interval["upper"], test["threshold"], test["direction"])
        passed = passed and gate
        result_tests.append({"name": test["name"], "ratio": interval["point"], "scale_log": interval["scale_log"], "simultaneous_lower": interval["lower"], "simultaneous_upper": interval["upper"], "threshold": test["threshold"], "direction": test["direction"], "passed": gate})
    secondary = []
    for cell in cells:
        metric_families = STANDALONE if cell["family"] == "mixed" else (cell["family"],)
        for allocator in ("mimalloc-secure", "mimalloc-standard"):
            for mode, load in (("capacity", 0), ("open_loop", 70), ("open_loop", 90)):
                for ordinal in range(1, protocol["confirmation_pairs"] + 1):
                    bounded, _ = metric(cell, mode, load, "executor", allocator, ordinal, allocator, "bounded")
                    tokio, _ = metric(cell, mode, load, "executor", allocator, ordinal, allocator, "tokio")
                    item = {
                        "allocator": allocator, "family": cell["family"], "profile": cell["profile"],
                        "mode": mode, "load_percent": load or None, "ordinal": ordinal,
                        "cpu_ratio_bounded_to_tokio": bounded["cpu_ns_per_completion"] / tokio["cpu_ns_per_completion"],
                        "rss_ratio_bounded_to_tokio": bounded["rss_after_drain_kib"] / tokio["rss_after_drain_kib"],
                        "gate_eligible": False,
                    }
                    if mode == "capacity":
                        if cell["family"] == "mixed":
                            item["throughput_ratios_by_family"] = {family: bounded["capacity_throughput_by_family"][family] / tokio["capacity_throughput_by_family"][family] for family in metric_families}
                        else:
                            item["capacity_ratio_bounded_to_tokio"] = bounded["capacity_per_second"] / tokio["capacity_per_second"]
                    else:
                        item["p99_ratios_by_family"] = {family: bounded["latency_p99_by_family_ns"][family] / tokio["latency_p99_by_family_ns"][family] for family in metric_families}
                    secondary.append(item)
    qualification_eligible = RUNTIME_QUALIFICATION_READBACK_SUPPORTED and (phase != "pressure" or EXTERNAL_PRESSURE_DRIVER_SUPPORTED)
    if not qualification_eligible:
        passed = False
    return {
        "schema": "allocatbelt.application-host-analysis.v1",
        "host_id": host_id,
        "comparison_family": "fixed_policy" if phase == "confirmation" else "external_pressure",
        "gate_scope": "independent_per_host_no_pooling",
        "family_size": len(tests),
        "confidence": protocol["confidence"],
        "simultaneous_method": bootstrap_metadata["method"],
        "bootstrap": bootstrap_metadata,
        "tests": result_tests,
        "secondary_executor_sanity": secondary,
        "qualification_eligible": qualification_eligible,
        "qualification_blocker": None if qualification_eligible else "production binary runtime-domain/policy/ceiling readback is not verified",
        "passed": passed,
    }


def validate_soak_receipt(
    receipt_path: Path, soak_dir: Path, job: dict[str, Any], source: dict[str, Any], spec: dict[str, Any], host_id: str,
) -> dict[str, Any]:
    require(RUNTIME_QUALIFICATION_READBACK_SUPPORTED, "soak qualification is hard-disabled until a production driver provides independently validated runtime readbacks and canonical per-ID references")
    receipt = read_json(receipt_path)
    exact_keys(receipt, {
        "schema", "campaign_id", "host_id", "run_id", "source_sha256", "binary_sha256", "allocator", "executor", "workload", "profile",
        "duration_seconds", "sample_interval_ms", "resource_ceiling_sha256", "resource_limits", "started_monotonic_ns", "ended_monotonic_ns", "attempted", "completed", "errors", "lost",
        "terminal_records", "terminal_stream_sha256", "terminal_stream_relative_path", "resource_samples_count", "resource_samples_sha256",
        "resource_samples_relative_path", "production_cpu_started_ns", "production_cpu_ended_ns", "production_cpu_ns", "production_completions",
        "cpu_ns_per_completion", "final_managed_bytes", "final_disk_ops", "final_network_ops", "final_task_count", "final_cpu_charges",
    }, "soak receipt")
    binary_sha = source["soak_artifacts"][job["allocator"]]["sha256"]
    cell = next(cell for cell in spec["cells"] if cell["family"] == "mixed" and cell["profile"] == job["profile"])
    identity = {
        "schema": "allocatbelt.application-soak-receipt.v1", "campaign_id": spec["campaign_id"], "host_id": host_id,
        "run_id": job["run_id"], "source_sha256": source["source"]["source_tree_sha256"], "binary_sha256": binary_sha,
        "allocator": job["allocator"], "executor": job["executor"], "workload": "mixed", "profile": job["profile"],
        "duration_seconds": spec["protocol"]["soak_seconds"], "sample_interval_ms": spec["soak"]["interval_ms"],
        "resource_ceiling_sha256": cell["resource_ceiling_sha256"], "resource_limits": cell["resource_limits"],
    }
    require(all(receipt.get(name) == value for name, value in identity.items()), "soak receipt identity/duration differs from the frozen treatment")
    start, end = parse_uint(receipt["started_monotonic_ns"], "soak start"), parse_uint(receipt["ended_monotonic_ns"], "soak end")
    duration_ns = spec["protocol"]["soak_seconds"] * 1_000_000_000
    require(end >= start and end - start >= duration_ns and end - start <= duration_ns + 5_000_000_000, "soak monotonic horizon is incomplete or exceeded its five-second allowance")
    attempted = parse_uint(receipt["attempted"], "soak attempted")
    completed = parse_uint(receipt["completed"], "soak completed")
    require(attempted > 0 and completed == attempted == parse_uint(receipt["terminal_records"], "terminal records"), "soak terminal count does not reconcile")
    require(parse_uint(receipt["errors"], "soak errors") == parse_uint(receipt["lost"], "soak lost") == 0, "soak contains terminal errors or lost work")
    require(is_sha256(receipt["terminal_stream_sha256"]) and is_sha256(receipt["resource_samples_sha256"]), "soak receipt lacks stream/sample digests")

    def artifact(relative_field: str, digest_field: str) -> Path:
        relative = Path(receipt[relative_field])
        require(not relative.is_absolute() and ".." not in relative.parts, "soak artifact path is not a safe relative path")
        path = soak_dir / relative
        require(path.is_file() and not path.is_symlink() and within(soak_dir, path) and sha256_file(path) == receipt[digest_field], f"soak artifact hash mismatch: {relative}")
        return path

    terminal_path = artifact("terminal_stream_relative_path", "terminal_stream_sha256")
    try:
        with terminal_path.open("r", encoding="utf-8") as stream:
            require(stream.readline().rstrip("\n") == "id\tworkload\tterminal\tchecksum\texpected_checksum", "soak terminal stream schema differs")
            families = STANDALONE
            terminal_count = 0
            for expected_id, line in enumerate(stream):
                fields = line.rstrip("\n").split("\t")
                require(len(fields) == 5 and fields[0] == str(expected_id) and fields[1] == families[expected_id % len(families)] and fields[2] == "completed", f"soak terminal record is invalid at ID {expected_id}")
                checksum, expected_checksum = parse_uint(fields[3], "soak terminal checksum"), parse_uint(fields[4], "soak expected terminal checksum")
                require(checksum == expected_checksum, f"soak terminal checksum differs from its canonical reference at ID {expected_id}")
                terminal_count += 1
    except (OSError, UnicodeError) as error:
        raise CampaignError(f"cannot read soak terminal stream: {error}") from error
    require(terminal_count == attempted, "soak terminal stream row count differs")

    samples_path = artifact("resource_samples_relative_path", "resource_samples_sha256")
    header, samples = read_tsv(samples_path)
    expected_header = ["elapsed_ns", "rss_kib", "managed_bytes", "disk_ops", "network_ops", "task_count", "cpu_charges"]
    require(header == expected_header and len(samples) == parse_uint(receipt["resource_samples_count"], "sample count"), "soak resource sample shape/count differs")
    required_sample_count = spec["protocol"]["soak_seconds"] * 1000 // spec["soak"]["interval_ms"] + 1
    require(len(samples) == required_sample_count, "soak does not contain one sample per frozen 100ms interval")
    elapsed = []
    rss = []
    for index, sample in enumerate(samples):
        time_ns = parse_uint(sample["elapsed_ns"], "sample elapsed")
        expected_ns = index * spec["soak"]["interval_ms"] * 1_000_000
        require(abs(time_ns - expected_ns) <= 10_000_000, f"soak sample {index} is missing, reordered, or late")
        elapsed.append(time_ns)
        rss.append(parse_uint(sample["rss_kib"], "sample RSS"))
        for field in expected_header[2:]:
            parse_uint(sample[field], field)
        limit_names = {"managed_bytes": "managed_bytes", "disk_ops": "disk_ops", "network_ops": "network_ops", "task_count": "tasks", "cpu_charges": "cpu_charges"}
        require(all(parse_uint(sample[field], field) <= receipt["resource_limits"][limit_names[field]] for field in expected_header[2:]), f"soak resource ceiling was exceeded at sample {index}")
    first_hour = [value for time_ns, value in zip(elapsed, rss, strict=True) if 300_000_000_000 <= time_ns < 3_900_000_000_000]
    final_hour = [value for time_ns, value in zip(elapsed, rss, strict=True) if 7_200_000_000_000 <= time_ns <= duration_ns]
    require(first_hour and final_hour, "soak lacks post-warmup first-hour or final-hour RSS samples")
    first_median, final_median = statistics.median(first_hour), statistics.median(final_hour)
    require(first_median > 0 and final_median / first_median <= 1 + spec["protocol"]["soak_rss_growth_percent"] / 100, "soak retained RSS grew beyond the frozen five-percent bound")

    cpu_start = parse_uint(receipt["production_cpu_started_ns"], "soak production CPU start")
    cpu_end = parse_uint(receipt["production_cpu_ended_ns"], "soak production CPU end")
    cpu_total = parse_uint(receipt["production_cpu_ns"], "soak production CPU total")
    cpu_completions = parse_uint(receipt["production_completions"], "soak production completions")
    cpu_normalized = parse_uint(receipt["cpu_ns_per_completion"], "soak normalized production CPU")
    require(cpu_end >= cpu_start and cpu_end - cpu_start == cpu_total and cpu_completions == completed and cpu_total // completed == cpu_normalized, "soak productive CPU boundaries/count normalization differ")
    final_fields = ("final_managed_bytes", "final_disk_ops", "final_network_ops", "final_task_count", "final_cpu_charges")
    require(all(parse_uint(receipt[field], field) == 0 for field in final_fields), "soak left resource/task/CPU charges after owner cleanup")
    return {"receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(), "terminal_stream_sha256": receipt["terminal_stream_sha256"], "resource_samples_sha256": receipt["resource_samples_sha256"], "attempted": attempted, "completed": completed, "rss_first_hour_median_kib": first_median, "rss_final_hour_median_kib": final_median, "rss_growth_ratio": final_median / first_median, "production_cpu_ns": cpu_total, "production_cpu_ns_per_completion": cpu_normalized, "passed": True}


def read_tsv(path: Path, expected_rows: int | None = None) -> tuple[list[str], list[dict[str, str]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CampaignError(f"cannot read TSV {path}: {error}") from error
    require(lines, f"TSV is empty: {path}")
    header = lines[0].split("\t")
    require(len(header) == len(set(header)), f"TSV header repeats columns: {path}")
    rows = []
    for index, line in enumerate(lines[1:], 2):
        values = line.split("\t")
        require(len(values) == len(header), f"TSV row {index} has wrong field count: {path}")
        rows.append(dict(zip(header, values)))
    if expected_rows is not None:
        require(len(rows) == expected_rows, f"TSV row count differs: {path}")
    return header, rows


def parse_uint(value: str, field: str, maximum: int = (1 << 64) - 1) -> int:
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None, f"invalid integer {field}")
    parsed = int(value)
    require(parsed <= maximum, f"{field} exceeds its finite bound")
    return parsed


def parse_decimal(value: str, field: str) -> float:
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is not None, f"invalid decimal {field}")
    parsed = float(value)
    require(math.isfinite(parsed) and parsed >= 0.0, f"non-finite or negative decimal {field}")
    return parsed


def parse_oracle(path: Path, entry: dict[str, Any], source: dict[str, Any], cell: dict[str, Any], rate: int) -> tuple[int, list[tuple[int, str, int]]]:
    require(hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], "trusted per-ID oracle hash mismatch")
    lines = path.read_text(encoding="utf-8").splitlines()
    workload = cell["workload"]
    profile = cell["profile"]
    count = cell["arrivals"]
    source_sha = source["source"]["source_tree_sha256"]
    binary_sha = source["artifacts"][entry["allocator"]]["sha256"]
    pulse = rate * 4 if profile == "burst" else rate
    duration = ((count + rate - 1) // rate) * 1_000_000_000 if profile == "burst" else count * 1_000_000_000 // rate
    header = [
        "schema\tallocatbelt-app-oracle-v2",
        f"source_sha256\t{source_sha}",
        f"binary_sha256\t{binary_sha}",
        f"profile\t{profile}",
        f"workload\t{workload}",
        "mode\topen_loop",
        f"average_rate_per_second\t{rate}",
        f"pulse_rate_per_second\t{pulse}",
        f"arrivals\t{count}",
        f"trace_duration_ns\t{duration}",
        f"kernel_config\t{oracle_kernel_config(workload)}",
        "id\tscheduled_ns\tworkload\texpected_checksum",
    ]
    require(len(lines) == len(header) + count and lines[: len(header)] == header, "trusted oracle metadata or row count differs")
    families = ("cpu", "memory", "http", "disk")
    oracle_rows = []
    for expected_id, line in enumerate(lines[len(header) :]):
        fields = line.split("\t")
        require(len(fields) == 4 and fields[0] == str(expected_id), f"trusted oracle ID malformed: {expected_id}")
        if profile == "burst":
            cycle, slot = divmod(expected_id, rate)
            scheduled = cycle * 1_000_000_000 + slot * 250_000_000 // rate
        else:
            scheduled = expected_id * 1_000_000_000 // rate
        family = families[expected_id % 4] if workload == "mixed" else workload
        require(fields[1] == str(scheduled) and fields[2] == family, f"trusted oracle schedule/family mismatch at ID {expected_id}")
        checksum = parse_uint(fields[3], "oracle checksum")
        oracle_rows.append((scheduled, family, checksum))
    return duration, oracle_rows


def extract_process_metrics(
    pair_dir: Path,
    process_row: dict[str, str],
    job: dict[str, Any],
    source: dict[str, Any],
    spec: dict[str, Any],
    campaign_artifacts: Path,
) -> dict[str, Any]:
    process_id = process_row["pair"]
    executor = process_row["executor"]
    require(executor in ("bounded", "tokio"), f"unknown pair executor: {executor}")
    process_allocator = process_row["allocator"]
    require(process_allocator in ALLOCATORS, f"unknown process allocator: {process_allocator}")
    label = "allocatbelt" if executor == "bounded" else "tokio-1.53.1"
    stdout_name = process_row["stdout"]
    require(Path(stdout_name).name == stdout_name and stdout_name.endswith(".stdout.tsv"), "runner stdout reference is not a basename")
    stdout_path = pair_dir / stdout_name
    header, rows = read_tsv(stdout_path, 1)
    expected_header = ("schema allocator executor workload mode async_workers blocking_workers topology logical_window global_task_limit retained_window arrival_rate_per_second requested_arrivals attempted admitted rejected_full rejected_resource completed_on_time completed_late errors cancellations unresolved lost result_digest expected_digest capacity_publications_per_second successful_throughput_through_drain_per_second setup_ns timer_pair_median_ns wall_through_drain_ns drain_tail_ns response_p50_ns response_p95_ns response_p99_ns producer_lateness_mean_ns producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops final_network_ops rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib hwm_after_drain_kib hwm_after_shutdown_kib shutdown_ns rejected_logical_window rejected_backend_full").split()
    require(header == expected_header and len(header) == 53, "benchmark row schema changed")
    row = rows[0]
    require((row["allocator"], row["executor"], row["workload"], row["mode"]) == (process_allocator, label, job["workload"], job["mode"]), "benchmark row identity differs from scheduled process")
    numeric_counts = {name: parse_uint(row[name], name) for name in ("attempted", "admitted", "rejected_full", "rejected_resource", "completed_on_time", "completed_late", "errors", "cancellations", "unresolved", "lost", "result_digest", "expected_digest", "final_managed_bytes", "final_disk_ops", "final_network_ops", "rss_after_drain_kib", "managed_limit_bytes")}
    completed = numeric_counts["completed_on_time"] + numeric_counts["completed_late"]
    require(numeric_counts["result_digest"] == numeric_counts["expected_digest"] and numeric_counts["admitted"] == completed and numeric_counts["attempted"] == numeric_counts["admitted"] + numeric_counts["rejected_full"] + numeric_counts["rejected_resource"], "benchmark counts or aggregate digest do not balance")
    require(numeric_counts["errors"] == numeric_counts["cancellations"] == numeric_counts["unresolved"] == numeric_counts["rejected_full"] == numeric_counts["rejected_resource"] == 0, "confirmation process has loss/rejection/error")
    require(numeric_counts["lost"] == 0 and numeric_counts["final_managed_bytes"] == numeric_counts["final_disk_ops"] == numeric_counts["final_network_ops"] == 0, "confirmation process has lost work or final resource charges")
    if job["workload"] in ("memory", "http", "mixed"):
        require(parse_uint(row["managed_limit_bytes"], "managed limit") > 0, "managed resource ceiling is missing for managed-memory workload")
    cpu_pair = f"{process_id}-{executor}.shutdown.tsv"
    shutdown_path = pair_dir / cpu_pair
    shutdown_lines = shutdown_path.read_text(encoding="utf-8").splitlines()
    shutdown_sha = hashlib.sha256(shutdown_path.read_bytes()).hexdigest()
    require(shutdown_sha == process_row["shutdown_sha256"], "phase sidecar hash differs from the process ledger")
    require(shutdown_lines and shutdown_lines[0] == "schema\tallocatbelt-app-phase-v1\t", "unsupported production phase sidecar schema")
    identity = {}
    phases = {}
    for line in shutdown_lines[1:]:
        fields = line.split("\t")
        require(len(fields) == 3, "phase sidecar row is malformed")
        if fields[0] == "identity":
            require(fields[1] not in identity, "phase sidecar repeats identity field")
            identity[fields[1]] = fields[2]
        elif fields[0] == "phase":
            require(fields[1] not in phases, "phase sidecar repeats phase")
            phases[fields[1]] = parse_uint(fields[2], fields[1])
    _, metadata_rows = read_tsv(pair_dir / "metadata.tsv")
    metadata_map = {item["key"]: item["value"] for item in metadata_rows}
    require(metadata_map.get("comparison_family") == job["comparison_family"], "runner metadata comparison family differs from the frozen fixed/pressure phase")
    expected_identity = {
        "report_nonce": metadata_map.get(f"report_nonce_{process_id}_{executor}"),
        "run_id": job["run_id"],
        "executor": label,
        "allocator": process_allocator,
        "workload": job["workload"],
        "profile": job["profile"],
        "source_sha256": source["source"]["source_tree_sha256"],
        "binary_sha256": source["artifacts"][process_allocator]["sha256"],
    }
    require(identity == expected_identity, "phase sidecar identity differs from this frozen process")
    cpu_per_completion = phases.get("cpu_ns_per_successful_completion")
    cpu_started, cpu_ended = phases.get("production_cpu_started_ns"), phases.get("production_cpu_ended_ns")
    cpu_total = phases.get("production_through_drain_cpu_ns")
    require(cpu_per_completion is not None and phases.get("successful_completions") == completed, "production CPU sidecar does not reconcile with completions")
    require(cpu_started is not None and cpu_ended is not None and cpu_ended >= cpu_started and cpu_ended - cpu_started == cpu_total, "production CPU phase boundaries do not reconcile")
    require(cpu_total // max(completed, 1) == cpu_per_completion, "production CPU normalization does not reconcile")
    metrics: dict[str, Any] = {
        "executor": executor,
        "allocator": process_allocator,
        "mode": job["mode"],
        "completed": completed,
        "completed_on_time": numeric_counts["completed_on_time"],
        "completed_late": numeric_counts["completed_late"],
        "capacity_per_second": parse_decimal(row["capacity_publications_per_second"], "capacity publications") if job["mode"] == "capacity" else None,
        "successful_throughput_per_second": parse_decimal(row["successful_throughput_through_drain_per_second"], "successful throughput"),
        "response_p50_ns": parse_uint(row["response_p50_ns"], "p50"),
        "response_p95_ns": parse_uint(row["response_p95_ns"], "p95"),
        "response_p99_ns": parse_uint(row["response_p99_ns"], "p99"),
        "cpu_ns_per_completion": cpu_per_completion,
        "production_cpu_started_ns": cpu_started,
        "production_cpu_ended_ns": cpu_ended,
        "production_cpu_ns": cpu_total,
        "phase_sha256": shutdown_sha,
        "rss_after_drain_kib": numeric_counts["rss_after_drain_kib"],
        "retained_managed_bytes": parse_uint(row["retained_managed_bytes"], "retained managed bytes"),
        "max_observed_managed_bytes": parse_uint(row["max_observed_managed_bytes"], "maximum managed bytes"),
        "managed_limit_bytes": numeric_counts["managed_limit_bytes"],
        "ids_sha256": None,
        "ids_path": None,
        "family_successes": {},
        "latency_p99_by_family_ns": {},
    }
    require(metrics["response_p50_ns"] <= metrics["response_p95_ns"] <= metrics["response_p99_ns"], "row quantiles are not monotone")
    if job["mode"] == "capacity" and job["workload"] == "mixed":
        family_name = stdout_name.removesuffix(".stdout.tsv") + ".capacity-families.tsv"
        family_path = pair_dir / family_name
        family_sha = sha256_file(family_path)
        require(family_sha == process_row["capacity_family_sha256"], "capacity family sidecar hash differs from the process ledger")
        family_lines = family_path.read_text(encoding="utf-8").splitlines()
        require(family_lines and family_lines[0] == "schema\tallocatbelt-app-capacity-families-v1\t", "capacity family sidecar schema differs")
        family_identity = {}
        family_counts = {}
        family_phases = {}
        for line in family_lines[1:]:
            fields = line.split("\t")
            if len(fields) == 3 and fields[0] == "identity":
                require(fields[1] not in family_identity, "capacity family identity repeats a field")
                family_identity[fields[1]] = fields[2]
            elif len(fields) == 4 and fields[0] == "family":
                require(fields[1] not in family_counts, "capacity family sidecar repeats a family")
                family_counts[fields[1]] = (parse_uint(fields[2], "family scheduled"), parse_uint(fields[3], "family completed"))
            elif len(fields) == 3 and fields[0] == "phase":
                require(fields[1] not in family_phases, "capacity family phase repeats a field")
                family_phases[fields[1]] = fields[2]
            else:
                raise CampaignError("capacity family sidecar row is malformed")
        family_identity_expected = {
            "report_nonce": metadata_map.get(f"report_nonce_{process_id}_{executor}"), "run_id": job["run_id"],
            "executor": label, "allocator": process_allocator, "workload": "mixed", "profile": job["profile"],
            "source_sha256": source["source"]["source_tree_sha256"], "binary_sha256": source["artifacts"][process_allocator]["sha256"],
        }
        require(family_identity == family_identity_expected and family_phases == {"trace_seconds": "30", "profile": job["profile"]}, "capacity family identity or horizon differs")
        require(set(family_counts) == set(STANDALONE) and sum(item[0] for item in family_counts.values()) == numeric_counts["attempted"] and sum(item[1] for item in family_counts.values()) == numeric_counts["completed_on_time"], "capacity family counts do not reconcile with on-time row totals")
        expected_family_counts = {family: numeric_counts["attempted"] // 4 + int(index < numeric_counts["attempted"] % 4) for index, family in enumerate(STANDALONE)}
        require(all(family_counts[family][0] == expected_family_counts[family] and family_counts[family][1] <= expected_family_counts[family] for family in STANDALONE), "capacity family scheduled IDs or on-time count is invalid")
        metrics["capacity_throughput_by_family"] = {family: count[1] / parse_uint(family_phases["trace_seconds"], "trace seconds") for family, count in family_counts.items()}
        metrics["capacity_family_sha256"] = family_sha
    else:
        require(process_row["capacity_family_sha256"] == "not_applicable", "unexpected capacity family sidecar for this process")
    if job["mode"] == "open_loop":
        ids_name = stdout_name.removesuffix(".stdout.tsv") + ".ids.tsv"
        ids_path = pair_dir / ids_name
        ids_sha = hashlib.sha256(ids_path.read_bytes()).hexdigest()
        require(ids_sha == process_row["ids_sha256"], "per-ID sidecar hash differs from the process ledger")
        _, metadata = read_tsv(pair_dir / "metadata.tsv")
        metadata_map = {item["key"]: item["value"] for item in metadata}
        nonce = metadata_map.get(f"report_nonce_{process_id}_{executor}")
        expected_binary_sha = source["artifacts"][process_allocator]["sha256"]
        expected_identity = ["identity", nonce, job["run_id"], label, process_allocator, job["workload"], job["profile"], source["source"]["source_tree_sha256"], expected_binary_sha]
        sidecar_lines = ids_path.read_text(encoding="utf-8").splitlines()
        require(len(sidecar_lines) == job["arrivals"] + 3 and sidecar_lines[0] == "schema\tallocatbelt-app-arrivals-v3" and sidecar_lines[1].split("\t") == expected_identity, "per-ID identity or row count differs")
        require(sidecar_lines[2] == "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum", "per-ID schema differs")
        oracle = job["oracles"][process_allocator] if job.get("comparison_kind") == "allocator" else job["oracle"]
        oracle_path = campaign_artifacts / oracle["relative_path"]
        oracle_duration, oracle_rows = parse_oracle(oracle_path, oracle, source, next(cell for cell in spec["cells"] if cell["family"] == job["family"] and cell["profile"] == job["profile"]), job["rate_per_second"])
        latencies: dict[str, list[int]] = {family: [] for family in STANDALONE}
        all_latencies: list[int] = []
        digest = 0
        rejected = errors = complete_count = 0
        on_time = 0
        for arrival_id, line in enumerate(sidecar_lines[3:]):
            fields = line.split("\t")
            require(len(fields) == 7 and fields[0] == str(arrival_id) and fields[1] == oracle_rows[arrival_id][1], f"per-ID family/ID mismatch at {arrival_id}")
            scheduled, completion = parse_uint(fields[2], "scheduled_ns"), parse_uint(fields[3], "completion_ns")
            checksum, expected_checksum = parse_uint(fields[5], "checksum"), parse_uint(fields[6], "expected_checksum")
            canonical_scheduled, family, canonical_checksum = oracle_rows[arrival_id]
            require(scheduled == canonical_scheduled and expected_checksum == canonical_checksum and completion >= scheduled, f"per-ID oracle/timestamp mismatch at {arrival_id}")
            terminal = fields[4]
            if terminal == "completed":
                require(checksum == expected_checksum, f"per-ID checksum mismatch at {arrival_id}")
                latency = completion - scheduled
                latencies[family].append(latency)
                all_latencies.append(latency)
                complete_count += 1
                on_time += completion <= oracle_duration
                digest = (digest + (checksum if job["workload"] == "http" else checksum ^ arrival_id)) & ((1 << 64) - 1)
            elif terminal == "rejected":
                require(checksum == 0, f"rejected ID has checksum at {arrival_id}")
                rejected += 1
            elif terminal == "error":
                errors += 1
            else:
                raise CampaignError(f"unknown terminal status at ID {arrival_id}")
        require(complete_count == completed and rejected == numeric_counts["rejected_full"] + numeric_counts["rejected_resource"] and errors == numeric_counts["errors"], "per-ID terminal counts do not reconcile")
        require(on_time == numeric_counts["completed_on_time"] and digest == numeric_counts["result_digest"], "per-ID on-time count/digest does not reconcile")
        require(not rejected and not errors, "confirmation per-ID trace contains loss")
        family_names = STANDALONE if job["workload"] == "mixed" else (job["workload"],)
        for quantile in (50, 95, 99):
            require(metrics[f"response_p{quantile}_ns"] == nearest_rank(all_latencies, quantile), "per-ID combined quantile differs from row")
        for family in family_names:
            samples = latencies[family]
            minimum = spec["protocol"]["family_min_successes"] if job["workload"] == "mixed" else spec["protocol"]["standalone_min_successes"]
            require(len(samples) >= minimum, f"successful observation minimum missed for {job['family']}/{job['profile']}/{family}")
        metrics["ids_sha256"] = ids_sha
        metrics["ids_path"] = ids_name
        metrics["family_successes"] = {family: len(values) for family, values in latencies.items() if values}
        metrics["latency_p99_by_family_ns"] = {family: nearest_rank(values, 99) for family, values in latencies.items() if values}
        metrics["trace_duration_ns"] = oracle_duration
    return metrics


def oracle_kernel_config(workload: str) -> str:
    return {
        "cpu": "rounds=50000",
        "memory": "initial_bytes=4096;grown_bytes=8192;seed=0x243f6a8885a308d3",
        "http": "body_bytes=4096",
        "disk": "bytes=196625;offset=4096;seed=0xa4093822299f31d0",
        "mixed": "interleave=cpu,memory,http,disk",
    }[workload]


def validate_oracle(path: Path, source_sha: str, binary_sha: str, workload: str, profile: str, rate: int, arrivals: int) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CampaignError(f"canonical oracle cannot be read: {error}") from error
    pulse_rate = rate * 4 if profile == "burst" else rate
    duration = ((arrivals + rate - 1) // rate) * 1_000_000_000 if profile == "burst" else arrivals * 1_000_000_000 // rate
    expected = [
        "schema\tallocatbelt-app-oracle-v2",
        f"source_sha256\t{source_sha}",
        f"binary_sha256\t{binary_sha}",
        f"profile\t{profile}",
        f"workload\t{workload}",
        "mode\topen_loop",
        f"average_rate_per_second\t{rate}",
        f"pulse_rate_per_second\t{pulse_rate}",
        f"arrivals\t{arrivals}",
        f"trace_duration_ns\t{duration}",
        f"kernel_config\t{oracle_kernel_config(workload)}",
        "id\tscheduled_ns\tworkload\texpected_checksum",
    ]
    require(len(lines) == len(expected) + arrivals and lines[: len(expected)] == expected, "oracle header or row count differs from the frozen cell")
    families = ("cpu", "memory", "http", "disk")
    for job_id, line in enumerate(lines[len(expected) :]):
        fields = line.split("\t")
        require(len(fields) == 4 and fields[0] == str(job_id), f"oracle row ID malformed at {job_id}")
        if profile == "burst":
            cycle, slot = divmod(job_id, rate)
            scheduled = cycle * 1_000_000_000 + slot * 250_000_000 // rate
        else:
            scheduled = job_id * 1_000_000_000 // rate
        family = families[job_id % 4] if workload == "mixed" else workload
        require(fields[1] == str(scheduled) and fields[2] == family, f"oracle schedule/family mismatch at ID {job_id}")
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[3]) is not None and int(fields[3]) < (1 << 64), f"oracle checksum outside u64 at ID {job_id}")


def prepare_oracles(spec: dict[str, Any], sources: dict[str, dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    validation = validate_spec(spec, sources)
    require(validation["rates_frozen"], "canonical open-loop oracles require frozen 70/90 rates")
    host_id = args.host_id
    require(host_id in sources, f"unknown host id: {host_id}")
    source = sources[host_id]
    source_root = Path(args.source_root).resolve(strict=True)
    verify_source_manifest(source, source_root, verify_artifacts=True)
    raw_output = Path(args.output_root)
    require(not raw_output.is_symlink(), "oracle output root may not be a symlink")
    output_root = raw_output.resolve()
    require(not within(source_root, output_root) and not output_root.exists(), "oracle root must be a new directory outside the source checkout")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    output_root.mkdir(mode=0o700, exist_ok=False)
    manifests: list[dict[str, Any]] = []
    try:
        source_sha = source["source"]["source_tree_sha256"]
        for cell in spec["cells"]:
            for allocator in ALLOCATORS:
                binary_pin = source["artifacts"][allocator]
                binary = source_root / binary_pin["path"]
                binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
                for rate_entry in (item for item in spec["rates"] if item["host_id"] == host_id and item["family"] == cell["family"] and item["profile"] == cell["profile"]):
                    relative_dir = Path(host_id) / cell["family"] / cell["profile"] / str(rate_entry["load_percent"]) / allocator
                    oracle_dir = output_root / relative_dir
                    oracle_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
                    oracle_path = oracle_dir / "canonical-oracle.tsv"
                    argv = [
                        str(binary), "--emit-oracle-only", str(oracle_path),
                        "--source-sha256", source_sha,
                        "--binary-sha256", binary_sha,
                        "--workload", cell["workload"],
                        "--profile", cell["profile"],
                        "--rate", str(rate_entry["arrivals_per_second"]),
                        "--arrivals", str(cell["arrivals"]),
                        "--trace-deadline-seconds", str(spec["deadlines"]["trace_seconds"]),
                    ]
                    timeout = max(120, spec["deadlines"]["process_seconds"])
                    try:
                        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
                    except (OSError, subprocess.TimeoutExpired) as error:
                        (oracle_dir / "oracle-generator.error.txt").write_text(str(error), encoding="utf-8")
                        raise CampaignError(f"oracle generation failed for {allocator}/{cell['family']}/{cell['profile']}/{rate_entry['load_percent']}: {error}") from error
                    (oracle_dir / "oracle-generator.stdout.txt").write_bytes(result.stdout)
                    (oracle_dir / "oracle-generator.stderr.txt").write_bytes(result.stderr)
                    require(result.returncode == 0 and oracle_path.is_file(), f"oracle generator refused {allocator}/{cell['family']}/{cell['profile']}/{rate_entry['load_percent']}")
                    validate_oracle(oracle_path, source_sha, binary_sha, cell["workload"], cell["profile"], rate_entry["arrivals_per_second"], cell["arrivals"])
                    sha = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
                    manifests.append({
                        "host_id": host_id,
                        "allocator": allocator,
                        "family": cell["family"],
                        "profile": cell["profile"],
                        "load_percent": rate_entry["load_percent"],
                        "relative_path": relative_dir.joinpath("canonical-oracle.tsv").as_posix(),
                        "sha256": sha,
                    })
    finally:
        os.umask(old_umask)
    result = {
        "schema": "allocatbelt.application-oracle-manifest.v1",
        "campaign_id": spec["campaign_id"],
        "spec_preregistration_sha256": preregistration_digest(spec),
        "source_manifest_sha256": source["manifest_sha256"],
        "host_id": host_id,
        "oracles": manifests,
    }
    result["manifest_sha256"] = digest_object(result)
    manifest_path = output_root / "oracle-manifest.json"
    manifest_path.write_bytes(canonical_bytes(result))
    return result


def build_jobs(spec: dict[str, Any], phase: str, host_id: str | None = None) -> list[dict[str, Any]]:
    protocol = spec["protocol"]
    hosts = [host for host in spec["hosts"] if host_id is None or host["host_id"] == host_id]
    require(hosts, f"unknown host id: {host_id}")
    jobs: list[dict[str, Any]] = []
    if phase in ("confirmation", "pressure") and (not spec["rates"] or not spec["oracles"]):
        return jobs
    rates = load_rate_map(spec)
    oracles = {(o["host_id"], o["allocator"], o["family"], o["profile"], o["load_percent"]): o for o in spec["oracles"]}
    fixed_predecessors = build_jobs(spec, "confirmation", host_id) if phase == "pressure" else []
    for host in hosts:
        hid = host["host_id"]
        for cell in spec["cells"]:
            modes = [("capacity", None)] if phase == "exploration" else [("capacity", None), ("open_loop", 70), ("open_loop", 90)] if phase in ("confirmation", "pressure") else []
            repeat_count = protocol["exploration_pairs"] if phase == "exploration" else protocol["confirmation_pairs"]
            for mode, load in modes:
                rate = None if load is None else rates[(hid, cell["family"], cell["profile"], load)]
                for ordinal in range(1, repeat_count + 1):
                    common = {
                        "host_id": hid,
                        "phase": phase,
                        "family": cell["family"],
                        "workload": cell["workload"],
                        "profile": cell["profile"],
                        "mode": mode,
                        "load_percent": load,
                        "rate_per_second": rate,
                        "arrivals": cell["arrivals"] if mode == "open_loop" else None,
                        "ordinal": ordinal,
                        "comparison_family": "external_pressure" if phase == "pressure" else "fixed_policy",
                        "predecessor_run_ids": [],
                    }
                    if phase == "exploration":
                        for allocator in ALLOCATORS:
                            jobs.append({
                                **common,
                                "allocator": allocator,
                                "comparison_kind": "capacity_pilot",
                                "pair_kind": "matched",
                                "oracle": None,
                                "run_id": f"{spec['campaign_id']}-{hid}-{cell['family']}-{cell['profile']}-{mode}-pilot-{allocator}-{ordinal:02d}",
                            })
                    elif phase in ("confirmation", "pressure"):
                        family_prefix = "pressure" if phase == "pressure" else "fixed"
                        allocator_pair_kind = "pressure-allocator-match" if phase == "pressure" else "allocator-match"
                        executor_pair_kind = "pressure-matched" if phase == "pressure" else "matched"
                        for baseline in ("mimalloc-secure", "mimalloc-standard"):
                            oracle_pair = {
                                allocator: oracles[(hid, allocator, cell["family"], cell["profile"], load)]
                                for allocator in ("allocatbelt", baseline)
                            } if load is not None else {}
                            jobs.append({
                                **common,
                                "allocator": "allocatbelt",
                                "baseline_allocator": baseline,
                                "comparison_kind": "allocator",
                                "executor": "bounded",
                                "pair_kind": allocator_pair_kind,
                                "oracles": oracle_pair,
                                "run_id": f"{spec['campaign_id']}-{hid}-{cell['family']}-{cell['profile']}-{family_prefix}-{mode}-{load or 'cap'}-allocatbelt-vs-{baseline}-bounded-{ordinal:02d}",
                            })
                        for executor_allocator in ("allocatbelt", "mimalloc-secure", "mimalloc-standard"):
                            oracle = None if load is None else oracles[(hid, executor_allocator, cell["family"], cell["profile"], load)]
                            jobs.append({
                                **common,
                                "allocator": executor_allocator,
                                "comparison_kind": "executor",
                                "pair_kind": executor_pair_kind,
                                "oracle": oracle,
                                "gate_role": "primary" if executor_allocator == "allocatbelt" else "secondary_sanity",
                                "run_id": f"{spec['campaign_id']}-{hid}-{cell['family']}-{cell['profile']}-{family_prefix}-{mode}-{load or 'cap'}-{executor_allocator}-bounded-vs-tokio-{ordinal:02d}",
                            })
        if phase == "aa":
            for control in spec["aa_controls"]:
                for ordinal in range(1, control["pairs"] + 1):
                    cell = next(item for item in spec["cells"] if item["family"] == control["family"] and item["profile"] == control["profile"])
                    load = control["load_percent"]
                    rate = None if load is None else rates[(hid, control["family"], control["profile"], load)]
                    oracle = None if load is None else next((o for o in spec["oracles"] if o["host_id"] == hid and o["allocator"] == control["allocator"] and o["family"] == control["family"] and o["profile"] == control["profile"] and o["load_percent"] == load), None)
                    if load is not None:
                        require(oracle is not None, f"A/A control lacks its trusted oracle: {control['control_id']}")
                    jobs.append({"host_id": hid, "phase": "aa", "comparison_family": "fixed_policy", "predecessor_run_ids": [], **control, "workload": cell["workload"], "rate_per_second": rate, "arrivals": cell["arrivals"] if load is not None else None, "oracle": oracle, "ordinal": ordinal, "pair_kind": f"aa-{control['executor']}", "run_id": f"{spec['campaign_id']}-{hid}-{control['control_id']}-{ordinal:02d}"})
        if phase == "soak":
            jobs.append({"host_id": hid, "phase": "soak", "comparison_family": "external_pressure", "predecessor_run_ids": [], "family": "mixed", **spec["soak"], "duration_seconds": spec["protocol"]["soak_seconds"], "adapter_relative_path": spec["soak"]["driver_relative_path"], "ordinal": 1, "run_id": f"{spec['campaign_id']}-{hid}-mixed-{spec['soak']['profile']}-soak-{spec['soak']['allocator']}-01"})
    if phase == "exploration":
        for job in jobs:
            job["comparison_family"] = "fixed_policy"
            job["predecessor_run_ids"] = []
    if phase == "pressure":
        def predecessor_key(job: dict[str, Any]) -> tuple[Any, ...]:
            contrast = job["baseline_allocator"] if job["comparison_kind"] == "allocator" else job["allocator"]
            pair_kind = job["pair_kind"].removeprefix("pressure-")
            return (job["host_id"], job["family"], job["profile"], job["mode"], job["load_percent"], job["comparison_kind"], contrast, pair_kind, job["ordinal"])

        fixed_by_key = {predecessor_key(job): job["run_id"] for job in fixed_predecessors}
        require(len(fixed_by_key) == len(fixed_predecessors), "fixed-policy predecessor matrix contains duplicate jobs")
        for job in jobs:
            predecessor = fixed_by_key.get(predecessor_key(job))
            require(predecessor is not None, "external-pressure job has no corresponding frozen fixed-policy predecessor")
            job["predecessor_run_ids"] = [predecessor]
    if phase == "soak":
        pressure_jobs = build_jobs(spec, "pressure", host_id)
        for job in jobs:
            predecessor_jobs = [
                pressure_job for pressure_job in pressure_jobs
                if pressure_job["host_id"] == job["host_id"]
                and pressure_job["family"] == "mixed"
                and pressure_job["profile"] == job["profile"]
                and pressure_job["comparison_kind"] == "executor"
                and pressure_job["allocator"] == job["allocator"]
            ]
            require(predecessor_jobs or not spec["rates"] or not spec["oracles"], "continuous pressure soak has no same-host treatment predecessor pairs")
            job["predecessor_run_ids"] = sorted(item["run_id"] for item in predecessor_jobs)
    require(jobs, f"no jobs for phase {phase}")
    # Deterministic interleaving prevents one family/profile from occupying a
    # long uninterrupted block of the host schedule.
    seed = spec["protocol"]["schedule_seed"]
    jobs.sort(key=lambda job: hashlib.sha256(f"{seed}:{job['host_id']}:{job.get('family', 'soak')}:{job.get('profile', '')}:{job.get('allocator', '')}:{job['ordinal']}:{job.get('mode', job['phase'])}".encode()).digest())
    return jobs


def freeze_plan(spec: dict[str, Any], sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    validation = validate_spec(spec, sources)
    plan = {
        "schema": PLAN_SCHEMA,
        "campaign_id": spec["campaign_id"],
        "spec_sha256": digest_object(spec),
        "source_manifests": {host: sources[host]["manifest_sha256"] for host in validation["host_ids"]},
        "protocol": spec["protocol"],
        "runtime_binding": spec["runtime_binding"],
        "execution_ready": validation["execution_ready"],
        "full_gate_ready": False,
        "full_gate_gaps": validation["full_gate_gaps"],
        "host_ids": validation["host_ids"],
        "cell_count": validation["cell_count"],
        "jobs": {phase: build_jobs(spec, phase) for phase in ("exploration", "aa", "confirmation", "pressure", "soak")},
    }
    plan["plan_sha256"] = digest_object(plan, "plan_sha256")
    return plan


def verify_plan(plan: dict[str, Any]) -> None:
    exact_keys(plan, {"schema", "campaign_id", "spec_sha256", "source_manifests", "protocol", "runtime_binding", "execution_ready", "full_gate_ready", "full_gate_gaps", "host_ids", "cell_count", "jobs", "plan_sha256"}, "campaign plan")
    require(plan["schema"] == PLAN_SCHEMA, "unsupported campaign-plan schema")
    require(is_sha256(plan["plan_sha256"]) and digest_object(plan, "plan_sha256") == plan["plan_sha256"], "campaign-plan digest mismatch")
    require(is_sha256(plan["spec_sha256"]) and isinstance(plan["source_manifests"], dict) and plan["source_manifests"], "campaign-plan source/spec digest missing")
    require(all(is_sha256(value) for value in plan["source_manifests"].values()), "campaign plan contains an invalid host source pin")


def within(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def read_ledger(path: Path) -> list[dict[str, Any]]:
    require(path.is_file(), f"required prior-phase ledger is missing: {path}")
    records: list[dict[str, Any]] = []
    previous = "0" * 64
    for line_number, line in enumerate(path.read_bytes().splitlines(), 1):
        try:
            envelope = json.loads(line, object_pairs_hook=no_duplicate_keys)
        except (json.JSONDecodeError, CampaignError) as error:
            raise CampaignError(f"malformed phase ledger line {line_number}: {error}") from error
        exact_keys(envelope, {"previous_sha256", "record", "record_sha256"}, f"phase ledger line {line_number}")
        require(envelope["previous_sha256"] == previous, f"broken ledger hash chain at line {line_number}")
        unsigned = {"previous_sha256": envelope["previous_sha256"], "record": envelope["record"]}
        expected_hash = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
        require(envelope["record_sha256"] == expected_hash, f"ledger digest mismatch at line {line_number}")
        require(isinstance(envelope["record"], dict), f"ledger record is not an object at line {line_number}")
        records.append(envelope["record"])
        previous = expected_hash
    return records


def pair_exit_disposition(exit_code: int) -> tuple[str, bool]:
    if exit_code == 0:
        return "valid_pair", False
    if exit_code == 1:
        return "failed_or_invalid_pair", False
    if exit_code == 2:
        return "halt_preflight_refusal", True
    return "halt_integrity_or_interruption", True


def terminate_process_group(process: subprocess.Popen[bytes], grace_seconds: int = 3) -> None:
    positive_int(grace_seconds, "process termination grace", 5)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        process.poll()
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    # The shell leader may have exited while one of its children ignored
    # TERM, so escalate against the process group even after Popen.poll().
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.wait()


def build_pair_runner_argv(
    runner: Path, binary: Path, job: dict[str, Any], cpu_set: str, output_dir: Path,
    deadlines: dict[str, int], arrivals: int, candidate_oracle: tuple[Path, str] | None = None,
    baseline_binary: Path | None = None, baseline_allocator: str | None = None,
    baseline_oracle: tuple[Path, str] | None = None,
) -> list[str]:
    rate_arg = "-" if job["mode"] == "capacity" else str(job["rate_per_second"])
    argv = [
        str(runner), str(binary), job["allocator"], job["workload"], job["mode"], rate_arg,
        cpu_set, job["run_id"], str(output_dir), str(arrivals if job["mode"] == "open_loop" else 5000),
        str(deadlines["trace_seconds"]), str(deadlines["drain_seconds"]), str(deadlines["shutdown_seconds"]), str(deadlines["process_seconds"]),
    ]
    if job["mode"] == "open_loop":
        require(candidate_oracle is not None, "open-loop pair command lacks its pinned candidate oracle")
        argv.extend([str(candidate_oracle[0]), candidate_oracle[1]])
    else:
        require(candidate_oracle is None, "capacity pair command must use explicit empty oracle arguments")
        argv.extend(["", ""])
    argv.extend([job["profile"], job["pair_kind"]])
    if job.get("comparison_kind") == "allocator":
        require(baseline_binary is not None and baseline_allocator is not None and baseline_oracle is not None if job["mode"] == "open_loop" else baseline_binary is not None and baseline_allocator is not None, "allocator-pair command lacks its frozen baseline inputs")
        argv.extend([str(baseline_binary), baseline_allocator])
        if job["mode"] == "open_loop":
            argv.extend([str(baseline_oracle[0]), baseline_oracle[1]])
        else:
            argv.extend(["", ""])
    else:
        require(baseline_binary is None and baseline_allocator is None and baseline_oracle is None, "non-allocator pair command contains baseline-only arguments")
    return argv


def oracle_map_for_job(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if job.get("phase") == "aa":
        oracle = job.get("oracle")
        require(isinstance(oracle, dict) and oracle.get("allocator") == job["allocator"], "A/A open-loop job lacks its allocator-bound oracle")
        return {job["allocator"]: oracle}
    if job.get("comparison_kind") == "allocator":
        oracles = job.get("oracles")
        require(isinstance(oracles, dict) and job["allocator"] in oracles, "allocator comparison lacks its candidate oracle map")
        return oracles
    oracle = job.get("oracle")
    require(isinstance(oracle, dict) and oracle.get("allocator") == job["allocator"], "matched executor job lacks its allocator-bound oracle")
    return {job["allocator"]: oracle}


def run_jobs(plan: dict[str, Any], spec: dict[str, Any], sources: dict[str, dict[str, Any]], args: argparse.Namespace) -> int:
    verify_plan(plan)
    if args.phase == "pressure":
        require(EXTERNAL_PRESSURE_DRIVER_SUPPORTED, "external-pressure phase is hard-disabled until the same-policy feedback driver and process readbacks are implemented")
    require(plan["execution_ready"], "qualification execution is hard-disabled until production binary runtime-domain/policy/ceiling readback is implemented and verified")
    require(args.phase in ("exploration", "aa", "confirmation", "pressure", "soak"), "unknown campaign phase")
    require(args.host_id in plan["host_ids"], "selected host is not in the frozen plan")
    source_root = Path(args.source_root).resolve(strict=True)
    source = sources[args.host_id]
    verify_source_manifest(source, source_root)
    raw_output_root = Path(args.output_root)
    require(not raw_output_root.is_symlink(), "raw output root may not be a symlink")
    output_root = raw_output_root.resolve()
    require(not within(source_root, output_root), "raw campaign output must be outside the source checkout")
    if args.phase == "soak":
        runner = (source_root / spec["soak"]["driver_relative_path"]).resolve(strict=True)
        require(args.soak_runner is None or Path(args.soak_runner).resolve(strict=True) == runner, "soak runner path differs from the portable frozen source path")
        require(runner.is_file() and os.access(runner, os.X_OK), "continuous soak runner must be executable")
        require(hashlib.sha256(runner.read_bytes()).hexdigest() == spec["soak"]["driver_sha256"] == spec["phase_adapters"]["three_hour_soak_sha256"], "continuous soak runner hash differs from its phase pin")
    else:
        require(args.pair_runner is not None, "matched workload phases require --pair-runner")
        runner = Path(args.pair_runner).resolve(strict=True)
        require(runner.is_file() and os.access(runner, os.X_OK), "pair runner must be executable")
        require(hashlib.sha256(runner.read_bytes()).hexdigest() == spec["runner_sha256"], "pair-runner hash differs from the preregistration")
    runner_sha256 = sha256_file(runner)
    current_host = read_json(Path(args.observed_host_contract))
    expected_host = next(host for host in spec["hosts"] if host["host_id"] == args.host_id)
    require(current_host == expected_host, "observed host controls differ from the frozen host contract")
    jobs = [job for job in plan["jobs"][args.phase] if job["host_id"] == args.host_id]
    require(jobs, "selected phase has no jobs for this host")
    if args.phase in ("aa", "confirmation", "pressure", "soak"):
        campaign_dir = output_root / spec["campaign_id"]
        prerequisites = {
            "aa": ("exploration",),
            "confirmation": ("exploration", "aa"),
            "pressure": ("exploration", "aa", "confirmation"),
            "soak": ("exploration", "aa", "confirmation", "pressure"),
        }[args.phase]
        prerequisite_ledgers: dict[str, list[dict[str, Any]]] = {}
        for prerequisite in prerequisites:
            expected = [job for job in plan["jobs"][prerequisite] if job["host_id"] == args.host_id]
            require(expected, f"frozen plan has no {prerequisite} controls for this host")
            ledger = read_ledger(campaign_dir / prerequisite / args.host_id / "controller-ledger.jsonl")
            require(len(ledger) == len(expected), f"{prerequisite} ledger is incomplete for this host")
            require(all(record.get("state") == "valid_pair" for record in ledger), f"{prerequisite} contains a failed, interrupted, or invalid pair")
            if args.phase in ("pressure", "soak") and prerequisite in ("confirmation", "pressure"):
                revalidate_pair_records(ledger, prerequisite, campaign_dir / prerequisite / args.host_id, source, spec, Path(args.campaign_artifacts))
            prerequisite_ledgers[prerequisite] = ledger
            if prerequisite == "aa":
                validate_aa_records(ledger, expected, args.host_id, spec["protocol"]["bootstrap_draws"], spec["protocol"]["bootstrap_seed"])
        if args.phase == "pressure":
            fixed_by_id = {record["job"]["run_id"]: record for record in prerequisite_ledgers["confirmation"]}
            pressure_predecessor_receipts = {}
            for job in jobs:
                predecessor_ids = job.get("predecessor_run_ids")
                require(isinstance(predecessor_ids, list) and len(predecessor_ids) == 1, "pressure schedule lacks its exact fixed predecessor ID")
                fixed = fixed_by_id.get(predecessor_ids[0])
                require(fixed is not None, "pressure schedule references an absent fixed predecessor pair")
                receipt = fixed_pressure_predecessor_receipt(job, fixed, spec)
                pressure_predecessor_receipts[job["run_id"]] = [receipt]
        else:
            pressure_predecessor_receipts = {}
        if args.phase == "soak":
            validate_pressure_predecessor_receipts(
                prerequisite_ledgers["pressure"],
                prerequisite_ledgers["confirmation"],
                spec,
            )
        if args.phase == "soak":
            analysis_path = campaign_dir / "analysis" / args.host_id / "pre-soak.json"
            analysis = read_json(analysis_path)
            require(analysis.get("schema") == "allocatbelt.application-campaign-analysis.v1" and analysis.get("stage") == "pre_soak" and analysis.get("host_id") == args.host_id and analysis.get("spec_sha256") == plan["spec_sha256"] and analysis.get("passed") is True, "soak phase requires a passing independent host pre-soak analysis")
        if args.phase == "pressure":
            fixed_analysis_path = campaign_dir / "analysis" / args.host_id / "fixed-pre-pressure.json"
            fixed_analysis = read_json(fixed_analysis_path)
            require(
                fixed_analysis.get("schema") == "allocatbelt.application-campaign-analysis.v1"
                and fixed_analysis.get("stage") == "fixed_pre_pressure"
                and fixed_analysis.get("host_id") == args.host_id
                and fixed_analysis.get("spec_sha256") == plan["spec_sha256"]
                and fixed_analysis.get("passed") is True,
                "external-pressure jobs require a passing independent fixed-policy analysis first",
            )
    ledger_dir = output_root / spec["campaign_id"] / args.phase / args.host_id
    require(not ledger_dir.exists(), f"campaign phase directory already exists: {ledger_dir}")
    old_umask = os.umask(0o077)
    ledger_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger_dir.chmod(0o700)
    ledger_path = ledger_dir / "controller-ledger.jsonl"
    previous = "0" * 64
    stopped = False
    stop_reason = "interrupt"
    had_failures = False
    active: subprocess.Popen[bytes] | None = None

    def write_record(record: dict[str, Any]) -> None:
        nonlocal previous
        envelope = {"previous_sha256": previous, "record": record}
        current = hashlib.sha256(canonical_bytes(envelope)).hexdigest()
        envelope["record_sha256"] = current
        with ledger_path.open("ab") as ledger:
            ledger.write(canonical_bytes(envelope))
            ledger.flush()
            os.fsync(ledger.fileno())
        previous = current

    def terminate_active() -> None:
        nonlocal active
        if active is None:
            return
        terminate_process_group(active, 3)

    def interrupt(signum: int, _frame: Any) -> None:
        nonlocal stopped, active, stop_reason
        stopped = True
        stop_reason = "interrupt"
        terminate_active()

    old_handlers = {signum: signal.signal(signum, interrupt) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        for position, job in enumerate(jobs):
            if stopped:
                write_record({"state": f"not_run_after_{stop_reason}", "job": job})
                continue
            job_started = time.monotonic()
            runner_hash_before = sha256_file(runner)
            require(runner_hash_before == runner_sha256, "pinned runner changed before a scheduled job")
            artifact_group = "soak_artifacts" if args.phase == "soak" else "artifacts"
            binary = source_root / source[artifact_group][job["allocator"]]["path"]
            binary_sha = sha256_file(binary)
            require(binary_sha == source[artifact_group][job["allocator"]]["sha256"], f"binary changed before job {job['run_id']}")
            if args.phase == "soak":
                runner_output = ledger_dir / "pairs" / "soak" / job["allocator"] / job["run_id"]
                runner_output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                argv = [
                    str(runner), str(binary), job["allocator"], job["executor"], job["profile"],
                    expected_host["controls"]["cpu_set"], spec["campaign_id"], args.host_id, job["run_id"], str(runner_output),
                    source["source"]["source_tree_sha256"], binary_sha, next(cell["resource_ceiling_sha256"] for cell in spec["cells"] if cell["family"] == "mixed" and cell["profile"] == job["profile"]),
                ]
            else:
                runner_output = ledger_dir / "pairs" / job.get("control_id", job["family"]) / job["profile"] / job["mode"] / job["allocator"]
                candidate_oracle = baseline_oracle = None
                baseline_binary = None
                baseline_allocator = None
                if job["mode"] == "open_loop":
                    oracle_pair = oracle_map_for_job(job)
                    oracle = oracle_pair[job["allocator"]]
                    oracle_path = Path(args.campaign_artifacts) / oracle["relative_path"]
                    require(oracle_path.is_file() and sha256_file(oracle_path) == oracle["sha256"], f"trusted oracle is missing or changed for {job['run_id']}")
                    candidate_oracle = (oracle_path, oracle["sha256"])
                if job.get("comparison_kind") == "allocator":
                    baseline = job["baseline_allocator"]
                    baseline_binary = source_root / source["artifacts"][baseline]["path"]
                    baseline_binary_sha = sha256_file(baseline_binary)
                    require(baseline_binary_sha == source["artifacts"][baseline]["sha256"], f"baseline binary changed before job {job['run_id']}")
                    baseline_allocator = baseline
                    if job["mode"] == "open_loop":
                        baseline_oracle = oracle_pair[baseline]
                        baseline_oracle_path = Path(args.campaign_artifacts) / baseline_oracle["relative_path"]
                        require(baseline_oracle_path.is_file() and sha256_file(baseline_oracle_path) == baseline_oracle["sha256"], f"baseline oracle is missing or changed for {job['run_id']}")
                        baseline_oracle = (baseline_oracle_path, baseline_oracle["sha256"])
                argv = build_pair_runner_argv(
                    runner, binary, job, expected_host["controls"]["cpu_set"], runner_output,
                    spec["deadlines"], job["arrivals"] or 5000, candidate_oracle,
                    baseline_binary, baseline_allocator, baseline_oracle,
                )
            stdout_path = ledger_dir / f"{position:06d}-{job['run_id']}.stdout.log"
            stderr_path = ledger_dir / f"{position:06d}-{job['run_id']}.stderr.log"
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            outer_budget = spec["deadlines"]["soak_outer_seconds"] if args.phase == "soak" else spec["deadlines"]["outer_seconds"]
            outer_remaining = outer_budget - (time.monotonic() - job_started)
            require(outer_remaining > 0, "job setup exceeded its finite outer deadline")
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                try:
                    active = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
                    exit_code = active.wait(timeout=outer_remaining)
                except subprocess.TimeoutExpired:
                    terminate_active()
                    active = None
                    exit_code = 124
                except OSError as error:
                    active = None
                    write_record({"state": "halt_launch_error", "job": job, "error": str(error)})
                    stopped = True
                    stop_reason = "launch_error"
                    for remaining in jobs[position + 1 :]:
                        write_record({"state": f"not_run_after_{stop_reason}", "job": remaining})
                    break
            active = None
            runner_hash_after = sha256_file(runner)
            state, halt = pair_exit_disposition(exit_code)
            if runner_hash_after != runner_sha256:
                state, halt = "runner_integrity_failed_stop", True
                stopped = True
                stop_reason = "runner_integrity_failure"
            source_check_remaining = outer_budget - (time.monotonic() - job_started)
            try:
                require(source_check_remaining > 0, "job outer deadline expired before post-run source verification")
                with hard_wall_deadline(source_check_remaining, "post-run source verification exceeded the remaining outer job deadline"):
                    verify_source_manifest(source, source_root, timeout_seconds=source_check_remaining)
            except CampaignError as error:
                state = "integrity_failed_stop"
                stopped = True
                stop_reason = "integrity_failure"
                write_record({"state": state, "exit_code": exit_code, "job": job, "error": str(error), "stdout": stdout_path.relative_to(ledger_dir).as_posix(), "stderr": stderr_path.relative_to(ledger_dir).as_posix()})
                for remaining in jobs[position + 1 :]:
                    write_record({"state": f"not_run_after_{stop_reason}", "job": remaining})
                break
            record = {"state": state, "exit_code": exit_code, "runner_sha256_before": runner_hash_before, "runner_sha256_after": runner_hash_after, "job": job, "stdout": stdout_path.relative_to(ledger_dir).as_posix(), "stderr": stderr_path.relative_to(ledger_dir).as_posix()}
            if args.phase == "pressure":
                record["predecessor_receipts"] = pressure_predecessor_receipts[job["run_id"]]
            if exit_code == 0:
                validation_budget = min(
                    spec["deadlines"]["pair_validation_seconds"],
                    outer_budget - (time.monotonic() - job_started),
                )
                require(validation_budget > 0, "job outer deadline expired before independent artifact validation")

                def validation_deadline(_signum: int, _frame: Any) -> None:
                    raise CampaignError("independent artifact validation exceeded its hard wall-clock deadline")

                previous_alarm_handler = signal.signal(signal.SIGALRM, validation_deadline)
                previous_alarm_timer = signal.getitimer(signal.ITIMER_REAL)
                signal.setitimer(signal.ITIMER_REAL, validation_budget)
                try:
                    validation_started = time.monotonic()
                    if args.phase == "soak":
                        receipt_path = runner_output / "soak-receipt.json"
                        record["soak_directory"] = runner_output.relative_to(ledger_dir).as_posix()
                        record["soak_metrics"] = validate_soak_receipt(receipt_path, runner_output, job, source, spec, args.host_id)
                        require(time.monotonic() - validation_started <= spec["deadlines"]["pair_validation_seconds"], "soak receipt validation exceeded its finite phase deadline")
                        write_record(record)
                        continue
                    pair_dir = runner_output / job["run_id"]
                    record["pair_directory"] = pair_dir.relative_to(ledger_dir).as_posix()
                    process_header, process_rows = read_tsv(pair_dir / "processes.tsv", 2)
                    expected_process_header = ("pair executor allocator exit_code row_validation p99_qualification argv stdout time_report ids_sha256 shutdown_sha256 capacity_family_sha256").split()
                    require(process_header == expected_process_header, "pair process ledger schema changed")
                    require(all(item["exit_code"] == "0" and item["row_validation"] == "valid" for item in process_rows), "pair process ledger contains an invalid process")
                    if job["phase"] == "aa":
                        expected_executors = (job["executor"], job["executor"])
                        expected_allocators = (job["allocator"], job["allocator"])
                    elif job.get("comparison_kind") == "allocator":
                        expected_executors = ("bounded", "bounded")
                        expected_allocators = (job["allocator"], job["baseline_allocator"])
                    else:
                        expected_executors = ("bounded", "tokio")
                        expected_allocators = (job["allocator"], job["allocator"])
                    require(sorted(item["executor"] for item in process_rows) == sorted(expected_executors), "pair executors differ from the preregistered treatment")
                    require(sorted(item["allocator"] for item in process_rows) == sorted(expected_allocators), "pair allocators differ from the preregistered treatment")
                    metrics = [extract_process_metrics(pair_dir, item, job, source, spec, Path(args.campaign_artifacts)) for item in process_rows]
                    require(time.monotonic() - validation_started <= spec["deadlines"]["pair_validation_seconds"], "pair artifact validation exceeded its finite phase deadline")
                    require(time.monotonic() - job_started <= outer_budget, "pair validation exceeded its finite outer job deadline")
                    record["process_metrics"] = metrics
                except (CampaignError, OSError, KeyError, ValueError) as error:
                    record["state"] = "independent_validation_failed"
                    record["validation_error"] = str(error)
                    had_failures = True
                finally:
                    signal.setitimer(signal.ITIMER_REAL, *previous_alarm_timer)
                    signal.signal(signal.SIGALRM, previous_alarm_handler)
                write_record(record)
                continue
            write_record(record)
            if exit_code == 1:
                # A complete but invalid pair is preserved and consumes its
                # preregistered ordinal. No replacements are made.
                had_failures = True
                continue
            if halt:
                stopped = True
                stop_reason = state
        return 2 if stopped else 1 if had_failures else 0
    finally:
        terminate_active()
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        os.umask(old_umask)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source-manifest", help="hash the current source/build/binary inputs without building or timing")
    source.add_argument("--source-root", required=True)
    source.add_argument("--host-id", required=True)
    source.add_argument("--target-triple", required=True)
    source.add_argument("--target-cpu", required=True)
    source.add_argument("--features-sha256", required=True)
    source.add_argument("--build-inputs-sha256", required=True)
    source.add_argument("--allocator-binary", action="append", required=True, metavar="ALLOCATOR=RELATIVE_PATH")
    source.add_argument("--soak-binary", action="append", required=True, metavar="ALLOCATOR=RELATIVE_PATH")
    source.add_argument("--analysis-binary", required=True, metavar="RELATIVE_PATH")
    source.add_argument("--output", required=True)
    for name in ("plan", "validate"):
        command = commands.add_parser(name, help="validate frozen inputs and build/check a deterministic campaign schedule")
        command.add_argument("--spec", required=True)
        command.add_argument("--source-root", required=True)
        if name == "plan":
            command.add_argument("--output", required=True)
    freeze = commands.add_parser("freeze-rates", help="derive exact 70/90 percent rates from six retained capacity pairs per cell")
    freeze.add_argument("--spec", required=True)
    freeze.add_argument("--pilot-manifest", required=True)
    freeze.add_argument("--output", required=True)
    oracle = commands.add_parser("prepare-oracles", help="emit and pin independent no-executor canonical references before timing")
    oracle.add_argument("--spec", required=True)
    oracle.add_argument("--source-root", required=True)
    oracle.add_argument("--host-id", required=True)
    oracle.add_argument("--output-root", required=True)
    analyze = commands.add_parser("analyze", help="validate and analyze one complete host without pooling observations")
    analyze.add_argument("--spec", required=True)
    analyze.add_argument("--plan", required=True)
    analyze.add_argument("--host-id", required=True)
    analyze.add_argument("--output-root", required=True)
    analyze.add_argument("--source-root", required=True)
    analyze.add_argument("--campaign-artifacts", required=True)
    analyze.add_argument("--pair-runner", required=True)
    analyze.add_argument("--output")
    analyze.add_argument("--analysis-script", default=str(Path(__file__).resolve()))
    analyze.add_argument("--stage", choices=("fixed_pre_pressure", "pre_soak", "final"), default="final")
    run = commands.add_parser("run", help="execute one frozen host/stage schedule; no retiming or replacement")
    run.add_argument("--plan", required=True)
    run.add_argument("--spec", required=True)
    run.add_argument("--source-root", required=True)
    run.add_argument("--host-id", required=True)
    run.add_argument("--observed-host-contract", required=True)
    run.add_argument("--phase", choices=("exploration", "confirmation", "pressure", "aa", "soak"), required=True)
    run.add_argument("--pair-runner")
    run.add_argument("--soak-runner")
    run.add_argument("--campaign-artifacts", required=True)
    run.add_argument("--output-root", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "source-manifest":
            manifest = source_manifest(args)
            output = Path(args.output)
            require(not output.exists(), f"refusing to replace source manifest: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_bytes(manifest))
            print(json.dumps({"manifest_sha256": manifest["manifest_sha256"], "source_tree_sha256": manifest["source"]["source_tree_sha256"]}, sort_keys=True))
            return 0
        if args.command == "freeze-rates":
            spec = read_json(Path(args.spec))
            pilot_path = Path(args.pilot_manifest)
            pilot = read_json(pilot_path)
            rates = freeze_rates(spec, pilot, hashlib.sha256(pilot_path.read_bytes()).hexdigest())
            output = Path(args.output)
            require(not output.exists(), f"refusing to replace frozen rates: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_bytes(rates))
            print(json.dumps({"manifest_sha256": rates["manifest_sha256"], "host_id": rates["host_id"], "cell_count": len(rates["rates"]) // 2}, sort_keys=True))
            return 0
        if args.command == "prepare-oracles":
            spec = read_json(Path(args.spec))
            source_root = Path(args.source_root).resolve(strict=True)
            sources = load_source_manifests(spec, Path(args.spec), source_root, args.host_id)
            manifest = prepare_oracles(spec, sources, args)
            print(json.dumps({"manifest_sha256": manifest["manifest_sha256"], "host_id": manifest["host_id"], "oracle_count": len(manifest["oracles"])}, sort_keys=True))
            return 0
        if args.command == "analyze":
            spec = read_json(Path(args.spec))
            plan = read_json(Path(args.plan))
            verify_plan(plan)
            require(digest_object(spec) == plan["spec_sha256"], "analysis spec differs from the frozen plan")
            require(args.host_id in plan["host_ids"], "analysis host is absent from the frozen plan")
            script = Path(args.analysis_script).resolve(strict=True)
            phase_adapter = spec["phase_adapters"]["simultaneous_analysis_sha256"]
            require(is_sha256(phase_adapter) and hashlib.sha256(script.read_bytes()).hexdigest() == phase_adapter, "analysis adapter source hash differs from the preregistration")
            pair_runner = Path(args.pair_runner).resolve(strict=True)
            require(pair_runner.is_file() and os.access(pair_runner, os.X_OK) and sha256_file(pair_runner) == spec["runner_sha256"], "analysis pair-runner hash differs from the preregistration")
            root = Path(args.output_root).resolve(strict=True)
            campaign_dir = root / spec["campaign_id"]
            source_root = Path(args.source_root).resolve(strict=True)
            sources = load_source_manifests(spec, Path(args.spec), source_root, args.host_id)
            require(plan == freeze_plan(spec, sources), "analysis plan schedule differs from the frozen specification and host source pins")
            campaign_artifacts = Path(args.campaign_artifacts).resolve(strict=True)
            source = sources[args.host_id]
            qualification_scope = validate_spec(spec, sources)
            aa_expected = [job for job in plan["jobs"]["aa"] if job["host_id"] == args.host_id]
            aa_path = campaign_dir / "aa" / args.host_id / "controller-ledger.jsonl"
            aa_ledger = read_ledger(aa_path)
            validate_phase_ledger(aa_ledger, aa_expected, "aa", args.host_id)
            revalidate_pair_records(aa_ledger, "aa", aa_path.parent, source, spec, campaign_artifacts)
            aa_result = validate_aa_records(aa_ledger, aa_expected, args.host_id, spec["protocol"]["bootstrap_draws"], spec["protocol"]["bootstrap_seed"])
            confirmation_ledger_path = campaign_dir / "confirmation" / args.host_id / "controller-ledger.jsonl"
            confirmation_ledger = read_ledger(confirmation_ledger_path)
            confirmation_expected = [job for job in plan["jobs"]["confirmation"] if job["host_id"] == args.host_id]
            validate_phase_ledger(confirmation_ledger, confirmation_expected, "confirmation", args.host_id)
            revalidate_pair_records(confirmation_ledger, "confirmation", confirmation_ledger_path.parent, source, spec, campaign_artifacts)
            analysis_artifact = source["analysis_artifact"]
            analysis_binary = source_root / analysis_artifact["path"]
            require(sha256_file(analysis_binary) == analysis_artifact["sha256"], "Rust analyzer binary differs from the frozen host source manifest")
            fixed_analysis = analyze_confirmation_host_gated(
                spec,
                args.host_id,
                confirmation_ledger,
                confirmation_ledger_path.parent,
                analysis_binary,
                analysis_artifact["sha256"],
                "confirmation",
            )
            pressure_analysis = None
            if args.stage != "fixed_pre_pressure":
                pressure_ledger_path = campaign_dir / "pressure" / args.host_id / "controller-ledger.jsonl"
                pressure_ledger = read_ledger(pressure_ledger_path)
                pressure_expected = [job for job in plan["jobs"]["pressure"] if job["host_id"] == args.host_id]
                validate_phase_ledger(pressure_ledger, pressure_expected, "pressure", args.host_id)
                validate_pressure_predecessor_receipts(pressure_ledger, confirmation_ledger, spec)
                revalidate_pair_records(pressure_ledger, "pressure", pressure_ledger_path.parent, source, spec, campaign_artifacts)
                pressure_analysis = analyze_confirmation_host_gated(
                    spec,
                    args.host_id,
                    pressure_ledger,
                    pressure_ledger_path.parent,
                    analysis_binary,
                    analysis_artifact["sha256"],
                    "pressure",
                )
            fixed_eligible = qualification_scope["runtime_readback_supported"] and qualification_scope["execution_binding_complete"]
            for family_analysis in (fixed_analysis, pressure_analysis):
                if family_analysis is None:
                    continue
                eligible = fixed_eligible and (family_analysis["comparison_family"] != "external_pressure" or qualification_scope["pressure_family_ready"])
                family_analysis["qualification_eligible"] = eligible
                if not eligible:
                    family_analysis["passed"] = False
                    family_analysis["qualification_blocker"] = (
                        "external-pressure driver/readbacks and matched-policy receipts are not implemented"
                        if family_analysis["comparison_family"] == "external_pressure" and not qualification_scope["pressure_family_ready"]
                        else "production binary runtime-domain/policy/ceiling readback is not verified"
                    )
            soak_result = None
            if args.stage == "final":
                soak_jobs = [job for job in plan["jobs"]["soak"] if job["host_id"] == args.host_id]
                soak_ledger_path = campaign_dir / "soak" / args.host_id / "controller-ledger.jsonl"
                soak_ledger = read_ledger(soak_ledger_path)
                validate_phase_ledger(soak_ledger, soak_jobs, "soak", args.host_id)
                require(len(soak_ledger) == 1 and isinstance(soak_ledger[0].get("soak_metrics"), dict) and soak_ledger[0]["soak_metrics"].get("passed") is True, "final analysis requires the completed continuous soak receipt")
                require(soak_ledger[0].get("runner_sha256_before") == spec["soak"]["driver_sha256"] == soak_ledger[0].get("runner_sha256_after"), "soak runner hash was not stable across the captured run")
                soak_relative = Path(soak_ledger[0].get("soak_directory", ""))
                require(not soak_relative.is_absolute() and ".." not in soak_relative.parts and within(soak_ledger_path.parent, soak_ledger_path.parent / soak_relative), "soak directory path is unsafe")
                soak_dir = soak_ledger_path.parent / soak_relative
                soak_result = validate_soak_receipt(soak_dir / "soak-receipt.json", soak_dir, soak_jobs[0], source, spec, args.host_id)
                require(soak_result == soak_ledger[0]["soak_metrics"], "stored soak metrics differ from independently revalidated receipt")
            pressure_passed = args.stage == "fixed_pre_pressure" or (pressure_analysis is not None and pressure_analysis["passed"])
            result = {"schema": "allocatbelt.application-campaign-analysis.v1", "stage": args.stage, "campaign_id": spec["campaign_id"], "spec_sha256": digest_object(spec), "plan_sha256": plan["plan_sha256"], "analysis_script_sha256": phase_adapter, "host_id": args.host_id, "aa": aa_result, "confirmation": fixed_analysis, "pressure": pressure_analysis, "soak": soak_result, "passed": aa_result["passed"] and fixed_analysis["passed"] and pressure_passed and (args.stage != "final" or soak_result is not None)}
            default_name = "fixed-pre-pressure.json" if args.stage == "fixed_pre_pressure" else "pre-soak.json" if args.stage == "pre_soak" else "analysis.json"
            output = Path(args.output) if args.output else campaign_dir / "analysis" / args.host_id / default_name
            require(not output.exists() and not output.is_symlink(), f"refusing to replace analysis output: {output}")
            require(sha256_file(pair_runner) == spec["runner_sha256"], "pair runner changed during independent reanalysis")
            require(sha256_file(analysis_binary) == analysis_artifact["sha256"], "Rust analyzer binary changed during independent reanalysis")
            require(hashlib.sha256(script.read_bytes()).hexdigest() == phase_adapter, "analysis adapter changed during independent reanalysis")
            verify_source_manifest(source, source_root)
            old_umask = os.umask(0o077)
            try:
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                output.write_bytes(canonical_bytes(result))
                output.chmod(0o600)
            finally:
                os.umask(old_umask)
            print(json.dumps({"host_id": args.host_id, "passed": result["passed"], "fixed_family_size": fixed_analysis["family_size"], "pressure_family_size": None if pressure_analysis is None else pressure_analysis["family_size"]}, sort_keys=True))
            return 0 if result["passed"] else 1
        if args.command in ("plan", "validate"):
            spec = read_json(Path(args.spec))
            source_root = Path(args.source_root).resolve(strict=True)
            sources = load_source_manifests(spec, Path(args.spec), source_root)
            summary = validate_spec(spec, sources)
            if args.command == "validate":
                print(json.dumps(summary, sort_keys=True))
                return 0
            plan = freeze_plan(spec, sources)
            output = Path(args.output)
            require(not output.exists(), f"refusing to replace campaign plan: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_bytes(plan))
            print(json.dumps({**summary, "plan_sha256": plan["plan_sha256"], "job_counts": {name: len(rows) for name, rows in plan["jobs"].items()}}, sort_keys=True))
            return 0
        plan = read_json(Path(args.plan))
        spec = read_json(Path(args.spec))
        verify_plan(plan)
        sources = load_source_manifests(spec, Path(args.spec), Path(args.source_root).resolve(strict=True), args.host_id)
        require(digest_object(spec) == plan["spec_sha256"] and sources[args.host_id]["manifest_sha256"] == plan["source_manifests"].get(args.host_id), "run inputs differ from frozen plan")
        require(plan == freeze_plan(spec, sources), "run plan schedule differs from the frozen specification and host source pins")
        return run_jobs(plan, spec, sources, args)
    except CampaignError as error:
        print(f"application campaign refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
