#!/usr/bin/env python3
"""Source5 host-evidence budget and bounded path-catalogue primitives.

The legacy schedule audit remains non-ready. The additive v2 budget binds the
original schedule to a producer-derived exact path catalogue and caller-owned
storage reservation before any host owner is launched.
"""

from __future__ import annotations

import hashlib
import heapq
import io
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator


AUDIT_SCHEMA = "allocatbelt.application-source5-host-evidence-budget-plan.v1"
SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v3"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v3"
SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v5"
INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
EXECUTION_SCHEMAS = {
    "allocatbelt.application-source5-campaign-execution.v2",
    "allocatbelt.application-source5-campaign-execution.v3",
    "allocatbelt.application-source5-campaign-execution.v4",
}
PHASES = ("exploration", "aa", "confirmation", "pressure", "soak")
ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
LOADS = (70, 90)
MAX_SOURCE_FILES = 100_000
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SYMLINK_BYTES = 4 * 1024
MAX_PATH_BYTES = 4096
MAX_U64 = (1 << 64) - 1
MAX_EVENT_BYTES = 4 * 1024 * 1024
LEGACY_EVENT_CAP = 100_000
CORE_EVIDENCE_ENTRY_CAP = 6_400_000
DISPATCH_ENTRY_CAP = 800_000
CORE_INDEX_BYTES_CAP = 256 * 1024 * 1024
DISPATCH_INDEX_BYTES_CAP = 256 * 1024 * 1024
CORE_ROLE_BYTES_CAP = 1024 * 1024 * 1024
DISPATCH_ROLE_BYTES_CAP = 1024 * 1024 * 1024
FIXED_COMPONENT_MAP_CAP = 4096
PRESSURE_COMPONENT_MAP_CAP = 16_384
FIXED_TMPDIR_ROOTS = 4
PRESSURE_TMPDIR_ROOTS = 4
OWNER_TMPDIR_INODES = 4096
SOAK_TERMINAL_BYTES_CAP = 32 * 1024 * 1024 * 1024
SOAK_SAMPLE_BYTES_CAP = 96 * 1024 * 1024
PATH_CATALOGUE_SCHEMA_V2 = "allocatbelt.application-source5-host-path-catalogue.v2"
RETENTION_POLICY_SCHEMA_V2 = "allocatbelt.application-source5-between-pair-retention.v2"
RETENTION_POLICY_MODE_V2 = "verified_between_pair_offload_v1"
SUCCESS_EMPTY_TMP_TREE_ROLES = frozenset({"normal_app_output", "opaque_trace"})
ARCHIVE_SIGNATURE_QUOTA_BYTES = 4096
ACK_BUNDLE_ALTERNATIVE_ROLES = frozenset({
    "source5_ack_bundle", "source5_ack_bundle_incoming",
})
TRANSIENT_JOB_EVIDENCE_ROLES = frozenset({
    "source5_transfer_packet", *ACK_BUNDLE_ALTERNATIVE_ROLES,
})
FAILURE_WINDOW_ONLY_ROLES = frozenset({"source5_job_disposition"})
NON_EXPORTABLE_JOB_RECORD_ROLES = frozenset({
    "source5_job_record", "source5_job_disposition",
})
ARCHIVE_LOCAL_METADATA_ROLES = frozenset({
    "source5_checkpoint_request", "source5_transfer_offer",
    "source5_checkpoint", "source5_object_manifest",
    "source5_archive_ack", "source5_archive_signature",
    "source5_stage_map",
})
ALWAYS_LOCAL_EVIDENCE_ROLES = frozenset({
    "directory_node", "source5_phase_ledger", "journal", "evidence_index",
    "evidence_index_data_chunk", "evidence_index_manifest_page",
    "origin_receipt", "host_evidence_budget", "host_evidence_budget_chunk",
    "source5_job_record", "source5_archive_signer_context",
    "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
    "source5_job_row_catalogue",
    *ARCHIVE_LOCAL_METADATA_ROLES,
})
PATH_CATALOGUE_CHUNK_BYTES = 8 * 1024 * 1024
PATH_CATALOGUE_RUN_ROWS = 256
PATH_CATALOGUE_MERGE_FANOUT = 64
PATH_CATALOGUE_ROW_BYTES = 64 * 1024
INDEX_DATA_CHUNK_BYTES = 8 * 1024 * 1024
INDEX_MANIFEST_FANOUT = 128
MAX_CAPTURED_STORE_ROOT_BYTES = 16 * 1024 * 1024
HOST_BUDGET_SCHEMA_V2 = "allocatbelt.application-source5-host-evidence-budget.v2"
STORAGE_RESERVATION_SCHEMA_V1 = "allocatbelt.application-source5-evidence-storage-reservation.v1"


class BudgetPlanError(ValueError):
    """An original Source5 plan or its source-bound budget inputs are malformed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BudgetPlanError(message)


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys,
             f"{label} has an unexpected field set")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise BudgetPlanError(f"{type(value).__name__} is not canonical JSON: {error}") from error


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any, label: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _uint(value: Any, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= (1 << 64) - 1,
             f"{label} is not a u64")
    _require(not positive or value > 0, f"{label} must be positive")
    return value


def _token(value: Any, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", value) is not None,
             f"{label} is not a bounded token")
    return value


def _run_id(value: Any, label: str) -> str:
    _require(type(value) is str and 0 < len(value.encode("utf-8", "strict")) <= 4096 and
             not any(ord(char) < 32 or ord(char) == 127 for char in value),
             f"{label} is not bounded path-safe text")
    return value


def _pin(value: Any, label: str) -> dict[str, str]:
    pin = _exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    path = pin["path"]
    _require(type(path) is str and path.startswith("/") and
             len(path.encode("utf-8", "strict")) <= 4096 and
             ".." not in PurePosixPath(path).parts and
             "\x00" not in path and
             not any(ord(char) < 32 or ord(char) == 127 for char in path),
             f"{label} path is not an absolute original pin")
    _digest(pin["raw_sha256"], f"{label} raw SHA-256")
    _digest(pin["semantic_sha256"], f"{label} semantic SHA-256")
    return pin


def _typed_inventory(source: dict[str, Any], host_id: str) -> tuple[list[dict[str, Any]], set[str], int]:
    source_body = source.get("source")
    _require(type(source_body) is dict, f"SourceV5 {host_id} has no source inventory")
    files = source_body.get("files")
    _require(type(files) is list and 0 < len(files) <= MAX_SOURCE_FILES,
             f"SourceV5 {host_id} typed inventory is outside its finite count bound")
    previous = ""
    paths: set[str] = set()
    directories: set[str] = set()
    total = 0
    for index, item_value in enumerate(files):
        if type(item_value) is not dict:
            raise BudgetPlanError(f"SourceV5 {host_id} source row[{index}] is malformed")
        kind = item_value.get("kind")
        keys = ({"path", "kind", "mode", "sha256", "size"} if kind == "file" else
                {"path", "kind", "mode", "target", "sha256", "size"})
        item = _exact(item_value, keys, f"SourceV5 {host_id} source row[{index}]")
        path = item["path"]
        _require(type(path) is str and path and "\\" not in path and "\x00" not in path,
                 f"SourceV5 {host_id} source path[{index}] is malformed")
        relative = PurePosixPath(path)
        _require(not relative.is_absolute() and ".." not in relative.parts and
                 relative.as_posix() == path and path > previous and path not in paths,
                 f"SourceV5 {host_id} source path[{index}] is duplicate or unordered")
        previous = path
        paths.add(path)
        _digest(item["sha256"], f"SourceV5 {host_id} source hash[{index}]")
        size = _uint(item["size"], f"SourceV5 {host_id} source size[{index}]")
        if kind == "file":
            _require(item["mode"] in ("100644", "100755") and
                     size <= MAX_SOURCE_FILE_BYTES,
                     f"SourceV5 {host_id} regular source row[{index}] exceeds its owner schema")
        else:
            target = item["target"]
            _require(kind == "symlink" and item["mode"] == "120000" and
                     type(target) is str and 0 < len(target.encode("utf-8")) <= MAX_SYMLINK_BYTES and
                     size == len(target.encode("utf-8")),
                     f"SourceV5 {host_id} literal link row[{index}] is outside its owner schema")
        total += size
        for length in range(1, len(relative.parts)):
            directories.add(PurePosixPath(*relative.parts[:length]).as_posix())
    _require(total <= MAX_SOURCE_TOTAL_BYTES,
             f"SourceV5 {host_id} typed source bytes exceed the frozen inventory ceiling")
    return files, directories, total


def _source_artifact_paths(source: dict[str, Any], host_id: str) -> set[str]:
    paths: set[str] = set()
    for field in ("artifacts", "soak_artifacts"):
        values = source.get(field)
        _require(type(values) is dict, f"SourceV5 {host_id} {field} is malformed")
        for label, value in values.items():
            item = _exact(value, {"path", "sha256"},
                          f"SourceV5 {host_id} {field} {label}")
            _digest(item["sha256"], f"SourceV5 {host_id} {field} {label} SHA-256")
            _require(type(item["path"]) is str and item["path"] not in paths,
                     f"SourceV5 {host_id} {field} path is duplicate or malformed")
            paths.add(item["path"])
    analysis = _exact(source.get("analysis_artifact"), {"path", "sha256"},
                      f"SourceV5 {host_id} analysis artifact")
    _digest(analysis["sha256"], f"SourceV5 {host_id} analysis artifact SHA-256")
    paths.add(analysis["path"])
    calibration = _exact(source.get("resource_domain_calibration"), {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, f"SourceV5 {host_id} resource calibration")
    for name in ("binary", "output"):
        item = _exact(calibration[name], {"path", "sha256"},
                      f"SourceV5 {host_id} calibration {name}")
        _digest(item["sha256"], f"SourceV5 {host_id} calibration {name} SHA-256")
        paths.add(item["path"])
    return paths


def _owner_schema_pins(source: dict[str, Any]) -> dict[str, dict[str, Any]]:
    expected = {
        "fixed_pair": "scripts/application-fixed-pair.py",
        "pressure_pair": "scripts/application-pressure-pair.py",
        "source5_controller": "scripts/application-source5-campaign.py",
        "source5_soak": "scripts/application-source5-soak.py",
        "soak_reader": "scripts/application-soak-readback.py",
        "feedback_composer": "scripts/application-feedback-composition.py",
        "feedback_reader": "scripts/application-feedback-readback.py",
        "pressure_reader": "scripts/application-pressure-readback.py",
        "evidence_transport": "scripts/application-source5-evidence-transport-v3.py",
    }
    records = source["source"]["files"]
    result: dict[str, dict[str, Any]] = {}
    for role, path in expected.items():
        matches = [row for row in records
                   if type(row) is dict and row.get("path") == path]
        _require(len(matches) == 1,
                 f"SourceV5 owner schema has no unique typed pin for {path}")
        row = _exact(matches[0], {
            "path", "kind", "mode", "sha256", "size",
        }, f"SourceV5 owner schema {path}")
        _require(row["kind"] == "file" and row["mode"] in ("100644", "100755"),
                 f"SourceV5 owner schema is not a regular typed source file: {path}")
        result[role] = {
            "path": path, "mode": row["mode"], "sha256": row["sha256"],
            "size": row["size"],
        }
    return result


def _job_phase_projection(
    plan: dict[str, Any], host_id: str, expected_hosts: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    jobs = plan.get("jobs")
    _require(type(jobs) is dict and set(jobs) == set(PHASES),
             "PlanV3 jobs do not contain the exact five original phases")
    by_phase: dict[str, list[dict[str, Any]]] = {}
    hashes: dict[str, str] = {}
    run_ids: set[str] = set()
    for phase in PHASES:
        values = jobs[phase]
        _require(type(values) is list,
                 f"PlanV3 {phase} job array is not a list")
        selected: list[dict[str, Any]] = []
        for index, item_value in enumerate(values):
            _require(type(item_value) is dict and item_value.get("phase") == phase,
                     f"PlanV3 {phase} job[{index}] is malformed or has a foreign phase")
            job_host = item_value.get("host_id")
            _require(type(job_host) is str and job_host in expected_hosts,
                     f"PlanV3 {phase} job[{index}] has an unknown host binding")
            if job_host != host_id:
                continue
            run_id = _run_id(item_value.get("run_id"),
                             f"PlanV3 {phase} job[{index}] run ID")
            _require(run_id not in run_ids,
                     f"PlanV3 repeats original run ID {run_id}")
            run_ids.add(run_id)
            selected.append(item_value)
        by_phase[phase] = selected
        hashes[phase] = _sha(_canonical(selected))
    return by_phase, hashes


def _validate_original_predecessors(phases: dict[str, list[dict[str, Any]]]) -> None:
    confirmation = {job["run_id"]: job for job in phases["confirmation"]}
    _require(len(confirmation) == len(phases["confirmation"]),
             "PlanV3 confirmation run IDs are not unique")
    for index, job in enumerate(phases["pressure"]):
        predecessors = job.get("predecessor_run_ids")
        _require(type(predecessors) is list and len(predecessors) == 1 and
                 predecessors[0] in confirmation,
                 f"PlanV3 pressure job[{index}] lost its one original confirmation predecessor")
        predecessor = confirmation[predecessors[0]]
        pressure_pair_kind = job.get("pair_kind")
        _require(type(pressure_pair_kind) is str and
                 pressure_pair_kind.startswith("pressure-"),
                 f"PlanV3 pressure job[{index}] pair kind is not source-derived")
        same_fields = (
            "host_id", "family", "profile", "mode", "load_percent",
            "comparison_kind", "ordinal",
        )
        _require(all(job.get(field) == predecessor.get(field)
                     for field in same_fields) and
                 predecessor.get("phase") == "confirmation" and
                 predecessor.get("pair_kind") == pressure_pair_kind.removeprefix("pressure-"),
                 f"PlanV3 pressure job[{index}] predecessor changes the original contrast/context/ordinal")


def _validate_aa_control_jobs(
    phases: dict[str, list[dict[str, Any]]], control_pairs: dict[str, int],
) -> None:
    seen: dict[str, set[int]] = {control_id: set() for control_id in control_pairs}
    for index, job in enumerate(phases["aa"]):
        control_id = _token(job.get("control_id"),
                            f"PlanV3 A/A job[{index}] control ID")
        _require(control_id in control_pairs and
                 job.get("pairs") == control_pairs[control_id],
                 f"PlanV3 A/A job[{index}] changed an original control or repeat count")
        ordinal = _uint(job.get("ordinal"),
                        f"PlanV3 A/A job[{index}] ordinal", positive=True)
        _require(ordinal <= control_pairs[control_id] and
                 ordinal not in seen[control_id],
                 f"PlanV3 A/A job[{index}] has a duplicate or out-of-range ordinal")
        seen[control_id].add(ordinal)
    for control_id, pairs in control_pairs.items():
        _require(seen[control_id] == set(range(1, pairs + 1)),
                 f"PlanV3 A/A control {control_id} has missing/replaced original repeats")


def build_host_evidence_budget_plan(
    spec_value: object, plan_value: object,
    source_manifest_values: object, execution_manifest_value: object,
    host_id_value: object, *, pins_value: object,
) -> dict[str, Any]:
    """Derive schedule and hard-cap conflicts without claiming a closed budget.

    The result is an analysis artifact only. It never sets an owner-launch,
    execution-ready, component-ready, or qualification-ready flag true.
    """
    spec = spec_value
    plan = plan_value
    execution_manifest = execution_manifest_value
    _require(type(spec) is dict and spec.get("schema") == SPEC_SCHEMA,
             "budget planning requires the original SpecV3")
    _require(type(plan) is dict and plan.get("schema") == PLAN_SCHEMA,
             "budget planning requires the original PlanV3")
    _require(type(execution_manifest) is dict and
             execution_manifest.get("schema") in EXECUTION_SCHEMAS,
             "budget planning requires a prepared Source5 execution manifest")
    host_id = _token(host_id_value, "budget planning host ID")
    hosts = spec.get("hosts")
    _require(type(hosts) is list and len(hosts) == 3 and
             all(type(item) is dict for item in hosts),
             "budget planning requires the original three-host SpecV3")
    host_ids = [_token(item.get("host_id"), "SpecV3 host ID") for item in hosts]
    _require(len(set(host_ids)) == 3 and host_id in host_ids and
             plan.get("host_ids") == host_ids and
             plan.get("campaign_id") == spec.get("campaign_id"),
             "PlanV3 host order/campaign differs from the original SpecV3")
    _token(spec.get("campaign_id"), "SpecV3 campaign ID")
    protocol = spec.get("protocol")
    _require(type(protocol) is dict, "SpecV3 protocol is malformed")
    exploration_pairs = _uint(protocol.get("exploration_pairs"),
                              "SpecV3 exploration pair repeats", positive=True)
    confirmation_pairs = _uint(protocol.get("confirmation_pairs"),
                               "SpecV3 confirmation pair repeats", positive=True)
    _require(exploration_pairs == 6 and confirmation_pairs == 36,
             "budget planning cannot change the original six/36 repeat protocol")
    cells = spec.get("cells")
    _require(type(cells) is list and len(cells) == 15,
             "original qualification plan must preserve all 15 workload/profile cells")
    cell_keys = {
        (item.get("family"), item.get("profile"))
        for item in cells if type(item) is dict
    }
    _require(len(cell_keys) == 15 and len(cell_keys) == len(cells),
             "SpecV3 repeats or malforms an original workload/profile cell")
    aa_controls = spec.get("aa_controls")
    _require(type(aa_controls) is list and bool(aa_controls),
             "original SpecV3 has no explicit A/A control list")
    control_pairs: dict[str, int] = {}
    for index, value in enumerate(aa_controls):
        control = _exact(value, {
            "control_id", "allocator", "family", "profile", "mode",
            "load_percent", "executor", "pairs", "purpose",
        }, f"SpecV3 A/A control[{index}]")
        control_id = _token(control["control_id"],
                            f"SpecV3 A/A control[{index}] ID")
        _require(control_id not in control_pairs,
                 "SpecV3 repeats an original A/A control ID")
        control_pairs[control_id] = _uint(
            control["pairs"], f"SpecV3 A/A {control_id} repeats", positive=True,
        )
        _require(control_pairs[control_id] <= 36,
                 f"SpecV3 A/A {control_id} exceeds the frozen per-control repeat bound")
    aa_total = sum(control_pairs.values())
    rates = spec.get("rates")
    _require(type(rates) is list and bool(rates),
             "final SpecV3 has no frozen open-loop rate matrix")
    host_rates = [row for row in rates
                  if type(row) is dict and row.get("host_id") == host_id]
    load_levels = {row.get("load_percent") for row in host_rates}
    _require(load_levels == set(LOADS) and
             len(host_rates) == len(cells) * len(LOADS),
             "original Source5 host rate matrix is not the frozen three-load design")
    by_context: dict[tuple[str, str], set[int]] = {}
    rate_keys: set[tuple[str, str, str, int]] = set()
    for index, row in enumerate(host_rates):
        family, profile, load = row.get("family"), row.get("profile"), row.get("load_percent")
        _require(type(family) is str and type(profile) is str and
                 type(load) is int,
                 f"SpecV3 rate row[{index}] has malformed context/load fields")
        rate_key = (host_id, family, profile, load)
        _require(rate_key not in rate_keys,
                 f"SpecV3 repeats an original host/context/load rate row[{index}]")
        rate_keys.add(rate_key)
        _require((family, profile) in {
            (cell.get("family"), cell.get("profile")) for cell in cells
        } and load in LOADS,
                 f"SpecV3 rate[{index}] references an unknown original context")
        by_context.setdefault((family, profile), set()).add(load)
    _require(set(by_context) == {
        (cell["family"], cell["profile"]) for cell in cells
    } and all(loads == set(LOADS) for loads in by_context.values()),
             "SpecV3 rate matrix omits or changes an original cell/load lane")

    expected_exploration = len(cells) * exploration_pairs * len(ALLOCATORS)
    expected_confirmation = len(cells) * (len(LOADS) + 1) * confirmation_pairs * 5
    host_schedule: dict[str, dict[str, Any]] = {}
    for planned_host in host_ids:
        phases, phase_hashes = _job_phase_projection(
            plan, planned_host, set(host_ids),
        )
        counts = {phase: len(phases[phase]) for phase in PHASES}
        _require(counts["exploration"] == expected_exploration and
                 counts["aa"] == aa_total and
                 counts["confirmation"] == expected_confirmation and
                 counts["pressure"] == expected_confirmation and
                 counts["soak"] == 1,
                 f"PlanV3 {planned_host} job arrays differ from the full original protocol/A/A controls")
        _validate_aa_control_jobs(phases, control_pairs)
        _validate_original_predecessors(phases)
        host_schedule[planned_host] = {
            "job_counts": counts,
            "phase_job_list_sha256": phase_hashes,
        }
    counts = host_schedule[host_id]["job_counts"]
    phase_hashes = host_schedule[host_id]["phase_job_list_sha256"]

    pins = _exact(pins_value, {
        "spec", "plan", "execution_manifest", "source_manifests",
    }, "original budget pins")
    spec_pin = _pin(pins["spec"], "original SpecV3 pin")
    plan_pin = _pin(pins["plan"], "original PlanV3 pin")
    execution_pin = _pin(pins["execution_manifest"],
                         "original execution-manifest pin")
    execution_schema = execution_manifest["schema"]
    source_pins = _exact(pins["source_manifests"], set(host_ids),
                         "original SourceV5 host manifest pins")
    sources = _exact(source_manifest_values, set(host_ids),
                     "original SourceV5 host manifests")
    spec_semantic = _sha(_canonical(spec))
    plan_body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan_semantic = _sha(_canonical(plan_body))
    _require(plan.get("spec_sha256") == spec_semantic and
             spec_pin["semantic_sha256"] == spec_semantic and
             plan_pin["semantic_sha256"] == plan_semantic and
             plan.get("plan_sha256") == plan_semantic,
             "budget source SpecV3/PlanV3 semantic pins are not mutually bound")
    source_files_by_host: dict[str, list[dict[str, Any]]] = {}
    source_tree_hashes: dict[str, str] = {}
    source_manifest_hashes: dict[str, str] = {}
    owner_pins_by_host: dict[str, dict[str, dict[str, Any]]] = {}
    artifact_paths: set[str] = set()
    for source_host in host_ids:
        manifest = sources[source_host]
        pin = _pin(source_pins[source_host],
                   f"original SourceV5 {source_host} pin")
        _require(type(manifest) is dict and manifest.get("schema") == SOURCE_SCHEMA and
                 manifest.get("manifest_sha256") == pin["semantic_sha256"] and
                 _sha(_canonical({key: value for key, value in manifest.items()
                                  if key != "manifest_sha256"})) == manifest["manifest_sha256"],
                 f"SourceV5 {source_host} manifest does not match its semantic pin")
        _digest(pin["raw_sha256"], f"SourceV5 {source_host} raw pin")
        files, _directories, _total = _typed_inventory(manifest, source_host)
        source_files_by_host[source_host] = files
        source_tree_hashes[source_host] = manifest["source"]["source_tree_sha256"]
        source_manifest_hashes[source_host] = manifest["manifest_sha256"]
        owner_pins_by_host[source_host] = _owner_schema_pins(manifest)
        inventory_sha = _sha(_canonical({
            "schema": INVENTORY_SCHEMA, "entries": files,
        }))
        _require(manifest["source"]["source_tree_sha256"] == inventory_sha,
                 f"SourceV5 {source_host} source-tree digest differs from its exact typed rows")
        artifact_paths.update(_source_artifact_paths(manifest, source_host))
    _require(all(source_files_by_host[host] == source_files_by_host[host_ids[0]]
                 for host in host_ids[1:]) and
             len(set(source_tree_hashes.values())) == 1 and
             all(owner_pins_by_host[host] == owner_pins_by_host[host_ids[0]]
                 for host in host_ids[1:]),
             "three SourceV5 hosts do not share one exact typed source tree")
    spec_source_refs = spec.get("source_manifests")
    _require(type(spec_source_refs) is list and len(spec_source_refs) == len(host_ids),
             "SpecV3 source-manifest references do not cover the original hosts")
    spec_refs: dict[str, dict[str, Any]] = {}
    for index, reference_value in enumerate(spec_source_refs):
        reference = _exact(reference_value, {
            "host_id", "relative_path", "sha256",
        }, f"SpecV3 source-manifest reference[{index}]")
        source_host = _token(reference["host_id"],
                             f"SpecV3 source-manifest host[{index}]")
        _digest(reference["sha256"],
                f"SpecV3 source-manifest semantic SHA[{index}]")
        _require(source_host not in spec_refs,
                 "SpecV3 repeats an original source-manifest host")
        spec_refs[source_host] = reference
    _require(set(spec_refs) == set(host_ids),
             "SpecV3 source-manifest references changed original host membership")
    spec_path = PurePosixPath(spec_pin["path"])
    for source_host in host_ids:
        reference = spec_refs[source_host]
        relative = PurePosixPath(reference["relative_path"])
        _require(not relative.is_absolute() and ".." not in relative.parts and
                 (spec_path.parent / relative).as_posix() ==
                 source_pins[source_host]["path"] and
                 reference["sha256"] == sources[source_host]["manifest_sha256"],
                 f"SpecV3 {source_host} source path/semantic pin differs from its original manifest")
    plan_source_pins = plan.get("source_manifests")
    _require(type(plan_source_pins) is dict and
             plan_source_pins == source_manifest_hashes,
             "PlanV3 SourceV5 semantic map differs from the three original manifests")
    original_inputs = _exact(execution_manifest.get("original_inputs"), {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "Source5 execution-manifest original inputs")
    for name, expected_pin in (("spec", spec_pin), ("plan", plan_pin)):
        reference = _exact(original_inputs[name], {"artifact", "semantic_sha256"},
                           f"Source5 original {name} reference")
        artifact = _exact(reference["artifact"], {"path", "raw_sha256"},
                          f"Source5 original {name} artifact pin")
        _require(artifact == {"path": expected_pin["path"],
                              "raw_sha256": expected_pin["raw_sha256"]} and
                 reference["semantic_sha256"] == expected_pin["semantic_sha256"],
                 f"execution manifest changed the original {name} pin")
    execution_source_pins = _exact(original_inputs["source_manifests"], set(host_ids),
                                    "Source5 execution-manifest source pins")
    for source_host in host_ids:
        reference = _exact(execution_source_pins[source_host], {
            "artifact", "semantic_sha256",
        }, f"Source5 execution-manifest {source_host} source reference")
        artifact = _exact(reference["artifact"], {"path", "raw_sha256"},
                          f"Source5 execution-manifest {source_host} source artifact")
        pinned = source_pins[source_host]
        _require(artifact == {"path": pinned["path"],
                              "raw_sha256": pinned["raw_sha256"]} and
                 reference["semantic_sha256"] == pinned["semantic_sha256"] ==
                 sources[source_host]["manifest_sha256"],
                 f"execution manifest changed the original {source_host} SourceV5 pin")
    _require(execution_manifest.get("campaign_id") == spec["campaign_id"] and
             execution_manifest.get("hosts") == host_ids and
             execution_manifest.get("qualification_eligible") is False,
             "Source5 execution manifest changed its original host/campaign/false-ready identity")
    execution_semantic = _sha(_canonical({
        key: value for key, value in execution_manifest.items()
        if key != "manifest_sha256"
    }))
    _require(execution_manifest.get("manifest_sha256") == execution_semantic ==
             execution_pin["semantic_sha256"],
             "Source5 execution-manifest semantic pin differs from its canonical original value")
    execution_sources = _exact(execution_manifest.get("execution_sources"), set(host_ids),
                               "Source5 execution source snapshots")
    for source_host in host_ids:
        row = _exact(execution_sources[source_host], {
            "source_root", "git_commit", "source_tree_sha256", "build_sha256",
        }, f"Source5 {source_host} execution source snapshot")
        _require(row["source_tree_sha256"] == source_tree_hashes[source_host] and
                 row["git_commit"] == sources[source_host]["source"]["git_commit"] and
                 row["build_sha256"] == _sha(_canonical(sources[source_host]["build"])),
                 f"Source5 {source_host} execution snapshot differs from its manifest")
    files, directories, source_bytes = _typed_inventory(
        sources[host_id], host_id,
    )
    relative_source_paths = {item["path"] for item in files}
    source_catalogue_count = len(relative_source_paths | artifact_paths) + len(directories)

    fixed_jobs = counts["exploration"] + counts["aa"] + counts["confirmation"]
    producer_output_slots_lower_bound = 35 * fixed_jobs + 70 * counts["pressure"]
    lower_bound_index_entries = source_catalogue_count + producer_output_slots_lower_bound
    lower_bound_store_entries = lower_bound_index_entries + 2
    paired_jobs = fixed_jobs + counts["pressure"]
    maximum_callbacks = 1 + 6 + 6 * paired_jobs + 4 * counts["soak"]
    maximum_journal_bytes = min(
        CORE_ROLE_BYTES_CAP, maximum_callbacks * MAX_EVENT_BYTES,
    )
    source_map_entries = len(relative_source_paths) + len(directories)
    fixed_component_map_upper = (
        source_map_entries + FIXED_TMPDIR_ROOTS * OWNER_TMPDIR_INODES + 35
    )
    pressure_component_map_upper = (
        source_map_entries + PRESSURE_TMPDIR_ROOTS * OWNER_TMPDIR_INODES + 70
    )

    blockers = [
        "exact per-job fixed/pressure/Soak path union is not yet generated from every owner declaration",
        "per-path role byte reservations and durable whole-host writable-domain reservation are not yet bound",
        "versioned chunked index and captured-store streaming are not wired; the legacy materialized schemas remain in force",
        "fixed/pressure component maps still use fixed entry caps rather than a budget-pinned exact owner catalogue",
        "budget pin is not yet carried by the execution manifest, origin receipt, index, offline request, and component replay",
    ]
    if lower_bound_store_entries > DISPATCH_ENTRY_CAP:
        blockers.append("producer-slot lower bound already exceeds the dispatcher 800000-entry store/index guard")
    if maximum_journal_bytes > CORE_ROLE_BYTES_CAP:
        blockers.append("per-event ceiling worst case exceeds the current one-GiB full journal role cap")
    if SOAK_TERMINAL_BYTES_CAP > min(CORE_ROLE_BYTES_CAP, DISPATCH_ROLE_BYTES_CAP):
        blockers.append("Soak owner terminal maximum exceeds the current one-GiB global artifact-role cap")
    if source_map_entries > min(FIXED_COMPONENT_MAP_CAP, PRESSURE_COMPONENT_MAP_CAP):
        blockers.append("typed SourceV5 files/directories alone exceed at least one component path-map cap")

    body = {
        "schema": AUDIT_SCHEMA,
        "campaign_id": spec["campaign_id"],
        "host_id": host_id,
        "execution_manifest_schema": execution_schema,
        "original_pins": {
            "spec": spec_pin,
            "plan": plan_pin,
            "execution_manifest": execution_pin,
            "source_manifests": source_pins,
            "source_tree_sha256": source_tree_hashes[host_id],
        },
        "schedule": {
            "job_counts": counts,
            "phase_job_list_sha256": phase_hashes,
            "all_host_job_counts": {
                host: row["job_counts"] for host, row in host_schedule.items()
            },
            "all_host_phase_job_list_sha256": {
                host: row["phase_job_list_sha256"]
                for host, row in host_schedule.items()
            },
            "aa_pair_count_from_spec": aa_total,
            "fixed_job_count": fixed_jobs,
            "pressure_job_count": counts["pressure"],
            "total_job_count": sum(counts.values()),
            "maximum_callback_events": maximum_callbacks,
            "maximum_callback_event_bytes": MAX_EVENT_BYTES,
            "worst_case_journal_bytes": maximum_journal_bytes,
            "plan_component_gate_claim": False,
        },
        "source_closure": {
            "typed_source_records": len(files),
            "typed_source_bytes": source_bytes,
            "unique_source_directories": len(directories),
            "source_and_declared_artifact_catalogue_entries": source_catalogue_count,
        },
        "producer_catalogue": {
            "schema_version": "source5-producer-slot-lower-bound.v1",
            "owner_schema_pins": owner_pins_by_host[host_id],
            "lower_bound_index_entries_before_soak/common_inputs": lower_bound_index_entries,
            "lower_bound_store_entries_before_soak/common_inputs": lower_bound_store_entries,
            "producer_slots_per_fixed_job": 35,
            "producer_slots_per_pressure_job": 70,
            "exact_catalogue_complete": False,
        },
        "component_map_bounds": {
            "source_tree_entries": source_map_entries,
            "fixed_pair_worst_case_entries_before_other_roots": fixed_component_map_upper,
            "pressure_pair_worst_case_entries_before_other_roots": pressure_component_map_upper,
            "fixed_pair_current_cap": FIXED_COMPONENT_MAP_CAP,
            "pressure_pair_current_cap": PRESSURE_COMPONENT_MAP_CAP,
        },
        "current_limits": {
            "legacy_dispatch_events": LEGACY_EVENT_CAP,
            "dispatcher_store_entries": DISPATCH_ENTRY_CAP,
            "core_evidence_entries": CORE_EVIDENCE_ENTRY_CAP,
            "core_index_bytes": CORE_INDEX_BYTES_CAP,
            "dispatcher_index_bytes": DISPATCH_INDEX_BYTES_CAP,
            "core_role_bytes": CORE_ROLE_BYTES_CAP,
            "dispatcher_role_bytes": DISPATCH_ROLE_BYTES_CAP,
            "soak_terminal_owner_bytes": SOAK_TERMINAL_BYTES_CAP,
            "soak_sample_owner_bytes": SOAK_SAMPLE_BYTES_CAP,
        },
        "blockers": blockers,
        "readiness": {
            "budget_complete": False,
            "execution_ready": False,
            "component_gate_ready": False,
            "qualification_eligible": False,
        },
    }
    return {**body, "budget_plan_sha256": _sha(_canonical(body))}


CATALOGUE_ROW_FIELDS = {
    "path", "kind", "role", "host_id", "max_bytes", "max_file_bytes",
    "max_inodes",
    "storage_root", "owner", "phase", "run_id", "member_index", "aggregate_id",
    "aggregate_max_bytes", "origin_pin",
}


def _catalogue_row(value: object, label: str) -> dict[str, Any]:
    row = _exact(value, CATALOGUE_ROW_FIELDS, label)
    path = row["path"]
    _require(type(path) is str and path.startswith("/") and
             len(path.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             ".." not in PurePosixPath(path).parts and "\x00" not in path and
             PurePosixPath(path).as_posix() == path and
             not any(ord(char) < 32 or ord(char) == 127 for char in path),
             f"{label} path is not a bounded normalized absolute path")
    _require(row["kind"] in {"file", "tree"},
             f"{label} has an unsupported evidence node kind")
    _token(row["role"], f"{label} role")
    _require(row["host_id"] is None or
             (type(row["host_id"]) is str and bool(row["host_id"])),
             f"{label} host ID is malformed")
    storage_root = row["storage_root"]
    _require(storage_root is None or
             (type(storage_root) is str and storage_root.startswith("/") and
              len(storage_root.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
              PurePosixPath(storage_root).as_posix() == storage_root and
              ".." not in PurePosixPath(storage_root).parts),
             f"{label} writable root is not normalized absolute path text")
    maximum_bytes = _uint(row["max_bytes"], f"{label} byte reservation")
    maximum_file_bytes = _uint(
        row["max_file_bytes"], f"{label} per-file byte reservation",
    )
    _require(maximum_file_bytes <= maximum_bytes and
             (row["kind"] != "file" or maximum_file_bytes == maximum_bytes),
             f"{label} per-file reservation differs from its owner limit")
    inodes = _uint(row["max_inodes"], f"{label} inode reservation")
    _require((row["kind"] == "file" and inodes == 1) or
             (row["kind"] == "tree" and inodes > 0),
             f"{label} inode reservation differs from its node kind")
    _token(row["owner"], f"{label} owner")
    _require(row["phase"] is None or row["phase"] in PHASES,
             f"{label} phase is outside the original phase enum")
    _require(row["run_id"] is None or
             _run_id(row["run_id"], f"{label} run ID") == row["run_id"],
             f"{label} run ID is malformed")
    member_index = row["member_index"]
    _require(member_index is None or
             (_uint(member_index, f"{label} member index") <= 1),
             f"{label} member index exceeds the original pair size")
    aggregate_id = row["aggregate_id"]
    _require(aggregate_id is None or
             _token(aggregate_id, f"{label} aggregate ID") == aggregate_id,
             f"{label} aggregate ID is malformed")
    maximum = row["aggregate_max_bytes"]
    _require((aggregate_id is None and maximum is None) or
             (aggregate_id is not None and
              _uint(maximum, f"{label} aggregate byte reservation", positive=True) > 0),
             f"{label} aggregate reservation is incomplete")
    if row["origin_pin"] is not None:
        pin = _exact(row["origin_pin"], {"raw_sha256", "semantic_sha256"},
                     f"{label} original input pin")
        _digest(pin["raw_sha256"], f"{label} original raw digest")
        _require(pin["semantic_sha256"] is None or
                 (type(pin["semantic_sha256"]) is str and
                  re.fullmatch(r"[0-9a-f]{64}", pin["semantic_sha256"]) is not None),
                 f"{label} original semantic digest is malformed")
    return row


def _write_exclusive(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            _require(written > 0, "Source5 catalogue writer made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _iter_catalogue_run(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            _require(bool(line) and line.endswith(b"\n") and b"\r" not in line,
                     f"Source5 catalogue sort run framing differs at {line_number}")
            try:
                value = json.loads(line.decode("ascii"))
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise BudgetPlanError(
                    f"Source5 catalogue sort row {line_number} is malformed",
                ) from error
            row = _catalogue_row(value, f"Source5 catalogue sort row {line_number}")
            _require(line == _canonical(row),
                     f"Source5 catalogue sort row {line_number} is not canonical")
            yield row


def _write_catalogue_run(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    """Write one canonical sorted run while keeping output memory bounded."""
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    total = 0
    try:
        for row in rows:
            raw = _canonical(row)
            _require(len(raw) <= PATH_CATALOGUE_ROW_BYTES,
                     "Source5 catalogue sort row exceeds its finite width")
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                _require(written > 0, "Source5 catalogue run writer made no progress")
                total += written
                view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return total


def _index_row_bound(row: dict[str, Any], *, path_length: int | None = None) -> int:
    path = row["path"] if path_length is None else "/" + ("x" * (path_length - 1))
    probe = {
        "role": row["role"], "host_id": row["host_id"],
        "origin_path": path, "local_path": path,
        "raw_sha256": "f" * 64,
        "semantic_sha256": "f" * 64,
        "byte_count": row["max_file_bytes"],
        "maximum_bytes": (1 << 64) - 1,
    }
    return len(_canonical(probe))


def _is_success_empty_tmp_tree(row: dict[str, Any]) -> bool:
    return row["kind"] == "tree" and row["role"] in SUCCESS_EMPTY_TMP_TREE_ROLES


def _archive_request_entry_bound(row: dict[str, Any]) -> bytes:
    """Return one maximum-width checkpoint-request entry for an exact path row."""
    return _canonical({
        "origin_path": row["path"], "role": row["role"],
        "byte_count": row["max_file_bytes"], "raw_sha256": "f" * 64,
        "semantic_sha256": "f" * 64,
    })


def _archive_pin_bound(path: str | None = None) -> dict[str, str]:
    return {
        "path": "/" + ("x" * (MAX_PATH_BYTES - 1) if path is None else path),
        "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
    }


def _archive_empty_tmp_proof_bounds() -> list[dict[str, Any]]:
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    return [{
        "role": "x" * 96, "path": maximum_path,
        "owner_receipt_pin": {
            "path": maximum_path, "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
        },
        "member_ordinal": ordinal, "device": MAX_U64,
        "inode": MAX_U64, "mode": MAX_U64,
        "mount": {
            "mount_id": MAX_U64, "major_minor": "9" * 41,
            "mount_root": maximum_path, "mount_point": maximum_path,
            "filesystem_type": "x" * MAX_PATH_BYTES,
            "mount_source": "x" * MAX_PATH_BYTES, "device": MAX_U64,
        },
        "bytes_used": 0, "file_count": 0, "directory_count": 0,
        "bytes_limit": MAX_U64, "inode_limit": MAX_U64,
    } for ordinal in range(2)]


def _archive_fixed_request_value(
    phase: str, receipt_roles: Iterable[str],
) -> dict[str, Any]:
    """Maximum accepted request envelope outside its exact object entries."""
    maximum_pin = _archive_pin_bound()
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    context = {
        "schema": "allocatbelt.application-source5-evidence-archive-context.v1",
        "campaign_id": "x" * 96, "host_id": "x" * 96,
        "phase": phase, "job_index": MAX_U64,
        "source_manifest_pin": maximum_pin,
        "execution_manifest_pin": maximum_pin,
        "plan_pin": maximum_pin, "resource_budget_pin": maximum_pin,
        "predecessor_ack_pin": maximum_pin,
        "authorized_signer_fingerprint": "F" * 64,
    }
    receipt_pins = {
        role: {
            "path": maximum_path, "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
        }
        for role in sorted(set(receipt_roles))
    }
    return {
        "schema": "allocatbelt.application-source5-evidence-checkpoint-request.v1",
        "context": context,
        "job_record_pin": {"path": maximum_path, "raw_sha256": "f" * 64},
        "authorization": {
            "authorization_id": "x" * 128,
            "authorization_head": "f" * 64, "terminal_head": "f" * 64,
            "component_sha256": "f" * 64,
            "process_metrics_sha256": "f" * 64,
        },
        "predecessor_ack_pin": maximum_pin,
        "owner_receipt_pins": receipt_pins,
        "empty_tmp_proofs": _archive_empty_tmp_proof_bounds(),
        "entries": [], "request_sha256": "f" * 64,
    }


def _archive_fixed_request_bound(
    phase: str, receipt_roles: Iterable[str],
) -> int:
    return len(_canonical(_archive_fixed_request_value(phase, receipt_roles)))


def _archive_manifest_entry_bound(row: dict[str, Any]) -> bytes:
    """Bound one final manifest row including the external archive object pin."""
    origin_sha = _sha(row["path"].encode("utf-8"))
    object_id = f"{origin_sha[:2]}/{origin_sha}-{'f' * 64}.bin"
    return _canonical({
        "origin_path": row["path"], "role": row["role"],
        "object_id": object_id, "byte_count": row["max_file_bytes"],
        "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
        "object_pin": {
            "path": "/" + ("x" * (MAX_PATH_BYTES - 1)),
            "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
            "byte_count": row["max_file_bytes"],
        },
    })


def _archive_stage_entry_bound(row: dict[str, Any]) -> bytes:
    origin_sha = _sha(row["path"].encode("utf-8"))
    object_id = f"{origin_sha[:2]}/{origin_sha}-{'f' * 64}.bin"
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    return _canonical({
        "origin_path": row["path"], "object_id": object_id,
        "remote_object_pin": {
            "path": maximum_path, "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
            "byte_count": row["max_file_bytes"],
        },
        "local_staged_file": {
            "path": row["path"], "kind": "symlink",
            "device": MAX_U64, "inode": MAX_U64,
            "mode": MAX_U64, "byte_count": row["max_file_bytes"],
            "raw_sha256": "f" * 64,
        },
    })


def _archive_tar_size(member_sizes: Iterable[int]) -> int:
    content = 0
    for size in member_sizes:
        content += _archive_tar_member_size(size)
    return ((content + 1024 + 10239) // 10240) * 10240


def _archive_tar_member_size(size: int) -> int:
    _uint(size, "Source5 archive transfer member size")
    content = 512 + ((size + 511) // 512) * 512
    if size > (1 << 33) - 1:
        body_length = len(f"size={size}\n".encode("ascii"))
        record_length = body_length + 2
        while True:
            next_length = body_length + len(str(record_length)) + 1
            if next_length == record_length:
                break
            record_length = next_length
        content += 512 + ((record_length + 511) // 512) * 512
    return content


def _archive_ack_bundle_bounds(
    phase: str, run_id: str, receipt_roles: Iterable[str], entry_count: int,
    checkpoint_entry_bytes: int, manifest_entry_bytes: int,
) -> dict[str, int]:
    """Bound each canonical response member and the four-file PAX envelope."""
    maximum_pin = _archive_pin_bound()
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    request_pin = maximum_pin
    checkpoint = {
        "schema": "allocatbelt.application-source5-evidence-job-checkpoint.v1",
        "request_pin": request_pin,
        "context": {
            "schema": "allocatbelt.application-source5-evidence-archive-context.v1",
            "campaign_id": "x" * 96, "host_id": "x" * 96,
            "phase": phase, "job_index": MAX_U64,
            "source_manifest_pin": maximum_pin,
            "execution_manifest_pin": maximum_pin,
            "plan_pin": maximum_pin, "resource_budget_pin": maximum_pin,
            "predecessor_ack_pin": maximum_pin,
            "authorized_signer_fingerprint": "F" * 64,
        },
        "job_record_pin": {"path": maximum_path, "raw_sha256": "f" * 64},
        "authorization": {
            "authorization_id": "x" * 128,
            "authorization_head": "f" * 64, "terminal_head": "f" * 64,
            "component_sha256": "f" * 64,
            "process_metrics_sha256": "f" * 64,
        },
        "predecessor_ack_pin": maximum_pin,
        "owner_receipt_pins": _archive_fixed_request_value(
            phase, receipt_roles,
        )["owner_receipt_pins"],
        "empty_tmp_proofs": _archive_empty_tmp_proof_bounds(),
        "object_manifest_pin": maximum_pin,
        "entries": [], "checkpoint_sha256": "f" * 64,
    }
    manifest = {
        "schema": "allocatbelt.application-source5-evidence-object-manifest.v1",
        "campaign_id": "x" * 96, "host_id": "x" * 96,
        "phase": phase, "job_index": MAX_U64, "job_ordinal": MAX_U64,
        "job_sha256": "f" * 64, "run_id": run_id,
        "job_record_raw_sha256": "f" * 64,
        "predecessor_ack_pin": maximum_pin,
        "objects": [], "object_count": entry_count,
        "payload_bytes": MAX_U64, "manifest_sha256": "f" * 64,
    }
    ack = {
        "schema": "allocatbelt.application-source5-evidence-durable-ack.v1",
        "checkpoint_pin": maximum_pin, "object_manifest_pin": maximum_pin,
        "predecessor_ack_pin": maximum_pin,
        "signer_fingerprint": "F" * 64,
        "durable_commit": {
            "commit_id": "f" * 64,
            "archive_source5_directory": {
                "path": maximum_path, "device": MAX_U64,
                "inode": MAX_U64, "mode": MAX_U64,
            },
            "checkpoint_pin": maximum_pin,
            "object_manifest_pin": maximum_pin,
            "object_reopen_sha256": "f" * 64,
            "object_count": MAX_U64, "payload_bytes": MAX_U64,
            "job_record_validation": {
                "path": maximum_path, "origin_path": maximum_path,
                "raw_sha256": "f" * 64,
                "semantic_sha256": "f" * 64,
                "byte_count": MAX_U64,
            },
        },
        "ack_sha256": "f" * 64,
    }
    checkpoint_bytes = (len(_canonical(checkpoint)) + checkpoint_entry_bytes +
                        max(0, entry_count - 1))
    manifest_bytes = (len(_canonical(manifest)) + manifest_entry_bytes +
                      max(0, entry_count - 1))
    ack_bytes = len(_canonical(ack))
    signature_bytes = ARCHIVE_SIGNATURE_QUOTA_BYTES
    return {
        "checkpoint_bytes": checkpoint_bytes,
        "object_manifest_bytes": manifest_bytes,
        "archive_ack_bytes": ack_bytes,
        "signature_bytes": signature_bytes,
        "ack_bundle_bytes": _archive_tar_size((
            checkpoint_bytes, manifest_bytes, ack_bytes, signature_bytes,
        )),
    }


def _archive_job_stats_add(
    groups: dict[tuple[str, str], dict[str, Any]], row: dict[str, Any],
) -> None:
    if row["role"] in NON_EXPORTABLE_JOB_RECORD_ROLES:
        if row["role"] == "source5_job_record":
            _require(row["kind"] == "file" and
                     row["path"].endswith(".json") and
                     not row["path"].endswith(".disposition.json") and
                     row["phase"] is not None and row["run_id"] is not None,
                     "Source5 local job-record row lacks its exact original job path")
            key = (row["phase"], row["run_id"])
            stats = groups.setdefault(key, {
                "phase": row["phase"], "file_count": 0,
                "request_entry_bytes": 0, "manifest_entry_bytes": 0,
                "stage_entry_bytes": 0, "packet_members_tar_bytes": 0,
                "validation_record_count": 0,
                "validation_record_tar_bytes": 0,
                "receipt_roles": set(),
            })
            stats["validation_record_count"] += 1
            stats["validation_record_bytes"] = row["max_file_bytes"]
            stats["validation_record_tar_bytes"] += _archive_tar_member_size(
                row["max_file_bytes"],
            )
        return
    if (row["phase"] is None or row["run_id"] is None or
            row["kind"] != "file" or
            row["role"] in ALWAYS_LOCAL_EVIDENCE_ROLES or
            row["role"] in TRANSIENT_JOB_EVIDENCE_ROLES or
            row["role"] in ARCHIVE_LOCAL_METADATA_ROLES):
        return
    stats = groups.setdefault((row["phase"], row["run_id"]), {
        "phase": row["phase"], "file_count": 0,
        "request_entry_bytes": 0, "manifest_entry_bytes": 0,
        "stage_entry_bytes": 0, "packet_members_tar_bytes": 0,
        "validation_record_count": 0, "validation_record_tar_bytes": 0,
        "validation_record_bytes": 0,
        "receipt_roles": set(),
    })
    stats["file_count"] += 1
    stats["request_entry_bytes"] += len(_archive_request_entry_bound(row))
    stats["manifest_entry_bytes"] += len(_archive_manifest_entry_bound(row))
    stats["stage_entry_bytes"] += len(_archive_stage_entry_bound(row))
    stats["packet_members_tar_bytes"] += _archive_tar_member_size(
        row["max_file_bytes"],
    )
    if "receipt" in row["role"].lower():
        _require(row["role"] not in stats["receipt_roles"],
                 "Source5 job has duplicate owner receipt roles")
        stats["receipt_roles"].add(row["role"])


def _archive_caps_from_stats(
    groups: dict[tuple[str, str], dict[str, Any]],
) -> dict[tuple[str, str], dict[str, int]]:
    result: dict[tuple[str, str], dict[str, int]] = {}
    for group, stats in groups.items():
        _require(stats["validation_record_count"] <= 1,
                 f"Source5 {group} has duplicate always-local validation records")
        request_bytes = (_archive_fixed_request_bound(
            stats["phase"], stats["receipt_roles"],
        ) + stats["request_entry_bytes"] +
            max(0, stats["file_count"] - 1))
        # The source-pinned PAX encoder adds a 512-byte header and 512-byte
        # block padding per member, a size extension for files beyond USTAR,
        # and its fixed trailer. Use exact path/role row widths plus the exact
        # raw owner byte ceilings for this original job.
        packet_content = (_archive_tar_member_size(request_bytes) +
                          stats["packet_members_tar_bytes"] +
                          stats["validation_record_tar_bytes"])
        packet_size = ((packet_content + 1024 + 10239) // 10240) * 10240
        metadata_caps = _archive_ack_bundle_bounds(
            stats["phase"], group[1], stats["receipt_roles"],
            stats["file_count"],
            stats["request_entry_bytes"], stats["manifest_entry_bytes"],
        )
        stage_map_bytes = (
            stats["stage_entry_bytes"] + max(0, stats["file_count"] - 1) +
            len(_canonical({
            "schema": "allocatbelt.application-source5-evidence-stage-map.v1",
            "checkpoint_pin": _archive_pin_bound(),
            "object_manifest_pin": _archive_pin_bound(),
            "rows": [], "stage_map_sha256": "f" * 64,
        })))
        maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
        offer_body = {
            "schema": "allocatbelt.application-source5-archive-transfer-offer.v1",
            "checkpoint_request_pin": _archive_pin_bound(),
            "transfer_packet_pin": {
                "path": maximum_path, "raw_sha256": "f" * 64,
                "byte_count": packet_size,
            },
            "acknowledgement_receiver": {
                "path": maximum_path,
                "maximum_bytes": metadata_caps["ack_bundle_bytes"],
            },
            "offer_sha256": "f" * 64,
        }
        offer_bytes = len(_canonical(offer_body))
        result[group] = {
            "checkpoint_request_bytes": request_bytes,
            "transfer_packet_bytes": packet_size,
            "validation_record_bytes": stats["validation_record_bytes"],
            **metadata_caps,
            "stage_map_bytes": stage_map_bytes,
            "transfer_offer_bytes": offer_bytes,
        }
    return result


def project_archive_job_caps(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    """Derive each original job's request/packet/ACK caps from exact rows."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        _archive_job_stats_add(groups, row)
    return _archive_caps_from_stats(groups)


def _retention_projection(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Derive host-local peak and full-index bounds under one sealed job window.

    Every named regular-file role remains in the all-original-job index. A
    successful owner proves its TMP tree empty; if any owner fails, execution
    stops and only that one original phase/run window may retain descendants.
    """
    roots: set[str] = set()
    base_bytes: dict[str, int] = {}
    base_inodes: dict[str, int] = {}
    group_bytes: dict[tuple[str, str], dict[str, int]] = {}
    group_inodes: dict[tuple[str, str], dict[str, int]] = {}
    tmp_tree_entries: dict[tuple[str, str], int] = {}
    tmp_tree_data_bytes: dict[tuple[str, str], int] = {}
    tmp_tree_payload_bytes: dict[tuple[str, str], int] = {}
    window_index_entries: dict[tuple[str, str], int] = {}
    window_index_data_bytes: dict[tuple[str, str], int] = {}
    archive_job_stats: dict[tuple[str, str], dict[str, Any]] = {}
    archive_role_rows: dict[tuple[str, str], dict[str, int]] = {}
    local_job_record_rows: dict[tuple[str, str], int] = {}
    persistent_archive_metadata_bytes = 0
    persistent_archive_metadata_inodes = 0
    persistent_local_job_record_count = 0
    persistent_archive_metadata_root_bytes: dict[str, int] = {}
    persistent_archive_metadata_root_inodes: dict[str, int] = {}
    persistent_archive_metadata_by_role: dict[str, int] = {}
    maximum_job_record_bytes = 0
    failure_suffix_bytes_by_phase: dict[str, dict[str, int]] = {}
    failure_suffix_inodes_by_phase: dict[str, dict[str, int]] = {}
    failure_job_bytes_by_phase: dict[str, int] = {}
    ack_bundle_window_rows: dict[tuple[str, str], tuple[int, int, str]] = {}
    files = 0
    file_index_data_bytes = 0
    non_tmp_tree_entries = 0
    non_tmp_tree_data_bytes = 0
    for row in rows:
        root = row["storage_root"]
        failure_suffix = (
            row["role"] in FAILURE_WINDOW_ONLY_ROLES and
            row["phase"] is not None and row["run_id"] is None
        )
        group = ((row["phase"], row["run_id"])
                 if row["phase"] is not None and row["run_id"] is not None and
                 row["role"] not in ALWAYS_LOCAL_EVIDENCE_ROLES
                 else None)
        if root is not None:
            roots.add(root)
            if failure_suffix:
                failure_suffix_bytes_by_phase.setdefault(row["phase"], {})[root] = (
                    failure_suffix_bytes_by_phase.setdefault(row["phase"], {}).get(root, 0) +
                    row["max_bytes"]
                )
                failure_suffix_inodes_by_phase.setdefault(row["phase"], {})[root] = (
                    failure_suffix_inodes_by_phase.setdefault(row["phase"], {}).get(root, 0) +
                    row["max_inodes"]
                )
            elif group is None and row["role"] not in FAILURE_WINDOW_ONLY_ROLES:
                base_bytes[root] = base_bytes.get(root, 0) + row["max_bytes"]
                base_inodes[root] = base_inodes.get(root, 0) + row["max_inodes"]
            elif group is not None and row["role"] in ACK_BUNDLE_ALTERNATIVE_ROLES:
                prior = ack_bundle_window_rows.get(group)
                _require(prior is None or
                         (prior[2] == root and prior[0] == row["max_bytes"] and
                          prior[1] == row["max_inodes"]),
                         f"Source5 {group} ACK upload alternatives disagree")
                ack_bundle_window_rows[group] = (
                    row["max_bytes"], row["max_inodes"], root,
                )
            elif group is not None:
                byte_rows = group_bytes.setdefault(group, {})
                inode_rows = group_inodes.setdefault(group, {})
                byte_rows[root] = byte_rows.get(root, 0) + row["max_bytes"]
                inode_rows[root] = inode_rows.get(root, 0) + row["max_inodes"]
        if row["role"] in ARCHIVE_LOCAL_METADATA_ROLES:
            persistent_archive_metadata_bytes += row["max_bytes"]
            persistent_archive_metadata_inodes += row["max_inodes"]
            persistent_archive_metadata_by_role[row["role"]] = (
                persistent_archive_metadata_by_role.get(row["role"], 0) +
                row["max_bytes"]
            )
            if root is not None:
                persistent_archive_metadata_root_bytes[root] = (
                    persistent_archive_metadata_root_bytes.get(root, 0) +
                    row["max_bytes"]
                )
                persistent_archive_metadata_root_inodes[root] = (
                    persistent_archive_metadata_root_inodes.get(root, 0) +
                    row["max_inodes"]
                )
        if row["role"] == "source5_job_record":
            _require(row["kind"] == "file" and
                     row["path"].endswith(".json") and
                     not row["path"].endswith(".disposition.json"),
                     "Source5 always-local job-record role is not an exact JSON record")
            persistent_local_job_record_count += 1
            maximum_job_record_bytes = max(
                maximum_job_record_bytes, row["max_file_bytes"],
            )
        if (row["role"] in ARCHIVE_LOCAL_METADATA_ROLES |
                TRANSIENT_JOB_EVIDENCE_ROLES | {"source5_job_record"}):
            _require(row["phase"] is not None and row["run_id"] is not None,
                     "Source5 archive transport path lacks its original job identity")
            key = (row["phase"], row["run_id"])
            paths = archive_role_rows.setdefault(key, {})
            _require(row["role"] not in paths,
                     f"Source5 archive transport role is duplicated for {key}")
            paths[row["role"]] = row["max_bytes"]
        if row["role"] == "source5_job_record":
            _require(row["phase"] is not None and row["run_id"] is not None,
                     "Source5 local job record lacks its original phase/run binding")
            key = (row["phase"], row["run_id"])
            local_job_record_rows[key] = local_job_record_rows.get(key, 0) + 1
        if row["kind"] == "file":
            is_transient = row["role"] in TRANSIENT_JOB_EVIDENCE_ROLES
            is_success_indexed = row["role"] not in (
                TRANSIENT_JOB_EVIDENCE_ROLES | FAILURE_WINDOW_ONLY_ROLES
            )
            if is_success_indexed:
                files += 1
                file_index_data_bytes += _index_row_bound(row)
            if group is not None and is_success_indexed:
                window_index_entries[group] = window_index_entries.get(group, 0) + 1
                window_index_data_bytes[group] = (
                    window_index_data_bytes.get(group, 0) + _index_row_bound(row)
                )
            if row["role"] in FAILURE_WINDOW_ONLY_ROLES and row["run_id"] is not None:
                failure_job_bytes_by_phase[row["phase"]] = max(
                    failure_job_bytes_by_phase.get(row["phase"], 0),
                    row["max_bytes"],
                )
            _archive_job_stats_add(archive_job_stats, row)
            continue
        if _is_success_empty_tmp_tree(row):
            _require(group is not None,
                     "Source5 success-empty TMP tree lacks its original phase/run window")
            children = row["max_inodes"] - 1
            tmp_tree_entries[group] = tmp_tree_entries.get(group, 0) + children
            tmp_tree_data_bytes[group] = (
                tmp_tree_data_bytes.get(group, 0) +
                children * _index_row_bound(row, path_length=MAX_PATH_BYTES)
            )
            tmp_tree_payload_bytes[group] = (
                tmp_tree_payload_bytes.get(group, 0) + row["max_bytes"]
            )
            window_index_entries[group] = window_index_entries.get(group, 0) + children
            window_index_data_bytes[group] = (
                window_index_data_bytes.get(group, 0) +
                children * _index_row_bound(row, path_length=MAX_PATH_BYTES)
            )
        else:
            children = row["max_inodes"] - 1
            non_tmp_tree_entries += children
            non_tmp_tree_data_bytes += (
                children * _index_row_bound(row, path_length=MAX_PATH_BYTES)
            )
            if group is not None:
                window_index_entries[group] = window_index_entries.get(group, 0) + children
                window_index_data_bytes[group] = (
                    window_index_data_bytes.get(group, 0) +
                    children * _index_row_bound(row, path_length=MAX_PATH_BYTES)
                )
    live_bytes: dict[str, int] = {}
    live_inodes: dict[str, int] = {}
    window_bytes: dict[str, int] = {}
    window_inodes: dict[str, int] = {}
    for group in list(group_bytes):
        suffix_bytes = failure_suffix_bytes_by_phase.get(group[0], {})
        suffix_inodes = failure_suffix_inodes_by_phase.get(group[0], {})
        for root, amount in suffix_bytes.items():
            group_bytes[group][root] = group_bytes[group].get(root, 0) + amount
        for root, amount in suffix_inodes.items():
            group_inodes[group][root] = group_inodes[group].get(root, 0) + amount
    for group, (amount, inodes, root) in ack_bundle_window_rows.items():
        byte_rows = group_bytes.setdefault(group, {})
        inode_rows = group_inodes.setdefault(group, {})
        byte_rows[root] = byte_rows.get(root, 0) + amount
        inode_rows[root] = inode_rows.get(root, 0) + inodes
    for root in roots:
        byte_peaks = [(values.get(root, 0), group)
                      for group, values in group_bytes.items()]
        inode_peaks = [(values.get(root, 0), group)
                       for group, values in group_inodes.items()]
        peak_bytes, _ = max(byte_peaks, default=(0, None))
        peak_inodes, _ = max(inode_peaks, default=(0, None))
        window_bytes[root] = peak_bytes
        window_inodes[root] = peak_inodes
        live_bytes[root] = base_bytes.get(root, 0) + peak_bytes
        live_inodes[root] = base_inodes.get(root, 0) + peak_inodes
    failure_window_group = max(
        tmp_tree_payload_bytes,
        key=lambda group: tmp_tree_payload_bytes[group],
        default=None,
    )
    failure_entries = max(tmp_tree_entries.values(), default=0)
    failure_data_bytes = max(tmp_tree_data_bytes.values(), default=0)
    failure_payload_bytes = (0 if failure_window_group is None else
                             tmp_tree_payload_bytes[failure_window_group])
    failure_disposition_bytes = max(
        (failure_job_bytes_by_phase.get(phase, 0) + sum(suffix.values())
         for phase, suffix in failure_suffix_bytes_by_phase.items()),
        default=max(failure_job_bytes_by_phase.values(), default=0),
    )
    archive_caps = _archive_caps_from_stats(archive_job_stats)
    _require(bool(archive_caps),
             "Source5 exact path catalogue has no original per-job archive closure")
    expected_archive_roles = {
        "source5_checkpoint_request": "checkpoint_request_bytes",
        "source5_job_record": "validation_record_bytes",
        "source5_transfer_offer": "transfer_offer_bytes",
        "source5_transfer_packet": "transfer_packet_bytes",
        "source5_ack_bundle": "ack_bundle_bytes",
        "source5_ack_bundle_incoming": "ack_bundle_bytes",
        "source5_checkpoint": "checkpoint_bytes",
        "source5_object_manifest": "object_manifest_bytes",
        "source5_archive_ack": "archive_ack_bytes",
        "source5_archive_signature": "signature_bytes",
        "source5_stage_map": "stage_map_bytes",
    }
    if archive_role_rows:
        _require(set(archive_role_rows) == set(archive_caps),
                 "Source5 transport roles do not close over every original job group")
        _require(set(local_job_record_rows) == set(archive_caps) and
                 all(count == 1 for count in local_job_record_rows.values()),
                 "Source5 original job records are not one-per-job local/indexed rows")
        for key, cap in archive_caps.items():
            observed = archive_role_rows[key]
            _require(set(observed) == set(expected_archive_roles) and
                     all(observed[role] == cap[field]
                         for role, field in expected_archive_roles.items()),
                     f"Source5 {key} transport path caps differ from its exact owner closure")
    maximum_archive_caps = {
        name: max(value[name] for value in archive_caps.values())
        for name in (
            "checkpoint_request_bytes", "transfer_packet_bytes",
            "validation_record_bytes",
            "checkpoint_bytes", "object_manifest_bytes", "archive_ack_bytes",
            "signature_bytes", "ack_bundle_bytes", "stage_map_bytes",
            "transfer_offer_bytes",
        )
    }
    maximum_window_total_bytes = max(
        (sum(amounts.values()) for amounts in group_bytes.values()), default=0,
    )
    maximum_window_total_inodes = max(
        (sum(amounts.values()) for amounts in group_inodes.values()), default=0,
    )
    maximum_window_index_entries = max(window_index_entries.values(), default=0)
    maximum_window_index_data_bytes = max(
        window_index_data_bytes.values(), default=0,
    )
    maximum_transfer_packet_bytes = maximum_archive_caps["transfer_packet_bytes"]
    return {
        "schema": RETENTION_POLICY_SCHEMA_V2,
        "mode": RETENTION_POLICY_MODE_V2,
        "success_empty_tree_roles": sorted(SUCCESS_EMPTY_TMP_TREE_ROLES),
        "always_local_roles": sorted(ALWAYS_LOCAL_EVIDENCE_ROLES),
        "max_live_job_windows": 1,
        "max_retained_failure_windows": 1,
        "stop_before_next_authorization_on": [
            "failed_owner", "missing_or_invalid_durable_ack",
            "nonempty_success_tmp", "unknown_owner_state",
        ],
        "reclaim_after": "detached_signature_verified_durable_ack",
        "archive_io_lane": "outside_timed_application_and_pressure_lanes",
        "job_group_count": len(group_bytes),
        "persistent_root_byte_bounds": {
            root: base_bytes.get(root, 0) for root in sorted(roots)
        },
        "persistent_root_inode_bounds": {
            root: base_inodes.get(root, 0) for root in sorted(roots)
        },
        "persistent_archive_metadata_root_byte_bounds": dict(sorted(
            persistent_archive_metadata_root_bytes.items(),
        )),
        "persistent_archive_metadata_root_inode_bounds": dict(sorted(
            persistent_archive_metadata_root_inodes.items(),
        )),
        "persistent_archive_metadata_bytes": persistent_archive_metadata_bytes,
        "persistent_archive_metadata_inodes": persistent_archive_metadata_inodes,
        "persistent_local_job_record_count": persistent_local_job_record_count,
        "maximum_job_record_bytes": maximum_job_record_bytes,
        "persistent_archive_metadata_byte_bounds_by_role": dict(sorted(
            persistent_archive_metadata_by_role.items(),
        )),
        "maximum_window_root_byte_bounds": dict(sorted(window_bytes.items())),
        "maximum_window_root_inode_bounds": dict(sorted(window_inodes.items())),
        "maximum_live_root_byte_bounds": dict(sorted(live_bytes.items())),
        "maximum_live_root_inode_bounds": dict(sorted(live_inodes.items())),
        "maximum_window_total_bytes": maximum_window_total_bytes,
        "maximum_window_total_inodes": maximum_window_total_inodes,
        "maximum_window_index_entries": maximum_window_index_entries,
        "maximum_window_index_data_bytes": maximum_window_index_data_bytes,
        "maximum_checkpoint_request_bytes": maximum_archive_caps[
            "checkpoint_request_bytes"],
        "maximum_validation_record_bytes": maximum_archive_caps[
            "validation_record_bytes"],
        "maximum_checkpoint_bytes": maximum_archive_caps["checkpoint_bytes"],
        "maximum_object_manifest_bytes": maximum_archive_caps[
            "object_manifest_bytes"],
        "maximum_archive_ack_bytes": maximum_archive_caps["archive_ack_bytes"],
        "maximum_signature_bytes": maximum_archive_caps["signature_bytes"],
        "maximum_ack_bundle_bytes": maximum_archive_caps["ack_bundle_bytes"],
        "maximum_stage_map_bytes": maximum_archive_caps["stage_map_bytes"],
        "maximum_transfer_offer_bytes": maximum_archive_caps[
            "transfer_offer_bytes"],
        "archive_metadata_job_group_count": len(archive_caps),
        "maximum_transfer_packet_bytes": maximum_transfer_packet_bytes,
        "maximum_transfer_packet_inodes": 1,
        "maximum_failure_window_tmp_payload_bytes": failure_payload_bytes,
        "maximum_failure_window_disposition_bytes": failure_disposition_bytes,
        "maximum_failure_window_tmp_index_entries": failure_entries,
        "maximum_failure_window_tmp_index_data_bytes": failure_data_bytes,
        "maximum_full_index_entries": files + non_tmp_tree_entries + failure_entries,
        "maximum_full_index_data_bytes": (
            file_index_data_bytes + non_tmp_tree_data_bytes + failure_data_bytes
        ),
    }


def _index_manifest_tree_bound(data_chunk_count: int) -> tuple[int, int]:
    """Return page count/bytes for the v3 bounded-fanout index manifest tree."""
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    descriptor = {
        "kind": "manifest_page", "path": maximum_path,
        "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
        "byte_count": (1 << 64) - 1,
        "entry_count": (1 << 64) - 1,
        "first_path": maximum_path, "last_path": maximum_path,
        "level": (1 << 64) - 1,
    }
    descriptor_bytes = len(_canonical(descriptor))
    page_header = {
        "schema": "allocatbelt.application-source5-journal-evidence-index-page.v1",
        "level": (1 << 64) - 1, "entry_count": (1 << 64) - 1,
        "entries": [], "page_sha256": "f" * 64,
    }
    page_header_bytes = len(_canonical(page_header))
    page_count = 0
    metadata_bytes = 0
    children = data_chunk_count
    while children > INDEX_MANIFEST_FANOUT:
        pages = (children + INDEX_MANIFEST_FANOUT - 1) // INDEX_MANIFEST_FANOUT
        metadata_bytes += children * descriptor_bytes + pages * page_header_bytes
        page_count += pages
        children = pages
    root = {
        "schema": "allocatbelt.application-source5-journal-evidence-index.v3",
        "campaign_id": "x" * 96, "host_id": "x" * 96,
        "source_root": maximum_path, "input_root": maximum_path,
        "output_root": maximum_path,
        "host_evidence_budget": {
            "path": maximum_path, "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
        },
        "entry_count": (1 << 64) - 1,
        "chunk_count": data_chunk_count,
        "manifest_page_count": page_count,
        "manifest_pages": [descriptor] * min(children, INDEX_MANIFEST_FANOUT),
        "index_sha256": "f" * 64,
    }
    root_bytes = len(_canonical(root))
    return page_count, metadata_bytes + root_bytes


def _captured_store_root_bound(metadata_chunk_count: int) -> int:
    """Bound the current v2 metadata-descriptor array before any object copy."""
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    pin = {
        "path": maximum_path, "raw_sha256": "f" * 64,
        "semantic_sha256": "f" * 64,
    }
    descriptor = {
        "path": maximum_path, "raw_sha256": "f" * 64,
        "semantic_sha256": "f" * 64,
        "byte_count": MAX_U64, "entry_count": MAX_U64,
        "first_path": maximum_path, "last_path": maximum_path,
    }
    body = {
        "schema": "allocatbelt.application-source5-captured-evidence.v2",
        "campaign_id": "x" * 96, "host_id": "x" * 96,
        "host_evidence_budget": pin, "evidence_index": pin,
        "origin_receipt": pin, "entry_count": MAX_U64,
        "payload_bytes": MAX_U64, "metadata_bytes": MAX_U64,
        "metadata_chunks": [], "object_directory": maximum_path,
    }
    empty_root = len(_canonical({**body, "store_sha256": "f" * 64}))
    descriptor_bytes = len(_canonical(descriptor))
    return empty_root + metadata_chunk_count * (descriptor_bytes + 1)


def write_path_catalogue_chunks(
    records: Iterable[object], output_directory_value: object,
    *, scratch_directory_value: object | None = None,
) -> dict[str, Any]:
    """Externally sort an exact path catalogue with bounded resident memory."""
    output_directory = Path(output_directory_value)
    _require(output_directory.is_absolute() and
             output_directory.resolve(strict=True) == output_directory and
             output_directory.is_dir() and not output_directory.is_symlink(),
             "Source5 path catalogue output must be an existing canonical directory")
    _require(not any(output_directory.iterdir()),
             "Source5 path catalogue output directory must start empty")
    scratch_directory = (output_directory if scratch_directory_value is None else
                         Path(scratch_directory_value))
    _require(scratch_directory.is_absolute() and
             scratch_directory.resolve(strict=True) == scratch_directory and
             scratch_directory.is_dir() and not scratch_directory.is_symlink(),
             "Source5 catalogue sort scratch must be an existing canonical directory")
    temp_root = Path(tempfile.mkdtemp(prefix=".catalogue-sort-",
                                      dir=scratch_directory))
    os.chmod(temp_root, 0o700)
    runs: list[Path] = []
    chunk_descriptors: list[dict[str, Any]] = []
    batch: list[dict[str, Any]] = []
    role_allowances: dict[str, int] = {}
    grouped_allowances: dict[str, tuple[int, int, str | None]] = {}
    ungrouped_allowances = 0
    maximum_inodes = 0
    root_byte_bounds: dict[str, int] = {}
    root_inode_bounds: dict[str, int] = {}
    maximum_index_entries = 0
    maximum_index_bytes = 0
    file_count = 0
    tree_count = 0
    unique_count = 0
    input_row_bytes = 0
    input_row_count = 0

    def flush_run() -> None:
        if not batch:
            return
        ordered = sorted(batch, key=lambda row: row["path"])
        run_path = temp_root / f"run-{len(runs):08d}.jsonl"
        _write_catalogue_run(run_path, ordered)
        runs.append(run_path)
        batch.clear()

    def merge_group_to_run(group: list[Path], target: Path) -> None:
        merged_group = heapq.merge(
            *(_iter_catalogue_run(path) for path in group),
            key=lambda row: row["path"],
        )
        _write_catalogue_run(target, merged_group)
        for path in group:
            path.unlink()

    def flush_chunk(
        buffer: bytearray, first_path: str, last_path: str,
        row_count: int, chunk_index: int,
    ) -> dict[str, Any]:
        raw = bytes(buffer)
        name = f"path-catalogue-{chunk_index:08d}.jsonl"
        final_path = output_directory / name
        _write_exclusive(final_path, raw)
        return {
            "path": str(final_path),
            "raw_sha256": _sha(raw), "semantic_sha256": _sha(raw),
            "byte_count": len(raw), "row_count": row_count,
            "first_path": first_path, "last_path": last_path,
        }

    try:
        for index, value in enumerate(records):
            row = _catalogue_row(
                value, f"Source5 path catalogue input[{index}]",
            )
            input_line = _canonical(row)
            _require(len(input_line) <= PATH_CATALOGUE_ROW_BYTES,
                     "Source5 path catalogue input row exceeds its finite width")
            input_row_bytes += len(input_line)
            input_row_count += 1
            batch.append(row)
            if len(batch) >= PATH_CATALOGUE_RUN_ROWS:
                flush_run()
        flush_run()
        _require(bool(runs), "Source5 exact path catalogue is empty")
        merge_pass = 0
        while len(runs) > PATH_CATALOGUE_MERGE_FANOUT:
            next_runs: list[Path] = []
            for group_index, offset in enumerate(
                    range(0, len(runs), PATH_CATALOGUE_MERGE_FANOUT)):
                group = runs[offset:offset + PATH_CATALOGUE_MERGE_FANOUT]
                target = temp_root / (
                    f"merge-{merge_pass:04d}-{group_index:08d}.jsonl"
                )
                merge_group_to_run(group, target)
                next_runs.append(target)
            runs = next_runs
            merge_pass += 1
        merged = heapq.merge(*(_iter_catalogue_run(path) for path in runs),
                             key=lambda row: row["path"])
        buffer = bytearray()
        first_path = ""
        last_path = ""
        chunk_rows = 0
        pending: dict[str, Any] | None = None

        def emit(row: dict[str, Any]) -> None:
            nonlocal buffer, first_path, last_path, chunk_rows
            nonlocal maximum_inodes, maximum_index_entries, maximum_index_bytes
            nonlocal file_count, tree_count, unique_count, ungrouped_allowances
            nonlocal root_byte_bounds, root_inode_bounds
            line = _canonical(row)
            _require(len(line) <= PATH_CATALOGUE_ROW_BYTES,
                     "Source5 path catalogue row exceeds its finite width")
            if buffer and len(buffer) + len(line) > PATH_CATALOGUE_CHUNK_BYTES:
                chunk_descriptors.append(flush_chunk(
                    buffer, first_path, last_path, chunk_rows,
                    len(chunk_descriptors),
                ))
                buffer = bytearray()
                first_path = ""
                chunk_rows = 0
            if not buffer:
                first_path = row["path"]
            buffer.extend(line)
            last_path = row["path"]
            chunk_rows += 1
            unique_count += 1
            maximum_inodes += row["max_inodes"]
            if row["storage_root"] is not None:
                root_byte_bounds.setdefault(row["storage_root"], 0)
                root_inode_bounds.setdefault(row["storage_root"], 0)
            if (row["storage_root"] is not None and row["role"] not in
                    (TRANSIENT_JOB_EVIDENCE_ROLES | FAILURE_WINDOW_ONLY_ROLES)):
                root_byte_bounds[row["storage_root"]] = (
                    root_byte_bounds.get(row["storage_root"], 0) + row["max_bytes"]
                )
                root_inode_bounds[row["storage_root"]] = (
                    root_inode_bounds.get(row["storage_root"], 0) + row["max_inodes"]
                )
            role_allowances[row["role"]] = (
                role_allowances.get(row["role"], 0) + row["max_bytes"]
            )
            if row["role"] in TRANSIENT_JOB_EVIDENCE_ROLES:
                # Transfer packets are live only until the ACK and are never
                # part of the final origin index or archived raw payload.
                pass
            elif row["role"] in FAILURE_WINDOW_ONLY_ROLES:
                # The first failed owner stops the horizon; only one failure
                # disposition window can be retained.
                pass
            elif _is_success_empty_tmp_tree(row):
                # Successful owner receipts prove zero retained bytes. The
                # conservative nonempty allowance is one failure window.
                pass
            elif row["aggregate_id"] is None:
                ungrouped_allowances += row["max_bytes"]
            else:
                aggregate_id = row["aggregate_id"]
                maximum = row["aggregate_max_bytes"]
                previous = grouped_allowances.get(aggregate_id)
                _require(previous is None or
                         previous[0] == maximum and
                         previous[2] == row["storage_root"],
                         f"Source5 aggregate {aggregate_id} spans roots or ceilings")
                total = row["max_bytes"] + (0 if previous is None else previous[1])
                grouped_allowances[aggregate_id] = (
                    maximum, total, row["storage_root"],
                )
            if row["kind"] == "file":
                file_count += 1
                if row["role"] not in (
                    TRANSIENT_JOB_EVIDENCE_ROLES | FAILURE_WINDOW_ONLY_ROLES
                ):
                    maximum_index_entries += 1
                    maximum_index_bytes += _index_row_bound(row)
            else:
                tree_count += 1
                maximum_index_entries += row["max_inodes"] - 1
                maximum_index_bytes += (row["max_inodes"] - 1) * _index_row_bound(
                    row, path_length=MAX_PATH_BYTES,
                )

        for row in merged:
            if pending is not None and row["path"] == pending["path"]:
                _require(row == pending,
                         f"Source5 path aliases incompatible declarations: {row['path']}")
                continue
            if pending is not None:
                emit(pending)
            pending = row
        if pending is not None:
            emit(pending)
        if buffer:
            chunk_descriptors.append(flush_chunk(
                buffer, first_path, last_path, chunk_rows,
                len(chunk_descriptors),
            ))

        directory_fd = os.open(output_directory, os.O_RDONLY |
                               getattr(os, "O_DIRECTORY", 0) |
                               getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        shutil.rmtree(temp_root, ignore_errors=True)
        for candidate in output_directory.iterdir():
            if candidate.is_file() and candidate.name.startswith("path-catalogue-"):
                candidate.unlink()
        raise
    shutil.rmtree(temp_root)

    def catalogue_rows_from_chunks() -> Iterator[dict[str, Any]]:
        for chunk_index, chunk in enumerate(chunk_descriptors):
            raw = _read_stable_catalogue_chunk(chunk, chunk_index)
            with io.BytesIO(raw) as stream:
                for row_index, line in enumerate(stream):
                    try:
                        value = json.loads(line.decode("ascii"))
                    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                        raise BudgetPlanError(
                            f"Source5 generated catalogue chunk[{chunk_index}] row[{row_index}] is malformed",
                        ) from error
                    row = _catalogue_row(value, "generated Source5 path catalogue row")
                    _require(line == _canonical(row),
                             "generated Source5 path catalogue row is not canonical")
                    yield row

    retention = _retention_projection(catalogue_rows_from_chunks())
    grouped_bytes = sum(min(total, maximum)
                        for maximum, total, _root in grouped_allowances.values())
    maximum_payload_bytes = (
        grouped_bytes + ungrouped_allowances +
        retention["maximum_failure_window_tmp_payload_bytes"] +
        retention["maximum_failure_window_disposition_bytes"]
    )
    role_byte_bounds = dict(role_allowances)
    maximum_index_entries = retention["maximum_full_index_entries"]
    maximum_index_data_bytes = retention["maximum_full_index_data_bytes"]
    maximum_index_bytes = maximum_index_data_bytes
    maximum_index_chunks = max(
        1, (maximum_index_bytes +
            (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES) - 1) //
            (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES),
    )
    maximum_index_manifest_pages, maximum_index_manifest_bytes = \
        _index_manifest_tree_bound(maximum_index_chunks)
    maximum_index_bytes += maximum_index_manifest_bytes
    _require(0 < maximum_index_entries <= MAX_U64 and
             0 < maximum_index_bytes <= (1 << 64) - 1,
             "Source5 full-horizon index rows/bytes exceed their u64 transport ceiling")
    index_sort_runs = max(
        1, (maximum_index_entries + PATH_CATALOGUE_RUN_ROWS - 1) //
        PATH_CATALOGUE_RUN_ROWS,
    )
    index_sort_merge_overlap = (
        (index_sort_runs + PATH_CATALOGUE_MERGE_FANOUT - 1) //
        PATH_CATALOGUE_MERGE_FANOUT
        if index_sort_runs > PATH_CATALOGUE_MERGE_FANOUT else 0
    )
    for root_name in root_byte_bounds:
        grouped_source = sum(total for _maximum, total, aggregate_root
                             in grouped_allowances.values()
                             if aggregate_root == root_name)
        grouped_limit = sum(min(total, maximum)
                            for maximum, total, aggregate_root
                            in grouped_allowances.values()
                            if aggregate_root == root_name)
        root_byte_bounds[root_name] += grouped_limit - grouped_source
    body = {
        "schema": PATH_CATALOGUE_SCHEMA_V2,
        "entry_count": unique_count,
        "file_count": file_count,
        "tree_count": tree_count,
        "chunk_bytes": PATH_CATALOGUE_CHUNK_BYTES,
        "sort_input_row_count": input_row_count,
        "sort_input_byte_count": input_row_bytes,
        "chunks": chunk_descriptors,
        "maximum_payload_bytes": maximum_payload_bytes,
        "maximum_inode_count": maximum_inodes,
        "maximum_live_inode_count": sum(
            retention["maximum_live_root_inode_bounds"].values()
        ),
        "root_byte_bounds": dict(sorted(root_byte_bounds.items())),
        "root_inode_bounds": dict(sorted(root_inode_bounds.items())),
        "retention_policy": retention,
        "maximum_index_entries": maximum_index_entries,
        "maximum_index_bytes": maximum_index_bytes,
        "maximum_index_chunks": maximum_index_chunks,
        "maximum_index_manifest_pages": maximum_index_manifest_pages,
        "maximum_index_manifest_bytes": maximum_index_manifest_bytes,
        "maximum_index_sort_scratch_bytes": maximum_index_data_bytes * 3,
        "maximum_index_sort_scratch_inodes":
            2 + index_sort_runs + index_sort_merge_overlap,
        # Caller spool plus old and new merge runs overlap at a pass boundary.
        "maximum_sort_scratch_bytes": input_row_bytes * 3,
        "maximum_sort_scratch_inodes": (
            2 + max(1, (input_row_count + PATH_CATALOGUE_RUN_ROWS - 1) //
                    PATH_CATALOGUE_RUN_ROWS) +
            ((max(1, (input_row_count + PATH_CATALOGUE_RUN_ROWS - 1) //
                  PATH_CATALOGUE_RUN_ROWS) + PATH_CATALOGUE_MERGE_FANOUT - 1) //
             PATH_CATALOGUE_MERGE_FANOUT
             if input_row_count > PATH_CATALOGUE_RUN_ROWS *
             PATH_CATALOGUE_MERGE_FANOUT else 0)
        ),
        "role_byte_bounds": dict(sorted(role_byte_bounds.items())),
    }
    return {**body, "semantic_sha256": _sha(_canonical(body))}


def validate_path_catalogue_manifest(value: object) -> dict[str, Any]:
    """Reject incomplete, unordered, or digest-edited catalogue manifests."""
    manifest = _exact(value, {
        "schema", "entry_count", "file_count", "tree_count", "chunk_bytes",
        "sort_input_row_count", "sort_input_byte_count",
        "chunks", "maximum_payload_bytes", "maximum_inode_count",
        "maximum_live_inode_count", "retention_policy",
        "root_byte_bounds", "root_inode_bounds",
        "maximum_index_entries", "maximum_index_bytes", "maximum_index_chunks",
        "maximum_index_manifest_pages", "maximum_index_manifest_bytes",
        "maximum_sort_scratch_bytes", "maximum_sort_scratch_inodes",
        "maximum_index_sort_scratch_bytes", "maximum_index_sort_scratch_inodes",
        "role_byte_bounds", "semantic_sha256",
    }, "Source5 path catalogue manifest v2")
    _require(manifest["schema"] == PATH_CATALOGUE_SCHEMA_V2 and
             manifest["chunk_bytes"] == PATH_CATALOGUE_CHUNK_BYTES and
             type(manifest["chunks"]) is list and bool(manifest["chunks"]),
             "Source5 path catalogue schema or chunk list differs")
    entry_count = _uint(manifest["entry_count"],
                        "Source5 path catalogue entry count", positive=True)
    file_count = _uint(manifest["file_count"],
                       "Source5 path catalogue file count")
    tree_count = _uint(manifest["tree_count"],
                       "Source5 path catalogue tree count")
    _require(file_count + tree_count == entry_count,
             "Source5 path catalogue node counts do not close")
    observed_entries = 0
    previous_last = ""
    previous_chunk = ""
    for index, value in enumerate(manifest["chunks"]):
        chunk = _exact(value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"Source5 path catalogue chunk[{index}]")
        _pin({"path": chunk["path"], "raw_sha256": chunk["raw_sha256"],
              "semantic_sha256": chunk["semantic_sha256"]},
             f"Source5 path catalogue chunk[{index}] pin")
        size = _uint(chunk["byte_count"],
                     f"Source5 path catalogue chunk[{index}] byte count",
                     positive=True)
        count = _uint(chunk["row_count"],
                      f"Source5 path catalogue chunk[{index}] row count",
                      positive=True)
        _require(size <= PATH_CATALOGUE_CHUNK_BYTES and
                 chunk["path"] > previous_chunk and
                 type(chunk["first_path"]) is str and
                 type(chunk["last_path"]) is str and
                 chunk["first_path"] > previous_last and
                 chunk["first_path"] <= chunk["last_path"],
                 f"Source5 path catalogue chunk[{index}] order or size differs")
        previous_chunk = chunk["path"]
        previous_last = chunk["last_path"]
        observed_entries += count
    _require(observed_entries == entry_count,
             "Source5 path catalogue chunk counts do not close")
    for field in ("maximum_payload_bytes", "maximum_inode_count",
                  "maximum_live_inode_count",
                  "maximum_index_entries", "maximum_index_bytes",
                  "maximum_index_chunks", "maximum_index_manifest_bytes",
                  "maximum_sort_scratch_bytes", "maximum_sort_scratch_inodes",
                  "maximum_index_sort_scratch_bytes",
                  "maximum_index_sort_scratch_inodes"):
        _uint(manifest[field], f"Source5 path catalogue {field}", positive=True)
    sort_rows = _uint(manifest["sort_input_row_count"],
                      "Source5 path catalogue sort input rows", positive=True)
    sort_bytes = _uint(manifest["sort_input_byte_count"],
                       "Source5 path catalogue sort input bytes", positive=True)
    _uint(manifest["maximum_index_manifest_pages"],
          "Source5 path catalogue manifest-page count")
    for field in ("root_byte_bounds", "root_inode_bounds"):
        roots = manifest[field]
        _require(type(roots) is dict and bool(roots),
                 f"Source5 path catalogue {field} is empty")
        for name, amount in roots.items():
            _require(type(name) is str and name.startswith("/") and
                     PurePosixPath(name).as_posix() == name and
                     ".." not in PurePosixPath(name).parts,
                     f"Source5 path catalogue {field} root is malformed")
            _uint(amount, f"Source5 path catalogue {name} {field}")
    _require(set(manifest["root_byte_bounds"]) ==
             set(manifest["root_inode_bounds"]),
             "Source5 path catalogue root byte/inode domain sets differ")
    retention = _exact(manifest["retention_policy"], {
        "schema", "mode", "success_empty_tree_roles", "always_local_roles",
        "max_live_job_windows", "max_retained_failure_windows",
        "stop_before_next_authorization_on", "reclaim_after",
        "archive_io_lane", "job_group_count", "persistent_root_byte_bounds",
        "persistent_root_inode_bounds",
        "persistent_archive_metadata_root_byte_bounds",
        "persistent_archive_metadata_root_inode_bounds",
        "persistent_archive_metadata_bytes", "persistent_archive_metadata_inodes",
        "persistent_local_job_record_count",
        "persistent_archive_metadata_byte_bounds_by_role",
        "maximum_window_root_byte_bounds",
        "maximum_window_root_inode_bounds", "maximum_live_root_byte_bounds",
        "maximum_live_root_inode_bounds", "maximum_failure_window_tmp_payload_bytes",
        "maximum_failure_window_disposition_bytes",
        "maximum_window_total_bytes", "maximum_window_total_inodes",
        "maximum_window_index_entries", "maximum_window_index_data_bytes",
        "maximum_checkpoint_request_bytes", "maximum_checkpoint_bytes",
        "maximum_validation_record_bytes",
        "maximum_job_record_bytes",
        "maximum_object_manifest_bytes", "maximum_archive_ack_bytes",
        "maximum_signature_bytes", "maximum_ack_bundle_bytes",
        "maximum_stage_map_bytes", "maximum_transfer_offer_bytes",
        "archive_metadata_job_group_count",
        "maximum_transfer_packet_bytes", "maximum_transfer_packet_inodes",
        "maximum_failure_window_tmp_index_entries",
        "maximum_failure_window_tmp_index_data_bytes",
        "maximum_full_index_entries", "maximum_full_index_data_bytes",
    }, "Source5 path catalogue between-pair retention policy")
    _require(retention["schema"] == RETENTION_POLICY_SCHEMA_V2 and
             retention["mode"] == RETENTION_POLICY_MODE_V2 and
             retention["success_empty_tree_roles"] ==
                sorted(SUCCESS_EMPTY_TMP_TREE_ROLES) and
             retention["always_local_roles"] ==
                sorted(ALWAYS_LOCAL_EVIDENCE_ROLES) and
             retention["max_live_job_windows"] == 1 and
             retention["max_retained_failure_windows"] == 1 and
             retention["stop_before_next_authorization_on"] == [
                 "failed_owner", "missing_or_invalid_durable_ack",
                 "nonempty_success_tmp", "unknown_owner_state",
             ] and
             retention["reclaim_after"] ==
                "detached_signature_verified_durable_ack" and
             retention["archive_io_lane"] ==
                "outside_timed_application_and_pressure_lanes",
             "Source5 path catalogue retention policy weakens the owner stop/reclaim contract")
    _uint(retention["job_group_count"],
          "Source5 retention original phase/run group count")
    for field in (
        "persistent_root_byte_bounds", "persistent_root_inode_bounds",
        "maximum_window_root_byte_bounds", "maximum_window_root_inode_bounds",
        "maximum_live_root_byte_bounds", "maximum_live_root_inode_bounds",
    ):
        bounds = retention[field]
        _require(type(bounds) is dict and
                 set(bounds) == set(manifest["root_byte_bounds"]),
                 f"Source5 retention {field} roots do not close over catalogue roots")
        for root, amount in bounds.items():
            _uint(amount, f"Source5 retention {field} {root}")
    for field in (
        "persistent_archive_metadata_root_byte_bounds",
        "persistent_archive_metadata_root_inode_bounds",
    ):
        bounds = retention[field]
        _require(type(bounds) is dict and set(bounds) <=
                 set(manifest["root_byte_bounds"]),
                 f"Source5 retention {field} escapes catalogue storage roots")
        for root, amount in bounds.items():
            _uint(amount, f"Source5 retention {field} {root}")
    metadata_by_role = retention["persistent_archive_metadata_byte_bounds_by_role"]
    _require(type(metadata_by_role) is dict and
             set(metadata_by_role) <= ARCHIVE_LOCAL_METADATA_ROLES,
             "Source5 persistent archive metadata roles are malformed")
    for role, amount in metadata_by_role.items():
        _uint(amount, f"Source5 persistent archive metadata {role}")
    for field in (
        "maximum_failure_window_tmp_payload_bytes",
        "maximum_failure_window_disposition_bytes",
        "maximum_failure_window_tmp_index_entries",
        "maximum_failure_window_tmp_index_data_bytes",
        "maximum_full_index_entries", "maximum_full_index_data_bytes",
        "maximum_window_total_bytes", "maximum_window_total_inodes",
        "maximum_window_index_entries", "maximum_window_index_data_bytes",
        "maximum_checkpoint_request_bytes", "maximum_checkpoint_bytes",
        "maximum_validation_record_bytes",
        "maximum_object_manifest_bytes", "maximum_archive_ack_bytes",
        "maximum_signature_bytes", "maximum_ack_bundle_bytes",
        "maximum_stage_map_bytes", "maximum_transfer_offer_bytes",
        "archive_metadata_job_group_count",
        "persistent_archive_metadata_bytes", "persistent_archive_metadata_inodes",
        "persistent_local_job_record_count",
        "maximum_job_record_bytes",
        "maximum_transfer_packet_bytes", "maximum_transfer_packet_inodes",
    ):
        _uint(retention[field], f"Source5 retention {field}")
    _require(retention["maximum_signature_bytes"] ==
             ARCHIVE_SIGNATURE_QUOTA_BYTES,
             "Source5 retention signature quota differs from the pinned campaign policy")
    expected_runs = max(
        1, (sort_rows + PATH_CATALOGUE_RUN_ROWS - 1) // PATH_CATALOGUE_RUN_ROWS,
    )
    expected_merge_overlap = (
        (expected_runs + PATH_CATALOGUE_MERGE_FANOUT - 1) //
        PATH_CATALOGUE_MERGE_FANOUT
        if expected_runs > PATH_CATALOGUE_MERGE_FANOUT else 0
    )
    _require(manifest["maximum_sort_scratch_bytes"] == sort_bytes * 3 and
             manifest["maximum_sort_scratch_inodes"] ==
                2 + expected_runs + expected_merge_overlap,
             "Source5 path catalogue sort scratch differs from its source spool bounds")
    index_sort_runs = max(
        1, (manifest["maximum_index_entries"] + PATH_CATALOGUE_RUN_ROWS - 1) //
        PATH_CATALOGUE_RUN_ROWS,
    )
    index_sort_merge_overlap = (
        (index_sort_runs + PATH_CATALOGUE_MERGE_FANOUT - 1) //
        PATH_CATALOGUE_MERGE_FANOUT
        if index_sort_runs > PATH_CATALOGUE_MERGE_FANOUT else 0
    )
    maximum_index_data_bytes = (
        manifest["maximum_index_bytes"] -
        manifest["maximum_index_manifest_bytes"]
    )
    _require(manifest["maximum_index_sort_scratch_bytes"] ==
                maximum_index_data_bytes * 3 and
             manifest["maximum_index_sort_scratch_inodes"] ==
                2 + index_sort_runs + index_sort_merge_overlap,
             "Source5 index sort scratch differs from its source-pinned index ceiling")
    role_bounds = manifest["role_byte_bounds"]
    _require(type(role_bounds) is dict and bool(role_bounds),
             "Source5 path catalogue has no role-specific budgets")
    for role, amount in role_bounds.items():
        _token(role, "Source5 path catalogue role")
        _uint(amount, f"Source5 {role} byte budget")
    body = {key: item for key, item in manifest.items()
            if key != "semantic_sha256"}
    _require(_digest(manifest["semantic_sha256"],
                     "Source5 path catalogue semantic digest") ==
             _sha(_canonical(body)),
             "Source5 path catalogue semantic digest differs")
    return manifest


def _read_stable_catalogue_chunk(chunk: dict[str, Any], index: int) -> bytes:
    path = Path(chunk["path"])
    _require(path.is_absolute() and path.resolve(strict=True) == path,
             f"Source5 path catalogue chunk[{index}] traverses an alias")
    try:
        before_path = path.lstat()
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and
                 before_path.st_size == chunk["byte_count"],
                 f"Source5 path catalogue chunk[{index}] is not exact private data")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise BudgetPlanError(
            f"cannot read Source5 path catalogue chunk[{index}]: {error}",
        ) from error
    try:
        before = os.fstat(descriptor)
        key = (before.st_dev, before.st_ino, before.st_mode, before.st_size,
               before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
        path_key = (before_path.st_dev, before_path.st_ino, before_path.st_mode,
                    before_path.st_size, before_path.st_mtime_ns,
                    before_path.st_ctime_ns, before_path.st_nlink)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                 stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
                 key == path_key and before.st_size == chunk["byte_count"],
                 f"Source5 path catalogue chunk[{index}] changed before read")
        pieces: list[bytes] = []
        total = 0
        while total < chunk["byte_count"]:
            block = os.read(descriptor, min(1024 * 1024,
                                            chunk["byte_count"] - total))
            _require(bool(block),
                     f"Source5 path catalogue chunk[{index}] ended early")
            total += len(block)
            _require(total <= PATH_CATALOGUE_CHUNK_BYTES,
                     f"Source5 path catalogue chunk[{index}] exceeded its byte cap")
            pieces.append(block)
        _require(os.read(descriptor, 1) == b"" and total == chunk["byte_count"],
                 f"Source5 path catalogue chunk[{index}] has trailing bytes")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
        after_path_key = (after_path.st_dev, after_path.st_ino, after_path.st_mode,
                          after_path.st_size, after_path.st_mtime_ns,
                          after_path.st_ctime_ns, after_path.st_nlink)
        _require(key == after_key == after_path_key,
                 f"Source5 path catalogue chunk[{index}] changed during read")
        raw = b"".join(pieces)
        _require(_sha(raw) == chunk["raw_sha256"] == chunk["semantic_sha256"],
                 f"Source5 path catalogue chunk[{index}] raw/semantic digest differs")
        return raw
    finally:
        os.close(descriptor)


def _catalogue_derived_bounds(
    manifest: dict[str, Any], rows: Iterable[dict[str, Any]],
    retention_rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    root_bytes: dict[str, int] = {}
    root_inodes: dict[str, int] = {}
    role_bytes: dict[str, int] = {}
    aggregate_limits: dict[str, tuple[int, str | None]] = {}
    aggregate_bytes: dict[str, int] = {}
    total_rows = 0
    files = 0
    trees = 0
    maximum_inodes = 0
    ungrouped_bytes = 0
    maximum_index_entries = 0
    maximum_index_data_bytes = 0
    for row in rows:
        total_rows += 1
        maximum_inodes += row["max_inodes"]
        if row["storage_root"] is not None:
            root = row["storage_root"]
            root_bytes.setdefault(root, 0)
            root_inodes.setdefault(root, 0)
            if row["role"] not in (
                TRANSIENT_JOB_EVIDENCE_ROLES | FAILURE_WINDOW_ONLY_ROLES
            ):
                root_bytes[root] += row["max_bytes"]
                root_inodes[root] += row["max_inodes"]
        role_bytes[row["role"]] = role_bytes.get(row["role"], 0) + row["max_bytes"]
        aggregate = row["aggregate_id"]
        if row["role"] in TRANSIENT_JOB_EVIDENCE_ROLES:
            pass
        elif row["role"] in FAILURE_WINDOW_ONLY_ROLES:
            pass
        elif _is_success_empty_tmp_tree(row):
            pass
        elif aggregate is None:
            ungrouped_bytes += row["max_bytes"]
        else:
            maximum = row["aggregate_max_bytes"]
            prior = aggregate_limits.get(aggregate)
            if prior is not None:
                _require(prior == (maximum, row["storage_root"]),
                         f"Source5 aggregate {aggregate} changes its root or ceiling")
            else:
                aggregate_limits[aggregate] = (maximum, row["storage_root"])
            aggregate_bytes[aggregate] = (
                aggregate_bytes.get(aggregate, 0) + row["max_bytes"]
            )
        if row["kind"] == "file":
            files += 1
            if row["role"] not in (
                TRANSIENT_JOB_EVIDENCE_ROLES | FAILURE_WINDOW_ONLY_ROLES
            ):
                maximum_index_entries += 1
                maximum_index_data_bytes += _index_row_bound(row)
        else:
            trees += 1
            maximum_index_entries += row["max_inodes"] - 1
            maximum_index_data_bytes += (
                row["max_inodes"] - 1
            ) * _index_row_bound(row, path_length=MAX_PATH_BYTES)
    grouped_bytes = 0
    for aggregate, amount in aggregate_bytes.items():
        maximum, root = aggregate_limits[aggregate]
        grouped_bytes += min(amount, maximum)
        if root is not None:
            root_bytes[root] -= amount - min(amount, maximum)
    retention = _retention_projection(retention_rows)
    maximum_payload = (
        grouped_bytes + ungrouped_bytes +
        retention["maximum_failure_window_tmp_payload_bytes"] +
        retention["maximum_failure_window_disposition_bytes"]
    )
    maximum_index_entries = retention["maximum_full_index_entries"]
    maximum_index_data_bytes = retention["maximum_full_index_data_bytes"]
    maximum_index_chunks = max(
        1, (maximum_index_data_bytes +
            (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES) - 1) //
            (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES),
    )
    maximum_pages, page_bytes = _index_manifest_tree_bound(maximum_index_chunks)
    maximum_index_bytes = maximum_index_data_bytes + page_bytes
    index_sort_runs = max(
        1, (maximum_index_entries + PATH_CATALOGUE_RUN_ROWS - 1) //
        PATH_CATALOGUE_RUN_ROWS,
    )
    index_sort_merge_overlap = (
        (index_sort_runs + PATH_CATALOGUE_MERGE_FANOUT - 1) //
        PATH_CATALOGUE_MERGE_FANOUT
        if index_sort_runs > PATH_CATALOGUE_MERGE_FANOUT else 0
    )
    return {
        "entry_count": total_rows, "file_count": files,
        "tree_count": trees, "maximum_inode_count": maximum_inodes,
        "maximum_live_inode_count": sum(
            retention["maximum_live_root_inode_bounds"].values()
        ),
        "maximum_payload_bytes": maximum_payload,
        "root_byte_bounds": dict(sorted(root_bytes.items())),
        "root_inode_bounds": dict(sorted(root_inodes.items())),
        "retention_policy": retention,
        "role_byte_bounds": dict(sorted(role_bytes.items())),
        "maximum_index_entries": maximum_index_entries,
        "maximum_index_bytes": maximum_index_bytes,
        "maximum_index_chunks": maximum_index_chunks,
        "maximum_index_manifest_pages": maximum_pages,
        "maximum_index_manifest_bytes": page_bytes,
        "maximum_index_sort_scratch_bytes": maximum_index_data_bytes * 3,
        "maximum_index_sort_scratch_inodes":
            2 + index_sort_runs + index_sort_merge_overlap,
    }


def iter_path_catalogue_rows(value: object) -> Iterator[dict[str, Any]]:
    """Stream and authenticate every exact producer row in a pinned catalogue."""
    manifest = validate_path_catalogue_manifest(value)
    previous_path = ""
    for chunk_index, chunk in enumerate(manifest["chunks"]):
        raw = _read_stable_catalogue_chunk(chunk, chunk_index)
        byte_count = 0
        row_count = 0
        first_path = ""
        last_path = ""
        with io.BytesIO(raw) as stream:
            while True:
                line = stream.readline(PATH_CATALOGUE_ROW_BYTES + 1)
                if not line:
                    break
                _require(len(line) <= PATH_CATALOGUE_ROW_BYTES and
                         line.endswith(b"\n") and b"\r" not in line,
                         f"Source5 path catalogue chunk[{chunk_index}] framing/row width differs")
                byte_count += len(line)
                _require(byte_count <= PATH_CATALOGUE_CHUNK_BYTES,
                         f"Source5 path catalogue chunk[{chunk_index}] exceeds its byte bound")
                try:
                    raw_row = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise BudgetPlanError(
                        f"Source5 path catalogue chunk[{chunk_index}] has malformed row {row_count}"
                    ) from error
                row = _catalogue_row(
                    raw_row, f"Source5 path catalogue chunk[{chunk_index}] row[{row_count}]",
                )
                _require(line == _canonical(row) and row["path"] > previous_path,
                         "Source5 path catalogue rows are noncanonical or globally unordered")
                previous_path = row["path"]
                if row_count == 0:
                    first_path = row["path"]
                last_path = row["path"]
                row_count += 1
                yield row
        digest = _sha(raw)
        _require(byte_count == chunk["byte_count"] and
                 row_count == chunk["row_count"] and
                 first_path == chunk["first_path"] and
                 last_path == chunk["last_path"] and
                 digest == chunk["raw_sha256"] == chunk["semantic_sha256"],
                 f"Source5 path catalogue chunk[{chunk_index}] differs from its raw/semantic pin")


def verify_path_catalogue_chunks(value: object) -> dict[str, Any]:
    """Authenticate the complete chunk closure before a consumer uses rows."""
    manifest = validate_path_catalogue_manifest(value)
    derived = _catalogue_derived_bounds(
        manifest, iter_path_catalogue_rows(manifest),
        iter_path_catalogue_rows(manifest),
    )
    for name, amount in derived.items():
        _require(manifest[name] == amount,
                 f"Source5 path catalogue {name} differs from its exact row-stream projection")
    return manifest


def iter_path_catalogue_rows_with_reader(
    value: object, reader,
) -> Iterator[dict[str, Any]]:
    """Stream authenticated catalogue rows supplied by a captured store."""
    manifest = validate_path_catalogue_manifest(value)
    previous_path = ""
    for chunk_index, chunk in enumerate(manifest["chunks"]):
        raw = reader(chunk["path"], chunk["byte_count"])
        _require(type(raw) is bytes and len(raw) == chunk["byte_count"] and
                 _sha(raw) == chunk["raw_sha256"] == chunk["semantic_sha256"],
                 f"captured Source5 path catalogue chunk[{chunk_index}] raw pin differs")
        row_count = 0
        first = ""
        last = ""
        with io.BytesIO(raw) as stream:
            while True:
                row = stream.readline(PATH_CATALOGUE_ROW_BYTES + 1)
                if not row:
                    break
                _require(row.endswith(b"\n") and b"\r" not in row and
                         len(row) <= PATH_CATALOGUE_ROW_BYTES,
                         f"captured Source5 catalogue chunk[{chunk_index}] framing/width differs")
                try:
                    value_row = json.loads(row.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise BudgetPlanError(
                        f"captured Source5 catalogue chunk[{chunk_index}] row is malformed"
                    ) from error
                checked = _catalogue_row(
                    value_row, f"captured Source5 catalogue chunk[{chunk_index}] row[{row_count}]",
                )
                _require(row == _canonical(checked) and checked["path"] > previous_path,
                         "captured Source5 catalogue rows are noncanonical or unordered")
                previous_path = checked["path"]
                if row_count == 0:
                    first = checked["path"]
                last = checked["path"]
                row_count += 1
                yield checked
        _require(row_count == chunk["row_count"] and first == chunk["first_path"] and
                 last == chunk["last_path"],
                 f"captured Source5 catalogue chunk[{chunk_index}] row closure differs")


def verify_path_catalogue_chunks_with_reader(value: object, reader) -> dict[str, Any]:
    """Authenticate captured catalogue chunk pins and complete row totals."""
    manifest = validate_path_catalogue_manifest(value)
    derived = _catalogue_derived_bounds(
        manifest, iter_path_catalogue_rows_with_reader(manifest, reader),
        iter_path_catalogue_rows_with_reader(manifest, reader),
    )
    for name, amount in derived.items():
        _require(manifest[name] == amount,
                 f"captured Source5 catalogue {name} differs from its exact row-stream projection")
    return manifest


def build_storage_reservation_value(
    campaign_id_value: object, host_id_value: object, roots_value: object,
) -> dict[str, Any]:
    """Canonicalize caller-pinned writable-domain byte/inode ceilings."""
    campaign_id = _token(campaign_id_value, "storage reservation campaign ID")
    host_id = _token(host_id_value, "storage reservation host ID")
    _require(type(roots_value) is list and len(roots_value) >= 3,
             "caller storage reservation needs artifact, output and evidence-store domains")
    checked_roots: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for index, value in enumerate(roots_value):
        row = _exact(value, {
            "path", "role", "reserved_bytes", "reserved_inodes", "filesystem_id",
        }, f"caller storage reservation root[{index}]")
        role = row["role"]
        _require(role in {"artifact", "output", "scratch", "evidence_store"},
                 f"caller storage reservation root[{index}] has an unsupported role")
        path = row["path"]
        _require(type(path) is str and path.startswith("/") and
                 len(path.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
                 ".." not in PurePosixPath(path).parts and
                 PurePosixPath(path).as_posix() == path,
                 f"caller storage root[{index}] is not a normalized absolute path")
        _require(path not in seen_paths and
                 (role not in {"artifact", "output", "evidence_store"} or
                  role not in seen_roles),
                 f"caller storage root[{index}] duplicates a path or unique root role")
        seen_paths.add(path)
        seen_roles.add(role)
        filesystem_id = row["filesystem_id"]
        _require(type(filesystem_id) is str and
                 re.fullmatch(r"[0-9]+", filesystem_id) is not None,
                 f"caller storage root[{index}] filesystem identity is malformed")
        checked_roots.append({
            "path": path,
            "role": role,
            "reserved_bytes": _uint(row["reserved_bytes"],
                                     f"caller storage root[{index}] reserved bytes", positive=True),
            "reserved_inodes": _uint(row["reserved_inodes"],
                                      f"caller storage root[{index}] reserved inodes", positive=True),
            "filesystem_id": filesystem_id,
        })
    _require({"artifact", "output", "evidence_store"} <= seen_roles,
             "caller storage reservation omits an artifact, output or evidence-store root")
    checked_roots.sort(key=lambda item: item["path"])
    body = {
        "schema": STORAGE_RESERVATION_SCHEMA_V1,
        "campaign_id": campaign_id, "host_id": host_id,
        "roots": checked_roots,
        "qualification_eligible": False,
    }
    return {**body, "reservation_sha256": _sha(_canonical(body))}


def build_host_evidence_budget_v2(
    audit_value: object, contract_value: object,
    catalogue_value: object, reservation_value: object,
    reservation_pin_value: object,
) -> dict[str, Any]:
    """Bind the original schedule, exact catalogue and caller storage ceiling."""
    audit = audit_value
    contract = contract_value
    _require(type(audit) is dict and audit.get("schema") == AUDIT_SCHEMA and
             audit.get("readiness") == {
                 "budget_complete": False, "execution_ready": False,
                 "component_gate_ready": False, "qualification_eligible": False,
             }, "Source5 v2 budget requires the unchanged non-ready v1 schedule audit")
    audit_body = {key: value for key, value in audit.items()
                  if key != "budget_plan_sha256"}
    _require(audit.get("budget_plan_sha256") == _sha(_canonical(audit_body)),
             "Source5 v2 schedule audit digest differs")
    catalogue = validate_path_catalogue_manifest(catalogue_value)
    catalogue = verify_path_catalogue_chunks(catalogue)
    retention = catalogue["retention_policy"]
    total_original_jobs = audit["schedule"]["total_job_count"]
    expected_metadata_roles = ARCHIVE_LOCAL_METADATA_ROLES
    _require(retention["archive_metadata_job_group_count"] == total_original_jobs and
             set(retention["persistent_archive_metadata_byte_bounds_by_role"]) ==
                 expected_metadata_roles and
             retention["persistent_local_job_record_count"] == total_original_jobs and
             retention["maximum_checkpoint_request_bytes"] > 0 and
             retention["maximum_ack_bundle_bytes"] > 0 and
             retention["maximum_transfer_offer_bytes"] > 0 and
             retention["maximum_stage_map_bytes"] > 0 and
             retention["maximum_transfer_packet_bytes"] > 0,
             "Source5 v2 budget requires exact request/offer/packet/ACK/stage rows for every original job")
    _require(type(contract) is dict and
             contract.get("schema") ==
                "allocatbelt.application-source5-owner-evidence-catalogue.v1" and
             contract.get("source_manifest_sha256") ==
                audit["original_pins"]["source_manifests"][audit["host_id"]][
                    "semantic_sha256"],
             "Source5 v2 owner contract differs from the selected typed source")
    reservation = reservation_value
    _require(type(reservation) is dict and
             reservation.get("schema") == STORAGE_RESERVATION_SCHEMA_V1 and
             reservation.get("campaign_id") == audit["campaign_id"] and
             reservation.get("host_id") == audit["host_id"] and
             reservation.get("qualification_eligible") is False,
             "Source5 storage reservation is not bound to this original host")
    reservation_body = {key: item for key, item in reservation.items()
                        if key != "reservation_sha256"}
    reservation_sha = _sha(_canonical(reservation_body))
    _require(reservation.get("reservation_sha256") == reservation_sha,
             "Source5 storage reservation semantic digest differs")
    reservation_pin_value = _exact(reservation_pin_value, {
        "path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "Source5 storage reservation raw/semantic pin")
    reservation_pin_base = _pin({
        "path": reservation_pin_value["path"],
        "raw_sha256": reservation_pin_value["raw_sha256"],
        "semantic_sha256": reservation_pin_value["semantic_sha256"],
    }, "Source5 storage reservation raw/semantic pin")
    reservation_pin = {
        **reservation_pin_base,
        "byte_count": _uint(reservation_pin_value["byte_count"],
                             "Source5 storage reservation byte count",
                             positive=True),
    }
    _require(reservation_pin["semantic_sha256"] == reservation_sha,
             "Source5 storage reservation pin differs from its canonical value")
    roots_value = reservation.get("roots")
    _require(type(roots_value) is list and len(roots_value) >= 3,
             "Source5 storage reservation root list is incomplete")
    roots: dict[str, dict[str, Any]] = {}
    roles: dict[str, str] = {}
    for index, root_value in enumerate(roots_value):
        root = _exact(root_value, {
            "path", "role", "reserved_bytes", "reserved_inodes", "filesystem_id",
        }, f"Source5 storage reservation root[{index}]")
        _require(type(root["path"]) is str and root["path"].startswith("/") and
                 root["path"] == root["path"].rstrip("/") and
                 type(root["filesystem_id"]) is str and root["filesystem_id"],
                 f"Source5 storage reservation root[{index}] is malformed")
        _require(root["role"] in {"artifact", "output", "scratch", "evidence_store"} and
                 root["path"] not in roots and
                 (root["role"] not in {"artifact", "output", "evidence_store"} or
                  root["role"] not in roles.values()),
                 f"Source5 storage reservation root[{index}] has duplicate path/role")
        _uint(root["reserved_bytes"], f"Source5 storage root[{index}] reserved bytes")
        _uint(root["reserved_inodes"], f"Source5 storage root[{index}] reserved inodes")
        roots[root["path"]] = root
        roles[root["path"]] = root["role"]
    _require({"artifact", "output", "evidence_store"} <= set(roles.values()),
             "Source5 storage reservation omits a required root role")
    scratch_roots = [path for path, role in roles.items() if role == "scratch"]
    _require(len(scratch_roots) == 1,
             "Source5 v2 catalogue sorting requires one caller-reserved scratch domain")
    catalogue_roots = set(retention["maximum_live_root_byte_bounds"])
    _require(catalogue_roots <= set(roots) and
             all(roles[path] in {"artifact", "output", "scratch"}
                 for path in catalogue_roots),
             "Source5 owner catalogue writable roots lack caller-pinned storage domains")
    schedule = audit["schedule"]
    event_count = _uint(schedule["maximum_callback_events"],
                         "Source5 v2 callback event bound", positive=True)
    event_bytes = _uint(schedule["maximum_callback_event_bytes"],
                         "Source5 v2 callback event width", positive=True)
    _require(schedule["worst_case_journal_bytes"] == min(
                 CORE_ROLE_BYTES_CAP, event_count * event_bytes,
             ),
             "Source5 v2 journal byte formula differs from the original plan projection")
    maximum_store_metadata_chunks = max(
        1, (catalogue["maximum_index_bytes"] +
            (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES) - 1) //
            (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES),
    )
    maximum_store_root_bytes = _captured_store_root_bound(
        maximum_store_metadata_chunks,
    )
    _require(maximum_store_root_bytes <= MAX_CAPTURED_STORE_ROOT_BYTES,
             "Source5 v2 store metadata descriptor closure exceeds its root-manifest ceiling")
    transport = {
        "index_schema": "allocatbelt.application-source5-journal-evidence-index.v3",
        "request_schema": "allocatbelt.application-source5-host-journal-request.v3",
        "captured_store_schema": "allocatbelt.application-source5-captured-evidence.v2",
        "catalogue_chunk_bytes": PATH_CATALOGUE_CHUNK_BYTES,
        "catalogue_entries": catalogue["entry_count"],
        "catalogue_file_entries": catalogue["file_count"],
        "catalogue_tree_roots": catalogue["tree_count"],
        "maximum_index_entries": catalogue["maximum_index_entries"],
        "maximum_index_bytes": catalogue["maximum_index_bytes"],
        "maximum_index_chunks": catalogue["maximum_index_chunks"],
        "maximum_index_manifest_pages":
            catalogue["maximum_index_manifest_pages"],
        "maximum_index_manifest_bytes":
            catalogue["maximum_index_manifest_bytes"],
        "maximum_store_metadata_bytes": catalogue["maximum_index_bytes"],
        "maximum_store_metadata_chunks": maximum_store_metadata_chunks,
        "maximum_store_root_bytes": maximum_store_root_bytes,
        "maximum_store_entries": catalogue["maximum_index_entries"] +
            catalogue["maximum_index_chunks"] +
            catalogue["maximum_index_manifest_pages"] +
            len(catalogue["chunks"]) +
            maximum_store_metadata_chunks + 2,
        "maximum_journal_events": event_count,
        "maximum_journal_bytes": schedule["worst_case_journal_bytes"],
        "maximum_record_bytes": MAX_EVENT_BYTES,
        "maximum_job_record_bytes": retention["maximum_job_record_bytes"],
        "maximum_job_packet_bytes": retention["maximum_transfer_packet_bytes"],
        "maximum_job_packet_inodes": retention["maximum_transfer_packet_inodes"],
        "maximum_ack_bundle_bytes": retention["maximum_ack_bundle_bytes"],
        "maximum_signature_bytes": retention["maximum_signature_bytes"],
        "retention_mode": retention["mode"],
        "legacy_v1_entry_cap_unchanged": DISPATCH_ENTRY_CAP,
        "legacy_v1_index_bytes_unchanged": DISPATCH_INDEX_BYTES_CAP,
    }
    catalogue_chunk_bytes = sum(chunk["byte_count"]
                                for chunk in catalogue["chunks"])
    receipt_bytes = contract["transport_caps"]["chronology"].get(
        "MAX_COMPLETION_BYTES",
    )
    _uint(receipt_bytes, "Source5 chronology origin-receipt ceiling", positive=True)
    transport["maximum_store_payload_bytes"] = (
        catalogue["maximum_payload_bytes"] +
        catalogue["maximum_index_bytes"] +
        catalogue_chunk_bytes + receipt_bytes
    )
    required_bytes = {
        path: retention["maximum_live_root_byte_bounds"].get(path, 0)
        for path in roots
    }
    required_inodes = {
        path: retention["maximum_live_root_inode_bounds"].get(path, 0)
        for path in roots
    }
    output_roots = [path for path, role in roles.items() if role == "output"]
    _require(len(output_roots) == 1,
             "Source5 v2 storage reservation needs one output root")
    required_bytes[output_roots[0]] += receipt_bytes
    scratch_root = scratch_roots[0]
    required_bytes[scratch_root] = (
        retention["persistent_root_byte_bounds"].get(scratch_root, 0) + max(
        retention["maximum_window_root_byte_bounds"].get(scratch_root, 0),
        catalogue["maximum_sort_scratch_bytes"],
        catalogue["maximum_index_sort_scratch_bytes"],
        transport["maximum_job_packet_bytes"],
        )
    )
    required_inodes[scratch_root] = (
        retention["persistent_root_inode_bounds"].get(scratch_root, 0) + max(
        retention["maximum_window_root_inode_bounds"].get(scratch_root, 0),
        catalogue["maximum_sort_scratch_inodes"],
        catalogue["maximum_index_sort_scratch_inodes"],
        transport["maximum_job_packet_inodes"],
        )
    )
    evidence_store_roots = [path for path, role in roles.items()
                            if role == "evidence_store"]
    _require(len(evidence_store_roots) == 1,
             "Source5 storage reservation needs one evidence-store root")
    evidence_store_root = evidence_store_roots[0]
    required_bytes[evidence_store_root] += (
        catalogue["maximum_index_bytes"] +
        transport["maximum_store_payload_bytes"] +
        transport["maximum_store_metadata_bytes"] +
        transport["maximum_store_root_bytes"]
    )
    required_inodes[evidence_store_root] += (
        catalogue["maximum_index_chunks"] + catalogue["maximum_index_manifest_pages"] +
        1 + transport["maximum_store_entries"] + 260
    )
    for path, role in roles.items():
        if role == "artifact":
            required_bytes[path] += catalogue_chunk_bytes
            required_inodes[path] += len(catalogue["chunks"]) + 1
    base_required_bytes = dict(required_bytes)
    budget_bytes = 0
    result: dict[str, Any] = {}
    for _ in range(32):
        required_bytes = dict(base_required_bytes)
        for path, role in roles.items():
            if role in {"artifact", "evidence_store"}:
                required_bytes[path] += budget_bytes
        body = {
            "schema": HOST_BUDGET_SCHEMA_V2,
            "campaign_id": audit["campaign_id"], "host_id": audit["host_id"],
            "original_pins": audit["original_pins"], "schedule": schedule,
            "owner_contract": contract, "path_catalogue": catalogue,
            "storage_reservation": {
                "pin": reservation_pin, "roots": roots,
                "required_bytes_by_root": required_bytes,
                "required_inodes_by_root": required_inodes,
            },
            "role_byte_reservations": catalogue["role_byte_bounds"],
            "transport": transport,
            "execution_blockers": [
                "source_derived_journal_width_not_bound",
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ],
            "readiness": {
                "budget_complete": False, "execution_ready": False,
                "component_gate_ready": False, "qualification_eligible": False,
            },
        }
        result = {**body, "budget_sha256": _sha(_canonical(body))}
        measured_budget_bytes = len(_canonical(result))
        if measured_budget_bytes == budget_bytes:
            break
        budget_bytes = measured_budget_bytes
    else:
        raise BudgetPlanError("Source5 budget-size reservation projection did not converge")
    for path, root in roots.items():
        _require(root["reserved_bytes"] >= required_bytes[path] and
                 root["reserved_inodes"] >= required_inodes[path],
                 f"Source5 storage reservation is below the original full-host bound: {path}")
    return result


def validate_host_evidence_budget_v2(value: object) -> dict[str, Any]:
    """Validate the canonical v2 budget and exact pre-execution readiness state."""
    budget = _exact(value, {
        "schema", "campaign_id", "host_id", "original_pins", "schedule",
        "owner_contract", "path_catalogue", "storage_reservation",
        "role_byte_reservations", "transport", "execution_blockers",
        "readiness", "budget_sha256",
    }, "Source5 host evidence budget v2")
    _require(budget["schema"] == HOST_BUDGET_SCHEMA_V2 and
             budget["execution_blockers"] == [
                 "source_derived_journal_width_not_bound",
                 "verified_between_pair_archive_ack_reclaim_not_integrated",
             ] and
             budget["readiness"] == {
                 "budget_complete": False, "execution_ready": False,
                 "component_gate_ready": False, "qualification_eligible": False,
             }, "Source5 v2 budget readiness differs from the pre-execution state")
    _token(budget["campaign_id"], "Source5 v2 campaign ID")
    _token(budget["host_id"], "Source5 v2 host ID")
    _require(type(budget["original_pins"]) is dict and
             type(budget["schedule"]) is dict,
             "Source5 v2 provenance or schedule is malformed")
    catalogue = validate_path_catalogue_manifest(budget["path_catalogue"])
    reservation = _exact(budget["storage_reservation"], {
        "pin", "roots", "required_bytes_by_root", "required_inodes_by_root",
    }, "Source5 v2 storage reservation binding")
    reservation_pin = _exact(reservation["pin"], {
        "path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "Source5 v2 storage reservation pin")
    _pin({key: reservation_pin[key] for key in (
        "path", "raw_sha256", "semantic_sha256",
    )}, "Source5 v2 storage reservation pin")
    _uint(reservation_pin["byte_count"],
          "Source5 v2 storage reservation byte count", positive=True)
    roots = reservation["roots"]
    _require(type(roots) is dict and len(roots) >= 3,
             "Source5 v2 storage reservation roots are incomplete")
    roles: dict[str, str] = {}
    for path, root_value in roots.items():
        root = _exact(root_value, {
            "path", "role", "reserved_bytes", "reserved_inodes", "filesystem_id",
        }, f"Source5 v2 root reservation {path}")
        _require(root["path"] == path and type(path) is str and path.startswith("/") and
                 type(root["filesystem_id"]) is str and root["filesystem_id"],
                 f"Source5 v2 root reservation {path} is malformed")
        _require(root["role"] in {"artifact", "output", "scratch", "evidence_store"},
                 f"Source5 v2 root reservation {path} has an unsupported role")
        roles[path] = root["role"]
        _uint(root["reserved_bytes"], f"Source5 v2 root bytes {path}")
        _uint(root["reserved_inodes"], f"Source5 v2 root inodes {path}")
    _require({"artifact", "output", "evidence_store"} <= set(roles.values()) and
             len([path for path, role in roles.items() if role == "artifact"]) == 1 and
             len([path for path, role in roles.items() if role == "output"]) == 1 and
             len([path for path, role in roles.items() if role == "evidence_store"]) == 1 and
             len([path for path, role in roles.items() if role == "scratch"]) == 1,
             "Source5 v2 root roles do not identify the exact three required domains")
    required_bytes = reservation["required_bytes_by_root"]
    required_inodes = reservation["required_inodes_by_root"]
    _require(type(required_bytes) is dict and set(required_bytes) == set(roots) and
             type(required_inodes) is dict and set(required_inodes) == set(roots),
             "Source5 v2 per-root requirements do not close over caller roots")
    _require(budget["role_byte_reservations"] == catalogue["role_byte_bounds"],
             "Source5 v2 reservation differs from exact owner path ceilings")
    for path in roots:
        _uint(required_bytes[path], f"Source5 v2 required bytes {path}")
        _uint(required_inodes[path], f"Source5 v2 required inodes {path}")
        _require(roots[path]["reserved_bytes"] >= required_bytes[path] and
                 roots[path]["reserved_inodes"] >= required_inodes[path],
                 f"Source5 v2 caller reservation is below its derived bound: {path}")
    _require(set(catalogue["root_byte_bounds"]) <= set(roots) and
             all(roles[path] in {"artifact", "output", "scratch"}
                 for path in catalogue["root_byte_bounds"]),
             "Source5 v2 catalogue roots lack their exact writable-domain reservations")
    catalogue_chunk_bytes = sum(item["byte_count"]
                                for item in catalogue["chunks"])
    receipt_bytes = budget["owner_contract"]["transport_caps"]["chronology"].get(
        "MAX_COMPLETION_BYTES",
    )
    _uint(receipt_bytes, "Source5 v2 origin-receipt ceiling", positive=True)
    transport = budget["transport"]
    _require(type(transport) is dict,
             "Source5 v2 transport reservation is malformed")
    expected_bytes = {
        path: catalogue["retention_policy"]["maximum_live_root_byte_bounds"].get(path, 0)
        for path in roots
    }
    expected_inodes = {
        path: catalogue["retention_policy"]["maximum_live_root_inode_bounds"].get(path, 0)
        for path in roots
    }
    output_root = next(path for path, role in roles.items() if role == "output")
    expected_bytes[output_root] += receipt_bytes
    scratch_root = next(path for path, role in roles.items() if role == "scratch")
    expected_bytes[scratch_root] = (
        catalogue["retention_policy"]["persistent_root_byte_bounds"].get(
            scratch_root, 0,
        ) + max(
        catalogue["retention_policy"]["maximum_window_root_byte_bounds"].get(
            scratch_root, 0,
        ),
        catalogue["maximum_sort_scratch_bytes"],
        catalogue["maximum_index_sort_scratch_bytes"],
        catalogue["retention_policy"]["maximum_transfer_packet_bytes"],
        )
    )
    expected_inodes[scratch_root] = (
        catalogue["retention_policy"]["persistent_root_inode_bounds"].get(
            scratch_root, 0,
        ) + max(
        catalogue["retention_policy"]["maximum_window_root_inode_bounds"].get(
            scratch_root, 0,
        ),
        catalogue["maximum_sort_scratch_inodes"],
        catalogue["maximum_index_sort_scratch_inodes"],
        catalogue["retention_policy"]["maximum_transfer_packet_inodes"],
        )
    )
    evidence_store_root = next(path for path, role in roles.items()
                               if role == "evidence_store")
    expected_bytes[evidence_store_root] += (
        catalogue["maximum_index_bytes"] +
        transport.get("maximum_store_payload_bytes", 0) +
        transport.get("maximum_store_metadata_bytes", 0) +
        transport.get("maximum_store_root_bytes", 0)
    )
    expected_inodes[evidence_store_root] += (
        catalogue["maximum_index_chunks"] + catalogue["maximum_index_manifest_pages"] +
        1 + transport.get("maximum_store_entries", 0) + 260
    )
    for path, role in roles.items():
        if role == "artifact":
            expected_bytes[path] += catalogue_chunk_bytes
            expected_inodes[path] += len(catalogue["chunks"]) + 1
    base_expected_bytes = dict(expected_bytes)
    budget_bytes = 0
    for _ in range(32):
        candidate_required_bytes = dict(base_expected_bytes)
        for path, role in roles.items():
            if role in {"artifact", "evidence_store"}:
                candidate_required_bytes[path] += budget_bytes
        candidate = dict(budget)
        candidate_reservation = dict(reservation)
        candidate_reservation["required_bytes_by_root"] = candidate_required_bytes
        candidate["storage_reservation"] = candidate_reservation
        candidate["budget_sha256"] = "f" * 64
        measured_budget_bytes = len(_canonical(candidate))
        if measured_budget_bytes == budget_bytes:
            expected_bytes = candidate_required_bytes
            break
        budget_bytes = measured_budget_bytes
    else:
        raise BudgetPlanError("Source5 v2 reservation projection did not converge")
    _require(required_bytes == expected_bytes and required_inodes == expected_inodes,
             "Source5 v2 caller reservation requirements differ from exact catalogue arithmetic")
    _require(type(transport) is dict and
             transport.get("catalogue_entries") == catalogue["entry_count"] and
             transport.get("maximum_index_entries") ==
                catalogue["maximum_index_entries"] and
             transport.get("maximum_index_bytes") ==
                catalogue["maximum_index_bytes"] and
             transport.get("maximum_index_chunks") ==
                catalogue["maximum_index_chunks"] and
             transport.get("maximum_index_manifest_pages") ==
                catalogue["maximum_index_manifest_pages"] and
             transport.get("maximum_index_manifest_bytes") ==
                catalogue["maximum_index_manifest_bytes"] and
             transport.get("maximum_store_metadata_bytes") ==
                catalogue["maximum_index_bytes"] and
             transport.get("maximum_store_metadata_chunks") ==
                max(1, (catalogue["maximum_index_bytes"] +
                    (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES) - 1) //
                    (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES)) and
             transport.get("maximum_store_root_bytes") ==
                _captured_store_root_bound(max(
                    1, (catalogue["maximum_index_bytes"] +
                        (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES) - 1) //
                        (INDEX_DATA_CHUNK_BYTES - PATH_CATALOGUE_ROW_BYTES),
                )) <= MAX_CAPTURED_STORE_ROOT_BYTES and
             transport.get("maximum_store_payload_bytes") ==
                catalogue["maximum_payload_bytes"] +
                catalogue["maximum_index_bytes"] + catalogue_chunk_bytes +
                receipt_bytes and
             transport.get("maximum_store_entries") ==
                catalogue["maximum_index_entries"] +
                catalogue["maximum_index_chunks"] +
                catalogue["maximum_index_manifest_pages"] +
                len(catalogue["chunks"]) +
                transport.get("maximum_store_metadata_chunks") + 2 and
             transport.get("maximum_journal_events") ==
                budget["schedule"].get("maximum_callback_events") and
             transport.get("maximum_journal_bytes") ==
                budget["schedule"].get("worst_case_journal_bytes") and
             transport.get("maximum_job_record_bytes") ==
                catalogue["retention_policy"]["maximum_job_record_bytes"] and
             transport.get("maximum_job_packet_bytes") ==
                catalogue["retention_policy"]["maximum_transfer_packet_bytes"] and
             transport.get("maximum_job_packet_inodes") ==
                catalogue["retention_policy"]["maximum_transfer_packet_inodes"] and
             transport.get("maximum_ack_bundle_bytes") ==
                catalogue["retention_policy"]["maximum_ack_bundle_bytes"] and
             transport.get("maximum_signature_bytes") ==
                catalogue["retention_policy"]["maximum_signature_bytes"] and
             transport.get("retention_mode") ==
                catalogue["retention_policy"]["mode"],
             "Source5 v2 transport limits differ from the frozen schedule/catalogue")
    body = {key: item for key, item in budget.items() if key != "budget_sha256"}
    _require(_digest(budget["budget_sha256"], "Source5 v2 budget semantic digest") ==
             _sha(_canonical(body)),
             "Source5 v2 budget raw/semantic identity differs")
    return budget
