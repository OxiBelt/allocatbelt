#!/usr/bin/env python3
"""Drive the original SourceV5 jobs through the locked component APIs.

This controller reads a closed execution manifest. It preserves SpecV3,
PlanV3, SourceV5 and their readiness bits, and writes per-job evidence under
the manifest's private roots. A complete component receipt is still only a
per-job result; phase and campaign gates are recorded separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import types
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


EXECUTION_SCHEMA = "allocatbelt.application-source5-campaign-execution.v1"
EXECUTION_SCHEMA_V2 = "allocatbelt.application-source5-campaign-execution.v2"
EXECUTION_SCHEMA_V3 = "allocatbelt.application-source5-campaign-execution.v3"
HELPER_INPUT_SCHEMA = "allocatbelt.application-source5-helper-input.v1"
JOB_RECORD_SCHEMA = "allocatbelt.application-source5-job-record.v1"
ANALYSIS_SCHEMA = "allocatbelt.application-source5-phase-analysis.v1"
PRESSURE_MATERIALS_SCHEMA = "allocatbelt.application-source5-pressure-job-materials.v1"
PRESSURE_MATERIALS_SCHEMA_V2 = "allocatbelt.application-source5-pressure-job-materials.v2"
PRESSURE_MATERIAL_INDEX_SCHEMA = "allocatbelt.application-source5-pressure-material-index.v1"
PRESSURE_MATERIAL_INDEX_SCHEMA_V2 = "allocatbelt.application-source5-pressure-material-index.v2"
PRESSURE_HELPER_PAYLOAD_SCHEMA_V2 = "allocatbelt.application-source5-pressure-helper-payload.v2"
PROBE_CAPTURE_BUNDLE_SCHEMA = "allocatbelt.application-source5-probe-capture-bundle.v1"
PRESSURE_RECIPE_SCHEMA_V2 = "allocatbelt.application-pressure-pair-recipe.v2"
PROBE_CAPTURE_RECEIPT_SCHEMA = "allocatbelt.application-feedback-probe-capture.v2"
PHASE_ORDER = (
    "exploration", "aa", "confirmation", "fixed_analysis", "pressure",
    "pressure_analysis", "soak", "final_analysis",
)
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_LEDGER_BYTES = 256 * 1024 * 1024


class Source5CampaignError(ValueError):
    """A frozen input, prerequisite, component, or campaign gate failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Source5CampaignError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise Source5CampaignError(f"value is not canonical JSON: {error}") from error
    return (text + "\n").encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def is_sha(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys,
            f"{label} has an unexpected field set")
    return value


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str, os.stat_result]:
    require(path.is_absolute() and path.resolve(strict=True) == path,
            f"{label} path is not canonical")
    before_path = path.lstat()
    require(stat.S_ISREG(before_path.st_mode), f"{label} is not a regular nonsymlink file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path) and
                0 <= before.st_size <= maximum,
                f"{label} changed or exceeds its finite size bound")
        parts: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while reading")
            parts.append(block)
            count += len(block)
        after = os.fstat(fd)
        path_after = path.lstat()
        require(key(before) == key(after) == key(path_after) and
                count == before.st_size,
                f"{label} changed during its bounded read")
        raw = b"".join(parts)
        return raw, sha256(raw), before
    finally:
        os.close(fd)


def read_json(path: Path, label: str, maximum: int,
              expected_sha256: str | None = None) -> tuple[dict[str, Any], bytes, str]:
    raw, actual, _info = read_stable(path, label, maximum)
    require(expected_sha256 is None or actual == expected_sha256,
            f"{label} differs from its raw pin")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Source5CampaignError(f"{label} is not bounded JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value),
            f"{label} is not a canonical JSON object")
    return value, raw, actual


def raw_pin(value: object, label: str) -> dict[str, str]:
    pin = exact(value, {"path", "raw_sha256"}, f"{label} raw pin")
    require(type(pin["path"]) is str and Path(pin["path"]).is_absolute() and
            is_sha(pin["raw_sha256"]), f"{label} raw pin is malformed")
    return {"path": pin["path"], "raw_sha256": pin["raw_sha256"]}


def api_pin(value: dict[str, str]) -> dict[str, str]:
    return {"path": value["path"], "sha256": value["raw_sha256"]}


def write_new(path: Path, raw: bytes, label: str) -> str:
    require(path.is_absolute() and path.parent.is_dir() and
            not path.exists() and not path.is_symlink(),
            f"refusing to replace {label} at {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY |
                           getattr(os, "O_DIRECTORY", 0) |
                           getattr(os, "O_CLOEXEC", 0) |
                           getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return sha256(raw)


def _load_module(raw: bytes, path: Path, name: str) -> types.ModuleType:
    module = types.ModuleType(f"source5_{name}_{sha256(raw)}")
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        sys.modules.pop(module.__name__, None)
        raise Source5CampaignError(f"pinned {name} module cannot be loaded: {error}") from error
    return module


@dataclass
class CampaignContext:
    manifest: dict[str, Any]
    manifest_pin: dict[str, str]
    scope: str
    host_id: str
    spec: dict[str, Any]
    plan: dict[str, Any]
    spec_pin: dict[str, str]
    plan_pin: dict[str, str]
    spec_semantic_sha256: str
    plan_semantic_sha256: str
    source_root: Path
    input_root: Path
    artifact_root: Path
    output_root: Path
    source: dict[str, Any]
    sources: dict[str, dict[str, Any]]
    source_manifest_pins: dict[str, dict[str, str]]
    observed_host_pin: dict[str, str]
    capacity_completion: dict[str, Any]
    prepared_input_completion: dict[str, Any] | None
    campaign: types.ModuleType
    chronology: types.ModuleType
    fixed_pair: types.ModuleType
    pressure_pair: types.ModuleType
    modules: dict[str, types.ModuleType]


def _safe_child(root: Path, relative: object, label: str) -> Path:
    require(type(relative) is str and relative and "\\" not in relative and
            "\x00" not in relative, f"{label} relative path is malformed")
    path = PurePosixPath(relative)
    require(not path.is_absolute() and path.as_posix() == relative and
            all(part not in ("", ".", "..") for part in path.parts),
            f"{label} path is not normalized and relative")
    candidate = root.joinpath(*path.parts)
    require(candidate.resolve(strict=True) == candidate and
            candidate.resolve(strict=True).is_relative_to(root.resolve(strict=True)),
            f"{label} path escaped its source root or traversed an alias")
    return candidate


def _inventory_record(source: dict[str, Any], relative: str) -> dict[str, Any]:
    files = source.get("source", {}).get("files")
    require(type(files) is list, "SourceV5 typed inventory is missing")
    matches = [item for item in files if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 inventory has no unique {relative} entry")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"},
                   f"SourceV5 inventory record {relative}")
    require(record["kind"] == "file" and record["mode"] in {"100644", "100755"} and
            is_sha(record["sha256"]) and type(record["size"]) is int and
            0 <= record["size"] <= MAX_SCRIPT_BYTES,
            f"SourceV5 module {relative} is not a bounded regular file")
    return record


def _load_source_module(context_data: dict[str, Any], source: dict[str, Any],
                        source_root: Path, relative: str, label: str) -> types.ModuleType:
    record = _inventory_record(source, relative)
    declared = context_data.get(relative)
    require(declared == {"path": relative, "sha256": record["sha256"]},
            f"{label} is not the exact Source5 execution-manifest pin")
    path = _safe_child(source_root, relative, label)
    raw, actual, info = read_stable(path, label, MAX_SCRIPT_BYTES)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == record["sha256"] and len(raw) == record["size"] and
            mode == record["mode"],
            f"{label} differs from its typed regular-file inventory record")
    return _load_module(raw, path, label.replace(" ", "_"))


def load_context(manifest_path: Path, host_id: str) -> CampaignContext:
    manifest, manifest_raw, manifest_sha = read_json(
        manifest_path.resolve(strict=True), "Source5 execution manifest",
        MAX_MANIFEST_BYTES,
    )
    base_manifest_fields = {
        "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
        "modules", "observed_hosts", "capacity_completions", "artifact_root",
        "output_root", "phase_order", "protocol_sha256", "qualification_eligible",
        "manifest_sha256",
    }
    schema = manifest.get("schema")
    if schema == EXECUTION_SCHEMA:
        exact(manifest, base_manifest_fields, "Source5 execution manifest v1")
        manifest_scope = None
        prepared_generation = None
        capacity_registration = None
    elif schema == EXECUTION_SCHEMA_V2:
        exact(manifest, (base_manifest_fields - {"capacity_completions"}) | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration",
        }, "Source5 execution manifest v2")
        manifest_scope = manifest["scope"]
        require(manifest_scope == "final_prepared",
                "Source5 execution manifest v2 accepts only the final-prepared scope")
        prepared_generation = exact(manifest["prepared_input_generation"], {
            "completion", "provenance",
        }, "Source5 prepared-input generation")
        capacity_registration = exact(manifest["prepared_capacity_registration"], {
            "completion", "host_completion", "host_verification", "ledger",
            "capacity_schedule_sha256", "registration_head",
        }, "Source5 prepared-capacity registration")
    elif schema == EXECUTION_SCHEMA_V3:
        exact(manifest, (base_manifest_fields - {"capacity_completions"}) | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration",
        }, "Source5 execution manifest v3")
        manifest_scope = manifest["scope"]
        require(manifest_scope == "final_prepared_bounded",
                "Source5 execution manifest v3 accepts only the bounded final-prepared scope")
        prepared_generation = exact(manifest["prepared_input_generation"], {
            "completion", "provenance",
        }, "Source5 bounded prepared-input generation")
        capacity_registration = exact(manifest["prepared_capacity_registration"], {
            "completion", "host_completion", "host_verification", "ledger",
            "capacity_schedule_sha256", "registration_head",
        }, "Source5 bounded prepared-capacity registration")
    else:
        raise Source5CampaignError("unsupported Source5 execution manifest version")
    require(
            manifest["phase_order"] == list(PHASE_ORDER) and
            manifest["qualification_eligible"] is False and
            manifest["manifest_sha256"] == sha256(canonical_bytes({
                key: value for key, value in manifest.items()
                if key != "manifest_sha256"
            })),
            "Source5 execution manifest schema, phase order, eligibility, or digest is invalid")
    require(host_id in manifest["hosts"] and type(manifest["hosts"]) is list and
            len(manifest["hosts"]) == 3 and len(set(manifest["hosts"])) == 3,
            "Source5 selected host is absent from the original three-host order")
    original = exact(manifest["original_inputs"], {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "Source5 original inputs")
    spec_ref = exact(original["spec"], {"artifact", "semantic_sha256"},
                      "Source5 original spec")
    plan_ref = exact(original["plan"], {"artifact", "semantic_sha256"},
                      "Source5 original plan")
    spec_raw_pin = raw_pin(spec_ref["artifact"], "Source5 original spec")
    plan_raw_pin = raw_pin(plan_ref["artifact"], "Source5 original plan")
    spec, spec_raw, spec_raw_sha = read_json(
        Path(spec_raw_pin["path"]), "original SpecV3", 32 * 1024 * 1024,
        spec_raw_pin["raw_sha256"],
    )
    plan, plan_raw, plan_raw_sha = read_json(
        Path(plan_raw_pin["path"]), "original PlanV3", 256 * 1024 * 1024,
        plan_raw_pin["raw_sha256"],
    )
    require(spec["schema"] == "allocatbelt.application-campaign-spec.v3" and
            plan["schema"] == "allocatbelt.application-campaign-plan.v3" and
            spec["campaign_id"] == plan["campaign_id"] == manifest["campaign_id"],
            "Source5 controller requires the unchanged original SpecV3 and PlanV3")
    spec_semantic = sha256(canonical_bytes(spec))
    plan_body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    plan_semantic = sha256(canonical_bytes(plan_body))
    require(spec_ref["semantic_sha256"] == spec_semantic and
            plan_ref["semantic_sha256"] == plan["plan_sha256"] == plan_semantic,
            "Source5 original semantic pins differ from canonical SpecV3/PlanV3 bytes")
    require(manifest["hosts"] == [item["host_id"] for item in spec["hosts"]] ==
            plan["host_ids"],
            "Source5 manifest host order differs from the original spec/plan")
    input_root = Path(spec_raw_pin["path"]).parent.resolve(strict=True)
    source_manifests = exact(original["source_manifests"], set(manifest["hosts"]),
                             "Source5 source-manifest pins")
    sources: dict[str, dict[str, Any]] = {}
    source_manifest_pins: dict[str, dict[str, str]] = {}
    refs = {item["host_id"]: item for item in spec["source_manifests"]}
    for selected in manifest["hosts"]:
        item = exact(source_manifests[selected], {"artifact", "semantic_sha256"},
                     f"Source5 {selected} source manifest")
        raw_ref = raw_pin(item["artifact"], f"Source5 {selected} source manifest")
        relative = refs[selected]["relative_path"]
        expected_path = _safe_child(input_root, relative, f"SourceV5 {selected} manifest")
        require(raw_ref["path"] == str(expected_path) and
                item["semantic_sha256"] == refs[selected]["sha256"],
                f"Source5 {selected} source-manifest raw/semantic pins differ from SpecV3")
        source, _raw, _sha = read_json(
            expected_path, f"SourceV5 {selected} source manifest",
            MAX_MANIFEST_BYTES, raw_ref["raw_sha256"],
        )
        require(source.get("manifest_sha256") == item["semantic_sha256"] and
                source.get("schema") == "allocatbelt.application-source-manifest.v5",
                f"Source5 {selected} SourceV5 manifest semantic pin differs")
        sources[selected] = source
        source_manifest_pins[selected] = raw_ref
    source = sources[host_id]
    source_root_value = exact(manifest["execution_sources"], set(manifest["hosts"]),
                              "Source5 execution source map")[host_id]
    source_root_value = exact(source_root_value, {
        "source_root", "git_commit", "source_tree_sha256", "build_sha256",
    }, "Source5 selected execution source")
    source_root = Path(source_root_value["source_root"]).resolve(strict=True)
    require(source_root_value["git_commit"] == source["source"]["git_commit"] and
            source_root_value["source_tree_sha256"] == source["source"]["source_tree_sha256"] and
            source_root_value["build_sha256"] == source["build"]["build_sha256"],
            "Source5 selected source/build identity differs from SourceV5")
    artifact_root = Path(manifest["artifact_root"]).resolve(strict=True)
    output_root = Path(manifest["output_root"]).resolve(strict=True)
    campaign_artifacts_root = Path(original["campaign_artifacts_root"]).resolve(strict=True)
    for root, label in ((artifact_root, "Source5 artifact root"),
                        (output_root, "Source5 output root")):
        root_info = root.stat(follow_symlinks=False)
        require(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == os.getuid() and
                stat.S_IMODE(root_info.st_mode) == 0o700 and root.resolve(strict=True) == root,
                f"{label} is not canonical owned mode-0700 storage")
        require(not root.is_relative_to(source_root) and
                not root.is_relative_to(input_root) and
                not root.is_relative_to(campaign_artifacts_root) and
                not campaign_artifacts_root.is_relative_to(root),
                f"{label} overlaps SourceV5, original inputs, or campaign artifacts")
    modules = exact(manifest["modules"], set(manifest["hosts"]),
                    "Source5 module inventory map")[host_id]
    require(type(modules) is dict, "Source5 modules must be path-keyed pins")
    expected_script_paths = {
        item["path"] for item in source["source"]["files"]
        if item["kind"] == "file" and item["path"].startswith("scripts/")
        and PurePosixPath(item["path"]).suffix in {".py", ".sh"}
    }
    require(set(modules) == expected_script_paths,
            "Source5 module inventory does not pin every regular script dependency")
    loaded: dict[str, types.ModuleType] = {}
    execution_paths = {
        "scripts/application-campaign.py",
        "scripts/application-campaign-chronology.py",
        "scripts/application-fixed-pair.py",
        "scripts/application-pressure-pair.py",
        "scripts/application-campaign-inputs.py",
        "scripts/application-source-inventory.py",
        "scripts/application-runtime-readback.py",
        "scripts/application-feedback-composition.py",
        "scripts/application-feedback-readback.py",
        "scripts/application-pressure-readback.py",
        "scripts/application-pressure-driver.py",
        "scripts/application-soak-readback.py",
        "scripts/application-byte-capacity.py",
        "scripts/application-soak-recipe.py",
        "scripts/application-source5-soak.py",
        "scripts/application-source5-offline-dispatch.py",
    }
    if schema in (EXECUTION_SCHEMA_V2, EXECUTION_SCHEMA_V3):
        execution_paths.add("scripts/application-source5-input-preparation.py")
    for relative in sorted(expected_script_paths):
        record = _inventory_record(source, relative)
        path = _safe_child(source_root, relative, relative)
        raw, actual, info = read_stable(path, relative, MAX_SCRIPT_BYTES)
        mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
        require(actual == record["sha256"] and len(raw) == record["size"] and
                mode == record["mode"] and
                modules[relative] == {"path": relative, "sha256": actual},
                f"Source5 execution source {relative} differs from its typed inventory pin")
        if relative in execution_paths:
            loaded[relative] = _load_module(raw, path, relative.replace("/", "_"))
    require(execution_paths <= set(loaded),
            "Source5 execution module inventory is missing a transitive dependency")
    if schema == EXECUTION_SCHEMA_V3:
        composition = loaded["scripts/application-feedback-composition.py"]
        require(callable(getattr(composition, "capture_calibrated_probe_v2", None)) and
                callable(getattr(composition, "compose_calibrated_policy_v5_offline", None)) and
                callable(getattr(composition, "_absolute_paths", None)),
                "bounded Source5 pressure requires the pinned ProbeV2 capture and offline-replay APIs")
    controller_path = Path(__file__).resolve(strict=True)
    require(controller_path == source_root / "scripts/application-source5-campaign.py" and
            modules["scripts/application-source5-campaign.py"]["sha256"] ==
            sha256(controller_path.read_bytes()),
            "executing Source5 controller differs from its selected-host typed inventory pin")
    campaign = loaded["scripts/application-campaign.py"]
    chronology = loaded["scripts/application-campaign-chronology.py"]
    fixed_pair = loaded["scripts/application-fixed-pair.py"]
    pressure_pair = loaded["scripts/application-pressure-pair.py"]
    soak_adapter = loaded["scripts/application-source5-soak.py"]
    soak_readback = loaded["scripts/application-soak-readback.py"]
    require(callable(getattr(chronology, "campaign_host_lock", None)) and
            callable(getattr(chronology, "authorize_source5_job_locked", None)) and
            callable(getattr(chronology, "run_authorized_source5_job_locked", None)),
            "inventory-pinned chronology lacks the Source5 locked execution API")
    require(callable(getattr(soak_adapter, "prepare_source5_soak", None)) and
            callable(getattr(soak_adapter, "run_source5_soak", None)) and
            callable(getattr(soak_adapter, "verify_source5_soak_component", None)) and
            callable(getattr(soak_readback, "launch_soak_v2_application", None)),
            "inventory-pinned Source5 Soak/readback modules lack their captured V2 adapter API")
    if schema in (EXECUTION_SCHEMA_V2, EXECUTION_SCHEMA_V3):
        require(callable(getattr(
                    chronology, "register_source5_prepared_capacity_locked", None,
                )),
                "inventory-pinned chronology lacks the prepared-capacity registration bridge API")
    prepared_completion = None
    try:
        for other_host, other_source in sources.items():
            campaign.verify_source_manifest(
                other_source,
                source_root=source_root if other_host == host_id else None,
                verify_artifacts=(other_host == host_id),
            )
        validation = campaign.validate_spec(spec, sources, input_root=input_root)
        campaign.verify_plan(
            plan, source["runtime_readback_validator"]["sha256"],
            validation["campaign_inputs_module_sha256"],
        )
        if spec["rates"] and spec["oracles"]:
            scope = "final_frozen"
            require(callable(getattr(
                        chronology, "verify_source5_completed_fixed_phase_locked", None,
                    )),
                    "inventory-pinned chronology lacks the bounded raw-journal fixed-phase verifier")
            for phase in ("exploration", "aa", "confirmation", "pressure", "soak"):
                require(plan["jobs"][phase] == campaign.build_jobs(spec, phase),
                        f"PlanV3 {phase} jobs differ from the original controller derivation")
        else:
            require(not spec["rates"] and not spec["oracles"],
                    "prospective Source5 scope cannot contain only one of frozen rates/oracles")
            scope = "prospective_exploration"
            require(plan["jobs"]["exploration"] == campaign.build_jobs(spec, "exploration") and
                    plan["jobs"]["pressure"] == [] and
                    plan["jobs"]["confirmation"] == [],
                    "prospective Source5 PlanV3 does not contain the exact exploration-only matrix")
        if schema in (EXECUTION_SCHEMA_V2, EXECUTION_SCHEMA_V3):
            expected_scope = ("final_prepared_bounded" if schema == EXECUTION_SCHEMA_V3
                              else "final_prepared")
            require(scope == "final_frozen" and manifest_scope == expected_scope,
                    "prepared-input execution requires the complete frozen final SpecV3/PlanV3")
            preparation = loaded["scripts/application-source5-input-preparation.py"]
            completion_pin = exact(prepared_generation["completion"], {
                "path", "raw_sha256", "semantic_sha256",
            }, "Source5 prepared-input completion pin")
            require(is_sha(completion_pin["raw_sha256"]) and
                    is_sha(completion_pin["semantic_sha256"]),
                    "Source5 prepared-input completion raw/semantic pins are malformed")
            completion_path = Path(completion_pin["path"])
            require(completion_path ==
                    Path(plan_raw_pin["path"]).parent /
                    "prepared-inputs-completion.json",
                    "prepared-input completion is not beside the exact final PlanV3 generation")
            prepared_completion = preparation.verify_prepared_inputs_completion(
                completion_pin, prepared_generation["provenance"],
                source_root, input_root,
            )
            require(type(prepared_completion) is dict and
                    prepared_completion.get("schema") ==
                    ("allocatbelt.application-source5-preparation-completion.v2"
                     if schema == EXECUTION_SCHEMA_V3 else
                     "allocatbelt.application-source5-preparation-completion.v1") and
                    prepared_completion.get("complete") is True and
                    prepared_completion.get("qualification_eligible") is False and
                    prepared_completion.get("campaign_id") == manifest["campaign_id"] and
                    prepared_completion.get("completion_sha256") ==
                    completion_pin["semantic_sha256"],
                    "prepared-input completion verifier returned another generation")
            require(prepared_completion["final_spec"] == {
                        "path": spec_raw_pin["path"],
                        "raw_sha256": spec_raw_sha,
                        "semantic_sha256": spec_semantic,
                        "preregistration_sha256":
                            campaign.preregistration_digest(spec),
                    } and
                    prepared_completion["final_plan"] == {
                        "path": plan_raw_pin["path"],
                        "raw_sha256": plan_raw_sha,
                        "semantic_sha256": plan_semantic,
                    },
                    "prepared-input completion differs from the exact final SpecV3/PlanV3 generation")
            for prepared_host, prepared_source in prepared_completion["source_manifests"].items():
                require(prepared_host in source_manifest_pins and
                        prepared_source == {
                            "path": source_manifest_pins[prepared_host]["path"],
                            "raw_sha256": source_manifest_pins[prepared_host]["raw_sha256"],
                            "semantic_sha256": sources[prepared_host]["manifest_sha256"],
                            "source_tree_sha256":
                                sources[prepared_host]["source"]["source_tree_sha256"],
                        },
                        f"prepared-input completion changed {prepared_host} source-generation pins")
            require(set(prepared_completion["source_manifests"]) ==
                    set(manifest["hosts"]),
                    "prepared-input completion does not cover the exact original host order")
            selected_rows = [item for item in
                             prepared_completion["capacity_preparations"]
                             if item.get("host_id") == host_id]
            require(len(selected_rows) == 1 and
                    capacity_registration["completion"] == completion_pin and
                    {key: capacity_registration["host_completion"][key]
                     for key in ("path", "raw_sha256")} ==
                        selected_rows[0]["completion"] and
                    capacity_registration["host_completion"]["semantic_sha256"] ==
                        selected_rows[0]["completion_sha256"] and
                    capacity_registration["host_verification"] ==
                        selected_rows[0]["host_verification"] and
                    capacity_registration["ledger"] == selected_rows[0]["ledger"] and
                    capacity_registration["capacity_schedule_sha256"] ==
                        selected_rows[0]["capacity_preparation_templates_sha256"] and
                    is_sha(capacity_registration["registration_head"]),
                    "prepared-capacity registration manifest differs from the selected verified 15-entry bridge row")
            if schema == EXECUTION_SCHEMA_V3:
                selected_budget = selected_rows[0].get("resource_budget")
                require(prepared_completion.get("resource_budgets", {}).get(host_id) == selected_budget and
                        type(selected_budget) is dict and
                        selected_rows[0].get("resource_monitor", {}).get("schema") ==
                            "allocatbelt.application-capacity-preparation-resource-monitor.v1" and
                        selected_rows[0]["resource_monitor"].get("report_count") == 30,
                        "bounded prepared-input generation does not bind the selected host budget and all monitor receipts")
    except Exception as error:
        raise Source5CampaignError(f"pinned campaign verifier rejected original inputs: {error}") from error
    require(plan["execution_ready"] is False and plan["full_gate_ready"] is False,
            "Source5 cannot change frozen execution/full-gate readiness bits")
    observed = exact(manifest["observed_hosts"], set(manifest["hosts"]),
                     "Source5 observed host map")[host_id]
    observed_artifact = raw_pin(observed["artifact"], "Source5 observed host")
    if schema == EXECUTION_SCHEMA:
        capacity_completion = exact(manifest["capacity_completions"],
                                    set(manifest["hosts"]),
                                    "Source5 capacity completion map")[host_id]
    else:
        ledger = exact(capacity_registration["ledger"], {
            "path", "raw_sha256", "terminal_head",
        }, "Source5 prepared-capacity ledger pin")
        capacity_completion = {
            "artifact": {
                "path": capacity_registration["host_completion"]["path"],
                "raw_sha256": capacity_registration["host_completion"]["raw_sha256"],
            },
            "schedule_sha256": capacity_registration["capacity_schedule_sha256"],
            "ledger_raw_sha256": ledger["raw_sha256"],
            "terminal_head": ledger["terminal_head"],
            "registration_head": capacity_registration["registration_head"],
        }
    return CampaignContext(
        manifest=manifest,
        manifest_pin={"path": str(manifest_path.resolve(strict=True)),
                      "raw_sha256": manifest_sha},
        scope=scope,
        host_id=host_id, spec=spec, plan=plan,
        spec_pin={"path": spec_raw_pin["path"], "raw_sha256": spec_raw_sha},
        plan_pin={"path": plan_raw_pin["path"], "raw_sha256": plan_raw_sha},
        spec_semantic_sha256=spec_semantic, plan_semantic_sha256=plan_semantic,
        source_root=source_root, input_root=input_root,
        artifact_root=artifact_root,
        output_root=output_root,
        source=source, sources=sources,
        source_manifest_pins=source_manifest_pins,
        observed_host_pin=observed_artifact,
        capacity_completion=capacity_completion,
        prepared_input_completion=prepared_completion,
        campaign=campaign, chronology=chronology, fixed_pair=fixed_pair,
        pressure_pair=pressure_pair, modules=loaded,
    )


def _validate_locked_context(context: CampaignContext, lock: Any) -> dict[str, Any]:
    chronology = context.chronology
    require(chronology._lock_token_is_live(lock),
            "Source5 controller lock is not the active chronology token")
    manifest, prepared, state, _manifest_pin = chronology._prepare_source5_context(
        lock, api_pin(context.manifest_pin),
    )
    chronology._validate_source5_manifest_value(
        manifest,
        canonical_bytes(manifest),
        prepared,
        verify_selected_files=True,
    )
    completion = context.capacity_completion
    completion_pin = raw_pin(completion["artifact"], "Source5 capacity completion")
    if context.prepared_input_completion is None:
        replay = chronology.verify_campaign_chronology_locked(
            lock, api_pin(context.plan_pin), api_pin(context.spec_pin),
            context.source_root, context.input_root, context.host_id,
            api_pin(context.observed_host_pin), context.output_root,
            api_pin(completion_pin), capacity_output_root=context.output_root,
        )
        require(replay["entry_count"] == 15 and
                replay["registration_head"] == completion["registration_head"] and
                replay["capacity_completion_raw_sha256"] == completion_pin["raw_sha256"] and
                replay["capacity_schedule_sha256"] == completion["schedule_sha256"] and
                replay["capacity_ledger_raw_sha256"] == completion["ledger_raw_sha256"] and
                replay["capacity_ledger_terminal_head"] == completion["terminal_head"] and
                replay["pending_authorization"] is False and
                replay["cleanup_blocked"] is False,
                "Source5 phase cannot begin without the exact clean locked 15-entry legacy capacity registration")
    else:
        registration = state["prepared_capacity_registration"]
        require(registration is not None and state["registration"] is None and
                state["registration_head"] == completion["registration_head"] and
                registration["completion"] == context.manifest[
                    "prepared_capacity_registration"]["completion"] and
                {key: registration["host_completion"][key]
                 for key in ("path", "raw_sha256")} == completion["artifact"] and
                registration["host_verification"] ==
                    context.manifest["prepared_capacity_registration"]["host_verification"] and
                registration["capacity_ledger"]["raw_sha256"] ==
                    completion["ledger_raw_sha256"] and
                registration["capacity_ledger"]["terminal_head"] ==
                    completion["terminal_head"] and
                registration["capacity_schedule_sha256"] ==
                    completion["schedule_sha256"] and
                state["pending"] is None and state["source5_pending"] is None and
                state["cleanup_blocked"] is False and
                state["source5_cleanup_blocked"] is False,
                "Source5 phase lacks the explicit replayed prepared-capacity registration and clean 15-entry ledger")
        replay = {
            "schema": "allocatbelt.application-source5-prepared-capacity-registration.v1",
            "registration_head": state["registration_head"],
            "capacity_completion_raw_sha256": completion["artifact"]["raw_sha256"],
            "capacity_schedule_sha256": completion["schedule_sha256"],
            "capacity_ledger_raw_sha256": completion["ledger_raw_sha256"],
            "capacity_ledger_terminal_head": completion["terminal_head"],
            "entry_count": 15, "pending_authorization": False,
            "cleanup_blocked": False, "qualification_eligible": False,
            "controller_chronology_proven": False,
        }
    return {"prepared": prepared, "state": state, "capacity_replay": replay}


def _private_directory(path: Path) -> Path:
    require(path.is_absolute(), "private Source5 directory must be absolute")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                f"private Source5 directory has unsafe ownership or mode: {path}")
    else:
        if not path.parent.exists():
            _private_directory(path.parent)
        parent_info = path.parent.lstat()
        require(stat.S_ISDIR(parent_info.st_mode) and
                not stat.S_ISLNK(parent_info.st_mode) and
                parent_info.st_uid == os.getuid() and
                stat.S_IMODE(parent_info.st_mode) == 0o700,
                f"Source5 parent directory is not owned private storage: {path.parent}")
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700,
                f"cannot establish a private Source5 directory: {path}")
        fd = os.open(path.parent, os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    require(path.resolve(strict=True) == path,
            f"private Source5 directory contains an alias: {path}")
    return path


def _host_jobs(context: CampaignContext, phase: str) -> list[dict[str, Any]]:
    jobs = [job for job in context.plan["jobs"][phase]
            if job.get("host_id") == context.host_id]
    require(jobs, f"original frozen plan has no {phase} jobs for {context.host_id}")
    return jobs


def _phase_root(context: CampaignContext, phase: str) -> Path:
    root = context.output_root / context.manifest["campaign_id"] / "source5" / context.host_id / phase
    require(root.is_relative_to(context.output_root), "Source5 phase output escaped output_root")
    return root


def _helper_prerequisites(
    state: dict[str, Any], phase: str,
) -> list[dict[str, Any]]:
    required = {
        "exploration": (),
        "aa": ("exploration",),
        "confirmation": ("exploration", "aa"),
        "pressure": ("fixed_analysis",),
        "soak": ("pressure_analysis",),
    }[phase]
    result: list[dict[str, Any]] = []
    for predecessor in required:
        analysis = state["source5_analyses"].get(predecessor)
        require(analysis is not None and analysis["phase_gate_passed"] is True,
                f"{phase} cannot launch before the exact passing {predecessor} analysis")
        result.append({
            "phase": predecessor,
            "analysis": analysis["analysis"],
            "analysis_sha256": analysis["analysis_sha256"],
            "event_head": analysis["event_head"],
        })
    return result


def _phase_ledger_records(path: Path) -> list[dict[str, Any]]:
    raw, _digest, _info = read_stable(path, "Source5 phase job ledger", MAX_LEDGER_BYTES)
    lines = raw.splitlines(keepends=True)
    require(all(line.endswith(b"\n") and b"\r" not in line for line in lines),
            "Source5 phase ledger framing differs")
    result: list[dict[str, Any]] = []
    previous_ids: set[str] = set()
    for index, line in enumerate(lines):
        try:
            value = json.loads(line)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise Source5CampaignError(f"Source5 phase ledger line {index + 1} is invalid JSON") from error
        record = exact(value, {
            "schema", "state", "job", "pair_directory", "process_metrics",
            "evidence", "chronology", "qualification_eligible", "record_sha256",
        }, f"Source5 phase ledger record[{index}]")
        body = {key: item for key, item in record.items() if key != "record_sha256"}
        require(line == canonical_bytes(record) and
                record["schema"] == JOB_RECORD_SCHEMA and
                record["record_sha256"] == sha256(canonical_bytes(body)) and
                record["qualification_eligible"] is False,
                f"Source5 phase ledger record[{index}] digest/schema/eligibility differs")
        run_id = record["job"].get("run_id")
        require(type(run_id) is str and run_id not in previous_ids,
                "Source5 phase ledger repeats an original run ID")
        previous_ids.add(run_id)
        result.append(record)
    return result


def _append_phase_record(ledger: Path, record: dict[str, Any]) -> None:
    raw = canonical_bytes(record)
    require(len(raw) <= 4 * 1024 * 1024,
            "Source5 job record exceeds its finite line bound")
    fd = os.open(ledger, os.O_WRONLY | os.O_APPEND |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600,
                "Source5 job ledger is not an owned mode-0600 regular file")
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_dispositions(
    directory: Path, jobs: list[dict[str, Any]], reason: str,
) -> dict[str, str]:
    material = {
        "schema": "allocatbelt.application-source5-not-run-dispositions.v1",
        "campaign_id": directory.parents[2].name,
        "host_id": directory.parents[0].name,
        "phase": directory.name,
        "reason": reason,
        "jobs": jobs,
        "qualification_eligible": False,
    }
    material["disposition_sha256"] = sha256(canonical_bytes(material))
    path = directory / "not-run-dispositions.json"
    raw = canonical_bytes(material)
    checksum = write_new(path, raw, "Source5 not-run dispositions")
    return {"path": str(path), "raw_sha256": checksum}


def _write_job_disposition(
    phase_root: Path, job: dict[str, Any], state: str, reason: str,
    *, authorization_id: str | None = None,
    terminal_head: str | None = None,
    component_sha256: str | None = None,
    error_sha256: str | None = None,
) -> dict[str, str]:
    body = {
        "schema": "allocatbelt.application-source5-job-disposition.v1",
        "job": job, "state": state, "reason": reason,
        "authorization_id": authorization_id,
        "job_terminal_head": terminal_head,
        "component_sha256": component_sha256,
        "error_sha256": error_sha256,
        "qualification_eligible": False,
    }
    body["disposition_sha256"] = sha256(canonical_bytes(body))
    path = phase_root / "job-records" / f"{job['run_id']}.disposition.json"
    checksum = write_new(path, canonical_bytes(body), "Source5 job disposition")
    return {"path": str(path), "raw_sha256": checksum}


def _seal_blocked_suffix(
    phase_root: Path, jobs: list[dict[str, Any]], index: int,
    error: BaseException, result: dict[str, Any] | None = None,
) -> dict[str, str]:
    disposition: dict[str, Any] = {
        "job": jobs[index],
        "reason": f"blocked_without_retry:{type(error).__name__}",
        "error_sha256": sha256(
            f"{type(error).__name__}:{error}".encode("utf-8", "replace"),
        ),
    }
    if type(result) is dict:
        chronology = result.get("chronology")
        if type(chronology) is dict:
            disposition.update({
                key: chronology[key] for key in
                ("authorization_id", "job_terminal_head") if key in chronology
            })
        component_sha = result.get("component_sha256")
        if is_sha(component_sha):
            disposition["component_sha256"] = component_sha
    dispositions = [disposition]
    dispositions.extend({"job": pending, "reason": "not_run_after_blocked_job"}
                        for pending in jobs[index + 1:])
    return _write_dispositions(phase_root, dispositions,
                               f"blocked original job {jobs[index]['run_id']}")


def _source5_fixed_original_pins(context: CampaignContext) -> dict[str, Any]:
    return {
        "spec": api_pin(context.spec_pin),
        "spec_semantic_sha256": context.spec_semantic_sha256,
        "plan": api_pin(context.plan_pin),
        "plan_semantic_sha256": context.plan_semantic_sha256,
        "source_manifests": {
            host: api_pin(pin) for host, pin in context.source_manifest_pins.items()
        },
        "campaign_artifacts_root": context.manifest["original_inputs"]["campaign_artifacts_root"],
    }


def _source5_fixed_execution_pins(context: CampaignContext) -> dict[str, Any]:
    fixed_module = context.fixed_pair
    pins = {}
    for name, relative in fixed_module.MODULE_PATHS.items():
        pins[name] = context.manifest["modules"][context.host_id][relative]
    return {
        "source_root": str(context.source_root),
        "selected_host_id": context.host_id,
        "modules": pins,
    }


def _helper_input_value(
    context: CampaignContext, phase: str, job_index: int,
    job: dict[str, Any], members: list[dict[str, Any]], payload: dict[str, Any],
    prerequisites: list[dict[str, Any]], helper: dict[str, str],
) -> dict[str, Any]:
    outer = context.spec["deadlines"].get(
        "soak_outer_seconds" if phase == "soak" else "outer_seconds",
    )
    require(type(outer) is int and outer > 0,
            f"Source5 {phase} has no original finite outer deadline")
    body = {
        "schema": HELPER_INPUT_SCHEMA,
        "scope": context.scope,
        "campaign_id": context.manifest["campaign_id"],
        "host_id": context.host_id,
        "phase": phase,
        "job_index": job_index,
        "job": job,
        "job_sha256": sha256(canonical_bytes(job)),
        "members": members,
        "helper": helper,
        "payload": payload,
        "prerequisites": prerequisites,
        "outer_deadline_seconds": outer,
        "effective_timeout_seconds": outer,
    }
    return {
        **body,
        "input_snapshot_sha256": sha256(canonical_bytes(body)),
        "qualification_eligible": False,
    }


def _member_descriptors_from_overlay(overlay: dict[str, Any]) -> list[dict[str, str]]:
    members = overlay.get("members")
    require(type(members) is list and len(members) == 2,
            "fixed overlay does not contain exactly two original members")
    descriptors = []
    for index, member in enumerate(members):
        exact(member, set(member), f"fixed overlay member[{index}]")
        descriptor = exact(member.get("descriptor"),
                            {"pair", "executor", "allocator"},
                            f"fixed overlay member[{index}] descriptor")
        descriptors.append(descriptor)
    return descriptors


def _build_fixed_helper_input(
    context: CampaignContext, phase: str, job_index: int,
    job: dict[str, Any], prerequisites: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, str], Path]:
    helper = context.modules["scripts/application-fixed-pair.py"]
    fixed_jobs_root = _private_directory(
        context.artifact_root / context.manifest["campaign_id"] / "source5" /
        context.host_id / "job-artifacts" / phase,
    )
    job_root = fixed_jobs_root / job["run_id"]
    require(not job_root.exists() and not job_root.is_symlink(),
            f"Source5 ordinal output already exists and cannot be retried: {job['run_id']}")
    original = _source5_fixed_original_pins(context)
    execution = _source5_fixed_execution_pins(context)
    overlay_pin = context.fixed_pair.build_fixed_pair_overlay(
        original, execution, job, api_pin(context.observed_host_pin), job_root,
    )
    overlay, _overlay_raw, _overlay_sha, _fixed_context, _reconstructed = \
        context.fixed_pair._read_overlay(overlay_pin)
    helper_value = _helper_input_value(
        context, phase, job_index, job,
        _member_descriptors_from_overlay(overlay),
        {"overlay_pin": overlay_pin}, prerequisites,
        {"path": "scripts/application-fixed-pair.py",
         "sha256": context.manifest["modules"][context.host_id][
             "scripts/application-fixed-pair.py"]["sha256"],
         "entrypoint": "run_fixed_pair_overlay"},
    )
    helper_dir = _private_directory(
        context.artifact_root / context.manifest["campaign_id"] / "source5" /
        context.host_id / "helper-inputs",
    )
    helper_path = helper_dir / f"{phase}-{job['run_id']}.json"
    helper_raw = canonical_bytes(helper_value)
    helper_sha = write_new(helper_path, helper_raw, "Source5 fixed helper input")
    return helper_value, {"path": str(helper_path), "raw_sha256": helper_sha}, job_root


def _write_record_file(
    phase_root: Path, ledger_path: Path, record: dict[str, Any],
) -> dict[str, str]:
    record_dir = _private_directory(phase_root / "job-records")
    path = record_dir / f"{record['job']['run_id']}.json"
    raw = canonical_bytes(record)
    raw_sha = write_new(path, raw, "Source5 job record")
    _append_phase_record(ledger_path, record)
    return {"path": str(path), "raw_sha256": raw_sha}


def _fixed_record_from_result(
    context: CampaignContext, result: dict[str, Any], phase: str,
) -> dict[str, Any]:
    state = result["state"]
    require(state in {"valid_pair", "invalid_pair"},
            "Source5 fixed component result is not a complete pair disposition")
    evidence_result = result["evidence"]
    overlay_ref = raw_pin(evidence_result.get("overlay"), "Source5 fixed overlay")
    receipt_ref = raw_pin(evidence_result.get("receipt"), "Source5 fixed receipt")
    overlay, _overlay_raw, _overlay_sha, _fixed_context, _reconstructed = \
        context.fixed_pair._read_overlay(api_pin(overlay_ref))
    verification = context.fixed_pair.verify_fixed_pair_overlay(
        api_pin(overlay_ref), api_pin(receipt_ref),
    )
    receipt, receipt_raw, receipt_sha = read_json(
        Path(receipt_ref["path"]), "Source5 fixed receipt",
        context.fixed_pair.MAX_RECEIPT_BYTES, receipt_ref["raw_sha256"],
    )
    component_status = "valid_pair" if state == "valid_pair" else "failed_or_invalid"
    require(verification.get("verified") is True and
            verification.get("status") == receipt.get("status") == component_status and
            receipt.get("qualification_eligible") is False and
            receipt.get("inputs_unchanged") is True and
            receipt_raw == canonical_bytes(receipt),
            "Source5 fixed result did not freshly replay to its canonical receipt")
    metrics = receipt.get("process_metrics")
    require(type(metrics) is list,
            "Source5 fixed receipt metrics are malformed")
    processes_path = Path(overlay["output_root"]) / "processes.tsv"
    processes_pin: dict[str, str] | None = None
    if receipt.get("processes_sha256") is not None:
        _process_raw, process_sha, _info = read_stable(
            processes_path, "Source5 fixed process ledger",
            context.fixed_pair.MAX_RUNTIME_BYTES,
        )
        require(process_sha == receipt["processes_sha256"],
                "Source5 fixed process ledger differs from the verified receipt")
        processes_pin = {"path": str(processes_path), "raw_sha256": process_sha}
    runtime_pin = overlay["runtime_bindings"]["pin"]
    runtime_path = Path(runtime_pin["path"])
    _runtime_raw, runtime_sha, _runtime_info = read_stable(
        runtime_path, "Source5 fixed runtime bindings",
        context.fixed_pair.MAX_RUNTIME_BYTES,
    )
    require(runtime_sha == runtime_pin["sha256"],
            "Source5 fixed runtime bindings differ from the reconstructed overlay")
    selected_manifest = overlay["sources"]["manifests"][context.host_id]
    source_snapshot = {
        "artifact": {
            "path": selected_manifest["pin"]["path"],
            "raw_sha256": selected_manifest["pin"]["sha256"],
        },
        "semantic_sha256": selected_manifest["manifest_sha256"],
        "source_tree_sha256": overlay["sources"]["selected"]["source_tree_sha256"],
    }
    chronology = result["chronology"]
    start_events = chronology["app_start_events"]
    terminal_events = chronology["app_terminal_events"]
    identities = []
    for index, event in enumerate(start_events):
        proof = event["proof"]
        identities.append({
            "descriptor": event["descriptor"],
            "pid": proof["pid"],
            "start_ticks": proof["start_ticks"],
            "member_index": index,
        })
    record_chronology = {
        "authorization_id": chronology["authorization_id"],
        "authorization_head": chronology["authorization_head"],
        "app_started_heads": chronology["app_started_heads"],
        "app_terminal_heads": chronology["app_terminal_heads"],
        "job_terminal_head": chronology["job_terminal_head"],
        "component_sha256": result["component_sha256"],
        "process_metrics_sha256": result["process_metrics_sha256"],
        "app_start_events": start_events,
        "app_terminal_events": terminal_events,
        "member_processes": identities,
    }
    body = {
        "schema": JOB_RECORD_SCHEMA,
        "state": state,
        "job": result["job"],
        "pair_directory": overlay["output_root"],
        "process_metrics": metrics,
        "evidence": {
            "kind": "source5_fixed_pair",
            "execution_manifest": evidence_result["execution_manifest"],
            "helper_input": evidence_result["helper_input"],
            "helper_module": evidence_result["helper_module"],
            "overlay": overlay_ref,
            "receipt": {"path": str(Path(receipt_ref["path"])),
                        "raw_sha256": receipt_sha},
            "processes": processes_pin,
            "runtime_bindings": {
                "path": runtime_pin["path"], "raw_sha256": runtime_sha,
            },
            "source_snapshot": source_snapshot,
        },
        "chronology": record_chronology,
        "qualification_eligible": False,
    }
    body["record_sha256"] = sha256(canonical_bytes(body))
    return body


def _fresh_fixed_phase_records(
    context: CampaignContext, lock: Any, phase: str,
    phase_root: Path, ledger_path: Path,
) -> list[dict[str, Any]]:
    records = _phase_ledger_records(ledger_path)
    expected = _host_jobs(context, phase)
    context.campaign.validate_phase_ledger(records, expected, phase, context.host_id)
    for record in records:
        require(record.get("evidence", {}).get("kind") == "source5_fixed_pair",
                f"{phase} contains a non-Source5 fixed component record")
        pin = _raw_record_pin(phase_root, record["job"]["run_id"])
        checked = context.chronology.verify_source5_completed_fixed_phase_locked(
            lock, api_pin(context.manifest_pin), pin,
        )
        require(checked["process_metrics"] == record["process_metrics"],
                "Source5 fixed journal replay and stored metrics differ")
    return records


def _raw_record_pin(phase_root: Path, run_id: str) -> dict[str, str]:
    path = phase_root / "job-records" / f"{run_id}.json"
    raw, raw_sha, _info = read_stable(path, "Source5 per-job record", 4 * 1024 * 1024)
    return {"path": str(path), "raw_sha256": raw_sha}


def _capacity_pilot(
    context: CampaignContext, records: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = _host_jobs(context, "exploration")
    by_key: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    for record in records:
        job = record["job"]
        key = (job["family"], job["profile"], job["allocator"], job["ordinal"])
        require(key not in by_key and record["state"] == "valid_pair",
                "Source5 exploration contains a repeated or invalid original capacity pair")
        by_key[key] = record
    require(len(records) == len(expected) and len(by_key) == len(expected),
            "Source5 exploration does not retain the exact original six-pair treatment matrix")
    cells: list[dict[str, Any]] = []
    for cell in context.spec["cells"]:
        for allocator in context.campaign.ALLOCATORS:
            pairs = []
            for ordinal in range(1, context.spec["protocol"]["exploration_pairs"] + 1):
                record = by_key[(cell["family"], cell["profile"], allocator, ordinal)]
                receipt, _raw, _sha = read_json(
                    Path(record["evidence"]["receipt"]["path"]),
                    "Source5 exploration receipt",
                    context.fixed_pair.MAX_RECEIPT_BYTES,
                    record["evidence"]["receipt"]["raw_sha256"],
                )
                rows = receipt.get("process_rows")
                require(type(rows) is list and len(rows) == 2,
                        "Source5 exploration receipt does not retain its two original process rows")
                by_executor = {row["executor"]: row for row in rows}
                require(set(by_executor) == {"bounded", "tokio"},
                        "Source5 exploration pair changed its bounded/Tokio process order or identity")
                def number(row: dict[str, Any], key: str) -> int:
                    value = row.get(key)
                    require(type(value) is str and value.isdecimal(),
                            f"Source5 exploration {key} is not a canonical process-row count")
                    return int(value)
                bounded, tokio = by_executor["bounded"], by_executor["tokio"]
                overlay_ref = raw_pin(record["evidence"]["overlay"],
                                      "Source5 capacity overlay")
                receipt_ref = raw_pin(record["evidence"]["receipt"],
                                      "Source5 capacity receipt")
                overlay_raw, overlay_sha, _overlay_info = read_stable(
                    Path(overlay_ref["path"]), "Source5 capacity overlay",
                    context.fixed_pair.MAX_PLAN_BYTES,
                )
                receipt_raw, receipt_sha, _receipt_info = read_stable(
                    Path(receipt_ref["path"]), "Source5 capacity receipt",
                    context.fixed_pair.MAX_RECEIPT_BYTES,
                )
                require(overlay_sha == overlay_ref["raw_sha256"] and
                        receipt_sha == receipt_ref["raw_sha256"],
                        "Source5 capacity pair changed after independent receipt replay")
                receipt_value = json.loads(receipt_raw)
                require(receipt_raw == canonical_bytes(receipt_value) and
                        receipt_value.get("run_id") == record["job"]["run_id"] and
                        receipt_value.get("host_id") == context.host_id and
                        receipt_value.get("status") == "valid_pair",
                        "Source5 pilot receipt identity/status differs from its original job")
                verified = context.fixed_pair.verify_fixed_pair_overlay(
                    api_pin(overlay_ref), api_pin(receipt_ref),
                )
                require(verified.get("verified") is True and
                        verified.get("status") == "valid_pair" and
                        verified.get("receipt_sha256") == receipt_sha,
                        "Source5 pilot pair failed its final raw-pinned fixed receipt replay")
                pairs.append({
                    "ordinal": ordinal,
                    "bounded_status": "valid", "tokio_status": "valid",
                    "bounded_on_time": number(bounded, "completed_on_time"),
                    "bounded_late": number(bounded, "completed_late"),
                    "bounded_attempted": number(bounded, "attempted"),
                    "bounded_admitted": number(bounded, "admitted"),
                    "bounded_rejected": number(bounded, "rejected_full") +
                                         number(bounded, "rejected_resource"),
                    "tokio_on_time": number(tokio, "completed_on_time"),
                    "tokio_late": number(tokio, "completed_late"),
                    "tokio_attempted": number(tokio, "attempted"),
                    "tokio_admitted": number(tokio, "admitted"),
                    "tokio_rejected": number(tokio, "rejected_full") +
                                       number(tokio, "rejected_resource"),
                    "raw_pair_sha256": sha256(canonical_bytes({
                        "overlay_raw_sha256": overlay_sha,
                        "receipt_raw_sha256": receipt_sha,
                        "verified_receipt_sha256": verified["receipt_sha256"],
                        "run_id": record["job"]["run_id"],
                    })),
                })
            cells.append({
                "family": cell["family"], "profile": cell["profile"],
                "allocator": allocator, "pairs": pairs,
            })
    return {
        "schema": "allocatbelt.application-capacity-pilot.v1",
        "spec_sha256": context.campaign.preregistration_digest(context.spec),
        "host_id": context.host_id,
        "cells": cells,
    }


def _frozen_rate_rows(
    host_id: str, frozen: dict[str, Any], pilot_sha256: str,
) -> list[dict[str, Any]]:
    require(frozen.get("host_id") == host_id and is_sha(pilot_sha256),
            "Source5 frozen rate export lacks its exact host or raw pilot provenance")
    rows = []
    for rate in frozen["rates"]:
        rows.append({
            "host_id": host_id,
            "family": rate["family"], "profile": rate["profile"],
            "load_percent": rate["load_percent"],
            "arrivals_per_second": rate["arrivals_per_second"],
            "pilot_manifest_sha256": pilot_sha256,
        })
    return rows


def _validate_probe_capture_contract(
    value: object, deadlines_value: object, composition: Any,
) -> dict[str, Any]:
    """Validate explicit ProbeV2 bounds before either member can launch."""
    capture = exact(value, {"capture_timeout_ns", "storage_budget"},
                    "Source5 ProbeV2 capture budget")
    deadlines = exact(deadlines_value, {
        "trace_seconds", "drain_seconds", "shutdown_seconds", "process_seconds",
        "outer_seconds", "application_wall_timeout_seconds",
        "application_term_grace_seconds", "pressure_exit_observation_seconds",
        "pressure_duration_seconds", "pressure_total_seconds",
    }, "Source5 pressure deadlines")
    timeout = capture["capture_timeout_ns"]
    require(type(timeout) is int and
            0 < timeout <= composition.MAX_PROBE_CAPTURE_TIMEOUT_NS and
            type(deadlines["process_seconds"]) is int and
            0 < deadlines["process_seconds"] <= 14_400 and
            timeout <= deadlines["process_seconds"] * 1_000_000_000,
            "Source5 ProbeV2 capture timeout is absent or exceeds its fixed/original process bound")
    budget = exact(capture["storage_budget"], {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes",
        "output_inodes",
    }, "Source5 ProbeV2 capture storage budget")
    for name, value in budget.items():
        require(type(value) is int and 0 < value <= (1 << 64) - 1,
                f"Source5 ProbeV2 capture storage budget {name} is not a positive u64")
    require(budget["tmpdir_bytes"] <= 1024 * 1024 * 1024 and
            budget["tmpdir_inodes"] <= 4096 and
            budget["stdout_bytes"] <= 512 * 1024 and
            budget["stderr_bytes"] <= composition.MAX_PROBE_STDERR_BYTES and
            budget["owner_result_bytes"] == composition.MAX_PROBE_OWNER_RESULT_BYTES and
            budget["inventory_bytes"] == composition.MAX_PROBE_TMPDIR_INVENTORY_BYTES and
            budget["failure_bytes"] == composition.MAX_PROBE_CAPTURE_FAILURE_BYTES and
            budget["receipt_bytes"] <= composition.MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            7 <= budget["output_inodes"] <= 4096,
            "Source5 ProbeV2 storage budget exceeds its captured FixedR8 sidecar limits")
    return {"capture_timeout_ns": timeout, "storage_budget": budget}


def _pressure_materials_index(
    context: CampaignContext, index_path: Path,
) -> dict[str, dict[str, Any]]:
    bounded = context.manifest["schema"] == EXECUTION_SCHEMA_V3
    index_schema = (PRESSURE_MATERIAL_INDEX_SCHEMA_V2 if bounded
                    else PRESSURE_MATERIAL_INDEX_SCHEMA)
    material_schema = (PRESSURE_MATERIALS_SCHEMA_V2 if bounded
                       else PRESSURE_MATERIALS_SCHEMA)
    index, _raw, _sha = read_json(index_path.resolve(strict=True),
                                  "Source5 pressure material index",
                                  MAX_MANIFEST_BYTES)
    exact(index, {"schema", "campaign_id", "host_id", "jobs", "manifest_sha256"},
          "Source5 pressure material index")
    require(index["schema"] == index_schema and
            index["campaign_id"] == context.manifest["campaign_id"] and
            index["host_id"] == context.host_id and
            index["manifest_sha256"] == sha256(canonical_bytes({
                key: value for key, value in index.items()
                if key != "manifest_sha256"
            })),
            "Source5 pressure material index identity/digest is invalid")
    jobs = _host_jobs(context, "pressure")
    refs = exact(index["jobs"], {job["run_id"] for job in jobs},
                 "Source5 pressure job material pins")
    result: dict[str, dict[str, Any]] = {}
    composition = context.modules["scripts/application-feedback-composition.py"]
    for job in jobs:
        pin = raw_pin(refs[job["run_id"]],
                      f"Source5 pressure material {job['run_id']}")
        path = Path(pin["path"])
        require(path.is_relative_to(context.artifact_root),
                "Source5 pressure material is outside the private artifact root")
        value, _material_raw, _actual = read_json(
            path, f"Source5 pressure material {job['run_id']}",
            MAX_ARTIFACT_BYTES, pin["raw_sha256"],
        )
        fields = {
            "schema", "campaign_id", "host_id", "run_id", "job_sha256",
            "shared_policy", "members", "deadlines", "artifact_budgets",
        }
        if bounded:
            fields.add("probe_capture")
        exact(value, fields, f"Source5 pressure material {job['run_id']}")
        require(value["schema"] == material_schema and
                value["campaign_id"] == context.manifest["campaign_id"] and
                value["host_id"] == context.host_id and
                value["run_id"] == job["run_id"] and
                value["job_sha256"] == sha256(canonical_bytes(job)) and
                type(value["members"]) is list and len(value["members"]) == 2,
                f"Source5 pressure material {job['run_id']} differs from its original plan job")
        if bounded:
            value["probe_capture"] = _validate_probe_capture_contract(
                value["probe_capture"], value["deadlines"], composition,
            )
        shared = exact(value["shared_policy"], {"path", "raw_sha256"},
                       f"Source5 {job['run_id']} shared policy")
        _shared, _shared_raw, _shared_sha = read_json(
            Path(shared["path"]), f"Source5 {job['run_id']} shared policy",
            MAX_ARTIFACT_BYTES, shared["raw_sha256"],
        )
        result[job["run_id"]] = value
    return result


def _completion_file_pin(
    context: CampaignContext, value: object, label: str,
    *, semantic_field: str | None = None, preserve_semantic: bool = False,
) -> dict[str, str]:
    fields = {"path", "raw_sha256"}
    if semantic_field is not None:
        fields.add(semantic_field)
    pin = exact(value, fields, f"{label} prepared-completion pin")
    path = Path(pin["path"])
    require(path.is_absolute(), f"{label} prepared-completion path is not absolute")
    try:
        relative = path.relative_to(context.input_root).as_posix()
    except ValueError as error:
        raise Source5CampaignError(
            f"{label} prepared-completion path is outside the frozen input root",
        ) from error
    local = _safe_child(context.input_root, relative, label)
    _raw, actual, _info = read_stable(local, label, MAX_ARTIFACT_BYTES)
    require(actual == pin["raw_sha256"],
            f"{label} prepared-completion bytes differ from their raw pin")
    result = {"path": str(local), "raw_sha256": actual}
    if semantic_field is not None:
        require(is_sha(pin[semantic_field]),
                f"{label} prepared-completion semantic digest is malformed")
        if preserve_semantic:
            result[semantic_field] = pin[semantic_field]
    return result


def _source5_pressure_calibration_binding_v2(
    context: CampaignContext, typed: dict[str, Any],
    condition_path: Path,
) -> dict[str, Any]:
    completion = context.prepared_input_completion
    require(type(completion) is dict,
            "Source5 pressure requires the verified final prepared-input completion")
    matches = [item for item in completion.get("pressure_calibrations", [])
               if type(item) is dict and
               item.get("host_id") == context.host_id and
               item.get("capacity_key", {}).get("workload") ==
                   typed["capacity_key"]["workload"] and
               item.get("capacity_key", {}).get("profile") ==
                   typed["capacity_key"]["profile"]]
    require(len(matches) == 1,
            "prepared-input completion has no unique V2 pressure scope for this context")
    record = matches[0]
    calibration_id = record["capacity_key"]["calibration_id"]
    pressure_calibration_id = record["pressure_calibration_id"]
    require(record["condition_id"] == typed["condition_id"] and
            record["capacity_key"] == typed["capacity_key"] and
            record["preparation_condition"] == {
                "path": str(condition_path),
                "raw_sha256": typed["condition"]["raw_sha256"],
            } and
            record["readiness_thresholds"] == typed["readiness_thresholds"] and
            record["condition_id"] != pressure_calibration_id != calibration_id and
            typed["pressure_calibration"]["calibration_id"] ==
                pressure_calibration_id,
            "prepared-input pressure scope changed the original condition/capacity identities")

    calibration_artifact = _completion_file_pin(
        context, record["calibration"], "Source5 context calibration artifact",
    )
    scope_receipt = _completion_file_pin(
        context, record["scope_receipt"],
        "Source5 context calibration scope receipt",
        semantic_field="scope_sha256", preserve_semantic=True,
    )
    context_policy = _completion_file_pin(
        context, record["context_policy"],
        "Source5 context-policy bundle",
        semantic_field="context_policy_sha256",
    )
    require(record["context_policy"]["context_policy_sha256"] ==
            record["context_policy_sha256"] and
            is_sha(record["context_policy_sha256"]),
            "prepared-input context-policy semantic digest differs")
    original_calibration = typed["pressure_calibration"]
    original_artifact = _safe_child(
        context.input_root, original_calibration["artifact"]["relative_path"],
        "original pressure calibration artifact",
    )
    original_receipt = _safe_child(
        context.input_root, original_calibration["receipt"]["relative_path"],
        "original pressure calibration receipt",
    )
    require(calibration_artifact == {
                "path": str(original_artifact),
                "raw_sha256": original_calibration["artifact"]["raw_sha256"],
            } and
            scope_receipt["path"] == str(original_receipt) and
            scope_receipt["raw_sha256"] ==
                original_calibration["receipt"]["raw_sha256"],
            "prepared V2 calibration/receipt changed the archived pressure provenance pins")
    validator = context.source["qualification_harness"]["pressure_validator"]
    require(validator["sha256"] == original_calibration["validator_sha256"],
            "prepared V2 scope reader differs from the original SourceV5 validator")
    return {
        "schema": "allocatbelt.application-pressure-calibration-binding.v2",
        "calibration_id": calibration_id,
        "pressure_calibration_id": pressure_calibration_id,
        "artifact": calibration_artifact,
        "scope_receipt": scope_receipt,
        "validator_sha256": validator["sha256"],
        "context_policy": context_policy,
        "capacity_bundle_pins": record["capacity_bundle_pin"],
        "observed_host": dict(context.observed_host_pin),
    }


def _source5_pressure_condition(context: CampaignContext, job: dict[str, Any]) -> dict[str, Any]:
    inputs_module = context.modules["scripts/application-campaign-inputs.py"]
    normalized = inputs_module.validate_qualification_inputs(
        context.spec["qualification_inputs"], context.plan["host_ids"],
        context.spec["cells"], context.sources, context.input_root,
    )
    matches = [item for item in normalized["pressure_conditions"]
               if item["host_id"] == context.host_id and
               item["capacity_key"]["workload"] == job["workload"] and
               item["capacity_key"]["profile"] == job["profile"]]
    require(len(matches) == 1,
            "Source5 pressure job has no unique original calibrated condition")
    value = matches[0]
    condition_path = _safe_child(context.input_root,
                                 value["condition"]["relative_path"],
                                 "Source5 pressure condition")
    calibration = value["pressure_calibration"]
    result = {
        "condition": {"path": str(condition_path),
                      "raw_sha256": value["condition"]["raw_sha256"]},
        "condition_id": value["condition_id"],
        "condition_sha256": value["condition_sha256"],
        "pressure_calibration": {
            "artifact": {
                "path": str(_safe_child(context.input_root,
                    calibration["artifact"]["relative_path"],
                    "Source5 pressure calibration artifact")),
                "raw_sha256": calibration["artifact"]["raw_sha256"],
            },
            "receipt": {
                "path": str(_safe_child(context.input_root,
                    calibration["receipt"]["relative_path"],
                    "Source5 pressure calibration receipt")),
                "raw_sha256": calibration["receipt"]["raw_sha256"],
            },
            "validator_sha256": calibration["validator_sha256"],
            "calibration_id": calibration["calibration_id"],
        },
        "readiness_thresholds": value["readiness_thresholds"],
        "schedule": value["schedule"],
    }
    if context.prepared_input_completion is not None:
        result["pressure_calibration_v2"] = \
            _source5_pressure_calibration_binding_v2(
                context, value, condition_path,
            )
    return result


def _capacity_bundle_from_completion(
    context: CampaignContext, job: dict[str, Any],
) -> dict[str, dict[str, str]]:
    if context.prepared_input_completion is not None:
        rows = [item for item in
                context.prepared_input_completion["capacity_preparations"]
                if item.get("host_id") == context.host_id]
        require(len(rows) == 1,
                "prepared-input completion has no unique selected-host capacity preparation")
        matches = [entry for entry in rows[0]["entries"]
                   if entry.get("capacity_key", {}).get("workload") ==
                       job["workload"] and
                   entry.get("capacity_key", {}).get("profile") ==
                       job["profile"]]
        require(len(matches) == 1,
                "prepared-input completion has no unique registered capacity bundle for this job")
        entry = matches[0]
        result = {}
        for name in ("request", "artifact", "receipt"):
            pin = exact(entry[name], {"path", "sha256"},
                        f"Source5 prepared capacity {name} pin")
            _raw, actual, _info = read_stable(
                Path(pin["path"]), f"Source5 prepared capacity {name}",
                MAX_ARTIFACT_BYTES,
            )
            require(actual == pin["sha256"],
                    f"Source5 prepared capacity {name} differs from its verified raw pin")
            result[name] = {"path": pin["path"], "raw_sha256": pin["sha256"]}
        return result
    completion_pin = raw_pin(context.capacity_completion["artifact"],
                             "Source5 capacity completion")
    completion, _raw, _sha = read_json(
        Path(completion_pin["path"]), "Source5 capacity completion", 16 * 1024 * 1024,
        completion_pin["raw_sha256"],
    )
    matches = [entry for entry in completion["entries"]
               if entry.get("workload") == job["workload"] and
               entry.get("profile") == job["profile"]]
    require(len(matches) == 1,
            "Source5 pressure job has no unique registered capacity producer bundle")
    entry = matches[0]
    result = {}
    for name in ("request", "artifact", "receipt"):
        pin = exact(entry[name], {"path", "sha256"},
                    f"Source5 capacity {name} pin")
        result[name] = {"path": pin["path"], "raw_sha256": pin["sha256"]}
        read_stable(Path(pin["path"]), f"Source5 capacity {name}",
                    16 * 1024 * 1024)
    return result


def _pressure_member_outputs(root: Path) -> dict[str, str]:
    trace = root / "feedback-trace"
    names = {
        "root": root,
        "stdout": root / "stdout.log",
        "stderr": root / "stderr.log",
        "timing": root / "time.json",
        "ids": root / "ids.tsv",
        "shutdown": root / "shutdown.json",
        "capacity_families": root / "capacity-families.tsv",
        "runtime_binding": root / "runtime-binding-v2.json",
        "trace_directory": trace,
        "feedback_manifest": trace / "feedback-trace-manifest.tsv",
        "feedback_events": trace / "feedback-events.jsonl",
        "feedback_samples": trace / "resource-samples.tsv",
        "feedback_validation": root / "feedback-validation.json",
        "pressure_readback": root / "pressure-readback.json",
        "app_launch_attestation": root / "app-launch-attestation.json",
        "supervision_receipt": root / "app-supervision-receipt.json",
        "cleanup_receipt": root / "app-cleanup-receipt.json",
        "runtime_expectation": root / "runtime-expectation.json",
        "finalization_request": root / "feedback-finalization-request.json",
        "finalization_receipt": root / "feedback-finalization-receipt.json",
    }
    return {key: str(value) for key, value in names.items()}


def _probe_capture_evidence_map(
    context: CampaignContext, composition: Any, request: dict[str, Any],
    capture: dict[str, Any], capture_pin: dict[str, str],
    capacity_bundle: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Build the closed identity map required for strict ProbeV2 replay."""
    reader = context.modules["scripts/application-feedback-readback.py"]
    source_path = Path(context.source_manifest_pins[context.host_id]["path"])
    source_manifest, _source_raw, _source_sha = read_json(
        source_path, "Source5 ProbeV2 source manifest", MAX_ARTIFACT_BYTES,
        context.source_manifest_pins[context.host_id]["raw_sha256"],
    )
    probe, _probe_raw, _probe_sha = read_json(
        Path(request["construction_probe"]["path"]),
        "Source5 ProbeV2 construction probe", composition.MAX_PROBE_BYTES,
        request["construction_probe"]["raw_sha256"],
    )
    capacity_request, _request_raw, _request_sha = read_json(
        Path(capacity_bundle["request"]["path"]),
        "Source5 ProbeV2 capacity request", MAX_ARTIFACT_BYTES,
        capacity_bundle["request"]["raw_sha256"],
    )
    expectation_pin = exact(capacity_request["expectation"], {"path", "sha256"},
                            "Source5 ProbeV2 capacity expectation pin")
    expectation, _expectation_raw, _expectation_sha = read_json(
        Path(expectation_pin["path"]), "Source5 ProbeV2 capacity expectation",
        MAX_ARTIFACT_BYTES, expectation_pin["sha256"],
    )
    capacity_receipt, _capacity_receipt_raw, _capacity_receipt_sha = read_json(
        Path(capacity_bundle["receipt"]["path"]),
        "Source5 ProbeV2 capacity receipt", MAX_ARTIFACT_BYTES,
        capacity_bundle["receipt"]["raw_sha256"],
    )
    observed_host, _observed_raw, _observed_sha = read_json(
        Path(context.observed_host_pin["path"]),
        "Source5 ProbeV2 observed-host context", MAX_ARTIFACT_BYTES,
        context.observed_host_pin["raw_sha256"],
    )
    owner_pin = exact(capture["owner_result_pin"], {
        "path", "raw_sha256", "owner_result_sha256",
    }, "Source5 ProbeV2 owner-result pin")
    owner_result, _owner_raw, _owner_sha = read_json(
        Path(owner_pin["path"]), "Source5 ProbeV2 owner result",
        composition.MAX_PROBE_OWNER_RESULT_BYTES, owner_pin["raw_sha256"],
    )
    inventory_pin = exact(capture["tmpdir_inventory_pin"], {
        "path", "raw_sha256", "inventory_sha256",
    }, "Source5 ProbeV2 TMPDIR inventory pin")
    inventory, _inventory_raw, _inventory_sha = read_json(
        Path(inventory_pin["path"]), "Source5 ProbeV2 TMPDIR inventory",
        composition.MAX_PROBE_TMPDIR_INVENTORY_BYTES,
        inventory_pin["raw_sha256"],
    )

    paths: set[str] = {str(context.source_root), str(source_path)}
    for value in (request, source_manifest, probe, capacity_request, expectation,
                  capacity_receipt, observed_host, capture, owner_result, inventory):
        paths.update(composition._absolute_paths(value))
    for item in source_manifest["source"]["files"]:
        relative = PurePosixPath(item["path"])
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == item["path"],
                "Source5 ProbeV2 source inventory path is not portable")
        paths.add(str(context.source_root.joinpath(*relative.parts)))
    for item in source_manifest["artifacts"].values():
        relative = PurePosixPath(item["path"])
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == item["path"],
                "Source5 ProbeV2 artifact inventory path is not portable")
        paths.add(str(context.source_root.joinpath(*relative.parts)))
    paths.add(context.observed_host_pin["path"])
    paths.add(capture_pin["path"])
    paths.add(str(Path(capture_pin["path"]).parent))
    paths.add(str(Path(capture["tmpdir_initial"]["path"])))
    paths.update(pin["path"] for pin in capacity_bundle.values())
    trace_root = Path(capacity_request["trace_directory"])
    paths.add(str(trace_root))
    paths.update(str(trace_root / name) for name in composition.CAPACITY_TRACE_FILES)
    paths.update(item["path"] for item in inventory["entries"])

    directories: set[str] = set()
    files: set[str] = set()
    for rendered in paths:
        path = Path(rendered)
        require(path.is_absolute(), "Source5 ProbeV2 evidence path is not absolute")
        try:
            require(path.resolve(strict=True) == path,
                    "Source5 ProbeV2 evidence path traverses a symlink or alias")
            info = path.lstat()
        except OSError as error:
            raise Source5CampaignError(
                f"Source5 ProbeV2 evidence path is unavailable: {error}"
            ) from error
        require(not stat.S_ISLNK(info.st_mode) and
                (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                "Source5 ProbeV2 evidence path is not a regular file or directory")
        (directories if stat.S_ISDIR(info.st_mode) else files).add(rendered)
    mapped = directories | files
    require(1 <= len(mapped) <= 16_384,
            "Source5 ProbeV2 evidence path map exceeds its finite entry bound")
    return {
        "schema": reader.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
        "evidence_path_map": {
            "schema": reader.EVIDENCE_PATH_MAP_SCHEMA,
            "entries": [{"origin": path, "local": path}
                        for path in sorted(mapped)],
        },
        "probe_capture_pin": capture_pin,
        "capacity_bundle": capacity_bundle,
    }


def _capture_source5_probe_bundle(
    context: CampaignContext, recipe_root: Path, job: dict[str, Any],
    members: list[dict[str, Any]], capacity_bundle: dict[str, dict[str, str]],
    probe_capture: dict[str, Any],
) -> dict[str, Any]:
    """Capture and offline-replay both original ProbeV2s before authorization."""
    composition = context.modules["scripts/application-feedback-composition.py"]
    reader = context.modules["scripts/application-feedback-readback.py"]
    capacity_request, _capacity_request_raw, _capacity_request_sha = read_json(
        Path(capacity_bundle["request"]["path"]),
        "Source5 pressure capacity request", MAX_ARTIFACT_BYTES,
        capacity_bundle["request"]["raw_sha256"],
    )
    source_pin = context.source_manifest_pins[context.host_id]
    capacity_floor_policy_id = context.spec.get("capacity_floor_policy_id")
    if capacity_floor_policy_id is not None:
        require(capacity_floor_policy_id == getattr(
            composition, "CAPACITY_FLOOR_POLICY_ID", None,
        ), "Source5 pressure SpecV3 selects an unknown capacity-floor policy")
        try:
            source_floor_policy = reader._validate_capacity_floor_policy_descriptor(
                context.source["feedback_policy"]["policy"].get("capacity_floor_policy"),
            )
        except Exception as error:
            raise Source5CampaignError(
                f"SourceV5 feedback reader rejected the selected floor policy: {error}"
            ) from error
        require(source_floor_policy["policy_id"] == capacity_floor_policy_id,
                "Source5 selected floor policy differs from its source artifact")
    else:
        require("capacity_floor_policy" not in
                context.source["feedback_policy"]["policy"],
                "static Source5 pressure cannot use a selected floor-policy artifact")
    expected_bundle = {
        name: {"path": capacity_bundle[name]["path"],
               "raw_sha256": capacity_bundle[name]["raw_sha256"]}
        for name in ("request", "artifact", "receipt")
    }
    prepared: list[tuple[dict[str, Any], str, dict[str, Any], dict[str, str]]] = []
    for index, member in enumerate(members):
        template_pin = exact(member["feedback_template"],
                             {"value", "template_sha256"},
                             f"Source5 pressure feedback template[{index}]")
        template = template_pin["value"]
        require(type(template) is dict and
                template.get("template_sha256") == template_pin["template_sha256"] and
                template.get("identity") == member["identity"] and
                template["identity"].get("comparison_family") == "external_pressure",
                f"Source5 pressure feedback template[{index}] differs from its plan member identity")
        template_policy = exact(template["policy"],
                                ({"version", "reader_contract", "algorithm", "context", "source_pins"}
                                 | ({"capacity_floor_policy", "capacity_floor_policy_id"}
                                    if capacity_floor_policy_id is not None else set())),
                                f"Source5 pressure feedback template[{index}] policy")
        if capacity_floor_policy_id is not None:
            require(template_policy.get("capacity_floor_policy_id") == capacity_floor_policy_id and
                    template_policy.get("capacity_floor_policy") == source_floor_policy,
                    f"Source5 pressure feedback template[{index}] lost its selected floor binding")
        else:
            require("capacity_floor_policy_id" not in template_policy and
                    "capacity_floor_policy" not in template_policy,
                    f"Source5 static pressure feedback template[{index}] has a floor selector")
        probe = exact(member["construction_probe"], {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, f"Source5 pressure construction probe[{index}]")
        refs = exact(member["composition"], {"request", "policy", "receipt"},
                     f"Source5 pressure composition[{index}]")
        request_pin = raw_pin(refs["request"],
                              f"Source5 pressure composition request[{index}]")
        request, _request_raw, request_sha = read_json(
            Path(request_pin["path"]),
            f"Source5 pressure composition request[{index}]",
            MAX_ARTIFACT_BYTES, request_pin["raw_sha256"],
        )
        expected_request = {
            "schema": (composition.REQUEST_SCHEMA_V2
                       if capacity_floor_policy_id is not None
                       else composition.REQUEST_SCHEMA),
            "source_root": str(context.source_root),
            "source_manifest": {"path": source_pin["path"],
                                "raw_sha256": source_pin["raw_sha256"]},
            "context": {
                "host_id": context.host_id,
                "workload": job["workload"],
                "profile": job["profile"],
                "calibration_id": capacity_request["calibration_id"],
            },
            "construction_probe": probe,
            "capacity_bundle": expected_bundle,
        }
        if capacity_floor_policy_id is not None:
            expected_request["capacity_floor_policy_id"] = capacity_floor_policy_id
        require(request == expected_request,
                f"Source5 pressure composition request[{index}] differs from its original source/probe/capacity pins")
        for name in ("policy", "receipt"):
            raw_pin(refs[name], f"Source5 pressure composition {name}[{index}]")
        prepared.append((request, request_sha, refs, probe))

    capture_parent = _private_directory(recipe_root / "probe-v2-captures")
    capture_pins: list[dict[str, str]] = []
    bundle_members: list[dict[str, Any]] = []
    for index, (request, request_sha, refs, probe) in enumerate(prepared):
        output_base = _private_directory(capture_parent / f"member-{index:02d}")
        result = composition.capture_calibrated_probe_v2(
            request, request_sha, context.observed_host_pin,
            output_root=output_base, capture_id=secrets.token_hex(16),
            capture_timeout_ns=probe_capture["capture_timeout_ns"],
            storage_budget=probe_capture["storage_budget"],
        )
        capture_pin = exact(result, {"path", "raw_sha256", "receipt_sha256"},
                            f"Source5 ProbeV2 capture receipt pin[{index}]")
        capture_path = Path(capture_pin["path"])
        require(capture_path.is_relative_to(output_base),
                f"Source5 ProbeV2 capture receipt[{index}] escaped its private output root")
        capture, capture_raw, capture_sha = read_json(
            capture_path, f"Source5 ProbeV2 capture receipt[{index}]",
            composition.MAX_PROBE_CAPTURE_RECEIPT_BYTES,
            capture_pin["raw_sha256"],
        )
        reader.validate_probe_capture_receipt_envelope(
            capture_raw, capture_sha, capture_pin["receipt_sha256"],
        )
        require(capture["schema"] == PROBE_CAPTURE_RECEIPT_SCHEMA and
                capture["capture_timeout_ns"] == probe_capture["capture_timeout_ns"] and
                capture["storage_budget"] == probe_capture["storage_budget"] and
                capture["probe_pin"] == probe and
                capture["capacity_bundle"] == expected_bundle,
                f"Source5 ProbeV2 capture receipt[{index}] differs from its budget or original inputs")
        replay_context = _probe_capture_evidence_map(
            context, composition, request, capture, capture_pin, expected_bundle,
        )
        replayed_policy, replayed_receipt = composition.compose_calibrated_policy_v5_offline(
            request, request_sha, replay_context=replay_context,
        )
        expected_policy, _policy_raw, _policy_sha = read_json(
            Path(refs["policy"]["path"]),
            f"Source5 pressure resolved policy[{index}]", MAX_ARTIFACT_BYTES,
            refs["policy"]["raw_sha256"],
        )
        expected_receipt, _receipt_raw, _receipt_sha = read_json(
            Path(refs["receipt"]["path"]),
            f"Source5 pressure composition receipt[{index}]", MAX_ARTIFACT_BYTES,
            refs["receipt"]["raw_sha256"],
        )
        require(replayed_policy == expected_policy and
                replayed_receipt == expected_receipt,
                f"Source5 ProbeV2 offline replay[{index}] differs from its original pinned policy/receipt")
        capture_pins.append(capture_pin)
        bundle_members.append({
            "ordinal": index,
            "construction_probe": probe,
            "capture_receipt": capture_pin,
            "capacity_bundle": expected_bundle,
        })
    require(len(capture_pins) == len(bundle_members) == 2,
            "Source5 pressure did not capture and replay both original ProbeV2 members")
    return {"schema": PROBE_CAPTURE_BUNDLE_SCHEMA, "members": bundle_members}


def _build_pressure_recipe(
    context: CampaignContext, lock: Any, job: dict[str, Any], job_index: int,
    material: dict[str, Any], phase_prerequisites: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, str], Path, dict[str, Any]]:
    pressure = context.pressure_pair
    descriptors = pressure.pressure_process_descriptors(job)
    require(len(descriptors) == 2 and len(material["members"]) == 2,
            "Source5 pressure material does not have the exact two original members")
    recipe_root = _private_directory(
        context.artifact_root / context.manifest["campaign_id"] /
        "source5" / context.host_id / "job-artifacts" / "pressure" /
        job["run_id"],
    )
    material_members = []
    for index, (descriptor, blueprint_value) in enumerate(zip(
        descriptors, material["members"], strict=True,
    )):
        blueprint = exact(blueprint_value, {
            "feedback_template", "identity", "application_binary",
            "construction_probe", "composition", "argv", "environment",
            "cwd", "tmpdir_path", "cpu_set", "cpu_affinity",
            "network_namespace_inode", "oracle", "pressure_recipe",
        }, f"Source5 pressure member material[{index}]")
        outputs_root = recipe_root / f"{index:02d}-{descriptor['pair']}-{descriptor['executor']}-{descriptor['allocator']}"
        outputs = _pressure_member_outputs(outputs_root)
        member = {"ordinal": index, "descriptor": descriptor,
                  **blueprint, "outputs": outputs}
        material_members.append(member)

    chronology_snapshot = context.chronology.source5_chronology_snapshot_locked(
        lock, api_pin(context.manifest_pin),
    )
    source_manifest_pin = context.source_manifest_pins[context.host_id]
    runner_relative = "scripts/application-pressure-pair.py"
    runner_pin = context.manifest["modules"][context.host_id][runner_relative]
    overlay_body = {
        "schema": pressure.EXECUTION_OVERLAY_SCHEMA,
        "campaign_id": context.manifest["campaign_id"],
        "host_id": context.host_id,
        "source_manifest": {
            "path": source_manifest_pin["path"],
            "raw_sha256": source_manifest_pin["raw_sha256"],
            "semantic_sha256": context.source["manifest_sha256"],
        },
        "spec": {
            "path": context.spec_pin["path"],
            "raw_sha256": context.spec_pin["raw_sha256"],
            "semantic_sha256": context.spec_semantic_sha256,
        },
        "plan": {
            "path": context.plan_pin["path"],
            "raw_sha256": context.plan_pin["raw_sha256"],
            "semantic_sha256": context.plan_semantic_sha256,
        },
        "job_index": job_index,
        "job_sha256": sha256(canonical_bytes(job)),
        "runner": {"path": str(context.source_root / runner_relative),
                   "raw_sha256": runner_pin["sha256"]},
        "capacity_completion": context.capacity_completion["artifact"],
        "chronology": {
            "observed_host": chronology_snapshot["observed_host"],
            "output_root": chronology_snapshot["output_root"],
            "capacity_output_root": chronology_snapshot["capacity_output_root"],
            "journal_head": chronology_snapshot["journal_head"],
            "journal_record_count": chronology_snapshot["journal_record_count"],
            "registration_head": chronology_snapshot["registration_head"],
            "dispatch_event_count": chronology_snapshot["dispatch_event_count"],
        },
    }
    overlay_body["overlay_sha256"] = sha256(canonical_bytes(overlay_body))
    overlay_path = recipe_root / "source5-execution-overlay.json"
    overlay_raw = canonical_bytes(overlay_body)
    overlay_sha = write_new(overlay_path, overlay_raw, "Source5 pressure execution overlay")
    require(overlay_sha == sha256(overlay_raw),
            "Source5 pressure execution overlay raw digest changed")

    capacity_bundle = _capacity_bundle_from_completion(context, job)
    pressure_condition = _source5_pressure_condition(context, job)
    shared_policy = raw_pin(material["shared_policy"],
                            f"Source5 {job['run_id']} shared policy")
    shared_policy_value, _shared_raw, _shared_sha = read_json(
        Path(shared_policy["path"]), f"Source5 {job['run_id']} shared policy",
        16 * 1024 * 1024, shared_policy["raw_sha256"],
    )
    fixed_run_id = job["predecessor_run_ids"]
    require(type(fixed_run_id) is list and len(fixed_run_id) == 1,
            "Source5 pressure job does not name exactly one fixed predecessor")
    fixed_phase_root = _phase_root(context, "confirmation")
    fixed_record_path = fixed_phase_root / "job-records" / f"{fixed_run_id[0]}.json"
    fixed_record_raw, fixed_record_sha, _fixed_record_info = read_stable(
        fixed_record_path, "Source5 successful fixed predecessor", 4 * 1024 * 1024,
    )
    fixed_record = json.loads(fixed_record_raw)
    require(fixed_record_raw == canonical_bytes(fixed_record) and
            fixed_record.get("state") == "valid_pair" and
            fixed_record.get("job", {}).get("run_id") == fixed_run_id[0],
            "Source5 pressure predecessor is absent or not a successful exact fixed record")
    context.chronology.verify_source5_completed_job_locked(
        lock, api_pin(context.manifest_pin), None,
        {"path": str(fixed_record_path), "raw_sha256": fixed_record_sha},
    )
    deadlines = exact(material["deadlines"], {
        "trace_seconds", "drain_seconds", "shutdown_seconds", "process_seconds",
        "outer_seconds", "application_wall_timeout_seconds",
        "application_term_grace_seconds", "pressure_exit_observation_seconds",
        "pressure_duration_seconds", "pressure_total_seconds",
    }, f"Source5 {job['run_id']} pressure deadlines")
    for field in ("trace_seconds", "drain_seconds", "shutdown_seconds", "process_seconds", "outer_seconds"):
        require(deadlines[field] == context.spec["deadlines"][field],
                f"Source5 pressure material changed original {field}")
    require(deadlines["application_wall_timeout_seconds"] ==
            context.spec["deadlines"]["process_seconds"],
            "Source5 pressure material changed the original APP process bound")
    bounded_pressure = context.manifest["schema"] == EXECUTION_SCHEMA_V3
    probe_capture_bundle = None
    recipe_schema = pressure.RECIPE_SCHEMA
    if bounded_pressure:
        require(material["schema"] == PRESSURE_MATERIALS_SCHEMA_V2,
                "bounded Source5 pressure requires caller-frozen pressure-material v2")
        require(getattr(pressure, "RECIPE_SCHEMA_V2", None) == PRESSURE_RECIPE_SCHEMA_V2,
                "pinned pressure helper lacks the exact probe-capture recipe-v2 contract")
        recipe_schema = pressure.RECIPE_SCHEMA_V2
        probe_capture_bundle = _capture_source5_probe_bundle(
            context, recipe_root, job, material_members, capacity_bundle,
            material["probe_capture"],
        )
    recipe = {
        "schema": recipe_schema,
        "spec": {"artifact": api_pin(context.spec_pin),
                 "semantic_sha256": context.spec_semantic_sha256},
        "plan": {"artifact": api_pin(context.plan_pin),
                 "semantic_sha256": context.plan_semantic_sha256},
        "source_manifest": {
            "artifact": api_pin(source_manifest_pin),
            "semantic_sha256": context.source["manifest_sha256"],
            "source_root": str(context.source_root),
        },
        "job": {"value": job, "semantic_sha256": sha256(canonical_bytes(job))},
        "execution_overlay": {"artifact": {
            "path": str(overlay_path), "raw_sha256": overlay_sha,
        }},
        "capacity_completion": {
            "artifact": context.capacity_completion["artifact"],
            "schedule_sha256": context.capacity_completion["schedule_sha256"],
            "registration_head": context.capacity_completion["registration_head"],
        },
        "capacity_bundle": capacity_bundle,
        "fixed_predecessor": {"record": {
            "path": str(fixed_record_path), "raw_sha256": fixed_record_sha,
        }},
        "shared_policy": {"artifact": shared_policy},
        "pressure_condition": pressure_condition,
        "members": material_members,
        "deadlines": deadlines,
        "artifact_budgets": material["artifact_budgets"],
        "validators": {
            "campaign_controller": context.source["qualification_harness"]["campaign_controller"],
            "campaign_chronology": context.manifest["modules"][context.host_id]["scripts/application-campaign-chronology.py"],
            "feedback_composition": {"path": "scripts/application-feedback-composition.py",
                "sha256": context.manifest["modules"][context.host_id]["scripts/application-feedback-composition.py"]["sha256"]},
            "feedback_validator": context.source["qualification_harness"]["feedback_validator"],
            "pressure_validator": context.source["qualification_harness"]["pressure_validator"],
            "soak_supervisor": context.source["qualification_harness"]["soak_validator"],
            "capacity_producer": context.source["qualification_harness"]["byte_capacity_producer"],
        },
    }
    if bounded_pressure:
        recipe["probe_capture"] = material["probe_capture"]
    require(type(recipe["artifact_budgets"]) is dict,
            "Source5 pressure material lacks actual finite artifact budgets")
    try:
        pressure._validate_recipe_shape(recipe)
    except Exception as error:
        raise Source5CampaignError(f"pinned pressure helper rejected assembled job recipe: {error}") from error
    recipe_path = recipe_root / "source5-pressure-recipe.json"
    recipe_raw = canonical_bytes(recipe)
    recipe_sha = write_new(recipe_path, recipe_raw, "Source5 pressure job recipe")
    return recipe, {"path": str(recipe_path), "raw_sha256": recipe_sha}, recipe_root, {
        "fixed_record": fixed_record,
        "fixed_record_pin": {"path": str(fixed_record_path), "raw_sha256": fixed_record_sha},
        "shared_policy": shared_policy_value,
        "chronology_snapshot": chronology_snapshot,
        "prerequisites": phase_prerequisites,
        "probe_capture_bundle": probe_capture_bundle,
    }


def _analysis_record(
    context: CampaignContext, phase: str, job_count: int, job_ids: list[str],
    job_evidence_complete: bool, numeric_gates_passed: bool,
    analysis_value: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": ANALYSIS_SCHEMA,
        "campaign_id": context.manifest["campaign_id"],
        "host_id": context.host_id,
        "phase": phase,
        "job_count": job_count,
        "job_set_sha256": sha256(canonical_bytes(job_ids)),
        "job_evidence_complete": job_evidence_complete,
        "numeric_gates_passed": numeric_gates_passed,
        "phase_gate_passed": job_evidence_complete and numeric_gates_passed,
        "campaign_qualification_eligible": False,
        "analysis": analysis_value,
    }
    body["analysis_sha256"] = sha256(canonical_bytes(body))
    return body


def _source5_analysis_matches_replay(
    phase: str, actual: object, expected: object,
) -> bool:
    """Compare deterministic analysis while allowing only documented Rust run metadata."""
    actual_value = json.loads(canonical_bytes(actual))
    expected_value = json.loads(canonical_bytes(expected))
    if phase in {"fixed_analysis", "pressure_analysis"}:
        for value in (actual_value, expected_value):
            bootstrap = value.get("bootstrap") if type(value) is dict else None
            if type(bootstrap) is dict:
                for name in ("analyzer_wall_seconds", "resident_peak_bytes",
                             "output_sha256"):
                    bootstrap.pop(name, None)
    return actual_value == expected_value


def _persist_analysis(
    context: CampaignContext, lock: Any, phase: str,
    source_phase: str, analysis_value: dict[str, Any],
    job_evidence_complete: bool, numeric_gates_passed: bool,
) -> dict[str, Any]:
    jobs = _host_jobs(context, source_phase)
    artifact_root = _private_directory(
        context.artifact_root / context.manifest["campaign_id"] /
        "source5" / context.host_id / "phase-analysis",
    )
    path = artifact_root / f"{phase}.json"
    record = _analysis_record(
        context, phase, len(jobs), [job["run_id"] for job in jobs],
        job_evidence_complete, numeric_gates_passed, analysis_value,
    )
    raw = canonical_bytes(record)
    raw_sha = write_new(path, raw, "Source5 phase analysis")
    registered = context.chronology.record_source5_analysis_locked(
        lock, api_pin(context.manifest_pin),
        {"path": str(path), "raw_sha256": raw_sha},
    )
    return {"record": record, "pin": {"path": str(path), "raw_sha256": raw_sha},
            "chronology": registered}


def analyze_phase(context: CampaignContext, phase: str) -> dict[str, Any]:
    require(phase in {
        "exploration", "aa", "fixed_analysis", "pressure_analysis",
        "soak", "final_analysis",
    },
            f"Source5 analysis phase is unsupported by this controller: {phase}")
    require(context.scope == "final_frozen" or phase == "exploration",
            "prospective Source5 scope is closed after exploration export")
    source_phase = {
        "fixed_analysis": "confirmation",
        "pressure_analysis": "pressure",
        "soak": "soak",
        "final_analysis": "soak",
    }.get(phase, phase)
    phase_root = _phase_root(context, source_phase)
    ledger_path = phase_root / "controller-ledger.jsonl"
    records = _phase_ledger_records(ledger_path)
    expected_jobs = _host_jobs(context, source_phase)
    if source_phase == "soak":
        require(len(records) == len(expected_jobs) == 1 and
                records[0]["state"] in {"valid_soak", "invalid_soak"},
                f"Source5 {phase} analysis lacks the one completed original Soak ordinal")
    else:
        context.campaign.validate_phase_ledger(
            records, expected_jobs, source_phase, context.host_id,
        )
        require(all(record["state"] == "valid_pair" for record in records),
                f"Source5 {phase} analysis is blocked by an original invalid/failed ordinal")
    with context.chronology.campaign_host_lock(
        context.output_root, context.manifest["campaign_id"], context.host_id,
    ) as lock:
        verified = _validate_locked_context(context, lock)
        state = verified["state"]
        if source_phase in {"exploration", "aa", "confirmation"}:
            records = _fresh_fixed_phase_records(
                context, lock, source_phase, phase_root, ledger_path,
            )
        elif source_phase == "pressure":
            records = _fresh_pressure_phase_records(
                context, lock, phase_root, ledger_path,
            )
        else:
            records = _fresh_soak_phase_records(
                context, lock, phase_root, ledger_path,
            )
        if phase == "exploration":
            pilot = _capacity_pilot(context, records)
            pilot_path = phase_root / "capacity-pilot.json"
            pilot_sha = write_new(pilot_path, canonical_bytes(pilot),
                                  "Source5 capacity pilot")
            frozen = context.campaign.freeze_rates(
                context.spec, pilot, pilot_sha,
            )
            existing = [row for row in context.spec["rates"]
                        if row["host_id"] == context.host_id]
            expected_rates = _frozen_rate_rows(context.host_id, frozen, pilot_sha)
            if context.scope == "final_frozen":
                require(existing == expected_rates,
                        "retained exploration pairs do not reproduce the already frozen original SpecV3 rates")
                rate_status = "verified_against_final_frozen_spec"
            else:
                require(existing == [],
                        "prospective exploration must retain an unfrozen SpecV3 rate table")
                rate_status = "candidate_for_separate_final_freeze"
            candidate_path = phase_root / "capacity-rate-candidate.json"
            candidate = {
                "schema": "allocatbelt.application-source5-rate-candidate.v1",
                "scope": context.scope,
                "pilot": {"path": str(pilot_path), "raw_sha256": pilot_sha},
                "candidate_rates": expected_rates,
                "original_spec_rates": existing,
                "status": rate_status,
                "qualification_eligible": False,
            }
            write_new(candidate_path, canonical_bytes(candidate),
                      "Source5 capacity rate candidate")
            value = {"schema": "allocatbelt.application-source5-exploration-analysis.v1",
                     "scope": context.scope,
                     "pilot": {"path": str(pilot_path), "raw_sha256": pilot_sha},
                     "rate_candidate": {"path": str(candidate_path),
                                        "raw_sha256": sha256(canonical_bytes(candidate))},
                     "rate_status": rate_status}
            numeric = True
        elif phase == "aa":
            aa = context.campaign.validate_aa_records(
                records, expected_jobs, context.host_id,
                context.spec["protocol"]["bootstrap_draws"],
                context.spec["protocol"]["bootstrap_seed"],
            )
            value = aa
            numeric = aa.get("passed") is True
        elif phase == "soak":
            component_pin = raw_pin(
                records[0]["evidence"]["soak_component"],
                "Source5 Soak component",
            )
            value = {
                "schema": "allocatbelt.application-source5-soak-analysis.v1",
                "component": component_pin,
                "readback": records[0]["process_metrics"][0],
                "record_sha256": records[0]["record_sha256"],
            }
            numeric = value["readback"].get("passed") is True
        elif phase == "final_analysis":
            phase_results = _fresh_source5_final_phase_results(
                context, lock, state, verified["prepared"],
            )
            value = _source5_final_decision_value(context, phase_results)
            numeric = value["numeric_gates_passed"] is True
        else:
            analysis = _source5_numeric_for_pairs(context, phase, records)
            value = analysis
            numeric = analysis.get("numeric_gates_passed") is True
        result = _persist_analysis(
            context, lock, phase, source_phase, value, True, numeric,
        )
        if phase not in {"soak", "final_analysis"}:
            require(result["record"]["phase_gate_passed"] is True,
                    f"Source5 {phase} phase gate failed; later phases remain blocked")
        return result


def run_fixed_phase(context: CampaignContext, phase: str) -> dict[str, Any]:
    require(phase in {"exploration", "aa", "confirmation"},
            "fixed component runner only accepts original fixed-policy phases")
    require(context.scope == "final_frozen" or phase == "exploration",
            "prospective Source5 scope is closed to exploration-only execution")
    jobs = _host_jobs(context, phase)
    phase_root = _phase_root(context, phase)
    require(not phase_root.exists() and not phase_root.is_symlink(),
            f"Source5 phase output already exists and its ordinals cannot be replaced: {phase_root}")
    with context.chronology.campaign_host_lock(
        context.output_root, context.manifest["campaign_id"], context.host_id,
    ) as lock:
        verified = _validate_locked_context(context, lock)
        state = verified["state"]
        prerequisites = _helper_prerequisites(state, phase)
        _private_directory(phase_root)
        job_records = _private_directory(phase_root / "job-records")
        del job_records
        ledger_path = phase_root / "controller-ledger.jsonl"
        ledger_fd = os.open(ledger_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                            getattr(os, "O_CLOEXEC", 0) |
                            getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(ledger_fd)
        for index, job in enumerate(jobs):
            result = None
            try:
                helper_value, helper_ref, _job_root = _build_fixed_helper_input(
                    context, phase, index, job, prerequisites,
                )
                del helper_value
                authorization = context.chronology.authorize_source5_job_locked(
                    lock, api_pin(context.manifest_pin), job, helper_ref,
                )
                result = context.chronology.run_authorized_source5_job_locked(
                    lock, authorization,
                )
                if result["state"] == "blocked":
                    dispositions = [{"job": job,
                                     "reason": "blocked_after_owned_process_or_preflight_failure",
                                     "authorization_id": result["chronology"]["authorization_id"],
                                     "job_terminal_head": result["chronology"]["job_terminal_head"],
                                     "error_sha256": result["error_sha256"]}]
                    dispositions.extend({"job": pending, "reason": "not_run_after_blocked_job"}
                                        for pending in jobs[index + 1:])
                    _write_dispositions(phase_root, dispositions,
                                        f"blocked original job {job['run_id']}")
                    return {"phase": phase, "blocked": True,
                            "job_run_id": job["run_id"],
                            "dispositions": str(phase_root / "not-run-dispositions.json")}
                if result["state"] == "invalid_pair":
                    _write_job_disposition(
                        phase_root, job, "invalid_pair",
                        "complete_invalid_fixed_component_consumes_original_ordinal",
                        authorization_id=result["chronology"]["authorization_id"],
                        terminal_head=result["chronology"]["job_terminal_head"],
                        component_sha256=result["component_sha256"],
                        error_sha256=result["error_sha256"],
                    )
                    continue
                record = _fixed_record_from_result(context, result, phase)
                _write_record_file(phase_root, ledger_path, record)
            except BaseException as error:
                _seal_blocked_suffix(phase_root, jobs, index, error, result)
                raise
        return {"phase": phase, "job_count": len(jobs),
                "ledger": str(ledger_path), "blocked": False}


def _pressure_record_from_result(
    context: CampaignContext, result: dict[str, Any],
    recipe: dict[str, Any], recipe_ref: dict[str, str],
    recipe_root: Path,
) -> dict[str, Any] | None:
    require(result["state"] in {"valid_pair", "invalid_pair"},
            "Source5 pressure disposition is not a complete pair")
    if result["state"] != "valid_pair":
        return None
    component = result["component"]
    require(component.get("schema") == "allocatbelt.application-source5-pressure-component.v1" and
            component.get("validated") is True and
            component.get("qualification_eligible") is False,
            "Source5 pressure component result is not independently validated")
    readback = raw_pin(component["readback"], "Source5 pressure readback")
    processes = raw_pin(component["processes"], "Source5 pressure process ledger")
    overlay = raw_pin(component["overlay"], "Source5 pressure execution overlay")
    fixed_predecessor_path = recipe_root / "preflight" / "fixed-pressure-predecessor.json"
    _fixed_raw, fixed_sha, _fixed_info = read_stable(
        fixed_predecessor_path, "Source5 fixed-pressure predecessor receipt",
        16 * 1024 * 1024,
    )
    source_ref = recipe["source_manifest"]
    source_snapshot = {
        "artifact": raw_pin(source_ref["artifact"], "Source5 source manifest"),
        "semantic_sha256": source_ref["semantic_sha256"],
        "source_tree_sha256": context.source["source"]["source_tree_sha256"],
    }
    chronology = result["chronology"]
    start_events = chronology["app_start_events"]
    identities = []
    for index, event in enumerate(start_events):
        proof = event["proof"]
        identities.append({
            "descriptor": event["descriptor"],
            "pid": proof["pid"],
            "start_ticks": proof["start_ticks"],
            "member_index": index,
        })
    record_chronology = {
        "authorization_id": chronology["authorization_id"],
        "authorization_head": chronology["authorization_head"],
        "app_started_heads": chronology["app_started_heads"],
        "app_terminal_heads": chronology["app_terminal_heads"],
        "job_terminal_head": chronology["job_terminal_head"],
        "component_sha256": result["component_sha256"],
        "process_metrics_sha256": result["process_metrics_sha256"],
        "app_start_events": start_events,
        "app_terminal_events": chronology["app_terminal_events"],
        "member_processes": identities,
    }
    body = {
        "schema": JOB_RECORD_SCHEMA,
        "state": "valid_pair",
        "job": result["job"],
        "pair_directory": str(recipe_root),
        "process_metrics": result["process_metrics"],
        "evidence": {
            "kind": "source5_pressure_pair",
            "execution_manifest": result["evidence"]["execution_manifest"],
            "helper_input": result["evidence"]["helper_input"],
            "helper_module": result["evidence"]["helper_module"],
            "recipe": recipe_ref,
            "overlay": overlay,
            "readback": readback,
            "processes": processes,
            "fixed_predecessor": {
                "path": str(fixed_predecessor_path), "raw_sha256": fixed_sha,
            },
            "source_snapshot": source_snapshot,
        },
        "chronology": record_chronology,
        "qualification_eligible": False,
    }
    body["record_sha256"] = sha256(canonical_bytes(body))
    return body


def _fresh_pressure_phase_records(
    context: CampaignContext, lock: Any, phase_root: Path,
    ledger_path: Path,
) -> list[dict[str, Any]]:
    records = _phase_ledger_records(ledger_path)
    expected = _host_jobs(context, "pressure")
    context.campaign.validate_phase_ledger(records, expected, "pressure", context.host_id)
    for record in records:
        require(record.get("evidence", {}).get("kind") == "source5_pressure_pair",
                "pressure phase contains a non-Source5 pressure record")
        record_pin = _raw_record_pin(phase_root, record["job"]["run_id"])
        checked_chain = context.chronology.verify_source5_completed_job_locked(
            lock, api_pin(context.manifest_pin), None, record_pin,
        )
        require(checked_chain["process_metrics"] == record["process_metrics"],
                "Source5 pressure journal replay and stored metrics differ")
        authorization_context = context.chronology.source5_authorization_context_locked(
            lock, api_pin(context.manifest_pin),
            record["chronology"]["authorization_id"],
        )
        recipe_ref = raw_pin(record["evidence"]["recipe"],
                             "Source5 pressure recipe")
        recipe, _recipe_raw, _recipe_sha = read_json(
            Path(recipe_ref["path"]), "Source5 pressure recipe",
            MAX_ARTIFACT_BYTES, recipe_ref["raw_sha256"],
        )
        validation = context.pressure_pair.validate_pressure_pair_artifacts(
            recipe, Path(record["pair_directory"]),
            Path(record["evidence"]["readback"]["path"]),
            record["evidence"]["readback"]["raw_sha256"],
            chronology_module=context.chronology,
            lock=lock,
            authorization_context=authorization_context,
        )
        require(validation["validated"] is True and
                validation["qualification_eligible"] is False and
                validation["pressure_metrics"] == record["process_metrics"],
                "Source5 pressure artifacts failed a fresh component replay")
    return records


def _fresh_soak_phase_records(
    context: CampaignContext, lock: Any, phase_root: Path,
    ledger_path: Path,
) -> list[dict[str, Any]]:
    records = _phase_ledger_records(ledger_path)
    expected = _host_jobs(context, "soak")
    require(len(expected) == len(records) == 1 and
            records[0]["job"] == expected[0] and
            records[0]["state"] in {"valid_soak", "invalid_soak"} and
            records[0]["evidence"].get("kind") == "source5_timed_soak",
            "Source5 Soak ledger does not preserve its one original completed ordinal")
    record_pin = _raw_record_pin(phase_root, expected[0]["run_id"])
    checked = context.chronology.verify_source5_completed_soak_job_locked(
        lock, api_pin(context.manifest_pin), record_pin,
    )
    require(checked["verified"] is True and
            checked["status"] == records[0]["state"] and
            checked["run_id"] == expected[0]["run_id"] and
            checked["process_metrics"] == records[0]["process_metrics"] and
            checked["qualification_eligible"] is False,
            "Source5 Soak record did not freshly replay its one direct APP lifecycle and full readback")
    return records


def _source5_numeric_for_pairs(
    context: CampaignContext, phase: str, records: list[dict[str, Any]],
) -> dict[str, Any]:
    analyzer = context.source.get("analysis_artifact")
    require(type(analyzer) is dict and set(analyzer) == {"path", "sha256"} and
            is_sha(analyzer["sha256"]),
            "SourceV5 source manifest has no pinned Rust paired-analysis binary")
    analysis_path = _safe_child(context.source_root, analyzer["path"],
                                "Source5 paired analysis binary")
    _analysis_raw, analysis_sha, analysis_info = read_stable(
        analysis_path, "Source5 paired analysis binary", 1024 * 1024 * 1024,
    )
    require(analysis_sha == analyzer["sha256"] and analysis_info.st_mode & 0o111 != 0,
            "Source5 paired analysis binary differs from SourceV5")
    result = context.campaign.analyze_confirmation_host_numeric(
        context.spec, context.host_id, records,
        context.artifact_root, analysis_path, analysis_sha,
        phase="confirmation" if phase == "fixed_analysis" else "pressure",
    )
    _after_raw, after_sha, _after_info = read_stable(
        analysis_path, "Source5 paired analysis binary after run",
        1024 * 1024 * 1024,
    )
    require(after_sha == analysis_sha,
            "Source5 paired-analysis binary changed during a fresh final replay")
    return result


def _source5_final_decision_value(
    context: CampaignContext, phase_results: list[dict[str, Any]],
) -> dict[str, Any]:
    require(len(phase_results) == 5 and
            [item.get("phase") for item in phase_results] == [
                "exploration", "aa", "fixed_analysis", "pressure_analysis", "soak",
            ], "Source5 per-host final decision does not contain every original required phase")
    require(all(type(item.get("numeric_gates_passed")) is bool and
                is_sha(item.get("analysis_sha256")) and
                is_sha(item.get("event_head")) and
                is_sha(item.get("records_sha256")) for item in phase_results),
            "Source5 final decision phase evidence is incomplete or malformed")
    failures = [item["phase"] for item in phase_results
                if item["numeric_gates_passed"] is False]
    completion = context.prepared_input_completion
    require(type(completion) is dict,
            "Source5 final decision lacks the replayed prepared-input completion")
    completion_pin = exact(
        context.manifest["prepared_input_generation"]["completion"],
        {"path", "raw_sha256", "semantic_sha256"},
        "Source5 final prepared-input completion pin",
    )
    host_rows = [item for item in completion["pilots"]
                 if item.get("host_id") == context.host_id]
    require(len(host_rows) == 1,
            "Source5 final decision has no unique prepared host binding")
    return {
        "schema": "allocatbelt.application-source5-final-host-numeric-decision.v1",
        "campaign_id": context.manifest["campaign_id"],
        "host_id": context.host_id,
        "original_spec": {
            "path": str(context.spec_pin["path"]),
            "raw_sha256": context.spec_pin["raw_sha256"],
            "semantic_sha256": context.spec_semantic_sha256,
        },
        "original_plan": {
            "path": str(context.plan_pin["path"]),
            "raw_sha256": context.plan_pin["raw_sha256"],
            "semantic_sha256": context.plan_semantic_sha256,
        },
        "prepared_input_completion": {
            "path": completion_pin["path"],
            "raw_sha256": completion_pin["raw_sha256"],
            "semantic_sha256": completion["completion_sha256"],
        },
        "source_manifest": {
            "path": context.source_manifest_pins[context.host_id]["path"],
            "raw_sha256": context.source_manifest_pins[context.host_id]["raw_sha256"],
            "semantic_sha256": context.source["manifest_sha256"],
            "source_tree_sha256": context.source["source"]["source_tree_sha256"],
            "build_sha256": context.source["build"]["build_sha256"],
        },
        "prepared_host_binding_sha256":
            host_rows[0]["prepared_host_binding"]["binding_sha256"],
        "phase_results": phase_results,
        "numeric_gates_passed": not failures,
        "failed_phases": failures,
        "cohort_status": "not_verified",
        "cohort_blockers": [
            "independent_three_host_final_decisions_not_replayed",
            "accepted_pressure_offline_replay_api_unavailable",
        ],
        "campaign_qualification_eligible": False,
    }


def _fresh_source5_final_phase_results(
    context: CampaignContext, lock: Any, state: dict[str, Any],
    chronology_prepared: dict[str, Any],
) -> list[dict[str, Any]]:
    required = ("exploration", "aa", "fixed_analysis", "pressure_analysis", "soak")
    stored = []
    for phase in required:
        event = state["source5_analyses"].get(phase)
        require(event is not None and type(event.get("phase_gate_passed")) is bool,
                f"Source5 final analysis lacks the durable {phase} analysis event")
        stored.append(event)
    checked_records: dict[str, tuple[list[dict[str, Any]], str]] = {}
    checked_records["exploration"] = (
        _fresh_fixed_phase_records(
            context, lock, "exploration", _phase_root(context, "exploration"),
            _phase_root(context, "exploration") / "controller-ledger.jsonl",
        ), "",
    )
    checked_records["aa"] = (
        _fresh_fixed_phase_records(
            context, lock, "aa", _phase_root(context, "aa"),
            _phase_root(context, "aa") / "controller-ledger.jsonl",
        ), "",
    )
    checked_records["confirmation"] = (
        _fresh_fixed_phase_records(
            context, lock, "confirmation", _phase_root(context, "confirmation"),
            _phase_root(context, "confirmation") / "controller-ledger.jsonl",
        ), "",
    )
    checked_records["pressure"] = (
        _fresh_pressure_phase_records(
            context, lock, _phase_root(context, "pressure"),
            _phase_root(context, "pressure") / "controller-ledger.jsonl",
        ), "",
    )
    soak_root = _phase_root(context, "soak")
    checked_records["soak"] = (
        _fresh_soak_phase_records(
            context, lock, soak_root, soak_root / "controller-ledger.jsonl",
        ), "",
    )
    records_by_key = {key: value[0] for key, value in checked_records.items()}
    exploration_pilot = _capacity_pilot(context, records_by_key["exploration"])
    exploration_analysis, _exploration_analysis_raw, _exploration_analysis_sha = read_json(
        Path(stored[0]["analysis"]["path"]), "Source5 original exploration analysis",
        MAX_ARTIFACT_BYTES, stored[0]["analysis"]["raw_sha256"],
    )
    pilot_ref = raw_pin(exploration_analysis["analysis"]["pilot"],
                        "Source5 original exploration pilot")
    pilot, _pilot_raw, pilot_sha = read_json(
        Path(pilot_ref["path"]), "Source5 original exploration capacity pilot",
        MAX_ARTIFACT_BYTES, pilot_ref["raw_sha256"],
    )
    require(pilot == exploration_pilot,
            "Source5 frozen pilot differs from a fresh six-pair cohort reconstruction")
    frozen = context.campaign.freeze_rates(context.spec, pilot, pilot_sha)
    expected_rates = _frozen_rate_rows(context.host_id, frozen, pilot_sha)
    existing_rates = [item for item in context.spec["rates"]
                      if item["host_id"] == context.host_id]
    exploration_passed = existing_rates == expected_rates
    aa_result = context.campaign.validate_aa_records(
        records_by_key["aa"], _host_jobs(context, "aa"), context.host_id,
        context.spec["protocol"]["bootstrap_draws"],
        context.spec["protocol"]["bootstrap_seed"],
    )
    fixed_result = _source5_numeric_for_pairs(
        context, "fixed_analysis", records_by_key["confirmation"],
    )
    pressure_result = _source5_numeric_for_pairs(
        context, "pressure_analysis", records_by_key["pressure"],
    )
    soak_component = records_by_key["soak"][0]["process_metrics"][0]
    gates = [exploration_passed, aa_result.get("passed") is True,
             fixed_result.get("numeric_gates_passed") is True,
             pressure_result.get("numeric_gates_passed") is True,
             soak_component.get("passed") is True]
    for event, expected_gate, phase_name in zip(stored, gates, required, strict=True):
        require(event["phase_gate_passed"] is expected_gate,
                f"Source5 durable {phase_name} gate differs from fresh original evidence replay")
    records_sha = {
        "exploration": context.chronology._source5_phase_records(
            chronology_prepared, state, "exploration")[1],
        "aa": context.chronology._source5_phase_records(
            chronology_prepared, state, "aa")[1],
        "fixed_analysis": context.chronology._source5_phase_records(
            chronology_prepared, state, "confirmation")[1],
        "pressure_analysis": context.chronology._source5_phase_records(
            chronology_prepared, state, "pressure")[1],
        "soak": context.chronology._source5_phase_records(
            chronology_prepared, state, "soak")[1],
    }
    return [{
        "phase": phase_name,
        "numeric_gates_passed": gate,
        "analysis_sha256": event["analysis_sha256"],
        "event_head": event["event_head"],
        "records_sha256": records_sha[phase_name],
    } for phase_name, gate, event in zip(required, gates, stored, strict=True)]


def _build_soak_helper_input(
    context: CampaignContext, job_index: int, job: dict[str, Any],
    prerequisites: list[dict[str, Any]], materials_index_path: Path,
) -> tuple[dict[str, Any], dict[str, str], Path]:
    soak = context.modules["scripts/application-source5-soak.py"]
    materials_path = materials_index_path.resolve(strict=True)
    require(materials_path.is_relative_to(context.artifact_root),
            "Source5 Soak materials index is outside the private artifact root")
    materials_raw, materials_sha, _materials_info = read_stable(
        materials_path, "Source5 Soak materials index", MAX_ARTIFACT_BYTES,
    )
    try:
        materials = json.loads(materials_raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Source5CampaignError("Source5 Soak materials index is malformed") from error
    require(type(materials) is dict and materials_raw == canonical_bytes(materials) and
            materials.get("schema") == soak.MATERIALS_INDEX_SCHEMA and
            materials.get("campaign_id") == context.manifest["campaign_id"] and
            materials.get("host_id") == context.host_id and
            materials.get("job") == job and
            materials.get("job_sha256") == sha256(canonical_bytes(job)) and
            materials.get("materials_sha256") == sha256(canonical_bytes({
                key: value for key, value in materials.items()
                if key != "materials_sha256"
            })),
            "Source5 Soak materials index does not bind this exact original host/job")
    prepared_completion = context.prepared_input_completion
    require(type(prepared_completion) is dict,
            "Source5 Soak requires a fully replayed prepared-input completion")
    selected = [item for item in prepared_completion["pilots"]
                if item.get("host_id") == context.host_id]
    require(len(selected) == 1 and
            materials.get("prepared_host_binding_sha256") ==
                selected[0]["prepared_host_binding"]["binding_sha256"],
            "Source5 Soak materials index changed the selected prepared-host binding")
    helper_root = _private_directory(
        context.artifact_root / context.manifest["campaign_id"] / "source5" /
        context.host_id / "job-artifacts" / "soak" / job["run_id"],
    )
    helper = {
        "path": "scripts/application-source5-soak.py",
        "sha256": context.manifest["modules"][context.host_id][
            "scripts/application-source5-soak.py"]["sha256"],
        "entrypoint": "run_source5_soak",
    }
    helper_value = _helper_input_value(
        context, "soak", job_index, job, [soak.soak_descriptor(job)],
        {"materials_index": {"path": str(materials_path),
                             "raw_sha256": materials_sha},
         "output_root": str(helper_root),
         "prepared_host_binding_sha256":
             selected[0]["prepared_host_binding"]["binding_sha256"]},
        prerequisites, helper,
    )
    helper_dir = _private_directory(
        context.artifact_root / context.manifest["campaign_id"] / "source5" /
        context.host_id / "helper-inputs",
    )
    helper_path = helper_dir / f"soak-{job['run_id']}.json"
    helper_sha = write_new(helper_path, canonical_bytes(helper_value),
                           "Source5 Soak helper input")
    return helper_value, {"path": str(helper_path), "raw_sha256": helper_sha}, helper_root


def _soak_record_from_result(
    context: CampaignContext, result: dict[str, Any],
) -> dict[str, Any]:
    require(result["state"] in {"valid_soak", "invalid_soak"},
            "Source5 Soak result is not a complete one-APP disposition")
    component = exact(result["component"], {
        "schema", "campaign_id", "host_id", "run_id", "validated", "passed",
        "qualification_eligible", "launch_enabled", "prepared_host_binding_sha256",
        "pins", "application_attestation", "application_cleanup", "pressure_cleanup",
        "terminal_event", "readback", "supervisor_sha256",
    }, "Source5 Soak component result")
    require(component["schema"] == context.modules[
                "scripts/application-source5-soak.py"].COMPONENT_SCHEMA and
            component["validated"] is True and
            component["qualification_eligible"] is False and
            component["passed"] is (result["state"] == "valid_soak"),
            "Source5 Soak component result differs from its verified numeric gate")
    evidence = result["evidence"]
    component_pin = raw_pin(evidence.get("soak_component"),
                            "Source5 Soak component artifact")
    readback = component["readback"]
    require(type(readback) is dict and readback.get("validated") is True and
            readback.get("qualification_eligible") is True and
            readback.get("passed") is component["passed"],
            "Source5 Soak readback result is not the exact validated component gate")
    terminal = result["chronology"]["app_terminal_events"]
    starts = result["chronology"]["app_start_events"]
    require(len(starts) == len(terminal) == 1,
            "Source5 Soak chronology did not retain one actual APP start and terminal")
    proof = starts[0]["proof"]
    identity = [{
        "descriptor": starts[0]["descriptor"],
        "pid": proof["pid"],
        "start_ticks": proof["start_ticks"],
        "member_index": 0,
    }]
    chronology = {
        "authorization_id": result["chronology"]["authorization_id"],
        "authorization_head": result["chronology"]["authorization_head"],
        "app_started_heads": result["chronology"]["app_started_heads"],
        "app_terminal_heads": result["chronology"]["app_terminal_heads"],
        "job_terminal_head": result["chronology"]["job_terminal_head"],
        "component_sha256": result["component_sha256"],
        "process_metrics_sha256": result["process_metrics_sha256"],
        "app_start_events": starts,
        "app_terminal_events": terminal,
        "member_processes": identity,
    }
    body = {
        "schema": JOB_RECORD_SCHEMA,
        "state": result["state"],
        "job": result["job"],
        "pair_directory": str(Path(
            result["component"]["pins"]["supervisor"]["path"],
        ).parent),
        "process_metrics": [readback],
        "evidence": {
            "kind": "source5_timed_soak",
            "execution_manifest": evidence["execution_manifest"],
            "helper_input": evidence["helper_input"],
            "helper_module": evidence["helper_module"],
            "soak_component": component_pin,
        },
        "chronology": chronology,
        "qualification_eligible": False,
    }
    body["record_sha256"] = sha256(canonical_bytes(body))
    return body


def run_pressure_phase(
    context: CampaignContext, materials_index: Path,
) -> dict[str, Any]:
    require(context.scope == "final_frozen",
            "external pressure requires the separately frozen final SpecV3/PlanV3/oracle scope")
    jobs = _host_jobs(context, "pressure")
    materials = _pressure_materials_index(context, materials_index)
    phase_root = _phase_root(context, "pressure")
    require(not phase_root.exists() and not phase_root.is_symlink(),
            f"Source5 pressure output already exists and its ordinals cannot be replaced: {phase_root}")
    with context.chronology.campaign_host_lock(
        context.output_root, context.manifest["campaign_id"], context.host_id,
    ) as lock:
        verified = _validate_locked_context(context, lock)
        prerequisites = _helper_prerequisites(verified["state"], "pressure")
        _private_directory(phase_root)
        _private_directory(phase_root / "job-records")
        ledger_path = phase_root / "controller-ledger.jsonl"
        fd = os.open(ledger_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fsync(fd)
        os.close(fd)
        for index, job in enumerate(jobs):
            recipe, recipe_pin, recipe_root, details = _build_pressure_recipe(
                context, lock, job, index, materials[job["run_id"]],
                prerequisites,
            )
            pressure_payload = {"recipe_pin": recipe_pin,
                                "output_root": str(recipe_root)}
            if context.manifest["schema"] == EXECUTION_SCHEMA_V3:
                bundle = exact(details["probe_capture_bundle"], {"schema", "members"},
                               "Source5 bounded pressure ProbeV2 bundle")
                require(bundle["schema"] == PROBE_CAPTURE_BUNDLE_SCHEMA and
                        type(bundle["members"]) is list and
                        len(bundle["members"]) == 2,
                        "Source5 bounded pressure did not retain both strict ProbeV2 receipt pins")
                pressure_payload = {
                    "schema": PRESSURE_HELPER_PAYLOAD_SCHEMA_V2,
                    "recipe_pin": recipe_pin,
                    "output_root": str(recipe_root),
                    "probe_capture_bundle": bundle,
                }
            helper_value = _helper_input_value(
                context, "pressure", index, job,
                [member["descriptor"] for member in recipe["members"]],
                pressure_payload,
                prerequisites,
                {"path": "scripts/application-pressure-pair.py",
                 "sha256": context.manifest["modules"][context.host_id][
                     "scripts/application-pressure-pair.py"]["sha256"],
                 "entrypoint": "run_pressure_pair_locked"},
            )
            helper_dir = _private_directory(
                context.artifact_root / context.manifest["campaign_id"] /
                "source5" / context.host_id / "helper-inputs",
            )
            helper_path = helper_dir / f"pressure-{job['run_id']}.json"
            helper_raw = canonical_bytes(helper_value)
            helper_sha = write_new(helper_path, helper_raw,
                                   "Source5 pressure helper input")
            try:
                authorization = context.chronology.authorize_source5_job_locked(
                    lock, api_pin(context.manifest_pin), job,
                    {"path": str(helper_path), "raw_sha256": helper_sha},
                )
                result = context.chronology.run_authorized_source5_job_locked(
                    lock, authorization,
                )
            except BaseException as error:
                dispositions = [{"job": job,
                                 "reason": f"authorization_or_component_failure:{type(error).__name__}"}]
                dispositions.extend({"job": pending, "reason": "not_run_after_blocked_job"}
                                    for pending in jobs[index + 1:])
                _write_dispositions(phase_root, dispositions,
                                    f"blocked job {job['run_id']}: {type(error).__name__}")
                raise
            if result["state"] == "blocked":
                dispositions = [{"job": job,
                                 "reason": "blocked_after_pressure_readiness_or_cleanup_failure",
                                 "authorization_id": result["chronology"]["authorization_id"],
                                 "job_terminal_head": result["chronology"]["job_terminal_head"],
                                 "error_sha256": result["error_sha256"]}]
                dispositions.extend({"job": pending, "reason": "not_run_after_blocked_job"}
                                    for pending in jobs[index + 1:])
                _write_dispositions(phase_root, dispositions,
                                    f"blocked original pressure job {job['run_id']}")
                return {"phase": "pressure", "blocked": True,
                        "job_run_id": job["run_id"],
                        "dispositions": str(phase_root / "not-run-dispositions.json")}
            record = _pressure_record_from_result(
                context, result, recipe, recipe_pin, recipe_root,
            )
            if record is None:
                _write_job_disposition(
                    phase_root, job, "invalid_pair",
                    "complete_invalid_pressure_component_consumes_original_ordinal",
                    authorization_id=result["chronology"]["authorization_id"],
                    terminal_head=result["chronology"]["job_terminal_head"],
                    component_sha256=result["component_sha256"],
                    error_sha256=result["error_sha256"],
                )
                continue
            _write_record_file(phase_root, ledger_path, record)
        return {"phase": "pressure", "job_count": len(jobs),
                "ledger": str(ledger_path), "blocked": False}


def run_soak_phase(
    context: CampaignContext, materials_index: Path,
) -> dict[str, Any]:
    require(context.scope == "final_frozen" and
            context.prepared_input_completion is not None,
            "Source5 continuous Soak requires the final prepared original cohort")
    jobs = _host_jobs(context, "soak")
    require(len(jobs) == 1,
            "Source5 host Soak must contain exactly its one original scheduled APP job")
    phase_root = _phase_root(context, "soak")
    require(not phase_root.exists() and not phase_root.is_symlink(),
            f"Source5 Soak output already exists and its original ordinal cannot be replaced: {phase_root}")
    with context.chronology.campaign_host_lock(
        context.output_root, context.manifest["campaign_id"], context.host_id,
    ) as lock:
        verified = _validate_locked_context(context, lock)
        prerequisites = _helper_prerequisites(verified["state"], "soak")
        _private_directory(phase_root)
        _private_directory(phase_root / "job-records")
        ledger_path = phase_root / "controller-ledger.jsonl"
        fd = os.open(ledger_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        for index, job in enumerate(jobs):
            result = None
            try:
                _helper_value, helper_ref, _job_root = _build_soak_helper_input(
                    context, index, job, prerequisites, materials_index,
                )
                authorization = context.chronology.authorize_source5_job_locked(
                    lock, api_pin(context.manifest_pin), job, helper_ref,
                )
                result = context.chronology.run_authorized_source5_job_locked(
                    lock, authorization,
                )
                if result["state"] == "blocked":
                    dispositions = [{
                        "job": job,
                        "reason": "blocked_after_original_soak_launch_or_cleanup_failure",
                        "authorization_id": result["chronology"]["authorization_id"],
                        "job_terminal_head": result["chronology"]["job_terminal_head"],
                        "component_sha256": result["component_sha256"],
                        "retained_failure": result["evidence"].get("soak_component"),
                        "error_sha256": result["error_sha256"],
                    }]
                    _write_dispositions(
                        phase_root, dispositions,
                        f"blocked original Soak job {job['run_id']}",
                    )
                    return {"phase": "soak", "blocked": True,
                            "job_run_id": job["run_id"],
                            "dispositions": str(phase_root / "not-run-dispositions.json"),
                            "qualification_eligible": False}
                record = _soak_record_from_result(context, result)
                _write_record_file(phase_root, ledger_path, record)
            except BaseException as error:
                _seal_blocked_suffix(phase_root, jobs, index, error, result)
                raise
        return {"phase": "soak", "job_count": len(jobs),
                "ledger": str(ledger_path), "blocked": False,
                "qualification_eligible": False}


def create_soak_material_index(
    context: CampaignContext, parent_recipe_path: Path,
    build_receipt_path: Path, output_path: Path,
) -> dict[str, Any]:
    """Bind one real externally built V2 recipe and receipt to the original Soak job."""
    require(context.scope == "final_frozen" and
            context.prepared_input_completion is not None,
            "Source5 Soak materials require the final prepared-input generation")
    jobs = _host_jobs(context, "soak")
    require(len(jobs) == 1,
            "Source5 host has no unique original Soak job")
    binding = context.modules["scripts/application-source5-soak.py"].\
        _selected_prepared_host_binding(
            context.prepared_input_completion, context.host_id,
        )
    recipe_path = parent_recipe_path.resolve(strict=True)
    receipt_path = build_receipt_path.resolve(strict=True)
    recipe_raw, recipe_sha, _recipe_info = read_stable(
        recipe_path, "Source5 original Soak recipe", MAX_ARTIFACT_BYTES,
    )
    receipt_raw, receipt_sha, _receipt_info = read_stable(
        receipt_path, "Source5 original Soak recipe-build receipt", MAX_ARTIFACT_BYTES,
    )
    require(recipe_raw == canonical_bytes(json.loads(recipe_raw)) and
            receipt_raw == canonical_bytes(json.loads(receipt_raw)),
            "Source5 Soak parent recipe or build receipt is not canonical JSON")
    helper = context.modules["scripts/application-source5-soak.py"]
    index = helper.make_material_index(
        context.manifest["campaign_id"], context.host_id, jobs[0],
        {"path": str(recipe_path), "raw_sha256": recipe_sha},
        {"path": str(receipt_path), "raw_sha256": receipt_sha},
        binding["binding_sha256"],
    )
    prep_context = {
        "campaign_id": context.manifest["campaign_id"],
        "host_id": context.host_id,
        "prepared": {
            "spec_path": Path(context.spec_pin["path"]),
            "spec_raw_sha256": context.spec_pin["raw_sha256"],
            "spec_semantic_sha256": context.spec_semantic_sha256,
            "plan_path": Path(context.plan_pin["path"]),
            "plan_raw_sha256": context.plan_pin["raw_sha256"],
            "plan_semantic_sha256": context.plan_semantic_sha256,
        },
        "source_manifest_raw_refs": {
            host: {
                "host_id": host,
                "path": pin["path"],
                "raw_sha256": pin["raw_sha256"],
                "semantic_sha256": context.sources[host]["manifest_sha256"],
                "source_tree_sha256":
                    context.sources[host]["source"]["source_tree_sha256"],
            }
            for host, pin in context.source_manifest_pins.items()
        },
        "source_root": context.source_root,
        "source": context.source,
    }
    helper._verify_build_receipt(
        index, prep_context, jobs[0], binding,
        context.modules["scripts/application-soak-readback.py"],
    )
    output = output_path.absolute()
    require(output.is_relative_to(context.artifact_root),
            "Source5 Soak materials index output is outside the private artifact root")
    output_parent = _private_directory(output.parent)
    output = output_parent / output.name
    require(output.parent.resolve(strict=True) == output.parent and
            stat.S_IMODE(output.parent.stat().st_mode) == 0o700 and
            not output.exists() and not output.is_symlink(),
            "Source5 Soak materials index output must be a new private artifact")
    raw = canonical_bytes(index)
    checksum = write_new(output, raw, "Source5 Soak materials index")
    return {"path": str(output), "raw_sha256": checksum,
            "materials_sha256": index["materials_sha256"]}


def run_host(context: CampaignContext, phase: str,
             pressure_material_index: Path | None = None,
             soak_material_index: Path | None = None) -> dict[str, Any]:
    require(phase in {
        "all", "exploration", "aa", "confirmation", "fixed_analysis",
        "pressure", "pressure_analysis", "soak", "final_analysis",
    }, "Source5 selected phase is outside the closed original phase enum")
    if context.scope == "prospective_exploration":
        require(phase in {"all", "exploration"},
                "prospective Source5 manifests are closed to exploration export only")
        if phase == "all":
            run_fixed_phase(context, "exploration")
            analysis = analyze_phase(context, "exploration")
            return {
                "scope": context.scope,
                "campaign_id": context.manifest["campaign_id"],
                "host_id": context.host_id,
                "phase_gate_passed": analysis["record"]["phase_gate_passed"],
                "rates": analysis["record"]["analysis"]["rate_status"],
                "campaign_qualification_eligible": False,
                "next_required_input": "separately_frozen_final_spec_plan_and_source_manifests",
            }
        return run_fixed_phase(context, "exploration")
    require(context.scope == "final_frozen",
            "Source5 scope is not one of the closed prospective/final values")
    sequence = {
        "exploration": ("fixed:exploration",),
        "aa": ("fixed:aa",),
        "confirmation": ("fixed:confirmation",),
        "fixed_analysis": ("analysis:fixed_analysis",),
        "pressure": ("pressure",),
        "pressure_analysis": ("analysis:pressure_analysis",),
        "soak": ("soak", "analysis:soak"),
        "final_analysis": ("analysis:final_analysis",),
        "all": (
            "fixed:exploration", "analysis:exploration",
            "fixed:aa", "analysis:aa",
            "fixed:confirmation", "analysis:fixed_analysis",
            "pressure", "analysis:pressure_analysis",
            "soak", "analysis:soak", "analysis:final_analysis",
        ),
    }[phase]
    outcomes = []
    for action in sequence:
        if action.startswith("fixed:"):
            outcomes.append(run_fixed_phase(context, action.split(":", 1)[1]))
        elif action.startswith("analysis:"):
            outcomes.append(analyze_phase(context, action.split(":", 1)[1]))
        elif action == "pressure":
            require(pressure_material_index is not None,
                    "Source5 pressure execution requires its closed, raw-pinned per-job actual producer-material index")
            outcomes.append(run_pressure_phase(context, pressure_material_index))
        elif action == "soak":
            require(soak_material_index is not None,
                    "Source5 Soak execution requires its raw-pinned original parent-recipe/build-receipt materials index")
            outcomes.append(run_soak_phase(context, soak_material_index))
    return {
        "scope": context.scope,
        "campaign_id": context.manifest["campaign_id"],
        "host_id": context.host_id,
        "actions": outcomes,
        "campaign_qualification_eligible": False,
    }


def verify_source5_final_cohort(manifest_paths: object) -> dict[str, Any]:
    """Replay three independent host journals and fail closed on missing offline pressure replay."""
    require(type(manifest_paths) is dict and len(manifest_paths) == 3 and
            all(type(key) is str and
                (type(value) is str or isinstance(value, Path))
                for key, value in manifest_paths.items()),
            "Source5 final cohort requires exactly three host-to-manifest paths")
    first_host = next(iter(manifest_paths))
    first_path = Path(manifest_paths[first_host]).resolve(strict=True)
    first_manifest, _first_raw, _first_sha = read_json(
        first_path, "Source5 first cohort execution manifest", MAX_MANIFEST_BYTES,
    )
    host_order = first_manifest.get("hosts")
    require(type(host_order) is list and len(host_order) == 3 and
            len(set(host_order)) == 3 and set(manifest_paths) == set(host_order),
            "Source5 final cohort manifests do not cover the exact original three-host order")
    common_projection = {
        key: first_manifest[key] for key in (
            "campaign_id", "hosts", "original_inputs", "execution_sources",
            "modules", "observed_hosts", "phase_order", "protocol_sha256",
            "scope", "prepared_input_generation",
        ) if key in first_manifest
    }
    require(first_manifest.get("schema") == EXECUTION_SCHEMA_V2 and
            first_manifest.get("scope") == "final_prepared" and
            first_manifest.get("phase_order") == list(PHASE_ORDER),
            "Source5 final cohort requires the immutable prepared Source5 execution schema")
    decisions: list[dict[str, Any]] = []
    blockers: list[str] = []
    common_registration = None
    for host_id in host_order:
        manifest_path = Path(manifest_paths[host_id]).resolve(strict=True)
        context = load_context(manifest_path, host_id)
        require(context.scope == "final_frozen" and
                context.prepared_input_completion is not None,
                f"Source5 {host_id} manifest is not in the final prepared generation")
        projection = {
            key: context.manifest[key] for key in common_projection
        }
        require(projection == common_projection,
                f"Source5 {host_id} manifest changed common immutable cohort provenance")
        registration = context.manifest["prepared_capacity_registration"]
        if common_registration is None:
            common_registration = registration["completion"]
        require(registration["completion"] == common_registration,
                f"Source5 {host_id} capacity registration uses another cohort completion")
        with context.chronology.campaign_host_lock(
            context.output_root, context.manifest["campaign_id"], host_id,
        ) as lock:
            replay = _validate_locked_context(context, lock)
            state = replay["state"]
            final_event = state["source5_analyses"].get("final_analysis")
            if final_event is None:
                blockers.append(f"missing_final_analysis:{host_id}")
                continue
            final_pin = raw_pin(final_event["analysis"],
                                f"Source5 {host_id} final decision")
            final_record, _raw, final_sha = read_json(
                Path(final_pin["path"]), f"Source5 {host_id} final decision",
                MAX_ARTIFACT_BYTES, final_pin["raw_sha256"],
            )
            final_body = {key: value for key, value in final_record.items()
                          if key != "analysis_sha256"}
            require(final_record.get("schema") == ANALYSIS_SCHEMA and
                    final_record.get("phase") == "final_analysis" and
                    final_record.get("campaign_id") == context.manifest["campaign_id"] and
                    final_record.get("host_id") == host_id and
                    final_record.get("campaign_qualification_eligible") is False and
                    final_record.get("analysis_sha256") ==
                        sha256(canonical_bytes(final_body)) and
                    final_pin["raw_sha256"] == final_sha,
                    f"Source5 {host_id} final analysis is not the fresh replayed host decision")
            numeric = final_record.get("numeric_gates_passed")
            require(type(numeric) is bool and
                    final_event["analysis_sha256"] == final_sha and
                    final_event["phase_gate_passed"] is numeric,
                    f"Source5 {host_id} final analysis event differs from its replayed decision")
            if numeric is not True:
                blockers.append(f"host_numeric_gate_failed:{host_id}")
            decisions.append({
                "host_id": host_id,
                "execution_manifest": {
                    "path": str(manifest_path),
                    "raw_sha256": context.manifest_pin["raw_sha256"],
                },
                "analysis": final_pin,
                "analysis_sha256": final_sha,
                "event_head": final_event["event_head"],
                "numeric_gates_passed": numeric,
            })
    blockers.append("accepted_pressure_offline_full_replay_api_unavailable")
    all_host_numeric = len(decisions) == 3 and all(
        item["numeric_gates_passed"] is True for item in decisions
    )
    return {
        "schema": "allocatbelt.application-source5-final-cohort-decision.v1",
        "campaign_id": first_manifest["campaign_id"],
        "host_order": host_order,
        "common_spec": first_manifest["original_inputs"]["spec"],
        "common_plan": first_manifest["original_inputs"]["plan"],
        "prepared_input_completion":
            first_manifest["prepared_input_generation"]["completion"],
        "host_decisions": decisions,
        "all_host_numeric_gates_passed": all_host_numeric,
        "cohort_numeric_gates_passed": False,
        "status": "blocked",
        "blockers": list(dict.fromkeys(blockers)),
        "campaign_qualification_eligible": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="validate closed SourceV5 inputs and the 15-entry capacity ancestry")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--host-id", required=True)
    index_soak = commands.add_parser(
        "index-soak-materials",
        help="verify and raw-pin the exact original Soak recipe/build receipt",
    )
    index_soak.add_argument("--manifest", required=True, type=Path)
    index_soak.add_argument("--host-id", required=True)
    index_soak.add_argument("--recipe", required=True, type=Path)
    index_soak.add_argument("--build-receipt", required=True, type=Path)
    index_soak.add_argument("--output", required=True, type=Path)
    cohort = commands.add_parser(
        "verify-final-cohort",
        help="freshly replay three independent host analyses and report aggregate blockers",
    )
    cohort.add_argument(
        "--host-manifest", action="append", required=True,
        metavar="HOST=PATH",
        help="one original host ID and its independent Source5 execution manifest; repeat three times",
    )
    run = commands.add_parser("run-host", help="execute the exact original phase schedule for one native host")
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--host-id", required=True)
    run.add_argument("--phase", choices=(
        "all", "exploration", "aa", "confirmation", "fixed_analysis",
        "pressure", "pressure_analysis", "soak", "final_analysis",
    ), default="all")
    run.add_argument("--pressure-material-index", type=Path)
    run.add_argument("--soak-material-index", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-final-cohort":
            manifest_paths: dict[str, Path] = {}
            for value in args.host_manifest:
                require(type(value) is str and "=" in value,
                        "each --host-manifest must use HOST=PATH")
                host_id, path_text = value.split("=", 1)
                require(host_id and path_text and host_id not in manifest_paths,
                        "Source5 final cohort repeats or omits a host manifest")
                manifest_paths[host_id] = Path(path_text)
            result = verify_source5_final_cohort(manifest_paths)
            sys.stdout.buffer.write(canonical_bytes(result))
            return 0 if result["status"] == "verified" else 3
        context = load_context(args.manifest, args.host_id)
        if args.command == "verify":
            with context.chronology.campaign_host_lock(
                context.output_root, context.manifest["campaign_id"],
                context.host_id, timeout_seconds=30.0,
            ) as lock:
                checked = _validate_locked_context(context, lock)
            result = {
                "schema": "allocatbelt.application-source5-campaign-verification.v1",
                "scope": context.scope,
                "campaign_id": context.manifest["campaign_id"],
                "host_id": context.host_id,
                "host_order": context.manifest["hosts"],
                "capacity_completion_raw_sha256": checked["capacity_replay"]["capacity_completion_raw_sha256"],
                "capacity_registration_head": checked["capacity_replay"]["registration_head"],
                "phase_order": list(PHASE_ORDER),
                "qualification_eligible": False,
                "execution_ready": False,
            }
        elif args.command == "index-soak-materials":
            result = {
                "schema": "allocatbelt.application-source5-soak-material-index-pin.v1",
                "campaign_id": context.manifest["campaign_id"],
                "host_id": context.host_id,
                **create_soak_material_index(
                    context, args.recipe, args.build_receipt, args.output,
                ),
                "qualification_eligible": False,
            }
        else:
            result = run_host(context, args.phase, args.pressure_material_index,
                              args.soak_material_index)
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except (Source5CampaignError, OSError, TypeError, ValueError, KeyError,
            AttributeError, AssertionError) as error:
        print(f"application source5 campaign refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
