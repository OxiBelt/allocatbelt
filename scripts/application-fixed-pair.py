#!/usr/bin/env python3
"""Execute and replay one immutable SourceV5 fixed-policy pair.

This component binds one original PlanV3 job and its two original runtime
recipes, then runs the normal application binaries directly.  A valid pair is
component evidence only; this module never enables campaign readiness.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, Callable


OVERLAY_SCHEMA = "allocatbelt.application-fixed-pair-execution-overlay.v1"
RECEIPT_SCHEMA = "allocatbelt.application-fixed-pair-execution-receipt.v1"
HOST_VERIFICATION_SCHEMA = "allocatbelt.application-fixed-pair-host-verification.v1"
HOST_VERIFICATION_IDENTITY_SCHEMA = "allocatbelt.application-fixed-pair-host-verification-identity.v1"
CAPTURED_REPLAY_CONTEXT_SCHEMA_V1 = "allocatbelt.application-fixed-pair-captured-replay-context.v1"
EVIDENCE_PATH_MAP_SCHEMA = "allocatbelt.application-pressure-evidence-path-map.v1"
PROBE_SCHEMA = "allocatbelt.application-fixed-pair-construction-probe.v1"
APP_STARTED_SCHEMA = "allocatbelt.application-fixed-pair-app-start.v1"
APP_TERMINAL_SCHEMA = "allocatbelt.application-fixed-pair-app-terminal.v1"
DIRECT_TIME_SCHEMA = "allocatbelt.application-fixed-pair-direct-launch-time.v1"
EXECUTION_STATUS = "source5_fixed_pair_component_only"
PAIR_PROCESS_HEADER_FALLBACK = (
    "pair executor allocator exit_code row_validation p99_qualification argv stdout time_report ids_sha256 "
    "shutdown_sha256 capacity_family_sha256 stdout_sha256 runtime_readback runtime_readback_sha256 "
    "runtime_expectation runtime_expectation_sha256 runtime_validation runtime_validation_sha256 "
    "runtime_recipe_sha256 resource_ceiling_sha256 policy_sha256 fixed_global_control_baseline "
    "validator_sha256 source_manifest_sha256 calibration_binary_sha256 calibration_output_sha256"
).split()

ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
EXECUTOR_LABELS = {"bounded": "allocatbelt", "tokio": "tokio-1.53.1"}
MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_ORACLE_BYTES = 512 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_BYTES = 128 * 1024
MAX_STDOUT_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_ID_BYTES = 16 * 1024 * 1024
MAX_PROBE_STDOUT_BYTES = 512 * 1024
MAX_PROBE_STDERR_BYTES = 64 * 1024
MAX_TIME_BYTES = 128 * 1024
MAX_PAIR_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_FILES = 4096
MAX_OUTPUT_DIRECTORIES = 1024
MAX_PROC_ENTRIES = 262_144
MAX_TMPDIR_BYTES = 1024 * 1024 * 1024
MAX_TMPDIR_INODES = 4096
TMPDIR_MONITOR_MAX_DEPTH = 32
# Bound a snapshot's temporary name collection to one full supported TMPDIR inode budget.
# This source-level work limit is independent of a caller's frozen inode allowance.
TMPDIR_MONITOR_MAX_ENUMERATED_ENTRIES = MAX_TMPDIR_INODES
TERM_GRACE_SECONDS = 3.0
KILL_REAP_SECONDS = 1.0
PROBE_TIMEOUT_SECONDS = 30.0
PROHIBITED_AMBIENT_ENV = (
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "PYTHONHOME", "PYTHONPATH",
    "PYTHONSTARTUP", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS",
)


class FixedPairError(ValueError):
    """A source pin, original binding, launch, or artifact failed validation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixedPairError(message)


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected field set")
    return value


def canonical_bytes(value: object) -> bytes:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise FixedPairError(f"value is not canonical JSON: {error}") from error
    return (payload + "\n").encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def is_sha(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _safe_absolute(value: object, label: str, *, must_exist: bool = True) -> Path:
    require(type(value) is str and Path(value).is_absolute(), f"{label} must be an absolute path")
    raw = Path(value)
    require(".." not in raw.parts and "\x00" not in value, f"{label} path is not normalized")
    try:
        resolved = raw.resolve(strict=must_exist)
    except OSError as error:
        raise FixedPairError(f"{label} is unavailable: {error}") from error
    require(resolved == raw, f"{label} traverses a symlink or alias")
    if must_exist:
        info = raw.lstat()
        require(not stat.S_ISLNK(info.st_mode), f"{label} is a symlink")
    return raw


def _safe_relative(value: object, label: str) -> str:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value, f"{label} is malformed")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and all(part not in ("", ".", "..") for part in path.parts), f"{label} is not normalized and relative")
    return value


def _stat_fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str, os.stat_result]:
    try:
        path_before = path.lstat()
        require(stat.S_ISREG(path_before.st_mode), f"{label} is not a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise FixedPairError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_fingerprint(before) == _stat_fingerprint(path_before), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite byte limit")
        chunks: list[bytes] = []
        hasher = hashlib.sha256()
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while reading")
            chunks.append(block)
            hasher.update(block)
            count += len(block)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        require(_stat_fingerprint(before) == _stat_fingerprint(after) == _stat_fingerprint(path_after) and count == before.st_size, f"{label} changed during its stable read")
        return b"".join(chunks), hasher.hexdigest(), before
    finally:
        os.close(descriptor)


def read_json_pin(pin_value: object, label: str, maximum: int) -> tuple[Path, dict[str, Any], bytes, str]:
    pin = exact(pin_value, {"path", "sha256"}, f"{label} raw pin")
    path = _safe_absolute(pin["path"], f"{label} path")
    require(is_sha(pin["sha256"]), f"{label} raw SHA-256 is malformed")
    raw, actual, _info = read_stable(path, label, maximum)
    require(actual == pin["sha256"], f"{label} differs from its raw SHA-256 pin")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value), f"{label} is not canonical JSON")
    return path, value, raw, actual


def write_exclusive(path: Path, raw: bytes, label: str, mode: int = 0o600) -> str:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {label}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise FixedPairError(f"cannot create {label}: {error}") from error
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            require(written > 0, f"short write while creating {label}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return sha256_bytes(raw)


def _load_pinned_module(raw: bytes, path: Path, label: str) -> types.ModuleType:
    module_name = f"fixed_pair_{label}_{sha256_bytes(raw)}_{id(raw):x}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException as error:
        sys.modules.pop(module_name, None)
        raise FixedPairError(f"pinned {label} cannot be loaded: {type(error).__name__}: {error}") from error
    return module


def _unescape_mount_field(value: str) -> str:
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def _mount_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    try:
        raw = Path("/proc/self/mountinfo").read_bytes()
    except OSError as error:
        raise FixedPairError(f"cannot read mount identity for private storage: {error}") from error
    require(len(raw) <= 2 * 1024 * 1024, "mount table exceeds its finite bound")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise FixedPairError("mount table is not UTF-8") from error
    matches: list[tuple[int, dict[str, Any]]] = []
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        before = left.split()
        after = right.split()
        if len(before) < 6 or len(after) < 3:
            continue
        mount_point = Path(_unescape_mount_field(before[4]))
        try:
            resolved.relative_to(mount_point)
        except ValueError:
            continue
        matches.append((len(str(mount_point)), {
            "mount_id": int(before[0]),
            "major_minor": before[2],
            "mount_root": _unescape_mount_field(before[3]),
            "mount_point": str(mount_point),
            "filesystem_type": after[0],
            "mount_source": _unescape_mount_field(after[1]),
        }))
    require(matches, f"cannot identify filesystem mount for {path}")
    identity = max(matches, key=lambda item: item[0])[1]
    require(identity["filesystem_type"] not in ("tmpfs", "ramfs", "devtmpfs"), "private output storage must not use a memory-backed filesystem")
    info = os.stat(resolved, follow_symlinks=False)
    stats = os.statvfs(resolved)
    identity.update({
        "device": info.st_dev,
        "available_bytes": stats.f_bavail * stats.f_frsize,
        "available_inodes": stats.f_favail,
    })
    return identity


def _private_output_root(value: object, source_root: Path, *, create: bool) -> Path:
    require(type(value) is str and Path(value).is_absolute(), "output_root must be an absolute path")
    raw = Path(value)
    require(".." not in raw.parts and not raw.is_symlink(), "output_root is aliased or traverses a symlink")
    if not raw.exists() and create:
        raw.mkdir(mode=0o700, parents=True)
    path = _safe_absolute(str(raw), "output_root")
    require(path.is_dir(), "output_root is not a directory")
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "output_root must be an owned mode-0700 directory")
    try:
        path.relative_to(source_root)
        inside_source = True
    except ValueError:
        inside_source = False
    require(not inside_source, "output_root must be outside the selected source tree")
    _mount_identity(path)
    return path


def _private_output_root_offline(value: object, source_root: Path) -> Path:
    """Check private path ownership without consulting the coordinator mount table."""
    require(type(value) is str and Path(value).is_absolute(), "offline output_root must be an absolute path")
    raw = Path(value)
    require(".." not in raw.parts and not raw.is_symlink(), "offline output_root is aliased or traverses a symlink")
    path = _safe_absolute(str(raw), "offline output_root")
    require(path.is_dir(), "offline output_root is not a directory")
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "offline output_root must be an owned mode-0700 directory")
    try:
        path.relative_to(source_root)
        inside_source = True
    except ValueError:
        inside_source = False
    require(not inside_source, "offline output_root must be outside the selected source tree")
    return path


def _parse_cpu_set(helper: types.ModuleType, value: str) -> list[int]:
    cpus = sorted(helper._parse_cpu_set(value))
    require(cpus and cpus == sorted(set(cpus)), "pinned host CPU set is empty or duplicated")
    return cpus


def _live_network_namespace_inode() -> int:
    try:
        value = os.stat("/proc/self/ns/net").st_ino
    except OSError as error:
        raise FixedPairError(f"cannot read current network namespace identity: {error}") from error
    require(type(value) is int and value > 0, "current network namespace inode is invalid")
    return value


def _reject_ambient_startup_hooks() -> None:
    present = [name for name in PROHIBITED_AMBIENT_ENV if os.environ.get(name)]
    require(not present, f"ambient code-loading/startup variables are present: {','.join(present)}")


def _safe_child(root: Path, relative: object, label: str) -> Path:
    text = _safe_relative(relative, label)
    candidate = root.joinpath(*PurePosixPath(text).parts)
    cursor = root
    for component in PurePosixPath(text).parts:
        cursor = cursor / component
        require(not cursor.is_symlink(), f"{label} traverses a symlink: {text}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise FixedPairError(f"{label} is missing or escaped its root: {text}") from error
    require(resolved == candidate, f"{label} path has an alias: {text}")
    return candidate


def _write_tsv(path: Path, header: list[str], rows: list[list[str]], label: str) -> str:
    require(all(len(row) == len(header) and all("\t" not in field and "\n" not in field and "\r" not in field for field in row) for row in rows), f"{label} rows are malformed")
    raw = ("\t".join(header) + "\n" + "".join("\t".join(row) + "\n" for row in rows)).encode("utf-8")
    return write_exclusive(path, raw, label)


def _read_pair_artifact(
    path: Path, label: str, maximum: int,
    artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> tuple[bytes, str]:
    if artifact_view is not None:
        return artifact_view.read(path, label, maximum)
    raw, checksum, _info = read_stable(path, label, maximum)
    return raw, checksum


def _pair_artifact_exists(path: Path, artifact_view: CapturedFixedPairArtifactsV1 | None) -> bool:
    if artifact_view is not None:
        return artifact_view.has_file(path)
    return path.exists() or path.is_symlink()


def _read_tsv(
    path: Path, label: str, max_bytes: int, *,
    artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> tuple[list[str], list[dict[str, str]], bytes, str]:
    raw, checksum = _read_pair_artifact(path, label, max_bytes, artifact_view)
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw, f"{label} framing is invalid")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise FixedPairError(f"{label} is not UTF-8") from error
    require(lines, f"{label} is empty")
    header = lines[0].split("\t")
    require(header and len(header) == len(set(header)), f"{label} has duplicate or empty columns")
    rows: list[dict[str, str]] = []
    for index, line in enumerate(lines[1:]):
        fields = line.split("\t")
        require(len(fields) == len(header), f"{label} row {index} has the wrong field count")
        rows.append(dict(zip(header, fields, strict=True)))
    return header, rows, raw, checksum


def _host_observation(host_pin: object, spec: dict[str, Any], host_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    pin = exact(host_pin, {"path", "sha256"}, "observed host contract raw pin")
    path = _safe_absolute(pin["path"], "observed host contract path")
    require(is_sha(pin["sha256"]), "observed host contract raw SHA-256 is malformed")
    raw, raw_sha, _info = read_stable(path, "observed host contract", MAX_MANIFEST_BYTES)
    require(raw_sha == pin["sha256"], "observed host contract differs from its raw pin")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"observed host contract is not bounded JSON: {error}") from error
    require(type(value) is dict, "observed host contract is not a JSON object")
    matches = [item for item in spec["hosts"] if type(item) is dict and item.get("host_id") == host_id]
    require(len(matches) == 1 and value == matches[0], "observed host contract differs from the original SpecV3 host entry")
    require(type(value.get("controls")) is dict, "observed host contract has no frozen controls")
    observation = {
        "pin": {"path": str(path), "sha256": raw_sha},
        "value": value,
        "controls_sha256": sha256_bytes(canonical_bytes(value["controls"])),
        "host_fingerprint_sha256": value["host_fingerprint_sha256"],
        "process_affinity": sorted(os.sched_getaffinity(0)),
        "network_namespace_inode": _live_network_namespace_inode(),
        "raw_sha256": raw_sha,
        "raw_bytes": len(raw),
    }
    return value, observation


def _host_observation_offline(
    host_pin: object, spec: dict[str, Any], host_id: str,
    host_verification: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use only facts captured by the strict peer verifier, never local /proc."""
    identity = exact(host_verification, {
        "schema", "host_id", "observed_host_raw_sha256", "process_affinity",
        "network_namespace_inode", "output_mount", "host_verification_sha256",
    }, "strict peer host identity")
    identity_body = {key: item for key, item in identity.items() if key != "host_verification_sha256"}
    require(identity["schema"] == HOST_VERIFICATION_IDENTITY_SCHEMA and
            identity["host_id"] == host_id and
            identity["host_verification_sha256"] == sha256_bytes(canonical_bytes(identity_body)),
            "strict peer host identity schema, host or digest is invalid")
    pin = exact(host_pin, {"path", "sha256"}, "observed host contract raw pin")
    path = _safe_absolute(pin["path"], "observed host contract path")
    require(is_sha(pin["sha256"]), "observed host contract raw SHA-256 is malformed")
    raw, raw_sha, _info = read_stable(path, "observed host contract", MAX_MANIFEST_BYTES)
    require(raw_sha == pin["sha256"] == host_verification["observed_host_raw_sha256"],
            "peer host-verification receipt refers to different observed-host bytes")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"observed host contract is not bounded JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value), "observed host contract is not canonical JSON")
    matches = [item for item in spec["hosts"] if type(item) is dict and item.get("host_id") == host_id]
    require(len(matches) == 1 and value == matches[0], "observed host contract differs from the original SpecV3 host entry")
    require(type(value.get("controls")) is dict, "observed host contract has no frozen controls")
    affinity = identity["process_affinity"]
    require(type(affinity) is list and affinity and
            affinity == sorted(set(uint for uint in affinity if type(uint) is int and 0 <= uint <= 65535)),
            "peer host-verification CPU affinity is malformed")
    netns = identity["network_namespace_inode"]
    require(type(netns) is int and netns > 0, "peer host-verification network namespace is malformed")
    observation = {
        "pin": {"path": str(path), "sha256": raw_sha},
        "value": value,
        "controls_sha256": sha256_bytes(canonical_bytes(value["controls"])),
        "host_fingerprint_sha256": value["host_fingerprint_sha256"],
        "process_affinity": affinity,
        "network_namespace_inode": netns,
        "raw_sha256": raw_sha,
        "raw_bytes": len(raw),
    }
    return value, observation


def _offline_host_observation(
    offline_facts: object, host_pin: object, spec: dict[str, Any], host_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate outer receipt and its separately versioned nested host identity."""
    facts = exact(offline_facts, {"schema", "host_verification"}, "strict peer host-verification receipt")
    require(facts["schema"] == HOST_VERIFICATION_SCHEMA,
            "strict peer host-verification receipt schema is invalid")
    identity = exact(facts["host_verification"], {
        "schema", "host_id", "observed_host_raw_sha256", "process_affinity",
        "network_namespace_inode", "output_mount", "host_verification_sha256",
    }, "strict peer nested host identity")
    require(identity["schema"] == HOST_VERIFICATION_IDENTITY_SCHEMA,
            "strict peer nested host identity schema is invalid")
    return _host_observation_offline(host_pin, spec, host_id, identity)


def _inventory_entry(inventory: list[dict[str, Any]], relative: str, label: str) -> dict[str, Any]:
    rows = [item for item in inventory if type(item) is dict and item.get("path") == relative]
    require(len(rows) == 1, f"SourceV5 typed inventory has no unique {label} entry")
    record = rows[0]
    exact(record, {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755") and is_sha(record["sha256"]), f"SourceV5 {label} is not a typed regular file")
    require(type(record["size"]) is int and 0 <= record["size"] <= MAX_SOURCE_BYTES, f"SourceV5 {label} size is outside its finite bound")
    return record


MODULE_PATHS = {
    "executor": "scripts/application-fixed-pair.py",
    "campaign_controller": "scripts/application-campaign.py",
    "inventory_verifier": "scripts/application-source-inventory.py",
    "runtime_reader": "scripts/application-runtime-readback.py",
    "feedback_reader": "scripts/application-feedback-readback.py",
    "campaign_inputs": "scripts/application-campaign-inputs.py",
    "launch_identity_helper": "scripts/application-soak-readback.py",
}


def _module_pins(source: dict[str, Any], source_root: Path, execution_pins: dict[str, Any]) -> tuple[dict[str, dict[str, str]], list[dict[str, Any]], types.ModuleType, dict[str, types.ModuleType]]:
    requested = exact(execution_pins["modules"], set(MODULE_PATHS), "execution module pins")
    inventory = source["source"]["files"]
    inv_record = _inventory_entry(inventory, "scripts/application-source-inventory.py", "inventory verifier")
    require(inv_record["sha256"] == "09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950", "SourceV5 inventory verifier differs from the controller's pinned inventory implementation")
    harness = source["qualification_harness"]
    expected_harness = {
        "campaign_controller": harness["campaign_controller"],
        "feedback_reader": harness["feedback_validator"],
        "launch_identity_helper": harness["soak_validator"],
    }
    expected_harness["runtime_reader"] = source["runtime_readback_validator"]
    modules: dict[str, dict[str, str]] = {}
    execution_records: list[dict[str, Any]] = []
    loaded: dict[str, types.ModuleType] = {}
    inventory_module: types.ModuleType | None = None
    for name, relative in MODULE_PATHS.items():
        record = _inventory_entry(inventory, relative, name.replace("_", " "))
        pin = exact(requested[name], {"path", "sha256"}, f"execution module {name}")
        require(pin["path"] == relative and pin["sha256"] == record["sha256"], f"execution module {name} is not the exact selected SourceV5 regular-file pin")
        if name in expected_harness:
            harness_pin = expected_harness[name]
            require(pin == {"path": harness_pin["path"], "sha256": harness_pin["sha256"]}, f"execution module {name} differs from its original SourceV5 pin")
        module_path = _safe_child(source_root, relative, f"pinned execution module {name}")
        raw, checksum, info = read_stable(module_path, f"pinned execution module {name}", MAX_SOURCE_BYTES)
        mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
        require(checksum == record["sha256"] and len(raw) == record["size"] and mode == record["mode"], f"execution module {name} differs from its typed inventory entry")
        if name == "executor":
            current_path = Path(__file__).resolve(strict=True)
            require(current_path == module_path and _hash_regular_file(current_path, MAX_SOURCE_BYTES, "executing fixed-pair module") == checksum, "running fixed-pair executor is not the exact selected SourceV5 inventoried bytes")
        modules[name] = {"path": relative, "sha256": checksum}
        execution_records.append(record)
        loaded[name] = _load_pinned_module(raw, module_path, name)
        if name == "inventory_verifier":
            inventory_module = loaded[name]
    require(inventory_module is not None, "pinned inventory verifier was not loaded")
    execution_records.sort(key=lambda item: item["path"].encode("utf-8"))
    return modules, execution_records, inventory_module, loaded


def _load_source_inputs(
    original_pins: dict[str, Any], execution_pins: dict[str, Any], exact_job: dict[str, Any],
    observed_host_pin: object, output_root_value: object, *, create_output: bool,
    offline_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Only the origin-host launcher inspects startup hooks or SIGCHLD. Offline
    # replay has no process/lock capability and consumes its pinned host facts.
    if offline_facts is None:
        _reject_ambient_startup_hooks()
        _require_waitable_sigchld()
    original = exact(original_pins, {
        "spec", "spec_semantic_sha256", "plan", "plan_semantic_sha256", "source_manifests", "campaign_artifacts_root",
    }, "original input pins")
    execution = exact(execution_pins, {"source_root", "selected_host_id", "modules"}, "execution pins")
    spec_path, spec, spec_raw, spec_raw_sha = read_json_pin(original["spec"], "original SpecV3", MAX_SPEC_BYTES)
    plan_path, plan, plan_raw, plan_raw_sha = read_json_pin(original["plan"], "original PlanV3", MAX_PLAN_BYTES)
    require(is_sha(original["spec_semantic_sha256"]) and sha256_bytes(canonical_bytes(spec)) == original["spec_semantic_sha256"], "SpecV3 semantic digest differs from its separate pin")
    require(spec.get("schema") == "allocatbelt.application-campaign-spec.v3", "fixed-pair executor requires the original immutable SpecV3")
    plan_semantic = plan.get("plan_sha256")
    require(is_sha(original["plan_semantic_sha256"]) and plan_semantic == original["plan_semantic_sha256"], "PlanV3 semantic digest differs from its separate pin")
    plan_body = dict(plan)
    plan_body.pop("plan_sha256", None)
    require(sha256_bytes(canonical_bytes(plan_body)) == plan_semantic, "PlanV3 internal semantic digest is invalid")

    source_root = _safe_absolute(execution["source_root"], "selected SourceV5 source root")
    require(source_root.is_dir(), "selected SourceV5 source root is not a directory")
    require(
        callable(getattr(os, "waitid", None)) and hasattr(os, "WNOWAIT") and hasattr(os, "P_PID")
        and callable(getattr(os, "pidfd_open", None)) and callable(getattr(signal, "pidfd_send_signal", None)),
        "direct APP cleanup requires Linux waitid(WNOWAIT) and pidfd signaling support",
    )
    input_root = spec_path.parent
    refs = spec.get("source_manifests")
    require(type(refs) is list and len(refs) in (2, 3),
            "SpecV3 must retain a complete supported host source manifest set")
    source_pins = exact(original["source_manifests"], {item.get("host_id") for item in refs if type(item) is dict}, "original source-manifest pins")
    sources: dict[str, dict[str, Any]] = {}
    source_manifest_records: dict[str, dict[str, Any]] = {}
    for index, reference_value in enumerate(refs):
        reference = exact(reference_value, {"host_id", "relative_path", "sha256"}, f"SpecV3 source reference[{index}]")
        host_id = reference["host_id"]
        relative = _safe_relative(reference["relative_path"], f"source manifest {host_id} relative path")
        source_path = _safe_child(input_root, relative, f"original source manifest {host_id}")
        supplied_pin = exact(source_pins[host_id], {"path", "sha256"}, f"source manifest {host_id} raw pin")
        require(supplied_pin["path"] == str(source_path) and is_sha(supplied_pin["sha256"]), f"source manifest {host_id} raw pin differs from its original SpecV3 reference path")
        raw, raw_sha, _info = read_stable(source_path, f"source manifest {host_id}", MAX_MANIFEST_BYTES)
        require(raw_sha == supplied_pin["sha256"], f"source manifest {host_id} differs from its raw pin")
        try:
            source_value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise FixedPairError(f"source manifest {host_id} is not bounded JSON: {error}") from error
        require(type(source_value) is dict and raw == canonical_bytes(source_value), f"source manifest {host_id} is not canonical JSON")
        require(source_value.get("schema") == "allocatbelt.application-source-manifest.v5", f"source manifest {host_id} is not SourceV5")
        require(source_value.get("manifest_sha256") == reference["sha256"], f"source manifest {host_id} semantic digest differs from its original SpecV3 reference")
        sources[host_id] = source_value
        source_manifest_records[host_id] = {
            "pin": {"path": str(source_path), "sha256": raw_sha},
            "manifest_sha256": source_value.get("manifest_sha256"),
        }
    require(set(source_pins) == set(sources), "source-manifest raw pins do not cover the original SpecV3 source set")

    require(type(exact_job) is dict, "exact_job must be the original plan job object")
    host_id = exact_job.get("host_id")
    require(host_id == execution["selected_host_id"] and host_id in sources, "selected SourceV5 host differs from the original job")
    require(exact_job.get("phase") in ("exploration", "aa", "confirmation") and exact_job.get("comparison_family") == "fixed_policy", "only original fixed-policy PlanV3 jobs can be dispatched")
    phase_jobs = plan.get("jobs", {}).get(exact_job.get("phase"))
    require(type(phase_jobs) is list, "PlanV3 has no original fixed phase schedule for the selected job")
    matches = [job for job in phase_jobs if type(job) is dict and job.get("run_id") == exact_job.get("run_id")]
    require(len(matches) == 1 and canonical_bytes(matches[0]) == canonical_bytes(exact_job), "exact_job differs from its unique original PlanV3 schedule row")

    selected_host = sources[host_id]
    if offline_facts is None:
        output_root = _private_output_root(output_root_value, source_root, create=create_output)
    else:
        require(not create_output, "offline replay cannot create or replace a fixed-pair output root")
        output_root = _private_output_root_offline(output_root_value, source_root)
    artifact_root = _safe_absolute(original["campaign_artifacts_root"], "campaign oracle artifact root")
    require(artifact_root.is_dir(), "campaign oracle artifact root is not a directory")
    try:
        artifact_root.relative_to(source_root)
        artifact_inside_source = True
    except ValueError:
        artifact_inside_source = False
    require(not artifact_inside_source, "campaign artifacts must remain outside the selected source tree")
    for protected_root, label in (
        (input_root, "original specification/source input root"),
        (artifact_root, "trusted campaign artifact root"),
    ):
        try:
            output_root.relative_to(protected_root)
            output_inside = True
        except ValueError:
            output_inside = False
        try:
            protected_root.relative_to(output_root)
            output_contains = True
        except ValueError:
            output_contains = False
        require(not output_inside and not output_contains, f"private output_root overlaps the {label}")
    if offline_facts is None:
        host_value, observed = _host_observation(observed_host_pin, spec, host_id)
    else:
        host_value, observed = _offline_host_observation(
            offline_facts, observed_host_pin, spec, host_id,
        )
    host_pin_path = observed["pin"]["path"]

    # The original SourceV5 controller validates every host manifest; only the
    # selected host has a live source checkout and executable artifacts here.
    requested_controller = execution["modules"].get("campaign_controller")
    require(type(requested_controller) is dict, "execution pins omit the captured campaign controller")
    controller_relative = "scripts/application-campaign.py"
    controller_record = _inventory_entry(selected_host["source"]["files"], controller_relative, "campaign controller")
    controller_path = _safe_child(source_root, controller_relative, "captured campaign controller")
    controller_raw, controller_sha, _controller_info = read_stable(controller_path, "captured campaign controller", MAX_SOURCE_BYTES)
    require(controller_sha == controller_record["sha256"] == selected_host["qualification_harness"]["campaign_controller"]["sha256"], "captured controller differs from SourceV5 typed inventory and harness pins")
    controller = _load_pinned_module(controller_raw, controller_path, "campaign_controller")
    for other_host, source_value in sources.items():
        try:
            controller.verify_source_manifest(
                source_value,
                source_root=source_root if other_host == host_id else None,
                verify_artifacts=(other_host == host_id),
            )
        except Exception as error:
            raise FixedPairError(f"captured SourceV5 full verifier rejected {other_host}: {error}") from error
    try:
        spec_validation = controller.validate_spec(spec, sources, input_root=input_root)
        input_module_sha = controller.campaign_inputs_source_sha256(sources)
        controller.verify_plan(plan, selected_host["runtime_readback_validator"]["sha256"], input_module_sha)
    except Exception as error:
        raise FixedPairError(f"captured SourceV5 controller rejected original SpecV3/PlanV3: {error}") from error
    require(plan["campaign_id"] == spec["campaign_id"] and plan["spec_sha256"] == original["spec_semantic_sha256"], "PlanV3 campaign/spec binding differs from the original SpecV3")
    require(plan["source_manifests"].get(host_id) == selected_host["manifest_sha256"], "PlanV3 selected host source differs from its raw manifest pin")

    module_values, execution_inventory, inventory_module, loaded_modules = _module_pins(selected_host, source_root, execution)
    require(loaded_modules["campaign_controller"].PAIR_PROCESS_HEADER == PAIR_PROCESS_HEADER_FALLBACK, "captured controller changed the closed original PAIR_PROCESS_HEADER")
    # Every helper is loaded from bytes just checked against this selected
    # SourceV5 inventory; no ambient Python import selects executable code.
    require(loaded_modules["campaign_controller"].SOURCE_SCHEMA_V5 == controller.SOURCE_SCHEMA_V5, "captured controller module roles disagree")
    try:
        source_tree_digest = inventory_module.digest_records(selected_host["source"]["files"])
        execution_inventory_digest = inventory_module.digest_records(execution_inventory)
    except Exception as error:
        raise FixedPairError(f"pinned SourceV5 inventory verifier rejected typed entries: {error}") from error
    require(source_tree_digest == selected_host["source"]["source_tree_sha256"], "SourceV5 typed inventory does not produce its selected tree digest")
    require(execution_inventory_digest, "execution module inventory digest is empty")
    try:
        cpu_ids = _parse_cpu_set(loaded_modules["launch_identity_helper"], host_value["controls"]["cpu_set"])
    except Exception as error:
        raise FixedPairError(f"pinned launch helper rejected the host CPU set: {error}") from error
    require(set(cpu_ids).issubset(set(observed["process_affinity"])), "frozen APP CPU set is outside the observed host process affinity")
    require(observed["host_fingerprint_sha256"] == host_value["host_fingerprint_sha256"], "observed host fingerprint changed during preflight")
    require(host_pin_path == observed_host_pin["path"], "observed host raw pin path changed")

    source_ref_pins = {
        host: {"path": value["pin"]["path"], "sha256": value["pin"]["sha256"]}
        for host, value in source_manifest_records.items()
    }
    return {
        "spec_path": spec_path,
        "spec": spec,
        "spec_raw": spec_raw,
        "spec_raw_sha256": spec_raw_sha,
        "spec_semantic_sha256": original["spec_semantic_sha256"],
        "plan_path": plan_path,
        "plan": plan,
        "plan_raw": plan_raw,
        "plan_raw_sha256": plan_raw_sha,
        "plan_semantic_sha256": plan_semantic,
        "source_pins": source_ref_pins,
        "source_manifest_records": source_manifest_records,
        "sources": sources,
        "source": selected_host,
        "source_root": source_root,
        "source_tree_sha256": selected_host["source"]["source_tree_sha256"],
        "source_git_commit": selected_host["source"]["git_commit"],
        "build_sha256": sha256_bytes(canonical_bytes(selected_host["build"])),
        "host_id": host_id,
        "host_value": host_value,
        "observed_host": observed,
        "host_pin": {"path": host_pin_path, "sha256": observed["raw_sha256"]},
        "campaign_artifacts_root": artifact_root,
        "output_root": output_root,
        "controller": controller,
        "inventory_module": inventory_module,
        "modules": module_values,
        "execution_inventory": execution_inventory,
        "execution_inventory_sha256": execution_inventory_digest,
        "loaded_modules": loaded_modules,
        "spec_validation": spec_validation,
        "job": exact_job,
        "cpu_ids": cpu_ids,
        "input_root": input_root,
        "offline_facts": offline_facts,
    }


def _member_descriptors(job: dict[str, Any], controller: types.ModuleType) -> list[dict[str, str]]:
    descriptors = [dict(item) for item in controller.process_descriptors(job)]
    require(len(descriptors) == 2, "original fixed job must have exactly two process descriptors")
    if job["phase"] == "aa":
        return descriptors
    if job.get("comparison_kind") == "allocator":
        require({item["pair"] for item in descriptors} == {"candidate", "baseline"}, "allocator-match descriptors differ from the original candidate/baseline pair")
        return descriptors if job["ordinal"] % 2 else list(reversed(descriptors))
    require({item["executor"] for item in descriptors} == {"bounded", "tokio"}, "executor-match descriptors differ from bounded/Tokio")
    return descriptors if job["ordinal"] % 2 == 0 else list(reversed(descriptors))


def _member_oracle(job: dict[str, Any], allocator: str) -> dict[str, Any] | None:
    if job["mode"] != "open_loop":
        return None
    if job.get("comparison_kind") == "allocator":
        oracle = job.get("oracles", {}).get(allocator)
    else:
        oracle = job.get("oracle")
    require(type(oracle) is dict and oracle.get("allocator") == allocator, "open-loop member has no exact original allocator-bound oracle")
    return oracle


def _member_argv(job: dict[str, Any], descriptor: dict[str, str], binary: Path, deadlines: dict[str, Any]) -> list[str]:
    argv = [
        str(binary), "--executor", descriptor["executor"], "--workload", job["workload"],
        "--profile", job["profile"], "--mode", job["mode"],
        "--trace-deadline-seconds", str(deadlines["trace_seconds"]),
        "--drain-deadline-seconds", str(deadlines["drain_seconds"]),
        "--shutdown-deadline-seconds", str(deadlines["shutdown_seconds"]),
        "--process-deadline-seconds", str(deadlines["process_seconds"]),
    ]
    if job["mode"] == "open_loop":
        argv.extend(["--rate", str(job["rate_per_second"]), "--arrivals", str(job["arrivals"])])
    require(argv[0] == str(binary), "normal APP argv does not start with the source-pinned executable")
    return argv


def _derive_expected_environment(
    job: dict[str, Any], descriptor: dict[str, str], binding: dict[str, Any], source: dict[str, Any],
    tmpdir: Path, outputs: dict[str, str], oracle_path: Path | None, oracle_sha256: str | None,
) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(tmpdir),
        "ALLOCATBELT_APP_SHUTDOWN_REPORT": outputs["shutdown"],
        "ALLOCATBELT_APP_ID_REPORT": outputs["ids"],
        "ALLOCATBELT_APP_FAMILY_REPORT": outputs["capacity_families"],
        "ALLOCATBELT_APP_RUNTIME_REPORT": outputs["runtime_readback"],
        "ALLOCATBELT_APP_COMPARISON_FAMILY": "fixed_policy",
        "ALLOCATBELT_APP_RESOURCE_CEILING_SHA256": binding["resource_ceiling_sha256"],
        "ALLOCATBELT_APP_POLICY_SHA256": binding["policy_sha256"],
        "ALLOCATBELT_APP_REPORT_NONCE": binding["report_nonce"],
        "ALLOCATBELT_APP_RUN_ID": job["run_id"],
        "ALLOCATBELT_APP_EXECUTOR": EXECUTOR_LABELS[descriptor["executor"]],
        "ALLOCATBELT_APP_ALLOCATOR": descriptor["allocator"],
        "ALLOCATBELT_APP_WORKLOAD": job["workload"],
        "ALLOCATBELT_APP_PROFILE": job["profile"],
        "ALLOCATBELT_APP_SOURCE_SHA256": source["source"]["source_tree_sha256"],
        "ALLOCATBELT_APP_BINARY_SHA256": source["artifacts"][descriptor["allocator"]]["sha256"],
        "ALLOCATBELT_APP_ORACLE_FILE": "" if oracle_path is None else str(oracle_path),
        "ALLOCATBELT_APP_ORACLE_SHA256": "" if oracle_sha256 is None else oracle_sha256,
    }


def _construct_members(context: dict[str, Any], runtime_bindings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    job = context["job"]
    spec = context["spec"]
    source = context["source"]
    root = context["output_root"]
    reader = context["loaded_modules"]["runtime_reader"]
    controller = context["controller"]
    descriptors = _member_descriptors(job, controller)
    binding_map = {(item["pair"], item["executor"], item["allocator"]): item for item in runtime_bindings}
    require(len(binding_map) == 2, "original runtime binding list has duplicate process identities")
    deadlines = dict(spec["deadlines"])
    deadlines.update({
        "term_grace_seconds": TERM_GRACE_SECONDS,
        "kill_reap_seconds": KILL_REAP_SECONDS,
        "probe_timeout_seconds": int(PROBE_TIMEOUT_SECONDS),
    })
    members: list[dict[str, Any]] = []
    for index, descriptor in enumerate(descriptors):
        identity = (descriptor["pair"], descriptor["executor"], descriptor["allocator"])
        binding = binding_map.get(identity)
        require(binding is not None, "original process descriptor has no unique frozen runtime binding")
        expected = reader.build_fixed_expectation(binding["recipe"])
        expected_raw = reader.canonical_bytes(expected)
        require(sha256_bytes(expected_raw) == binding["expectation_sha256"], "frozen runtime expectation hash differs from the pinned runtime reader")
        contract = expected["contract"]
        require(contract["configuration"]["resource_policy"] == "fixed_primary_v1" and contract["configuration"]["feedback_enabled"] == "false", "fixed APP expectation changed its original fixed-policy/feedback-off contract")
        for bucket in contract["byte_buckets"].values():
            require(bucket["bytes_per_second"] == 17_179_869_184 and bucket["ceiling_bytes_per_second"] == 17_179_869_184, "fixed APP byte rate differs from the original 16 GiB/s contract")
        binary_pin = source["artifacts"][descriptor["allocator"]]
        binary = _safe_child(context["source_root"], binary_pin["path"], f"SourceV5 {descriptor['allocator']} APP binary")
        raw_sha = _hash_regular_file(binary, MAX_BINARY_BYTES, "SourceV5 APP binary")
        require(raw_sha == binary_pin["sha256"] and binding["recipe"]["identity"]["binary_sha256"] == raw_sha, "APP binary differs from original SourceV5/runtime binding")
        require(binary.stat().st_mode & 0o111 != 0, "SourceV5 APP binary is not executable")
        oracle_entry = _member_oracle(job, descriptor["allocator"])
        oracle_path = None
        oracle_sha256 = None
        oracle = None
        if oracle_entry is not None:
            relative = _safe_relative(oracle_entry["relative_path"], "original oracle relative path")
            oracle_path = _safe_child(context["campaign_artifacts_root"], relative, "original trusted APP oracle")
            oracle_sha256 = _hash_regular_file(oracle_path, MAX_ORACLE_BYTES, "original APP oracle")
            require(oracle_sha256 == oracle_entry["sha256"], "original APP oracle differs from its exact PlanV3 pin")
            try:
                controller.validate_oracle(
                    oracle_path, source["source"]["source_tree_sha256"], raw_sha,
                    job["workload"], job["profile"], job["rate_per_second"], job["arrivals"],
                )
            except Exception as error:
                raise FixedPairError(f"captured controller rejected original APP oracle: {error}") from error
            oracle = {"entry": oracle_entry, "artifact": {"path": str(oracle_path), "sha256": oracle_sha256}}
        require((job["mode"] == "open_loop") == (oracle is not None), "original APP oracle presence differs from its frozen mode")

        slug = f"{index:02d}-{descriptor['pair']}-{descriptor['executor']}-{descriptor['allocator']}"
        outputs = {
            "root": str(root),
            "stdout": str(root / f"{descriptor['pair']}-{descriptor['executor']}.stdout.tsv"),
            "stderr": str(root / f"{descriptor['pair']}-{descriptor['executor']}.stderr.txt"),
            "time_report": str(root / f"{descriptor['pair']}-{descriptor['executor']}.direct-time.json"),
            "ids": str(root / f"{descriptor['pair']}-{descriptor['executor']}.ids.tsv"),
            "shutdown": str(root / f"{descriptor['pair']}-{descriptor['executor']}.shutdown.tsv"),
            "capacity_families": str(root / f"{descriptor['pair']}-{descriptor['executor']}.capacity-families.tsv"),
            "runtime_readback": str(root / f"{descriptor['pair']}-{descriptor['executor']}.runtime.tsv"),
            "runtime_expectation": str(root / f"{descriptor['pair']}-{descriptor['executor']}.runtime-expectation.json"),
            "runtime_validation": str(root / f"{descriptor['pair']}-{descriptor['executor']}.runtime-validation.json"),
            "probe_stdout": str(root / "probes" / f"{slug}.stdout.json"),
            "probe_stderr": str(root / "probes" / f"{slug}.stderr.txt"),
            "probe_replay_stdout": str(root / "probes" / f"{slug}.replay.stdout.json"),
            "probe_replay_stderr": str(root / "probes" / f"{slug}.replay.stderr.txt"),
            "tmpdir": str(root / "tmp" / slug),
            "probe_tmpdir": str(root / "probes" / "tmp" / slug),
        }
        tmpdir = Path(outputs["tmpdir"])
        environment = _derive_expected_environment(job, descriptor, binding, source, tmpdir, outputs, oracle_path, oracle_sha256)
        argv = _member_argv(job, descriptor, binary, deadlines)
        members.append({
            "ordinal": index,
            "descriptor": descriptor,
            "binary": {"path": str(binary), "sha256": raw_sha},
            "runtime_recipe": {"value": binding["recipe"], "sha256": binding["recipe_sha256"]},
            "runtime_binding": binding,
            "runtime_expectation": {"value": expected, "sha256": binding["expectation_sha256"]},
            "argv": argv,
            "environment": environment,
            "cwd": str(context["source_root"]),
            "tmpdir": {"path": str(tmpdir), "bytes_limit": MAX_TMPDIR_BYTES, "inode_limit": MAX_TMPDIR_INODES},
            "affinity": {"cpu_set": context["host_value"]["controls"]["cpu_set"], "cpus": context["cpu_ids"]},
            "network_namespace_inode": context["observed_host"]["network_namespace_inode"],
            "oracle": oracle,
            "outputs": outputs,
        })
    return members


def _hash_regular_file(path: Path, maximum: int, label: str) -> str:
    try:
        path_before = path.lstat()
        require(stat.S_ISREG(path_before.st_mode), f"{label} is not a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise FixedPairError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_fingerprint(before) == _stat_fingerprint(path_before), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite byte limit")
        hasher = hashlib.sha256()
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while hashing")
            count += len(block)
            hasher.update(block)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        require(_stat_fingerprint(before) == _stat_fingerprint(after) == _stat_fingerprint(path_after) and count == before.st_size, f"{label} changed while hashing")
        return hasher.hexdigest()
    finally:
        os.close(descriptor)


def _mount_static(identity: dict[str, Any]) -> dict[str, Any]:
    return {key: identity[key] for key in (
        "mount_id", "major_minor", "mount_root", "mount_point", "filesystem_type", "mount_source", "device",
    )}


def _validate_output_mount_attestation(value: object, output_root: Path) -> dict[str, Any]:
    mount = exact(value, {
        "mount_id", "major_minor", "mount_root", "mount_point", "filesystem_type",
        "mount_source", "device", "available_bytes", "available_inodes",
    }, "strict peer output mount attestation")
    require(type(mount["mount_id"]) is int and mount["mount_id"] > 0 and
            type(mount["major_minor"]) is str and re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
            type(mount["mount_root"]) is str and mount["mount_root"].startswith("/") and
            type(mount["mount_point"]) is str and Path(mount["mount_point"]).is_absolute() and
            type(mount["filesystem_type"]) is str and mount["filesystem_type"] not in ("tmpfs", "ramfs", "devtmpfs") and
            type(mount["mount_source"]) is str and type(mount["device"]) is int and mount["device"] >= 0 and
            type(mount["available_bytes"]) is int and mount["available_bytes"] >= 0 and
            type(mount["available_inodes"]) is int and mount["available_inodes"] >= 0,
            "strict peer output mount attestation is malformed or memory-backed")
    try:
        output_root.relative_to(Path(mount["mount_point"]))
    except ValueError as error:
        raise FixedPairError("strict peer output mount does not contain the frozen private output root") from error
    return mount


def _artifact_budgets() -> dict[str, int]:
    return {
        "stdout_bytes": MAX_STDOUT_BYTES,
        "stderr_bytes": MAX_STDERR_BYTES,
        "time_report_bytes": MAX_TIME_BYTES,
        "ids_bytes": MAX_ID_BYTES,
        "shutdown_bytes": MAX_RUNTIME_BYTES,
        "capacity_families_bytes": MAX_RUNTIME_BYTES,
        "runtime_receipt_bytes": MAX_RUNTIME_BYTES,
        "runtime_expectation_bytes": MAX_RUNTIME_BYTES,
        "runtime_validation_bytes": MAX_RUNTIME_BYTES,
        "construction_probe_stdout_bytes": MAX_PROBE_STDOUT_BYTES,
        "construction_probe_stderr_bytes": MAX_PROBE_STDERR_BYTES,
        "pair_output_total_bytes": MAX_PAIR_OUTPUT_BYTES,
        "tmpdir_bytes": MAX_TMPDIR_BYTES,
        "tmpdir_inodes": MAX_TMPDIR_INODES,
    }


def _runtime_bindings_for_job(context: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], bytes, str]:
    controller = context["controller"]
    job = context["job"]
    plan = context["plan"]
    spec = context["spec"]
    source = context["source"]
    try:
        bindings = controller.build_runtime_process_bindings(job, spec, source)
    except Exception as error:
        raise FixedPairError(f"captured controller cannot derive the original fixed runtime bindings: {error}") from error
    planned = plan.get("runtime_process_bindings", {}).get(job["run_id"])
    require(type(planned) is list and canonical_bytes(planned) == canonical_bytes(bindings), "derived fixed runtime bindings differ byte-for-byte from PlanV3")
    require(len(bindings) == 2, "PlanV3 must contain exactly two original runtime bindings for this fixed pair")
    try:
        manifest = controller.runtime_binding_manifest_value(bindings, job, spec, source)
    except Exception as error:
        raise FixedPairError(f"captured controller cannot build the original runtime binding manifest: {error}") from error
    raw = canonical_bytes(manifest)
    require(len(raw) <= MAX_RUNTIME_BYTES, "original runtime binding manifest exceeds its finite size bound")
    output_path = context["output_root"] / ".fixed-pair-runtime-bindings.json"
    checksum = sha256_bytes(raw)
    if context.get("write_runtime_bindings") is True:
        write_exclusive(output_path, raw, "original runtime binding manifest")
    else:
        view = context.get("artifact_view")
        if view is None:
            stored, stored_sha, info = read_stable(output_path, "original runtime binding manifest", MAX_RUNTIME_BYTES)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, "original runtime binding manifest permissions are not private")
        else:
            stored, stored_sha = view.read(output_path, "original runtime binding manifest", MAX_RUNTIME_BYTES)
        require(stored_sha == checksum and stored == raw, "pinned runtime binding manifest differs from the exact PlanV3 recipes")
    return bindings, manifest, raw, checksum


def _construct_overlay(
    original_pins: dict[str, Any], execution_pins: dict[str, Any], exact_job: dict[str, Any],
    observed_host_pin: object, output_root_value: object, *, create_output: bool, write_runtime_bindings: bool,
    offline_facts: dict[str, Any] | None = None,
    artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    context = _load_source_inputs(
        original_pins, execution_pins, exact_job, observed_host_pin, output_root_value,
        create_output=create_output, offline_facts=offline_facts,
    )
    context["write_runtime_bindings"] = write_runtime_bindings
    context["artifact_view"] = artifact_view
    bindings, binding_manifest, binding_raw, binding_sha = _runtime_bindings_for_job(context)
    members = _construct_members(context, bindings)
    context["members"] = members
    context["runtime_bindings_raw"] = binding_raw
    context["runtime_bindings_sha256"] = binding_sha
    output_root = context["output_root"]
    if offline_facts is None:
        output_identity = _mount_identity(output_root)
        output_mount = _mount_static(output_identity)
        require(output_identity["available_bytes"] >= MAX_PAIR_OUTPUT_BYTES + 2 * MAX_TMPDIR_BYTES, "private output filesystem lacks the original finite output/TMPDIR allowance")
        require(output_identity["available_inodes"] >= 2 * MAX_TMPDIR_INODES + 64, "private output filesystem lacks the original finite inode allowance")
    else:
        host_verification = exact(offline_facts["host_verification"], {
            "schema", "host_id", "observed_host_raw_sha256", "process_affinity",
            "network_namespace_inode", "output_mount", "host_verification_sha256",
        }, "strict peer host-verification facts")
        output_identity = _validate_output_mount_attestation(host_verification["output_mount"], output_root)
        require(output_identity["available_bytes"] >= MAX_PAIR_OUTPUT_BYTES + 2 * MAX_TMPDIR_BYTES and
                output_identity["available_inodes"] >= 2 * MAX_TMPDIR_INODES + 64,
                "strict peer output-mount receipt cannot satisfy the original finite output allowance")
        output_mount = _mount_static(output_identity)
        context["offline_output_mount"] = output_mount
    source_manifest_pins = context["source_manifest_records"]
    source_manifests = {
        host: {
            "pin": value["pin"],
            "manifest_sha256": value["manifest_sha256"],
        }
        for host, value in source_manifest_pins.items()
    }
    selected = {
        "host_id": context["host_id"],
        "root": str(context["source_root"]),
        "git_commit": context["source_git_commit"],
        "source_tree_sha256": context["source_tree_sha256"],
        "build_sha256": context["build_sha256"],
    }
    sources = {
        "manifests": source_manifests,
        "selected": selected,
        "campaign_artifacts_root": str(context["campaign_artifacts_root"]),
        "observed_host": {
            "pin": context["host_pin"],
            "host_fingerprint_sha256": context["observed_host"]["host_fingerprint_sha256"],
            "controls_sha256": context["observed_host"]["controls_sha256"],
            "process_affinity": context["observed_host"]["process_affinity"],
            "network_namespace_inode": context["observed_host"]["network_namespace_inode"],
        },
        "historical_runner_sha256": context["spec"]["runner_sha256"],
        "output_mount": output_mount,
    }
    overlay = {
        "schema": OVERLAY_SCHEMA,
        "campaign_id": context["spec"]["campaign_id"],
        "host_id": context["host_id"],
        "spec": {
            "pin": {"path": str(context["spec_path"]), "sha256": context["spec_raw_sha256"]},
            "semantic_sha256": context["spec_semantic_sha256"],
        },
        "plan": {
            "pin": {"path": str(context["plan_path"]), "sha256": context["plan_raw_sha256"]},
            "semantic_sha256": context["plan_semantic_sha256"],
        },
        "sources": sources,
        "execution_source": {
            "git_commit": context["source_git_commit"],
            "source_tree_sha256": context["source_tree_sha256"],
            "inventory_schema": context["inventory_module"].SCHEMA,
            "inventory": context["execution_inventory"],
            "inventory_sha256": context["execution_inventory_sha256"],
        },
        "modules": context["modules"],
        "job": {"value": context["job"], "sha256": sha256_bytes(canonical_bytes(context["job"]))},
        "runtime_bindings": {
            "pin": {
                "path": str(context["output_root"] / ".fixed-pair-runtime-bindings.json"),
                "sha256": binding_sha,
            },
            "manifest_sha256": binding_manifest["manifest_sha256"],
            "plan_entry_sha256": sha256_bytes(canonical_bytes(bindings)),
            "value": binding_manifest,
        },
        "members": members,
        "deadlines": {
            **context["spec"]["deadlines"],
            "term_grace_seconds": TERM_GRACE_SECONDS,
            "kill_reap_seconds": KILL_REAP_SECONDS,
            "construction_probe_seconds": int(PROBE_TIMEOUT_SECONDS),
        },
        "artifact_budgets": _artifact_budgets(),
        "output_root": str(output_root),
    }
    exact(overlay, {
        "schema", "campaign_id", "host_id", "spec", "plan", "sources", "execution_source", "modules",
        "job", "runtime_bindings", "members", "deadlines", "artifact_budgets", "output_root",
    }, "fixed-pair overlay")
    require(overlay["schema"] == OVERLAY_SCHEMA, "fixed-pair overlay schema changed")
    require(len(members) == 2, "fixed-pair overlay does not contain exactly two APP members")
    return overlay, context


def _derive_overlay_inputs(overlay: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str]:
    exact(overlay, {
        "schema", "campaign_id", "host_id", "spec", "plan", "sources", "execution_source", "modules",
        "job", "runtime_bindings", "members", "deadlines", "artifact_budgets", "output_root",
    }, "fixed-pair overlay")
    require(overlay["schema"] == OVERLAY_SCHEMA, "unsupported fixed-pair overlay schema")
    spec = exact(overlay["spec"], {"pin", "semantic_sha256"}, "overlay SpecV3 binding")
    plan = exact(overlay["plan"], {"pin", "semantic_sha256"}, "overlay PlanV3 binding")
    sources = exact(overlay["sources"], {
        "manifests", "selected", "campaign_artifacts_root", "observed_host", "historical_runner_sha256", "output_mount",
    }, "overlay source bindings")
    selected = exact(sources["selected"], {"host_id", "root", "git_commit", "source_tree_sha256", "build_sha256"}, "selected SourceV5 snapshot")
    observed = exact(sources["observed_host"], {
        "pin", "host_fingerprint_sha256", "controls_sha256", "process_affinity", "network_namespace_inode",
    }, "observed host identity")
    job = exact(overlay["job"], {"value", "sha256"}, "original fixed job")
    require(type(job["value"]) is dict and job["sha256"] == sha256_bytes(canonical_bytes(job["value"])), "original fixed job canonical digest is invalid")
    runtime = exact(overlay["runtime_bindings"], {"pin", "manifest_sha256", "plan_entry_sha256", "value"}, "original runtime bindings")
    original_pins = {
        "spec": spec["pin"],
        "spec_semantic_sha256": spec["semantic_sha256"],
        "plan": plan["pin"],
        "plan_semantic_sha256": plan["semantic_sha256"],
        "source_manifests": {host: value["pin"] for host, value in sources["manifests"].items()},
        "campaign_artifacts_root": sources["campaign_artifacts_root"],
    }
    execution_pins = {
        "source_root": selected["root"],
        "selected_host_id": selected["host_id"],
        "modules": overlay["modules"],
    }
    return original_pins, execution_pins, job["value"], observed["pin"], overlay["output_root"]


def _read_overlay_raw(
    overlay_pin: object, *, artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> tuple[dict[str, Any], bytes, str, Path]:
    pin = exact(overlay_pin, {"path", "sha256"}, "fixed-pair overlay raw pin")
    if artifact_view is None:
        path = _safe_absolute(pin["path"], "fixed-pair overlay path")
        raw, raw_sha, info = read_stable(path, "fixed-pair execution overlay", MAX_PLAN_BYTES)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, "fixed-pair execution overlay permissions are not private")
    else:
        path = _captured_origin_path(pin["path"], "fixed-pair overlay origin")
        raw, raw_sha = artifact_view.read(path, "fixed-pair execution overlay", MAX_PLAN_BYTES)
    require(is_sha(pin["sha256"]) and raw_sha == pin["sha256"], "fixed-pair overlay differs from its raw pin")
    try:
        overlay = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"fixed-pair overlay is not bounded JSON: {error}") from error
    require(type(overlay) is dict and raw == canonical_bytes(overlay), "fixed-pair overlay is not canonical")
    exact(overlay, {
        "schema", "campaign_id", "host_id", "spec", "plan", "sources", "execution_source", "modules",
        "job", "runtime_bindings", "members", "deadlines", "artifact_budgets", "output_root",
    }, "fixed-pair overlay")
    require(overlay["schema"] == OVERLAY_SCHEMA, "unsupported fixed-pair overlay schema")
    require(path == Path(overlay["output_root"]) / "fixed-pair-execution-overlay.json",
            "overlay path differs from its immutable output-root location")
    return overlay, raw, raw_sha, path


def _read_overlay_with_host_facts(
    overlay_pin: object, offline_facts: dict[str, Any] | None = None,
    *, artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> tuple[dict[str, Any], bytes, str, dict[str, Any], dict[str, Any]]:
    overlay, raw, raw_sha, path = _read_overlay_raw(overlay_pin, artifact_view=artifact_view)
    original_pins, execution_pins, job, host_pin, output_root = _derive_overlay_inputs(overlay)
    require(path == Path(output_root) / "fixed-pair-execution-overlay.json", "overlay path differs from its immutable output-root location")
    reconstructed, context = _construct_overlay(
        original_pins, execution_pins, job, host_pin, output_root,
        create_output=False, write_runtime_bindings=False, offline_facts=offline_facts,
        artifact_view=artifact_view,
    )
    require(canonical_bytes(reconstructed) == raw, "fixed-pair overlay differs from independent SourceV5/PlanV3 reconstruction")
    return overlay, raw, raw_sha, context, reconstructed


def _read_overlay(overlay_pin: object) -> tuple[dict[str, Any], bytes, str, dict[str, Any], dict[str, Any]]:
    """Keep the archived v1 reader on strict live-host reconstruction."""
    return _read_overlay_with_host_facts(overlay_pin, None)


def _validate_fixed_pair_evidence_path_map(value: object, overlay: dict[str, Any], host_receipt_path: Path) -> dict[str, Path]:
    mapping = exact(value, {"schema", "entries"}, "fixed-pair offline evidence path map")
    require(mapping["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(mapping["entries"]) is list and 1 <= len(mapping["entries"]) <= 4096,
            "fixed-pair offline path map schema or entry count is invalid")
    roots: dict[str, Path] = {}
    local_paths: set[str] = set()
    previous = ""
    directories: set[str] = set()
    for index, entry_value in enumerate(mapping["entries"]):
        entry = exact(entry_value, {"origin", "local"}, f"fixed-pair path map entry[{index}]")
        require(type(entry["origin"]) is str and type(entry["local"]) is str,
                f"fixed-pair path map entry[{index}] paths must be strings")
        origin = _safe_absolute(entry["origin"], f"fixed-pair evidence origin[{index}]")
        local = _safe_absolute(entry["local"], f"fixed-pair evidence local[{index}]")
        origin_text, local_text = str(origin), str(local)
        require(origin_text > previous, "fixed-pair evidence map origins must be sorted and unique")
        previous = origin_text
        require(origin == local and local_text not in local_paths,
                "fixed-pair evidence maps must be unique identity paths")
        info = local.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                f"fixed-pair evidence path map entry[{index}] is not a regular file or directory")
        roots[origin_text] = local
        local_paths.add(local_text)
        if stat.S_ISDIR(info.st_mode):
            directories.add(origin_text)
    selected = exact(overlay["sources"]["selected"], {
        "host_id", "root", "git_commit", "source_tree_sha256", "build_sha256",
    }, "selected SourceV5 identity")
    spec_pin = exact(overlay["spec"], {"pin", "semantic_sha256"}, "fixed-pair SpecV3 binding")["pin"]
    artifact_root = _safe_absolute(overlay["sources"]["campaign_artifacts_root"], "campaign artifact root")
    output_root = _safe_absolute(overlay["output_root"], "fixed-pair output root")
    required_directories = {
        str(_safe_absolute(selected["root"], "SourceV5 root")),
        str(_safe_absolute(str(Path(spec_pin["path"]).parent), "fixed-pair input root")),
        str(artifact_root), str(output_root),
    }
    require(required_directories <= directories,
            "fixed-pair evidence path map omits a SourceV5/input/artifact/output directory")
    require(any(host_receipt_path == Path(root) or str(host_receipt_path).startswith(root + "/")
                for root in roots),
            "fixed-pair evidence path map omits its strict host receipt")
    return roots


def build_fixed_pair_overlay(
    original_pins: dict[str, Any], execution_pins: dict[str, Any], exact_job: dict[str, Any],
    observed_host_pin: dict[str, Any], output_root: Path | str,
) -> dict[str, str]:
    """Verify original SourceV5/PlanV3 inputs and write one immutable overlay pin."""
    source_root_value = exact(execution_pins, {"source_root", "selected_host_id", "modules"}, "execution pins")["source_root"]
    source_root = _safe_absolute(source_root_value, "selected SourceV5 source root")
    root = _private_output_root(str(Path(output_root).absolute()), source_root, create=True)
    require(not any(root.iterdir()), "fixed-pair output root must be empty before overlay construction")
    overlay, _context = _construct_overlay(
        original_pins, execution_pins, exact_job, observed_host_pin, str(root),
        create_output=False, write_runtime_bindings=True,
    )
    overlay_raw = canonical_bytes(overlay)
    require(len(overlay_raw) <= MAX_PLAN_BYTES, "fixed-pair execution overlay exceeds its finite byte bound")
    path = root / "fixed-pair-execution-overlay.json"
    checksum = write_exclusive(path, overlay_raw, "fixed-pair execution overlay")
    return {"path": str(path), "sha256": checksum}


def _read_proc_stat(pid: int) -> dict[str, Any]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError as error:
        raise FixedPairError(f"cannot read process identity for pid {pid}: {error}") from error
    require(len(raw) <= 16 * 1024, f"process stat for pid {pid} exceeds its finite bound")
    close = raw.rfind(b")")
    require(close > 0, f"process stat for pid {pid} is malformed")
    fields = raw[close + 2 :].split()
    require(len(fields) >= 20, f"process stat for pid {pid} is truncated")
    try:
        return {
            "state": fields[0].decode("ascii"),
            "parent_pid": int(fields[1]),
            "process_group": int(fields[2]),
            "session_id": int(fields[3]),
            "start_ticks": int(fields[19]),
        }
    except (UnicodeError, ValueError) as error:
        raise FixedPairError(f"process stat for pid {pid} has invalid numeric fields") from error


def _waitid_nowait(process: subprocess.Popen[bytes]) -> Any | None:
    try:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise FixedPairError("direct APP leader was reaped before bounded session cleanup") from error
    return result if result is not None and result.si_pid == process.pid else None


def _require_waitable_sigchld(*, owned_handler: bool = False) -> None:
    disposition = signal.getsignal(signal.SIGCHLD)
    if owned_handler:
        require(disposition is _sigchld_noop, "SIGCHLD ownership handler changed before numeric process-group signaling")
        return
    require(disposition in (signal.SIG_DFL, None, _sigchld_noop), "SIGCHLD must retain a waitable disposition for WNOWAIT ownership")


def _sigchld_noop(_signum: int, _frame: Any) -> None:
    """Keep child exit notification from auto-reaping a WNOWAIT-owned leader."""
    return None


def _session_members(session_id: int) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise FixedPairError(f"cannot scan /proc for owned APP session members: {error}") from error
    count = 0
    try:
        for entry in entries:
            count += 1
            require(count <= MAX_PROC_ENTRIES, "/proc process inventory exceeded its finite entry bound")
            if not entry.name.isdecimal():
                continue
            pid = int(entry.name)
            try:
                record = _read_proc_stat(pid)
            except FixedPairError as error:
                cause = error.__cause__
                if isinstance(cause, (FileNotFoundError, ProcessLookupError)):
                    continue
                raise
            if record["session_id"] == session_id:
                members.append({"pid": pid, **record})
    finally:
        entries.close()
    return members


def _pidfd_signal_if_same_start(pid: int, expected_start_ticks: int, signum: int) -> bool:
    require(callable(getattr(os, "pidfd_open", None)) and callable(getattr(signal, "pidfd_send_signal", None)), "safe owned-member cleanup requires pidfd signal support")
    try:
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return False
    try:
        try:
            current = _read_proc_stat(pid)
        except FixedPairError as error:
            if isinstance(error.__cause__, (FileNotFoundError, ProcessLookupError)):
                return False
            raise
        if current["start_ticks"] != expected_start_ticks:
            return False
        try:
            signal.pidfd_send_signal(descriptor, signum, None, 0)
        except ProcessLookupError:
            return False
        return True
    finally:
        os.close(descriptor)


def _signal_owned_session(
    process: subprocess.Popen[bytes], leader_start_ticks: int, signum: int,
) -> dict[str, Any]:
    _require_waitable_sigchld(owned_handler=True)
    require(process.returncode is None, "refusing process-group signaling after leader reaping")
    leader_waitable = _waitid_nowait(process)
    leader_stat = _read_proc_stat(process.pid)
    require(
        leader_stat["start_ticks"] == leader_start_ticks
        and leader_stat["process_group"] == process.pid
        and leader_stat["session_id"] == process.pid
        and (leader_waitable is not None or leader_stat["state"] not in ("Z", "X")),
        "waitid/proc identity no longer proves the original unreaped session leader before process-group signal",
    )
    group_signal = {"signal": signum, "leader_pid": process.pid, "leader_start_ticks": leader_start_ticks, "leader_unreaped": True}
    group_error = None
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except OSError as error:
        group_error = f"{type(error).__name__}: {error}"
    try:
        members = _session_members(process.pid)
    except BaseException as error:
        return {
            "group_signal": group_signal,
            "group_error": group_error,
            "pidfd_signals": [],
            "scan_error": f"{type(error).__name__}: {error}",
            "members": None,
        }
    pidfd_signals = []
    errors = []
    for member in members:
        if member["pid"] == process.pid or member["process_group"] == process.pid or member["state"] in ("Z", "X"):
            continue
        try:
            signaled = _pidfd_signal_if_same_start(member["pid"], member["start_ticks"], signum)
            pidfd_signals.append({"pid": member["pid"], "start_ticks": member["start_ticks"], "signal": signum, "sent": signaled})
        except BaseException as error:
            errors.append(f"pid {member['pid']}: {type(error).__name__}: {error}")
    return {
        "group_signal": group_signal,
        "group_error": group_error,
        "pidfd_signals": pidfd_signals,
        "scan_error": "; ".join(errors) if errors else None,
        "members": members,
    }


def _live_session_members(members: list[dict[str, Any]] | None, leader_pid: int) -> list[dict[str, Any]] | None:
    if members is None:
        return None
    return [item for item in members if item["pid"] != leader_pid and item["state"] not in ("Z", "X")]


def _open_capture(path: Path, label: str) -> int:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {label}")
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as error:
        raise FixedPairError(f"cannot create {label}: {error}") from error


def _check_capture_sizes(captures: list[tuple[Path, int]]) -> bool:
    exceeded = False
    for path, maximum in captures:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISREG(info.st_mode), f"capture is not a regular file: {path.name}")
        exceeded |= info.st_size > maximum
    return exceeded


def _proc_environment(pid: int) -> dict[str, str]:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError as error:
        raise FixedPairError(f"cannot read full APP environment for pid {pid}: {error}") from error
    require(len(raw) <= 16 * 1024 * 1024, "APP environment exceeds its finite launch-proof bound")
    result: dict[str, str] = {}
    for item in raw.split(b"\x00"):
        if not item:
            continue
        key, separator, value = item.partition(b"=")
        require(bool(separator), "APP environment contains a malformed entry")
        try:
            decoded_key = key.decode("ascii")
            decoded_value = value.decode("utf-8")
        except UnicodeError as error:
            raise FixedPairError("APP environment is not ASCII-keyed UTF-8") from error
        require(decoded_key not in result, f"APP environment repeats key {decoded_key}")
        result[decoded_key] = decoded_value
    return result


def _capture_started_identity(
    process: subprocess.Popen[bytes], binary: Path, binary_sha256: str, binary_info: os.stat_result,
    command: list[str], environment: dict[str, str], cwd: Path, cpu_ids: list[int], tmpdir: Path,
    expected_network_inode: int, helper: types.ModuleType,
) -> dict[str, Any]:
    pid = process.pid
    require(type(pid) is int and pid > 0, "APP PID is not a positive integer")
    start_ticks = helper._proc_start_ticks(pid)
    try:
        executable_link = os.readlink(f"/proc/{pid}/exe")
        executable_info = os.stat(f"/proc/{pid}/exe")
        cwd_link = os.readlink(f"/proc/{pid}/cwd")
        actual_affinity = sorted(os.sched_getaffinity(pid))
        actual_network_inode = os.stat(f"/proc/{pid}/ns/net").st_ino
        actual_environment = _proc_environment(pid)
        command_raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as error:
        raise FixedPairError(f"cannot capture actual APP start identity: {error}") from error
    require(len(command_raw) <= 1024 * 1024 and command_raw.endswith(b"\x00"), "actual APP argv exceeds its finite bound or has invalid framing")
    try:
        actual_argv = [os.fsdecode(item) for item in command_raw[:-1].split(b"\x00")]
    except UnicodeError as error:
        raise FixedPairError("actual APP argv cannot be decoded") from error
    require(actual_argv == command, "executed APP argv differs from the exact requested original argv")
    require(Path(executable_link) == binary and (executable_info.st_dev, executable_info.st_ino) == (binary_info.st_dev, binary_info.st_ino), "started APP executable path/device/inode differs from its verified open descriptor")
    require(executable_info.st_size == binary_info.st_size and binary_sha256 == _hash_regular_file(binary, MAX_BINARY_BYTES, "APP after start"), "started APP executable bytes changed")
    require(Path(cwd_link) == cwd and cwd.resolve(strict=True) == Path(cwd_link), "started APP cwd differs from its frozen path")
    require(actual_environment == environment, "started APP full environment differs from its exact allowlisted identity environment")
    require(actual_environment.get("TMPDIR") == str(tmpdir), "started APP TMPDIR differs from its private member directory")
    require(actual_affinity == cpu_ids, "started APP affinity differs from the frozen host CPU set")
    require(actual_network_inode == expected_network_inode, "started APP network namespace inode differs from the observed host pin")
    material = {
        "schema": APP_STARTED_SCHEMA,
        "role": "fixed_application_member",
        "pid": pid,
        "start_ticks": start_ticks,
        "executable_path": str(binary),
        "executable_sha256": binary_sha256,
        "executable_device": binary_info.st_dev,
        "executable_inode": binary_info.st_ino,
        "executable_size": binary_info.st_size,
        "requested_argv": command,
        "requested_argv_sha256": sha256_bytes(canonical_bytes(command)),
        "executed_argv": actual_argv,
        "executed_argv_sha256": sha256_bytes(canonical_bytes(actual_argv)),
        "environment": actual_environment,
        "environment_sha256": sha256_bytes(canonical_bytes(actual_environment)),
        "cwd": str(cwd),
        "tmpdir": str(tmpdir),
        "cpu_affinity": actual_affinity,
        "network_namespace_inode": actual_network_inode,
    }
    material["identity_sha256"] = sha256_bytes(canonical_bytes(material))
    return material


def _wait_for_process_group(
    process: subprocess.Popen[bytes], leader_start_ticks: int, timeout_seconds: float,
    captures: list[tuple[Path, int]], *, on_started: Callable[[dict[str, Any]], None] | None,
    started_proof: dict[str, Any] | None, received_signal: list[int], start_clock: float,
    resource_monitor: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    term_started: float | None = None
    kill_sent_at: float | None = None
    leader_info: Any | None = None
    timed_out = False
    artifact_limit = False
    cleanup_errors: list[str] = []
    signal_records: list[dict[str, Any]] = []
    cleanup_required = False
    last_members: list[dict[str, Any]] | None = None
    app_deadline = start_clock + timeout_seconds

    try:
        if on_started is not None:
            require(started_proof is not None, "normal APP start callback has no captured process proof")
            on_started(started_proof)
        while True:
            now = time.monotonic()
            if not artifact_limit and _check_capture_sizes(captures):
                artifact_limit = True
            if not artifact_limit and resource_monitor is not None:
                try:
                    artifact_limit = resource_monitor()
                except BaseException as error:
                    cleanup_errors.append(f"TMPDIR monitor: {type(error).__name__}: {error}")
                    artifact_limit = True
            try:
                leader_info = _waitid_nowait(process)
            except BaseException as error:
                cleanup_errors.append(f"waitid: {type(error).__name__}: {error}")
                cleanup_required = True
            requested_stop = bool(received_signal) or timed_out or artifact_limit
            if now >= app_deadline and leader_info is None and not requested_stop:
                timed_out = True
                requested_stop = True
            if requested_stop and not cleanup_required:
                cleanup_required = True
                term_started = now
                try:
                    signal_records.append(_signal_owned_session(process, leader_start_ticks, signal.SIGTERM))
                except BaseException as error:
                    cleanup_errors.append(f"TERM cleanup: {type(error).__name__}: {error}")
            if leader_info is not None and not cleanup_required:
                try:
                    members = _session_members(process.pid)
                    last_members = members
                    live_descendants = _live_session_members(members, process.pid)
                    if live_descendants:
                        cleanup_required = True
                        term_started = now
                        signal_records.append(_signal_owned_session(process, leader_start_ticks, signal.SIGTERM))
                    else:
                        break
                except BaseException as error:
                    cleanup_errors.append(f"post-exit ownership scan: {type(error).__name__}: {error}")
                    cleanup_required = True
                    term_started = now
                    # Emergency signaling remains safe while WNOWAIT keeps the
                    # leader PID allocated, even when /proc scanning failed.
                    try:
                        signal_records.append(_signal_owned_session(process, leader_start_ticks, signal.SIGTERM))
                    except BaseException as signal_error:
                        cleanup_errors.append(f"emergency TERM: {type(signal_error).__name__}: {signal_error}")
            if cleanup_required:
                if term_started is None:
                    term_started = now
                    try:
                        signal_records.append(_signal_owned_session(process, leader_start_ticks, signal.SIGTERM))
                    except BaseException as error:
                        cleanup_errors.append(f"fallback TERM cleanup: {type(error).__name__}: {error}")
                elapsed_after_term = 0.0 if term_started is None else now - term_started
                if elapsed_after_term >= TERM_GRACE_SECONDS and kill_sent_at is None:
                    try:
                        signal_records.append(_signal_owned_session(process, leader_start_ticks, signal.SIGKILL))
                    except BaseException as error:
                        cleanup_errors.append(f"SIGKILL cleanup: {type(error).__name__}: {error}")
                    kill_sent_at = now
                try:
                    members = _session_members(process.pid)
                    last_members = members
                    live_descendants = _live_session_members(members, process.pid)
                except BaseException as error:
                    cleanup_errors.append(f"owned-session scan: {type(error).__name__}: {error}")
                    live_descendants = None
                if leader_info is None:
                    try:
                        leader_info = _waitid_nowait(process)
                    except BaseException as error:
                        cleanup_errors.append(f"waitid during cleanup: {type(error).__name__}: {error}")
                if leader_info is not None and live_descendants == []:
                    break
                if kill_sent_at is not None and now - kill_sent_at >= KILL_REAP_SECONDS:
                    # Retry only while the original leader is still unreaped.
                    # This is the bounded emergency fallback for scan errors.
                    try:
                        signal_records.append(_signal_owned_session(process, leader_start_ticks, signal.SIGKILL))
                    except BaseException as error:
                        cleanup_errors.append(f"bounded emergency SIGKILL: {type(error).__name__}: {error}")
                    try:
                        leader_info = _waitid_nowait(process)
                        last_members = _session_members(process.pid)
                    except BaseException as error:
                        cleanup_errors.append(f"bounded emergency ownership check: {type(error).__name__}: {error}")
                    live_descendants = _live_session_members(last_members, process.pid)
                    if leader_info is not None and live_descendants == []:
                        break
                    cleanup_errors.append("owned APP session did not become empty before its hard cleanup bound")
                    break
            time.sleep(0.01)
    except BaseException as error:
        cleanup_errors.append(f"supervisor: {type(error).__name__}: {error}")
        cleanup_required = True
        if term_started is None:
            term_started = time.monotonic()
        # A final best-effort TERM/KILL/reap path is explicitly bounded.  It
        # never signals the numeric group after the unreaped leader is gone.
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                signal_records.append(_signal_owned_session(process, leader_start_ticks, signum))
            except BaseException as signal_error:
                cleanup_errors.append(f"emergency signal {signum}: {type(signal_error).__name__}: {signal_error}")
        emergency_deadline = time.monotonic() + KILL_REAP_SECONDS
        while time.monotonic() < emergency_deadline:
            try:
                leader_info = _waitid_nowait(process)
                last_members = _session_members(process.pid)
                if leader_info is not None and _live_session_members(last_members, process.pid) == []:
                    break
            except BaseException as cleanup_error:
                cleanup_errors.append(f"emergency ownership check: {type(cleanup_error).__name__}: {cleanup_error}")
            time.sleep(0.01)
    try:
        if leader_info is None:
            leader_info = _waitid_nowait(process)
    except BaseException as error:
        cleanup_errors.append(f"final WNOWAIT: {type(error).__name__}: {error}")
    # Decide ownership cleanup from the final pre-reap scan.  Once process.wait
    # consumes the leader, its numeric PID/process-group identity is never used
    # for another signal or ownership scan.
    try:
        remaining = _live_session_members(last_members, process.pid)
    except BaseException as error:
        cleanup_errors.append(f"pre-reap session proof: {type(error).__name__}: {error}")
        remaining = None
    if leader_info is not None:
        try:
            process.wait(timeout=0)
        except (subprocess.TimeoutExpired, ChildProcessError, OSError) as error:
            cleanup_errors.append(f"bounded reap: {type(error).__name__}: {error}")
    leader_reaped = process.returncode is not None
    if not leader_reaped:
        cleanup_errors.append("direct APP leader remained unreaped at the hard cleanup bound")
    cleanup_verified = leader_reaped and remaining == [] and not cleanup_errors
    return {
        "leader_info": None if leader_info is None else {
            "si_code": leader_info.si_code,
            "si_status": leader_info.si_status,
            "si_pid": leader_info.si_pid,
        },
        "child_return_code": process.returncode,
        "timed_out": timed_out,
        "artifact_budget_exceeded": artifact_limit,
        "received_signal": received_signal[0] if received_signal else None,
        "term_grace_seconds": TERM_GRACE_SECONDS,
        "kill_reap_seconds": KILL_REAP_SECONDS,
        "signals": signal_records,
        "leader_unreaped_during_group_signals": all(item.get("group_signal", {}).get("leader_unreaped") is True for item in signal_records),
        "group_signal_after_leader_reap_count": sum(
            1 for item in signal_records if item.get("group_signal", {}).get("leader_unreaped") is not True
        ),
        "leader_reaped": leader_reaped,
        "remaining_session_members": remaining,
        "cleanup_errors": cleanup_errors,
        "cleanup_status": "verified" if cleanup_verified else "failed",
    }


def _run_direct_process(
    command: list[str], binary: Path, expected_binary_sha256: str, cwd: Path, environment: dict[str, str],
    cpu_ids: list[int], output_path: Path, error_path: Path, output_maximum: int, error_maximum: int,
    timeout_seconds: float, helper: types.ModuleType, *, expected_tmpdir: Path,
    expected_network_inode: int, on_started: Callable[[dict[str, Any]], None] | None = None,
    capture_identity: bool = True, resource_monitor: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    require(command and command[0] == str(binary) and all(type(item) is str and "\x00" not in item for item in command), "direct APP command is malformed")
    require(0 < timeout_seconds <= 14_400, "direct APP process deadline is outside its finite bound")
    for name, value in environment.items():
        require(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None and type(value) is str and "\x00" not in value, "direct APP environment contains a malformed entry")
    require(environment.get("PATH") == "/usr/bin:/bin" and not (set(environment) & set(PROHIBITED_AMBIENT_ENV)), "direct APP environment is not the pinned allowlist")
    stdout_fd = _open_capture(output_path, "direct APP stdout")
    stderr_fd: int | None = None
    binary_fd: int | None = None
    inherited_fd: int | None = None
    process: subprocess.Popen[bytes] | None = None
    start_identity: dict[str, Any] | None = None
    launch_monotonic_ns = time.monotonic_ns()
    received_signal: list[int] = []
    old_handlers: dict[int, Any] = {}

    def remember_signal(signum: int, _frame: Any) -> None:
        if not received_signal:
            received_signal.append(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, remember_signal)
        old_handlers[signal.SIGCHLD] = signal.signal(signal.SIGCHLD, _sigchld_noop)
        require(not received_signal, "external signal arrived before the APP process was launched")
        stderr_fd = _open_capture(error_path, "direct APP stderr")
        binary_fd = os.open(binary, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        binary_sha, binary_info = helper._hash_open_executable(binary_fd, binary, "source-pinned normal APP")
        require(binary_sha == expected_binary_sha256, "open APP executable descriptor differs from its SourceV5 hash")
        require(binary_info.st_mode & 0o111 != 0 and binary_info.st_size <= MAX_BINARY_BYTES, "source-pinned APP is not a bounded executable")
        inherited_fd = fcntl.fcntl(binary_fd, fcntl.F_DUPFD, 200)
        os.set_inheritable(inherited_fd, True)
        executable_fd_path = f"/proc/self/fd/{inherited_fd}"
        require(not received_signal, "external signal arrived before APP Popen")
        def set_affinity_before_exec() -> None:
            os.sched_setaffinity(0, set(cpu_ids))
        launch_clock = time.monotonic()
        launch_monotonic_ns = time.monotonic_ns()
        process = subprocess.Popen(
            command,
            executable=executable_fd_path,
            cwd=cwd,
            env=environment,
            preexec_fn=set_affinity_before_exec,
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            close_fds=True,
            pass_fds=(inherited_fd,),
            start_new_session=True,
        )
        require(process.pid > 0, "Popen returned a nonpositive APP PID")
        if capture_identity:
            start_identity = _capture_started_identity(
                process, binary, binary_sha, binary_info, command, environment, cwd, cpu_ids,
                expected_tmpdir, expected_network_inode, helper,
            )
        else:
            try:
                start_ticks = helper._proc_start_ticks(process.pid)
            except BaseException as error:
                raise FixedPairError(f"cannot capture the construction-probe PID/start ticks: {error}") from error
            start_identity = {
                "pid": process.pid,
                "start_ticks": start_ticks,
                "requested_argv": command,
                "requested_argv_sha256": sha256_bytes(canonical_bytes(command)),
                "environment_sha256": sha256_bytes(canonical_bytes(environment)),
            }
        supervised = _wait_for_process_group(
            process, start_identity["start_ticks"], timeout_seconds,
            [(output_path, output_maximum), (error_path, error_maximum)],
            on_started=on_started, started_proof=start_identity, received_signal=received_signal,
            start_clock=launch_clock, resource_monitor=resource_monitor,
        )
        after_sha, after_info = helper._hash_open_executable(binary_fd, binary, "normal APP after execution")
        require(after_sha == binary_sha and helper._fingerprint(after_info) == helper._fingerprint(binary_info), "normal APP binary changed during execution")
        os.fsync(stdout_fd)
        os.fsync(stderr_fd)
        ended_ns = time.monotonic_ns()
        return_code = supervised["child_return_code"]
        if supervised["timed_out"]:
            status = 124
        elif supervised["artifact_budget_exceeded"]:
            status = 125
        elif supervised["received_signal"] is not None:
            status = 128 + supervised["received_signal"]
        elif type(return_code) is int and return_code < 0:
            status = 128 + (-return_code)
        elif type(return_code) is int:
            status = return_code
        else:
            status = 125
        if supervised["cleanup_status"] != "verified":
            status = 125
        timing = {
            "schema": DIRECT_TIME_SCHEMA,
            "time_source": "monotonic_direct_supervisor",
            "pid": process.pid,
            "started_monotonic_ns": launch_monotonic_ns,
            "ended_monotonic_ns": ended_ns,
            "elapsed_ns": max(0, ended_ns - launch_monotonic_ns),
            "exit_code": status,
            "child_return_code": return_code,
            "timed_out": supervised["timed_out"],
            "artifact_budget_exceeded": supervised["artifact_budget_exceeded"],
            "cleanup_status": supervised["cleanup_status"],
        }
        return {
            "status": status,
            "child_return_code": return_code,
            "start": start_identity,
            "binary_path": str(binary),
            "binary_sha256": binary_sha,
            "binary_device": binary_info.st_dev,
            "binary_inode": binary_info.st_ino,
            "binary_size": binary_info.st_size,
            "requested_argv": command,
            "requested_argv_sha256": sha256_bytes(canonical_bytes(command)),
            "environment": environment,
            "environment_sha256": sha256_bytes(canonical_bytes(environment)),
            "cwd": str(cwd),
            "cpu_affinity": cpu_ids,
            "network_namespace_inode": expected_network_inode,
            "received_signal": supervised["received_signal"],
            "supervision": supervised,
            "timing": timing,
            "started_monotonic_ns": launch_monotonic_ns,
            "ended_monotonic_ns": ended_ns,
        }
    except BaseException as error:
        if process is not None and process.returncode is None:
            try:
                start_ticks = (start_identity or {}).get("start_ticks")
                if type(start_ticks) is not int:
                    start_ticks = _read_proc_stat(process.pid)["start_ticks"]
                emergency = _wait_for_process_group(
                    process, start_ticks, 0.05, [(output_path, output_maximum), (error_path, error_maximum)],
                    on_started=None, started_proof=None, received_signal=received_signal,
                    start_clock=time.monotonic(),
                )
            except BaseException as cleanup_error:
                emergency = {
                    "cleanup_status": "failed",
                    "leader_reaped": process.returncode is not None,
                    "group_signal_after_leader_reap_count": 0,
                    "cleanup_errors": [f"{type(cleanup_error).__name__}: {cleanup_error}"],
                }
        else:
            emergency = {"cleanup_status": "not_started", "leader_reaped": process is None or process.returncode is not None, "group_signal_after_leader_reap_count": 0, "cleanup_errors": []}
        raise FixedPairError(f"direct APP launch/supervision failed: {type(error).__name__}: {error}; cleanup={emergency}") from error
    finally:
        restore_errors: list[str] = []
        for signum, old_handler in old_handlers.items():
            try:
                signal.signal(signum, old_handler)
            except (OSError, ValueError) as error:
                restore_errors.append(f"signal handler {signum}: {type(error).__name__}: {error}")
        for descriptor in (inherited_fd, binary_fd, stderr_fd, stdout_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if restore_errors:
            raise FixedPairError(f"failed to restore parent signal handlers: {'; '.join(restore_errors)}")


def _prepare_member_tmpdir(path: Path, output_root: Path, budgets: dict[str, int]) -> dict[str, Any]:
    require(path.parent.is_dir() and not path.parent.is_symlink(), "private TMPDIR parent is missing or aliased")
    require(not path.exists() and not path.is_symlink(), f"refusing to reuse member TMPDIR {path}")
    path.mkdir(mode=0o700)
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "member TMPDIR is not an owned mode-0700 directory")
    root_mount = _mount_static(_mount_identity(output_root))
    tmp_mount = _mount_static(_mount_identity(path))
    require(tmp_mount == root_mount, "member TMPDIR mount identity differs from its private output root")
    stats = os.statvfs(path)
    initial = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "mount": tmp_mount,
        "available_bytes": stats.f_bavail * stats.f_frsize,
        "available_inodes": stats.f_favail,
        "bytes_limit": budgets["tmpdir_bytes"],
        "inode_limit": budgets["tmpdir_inodes"],
    }
    require(initial["available_bytes"] >= budgets["tmpdir_bytes"] and initial["available_inodes"] >= budgets["tmpdir_inodes"], "private TMPDIR storage cannot satisfy its frozen byte/inode bounds")
    return initial


def _tmpdir_usage(path: Path, budget: dict[str, int]) -> dict[str, Any]:
    total_bytes = 0
    file_count = 0
    directory_count = 0
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            raise FixedPairError(f"cannot enumerate member TMPDIR {current}: {error}") from error
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), "member TMPDIR contains a link or special file")
            if stat.S_ISDIR(info.st_mode):
                directory_count += 1
                pending.append(Path(entry.path))
            else:
                total_bytes += info.st_size
                file_count += 1
            require(total_bytes <= budget["bytes_limit"] and file_count + directory_count <= budget["inode_limit"], "member TMPDIR exceeded its frozen byte or inode bound")
    info = path.stat(follow_symlinks=False)
    mount = _mount_static(_mount_identity(path))
    stats = os.statvfs(path)
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode),
        "mount": mount,
        "bytes_used": total_bytes,
        "file_count": file_count,
        "directory_count": directory_count,
        "bytes_limit": budget["bytes_limit"],
        "inode_limit": budget["inode_limit"],
        "available_bytes": stats.f_bavail * stats.f_frsize,
        "available_inodes": stats.f_favail,
    }


def _verify_tmpdir_storage(
    initial: dict[str, Any], final: dict[str, Any], path_value: str,
    byte_limit: int, inode_limit: int, label: str,
) -> None:
    require(type(initial) is dict and type(final) is dict, f"{label} initial/final storage proof is missing")
    path = _safe_absolute(path_value, f"{label} TMPDIR")
    require(initial.get("path") == final.get("path") == str(path), f"{label} TMPDIR path changed")
    require(initial.get("bytes_limit") == final.get("bytes_limit") == byte_limit and initial.get("inode_limit") == final.get("inode_limit") == inode_limit, f"{label} TMPDIR byte/inode budgets changed")
    require(initial.get("mode") == final.get("mode") == 0o700, f"{label} TMPDIR mode is not private")
    require(type(initial.get("available_bytes")) is int and initial["available_bytes"] >= byte_limit and type(initial.get("available_inodes")) is int and initial["available_inodes"] >= inode_limit, f"{label} TMPDIR initial storage cannot satisfy its bounds")
    info = path.stat(follow_symlinks=False)
    require(info.st_uid == os.getuid() and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, f"{label} TMPDIR is no longer an owned mode-0700 directory")
    require((initial.get("device"), initial.get("inode")) == (info.st_dev, info.st_ino) == (final.get("device"), final.get("inode")), f"{label} TMPDIR device/inode changed")
    require(initial.get("mount") == final.get("mount") == _mount_static(_mount_identity(path)), f"{label} TMPDIR mount identity changed")
    actual = _tmpdir_usage(path, {"bytes_limit": byte_limit, "inode_limit": inode_limit})
    for key in ("bytes_used", "file_count", "directory_count", "path", "device", "inode", "mode", "mount", "bytes_limit", "inode_limit"):
        require(actual.get(key) == final.get(key), f"{label} TMPDIR final usage differs at {key}")


def _tmpdir_usage_offline(path: Path, byte_limit: int, inode_limit: int) -> dict[str, int]:
    total_bytes = 0
    file_count = 0
    directory_count = 0
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as error:
            raise FixedPairError(f"cannot enumerate copied peer TMPDIR {current}: {error}") from error
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
                    "copied peer TMPDIR contains a link or special file")
            if stat.S_ISDIR(info.st_mode):
                directory_count += 1
                pending.append(Path(entry.path))
            else:
                total_bytes += info.st_size
                file_count += 1
            require(total_bytes <= byte_limit and file_count + directory_count <= inode_limit,
                    "copied peer TMPDIR exceeds its frozen byte or inode bound")
    return {"bytes_used": total_bytes, "file_count": file_count, "directory_count": directory_count}


def _verify_tmpdir_storage_offline(
    initial: object, final: object, path_value: str,
    byte_limit: int, inode_limit: int, output_mount: dict[str, Any], label: str,
) -> None:
    initial_value = exact(initial, {
        "path", "device", "inode", "mode", "mount", "available_bytes", "available_inodes",
        "bytes_limit", "inode_limit",
    }, f"{label} peer initial TMPDIR proof")
    final_value = exact(final, {
        "path", "device", "inode", "mode", "mount", "bytes_used", "file_count", "directory_count",
        "bytes_limit", "inode_limit", "available_bytes", "available_inodes",
    }, f"{label} peer final TMPDIR proof")
    path = _safe_absolute(path_value, f"{label} peer TMPDIR")
    require(initial_value["path"] == final_value["path"] == str(path) and
            initial_value["bytes_limit"] == final_value["bytes_limit"] == byte_limit and
            initial_value["inode_limit"] == final_value["inode_limit"] == inode_limit and
            initial_value["mode"] == final_value["mode"] == 0o700,
            f"{label} peer TMPDIR path/mode/budget differs")
    require(type(initial_value["device"]) is int and initial_value["device"] >= 0 and
            type(initial_value["inode"]) is int and initial_value["inode"] > 0 and
            (initial_value["device"], initial_value["inode"]) == (final_value["device"], final_value["inode"]),
            f"{label} peer TMPDIR device/inode changed during execution")
    require(initial_value["mount"] == final_value["mount"] == _mount_static(output_mount),
            f"{label} peer TMPDIR mount differs from its strict host receipt")
    require(type(initial_value["available_bytes"]) is int and initial_value["available_bytes"] >= byte_limit and
            type(initial_value["available_inodes"]) is int and initial_value["available_inodes"] >= inode_limit,
            f"{label} peer TMPDIR initial storage proof cannot satisfy its frozen bounds")
    require(type(final_value["bytes_used"]) is int and 0 <= final_value["bytes_used"] <= byte_limit and
            type(final_value["file_count"]) is int and final_value["file_count"] >= 0 and
            type(final_value["directory_count"]) is int and final_value["directory_count"] >= 0 and
            final_value["file_count"] + final_value["directory_count"] <= inode_limit,
            f"{label} peer TMPDIR final usage is malformed or exceeds its frozen bounds")
    try:
        info = path.lstat()
    except OSError as error:
        raise FixedPairError(f"copied peer TMPDIR is unavailable: {error}") from error
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
            stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            f"copied peer TMPDIR is not a private regular directory")
    usage = _tmpdir_usage_offline(path, byte_limit, inode_limit)
    require(usage == {key: final_value[key] for key in ("bytes_used", "file_count", "directory_count")},
            f"{label} peer TMPDIR copied contents differ from the strict host usage proof")


def _open_tmpdir_absolute_directory(path: Path) -> int:
    require(path.is_absolute() and ".." not in path.parts and "\x00" not in str(path),
            "member TMPDIR path is not a normalized absolute path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            old_descriptor = descriptor
            descriptor = next_descriptor
            os.close(old_descriptor)
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _tmpdir_directory_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_uid,
        stat.S_IMODE(info.st_mode), stat.S_IFMT(info.st_mode),
    )


def _validate_tmpdir_directory(info: os.stat_result, root_device: int, label: str) -> None:
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == root_device,
            f"{label} is not an owned mode-0700 directory on the TMPDIR device")


def _tmpdir_usage_snapshot(
    path: Path, byte_limit: int, inode_limit: int,
    expected_root_identity: tuple[int, int] | None,
    *, allow_descendant_enoent: bool,
) -> dict[str, int]:
    require(type(byte_limit) is int and byte_limit >= 0 and
            type(inode_limit) is int and inode_limit >= 0,
            "member TMPDIR budget is malformed")
    root_fd = _open_tmpdir_absolute_directory(path)
    root_before: os.stat_result | None = None
    total_bytes = 0
    inode_count = 0
    try:
        root_before = os.fstat(root_fd)
        _validate_tmpdir_directory(root_before, root_before.st_dev, "member TMPDIR root")
        root_identity = (root_before.st_dev, root_before.st_ino)
        require(expected_root_identity is None or root_identity == expected_root_identity,
                "member TMPDIR root device/inode changed")
        root_signature = _tmpdir_directory_signature(root_before)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        file_flags = (getattr(os, "O_PATH", os.O_RDONLY | os.O_NONBLOCK) |
                      os.O_NOFOLLOW | os.O_CLOEXEC)
        enumeration_limit = max(TMPDIR_MONITOR_MAX_ENUMERATED_ENTRIES, inode_limit)
        enumerated_entries = 0

        # Close each scandir stream after collecting names, before inspecting
        # children or recursing; directory descriptors remain depth-bounded.
        def visit(directory_fd: int, depth: int) -> None:
            nonlocal total_bytes, inode_count, enumerated_entries
            names: list[str] = []
            with os.scandir(directory_fd) as children:
                for child in children:
                    name = child.name
                    require(type(name) is str and name not in ("", ".", "..") and "/" not in name,
                            "member TMPDIR contains an invalid directory entry name")
                    enumerated_entries += 1
                    require(enumerated_entries <= enumeration_limit,
                            "member TMPDIR exceeded its finite enumeration-work bound")
                    names.append(name)
            for name in names:
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as error:
                    if allow_descendant_enoent and error.errno == errno.ENOENT:
                        # A name that vanished before it was observed is not usage.
                        continue
                    raise
                inode_count += 1
                require(inode_count <= inode_limit,
                        "member TMPDIR exceeded its frozen inode bound")
                require(info.st_uid == os.getuid() and info.st_dev == root_before.st_dev and
                        not stat.S_ISLNK(info.st_mode),
                        "member TMPDIR contains an unowned, cross-device, or linked entry")
                if stat.S_ISDIR(info.st_mode):
                    _validate_tmpdir_directory(info, root_before.st_dev, "member TMPDIR child")
                    require(depth < TMPDIR_MONITOR_MAX_DEPTH,
                            "member TMPDIR exceeded its finite directory-depth bound")
                    try:
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                    except OSError as error:
                        if allow_descendant_enoent and error.errno == errno.ENOENT:
                            continue
                        raise
                    try:
                        opened = os.fstat(child_fd)
                        require(_tmpdir_directory_signature(opened) ==
                                _tmpdir_directory_signature(info),
                                "member TMPDIR directory changed between stat and open")
                        try:
                            visit(child_fd, depth + 1)
                        except OSError as error:
                            if not (allow_descendant_enoent and error.errno == errno.ENOENT):
                                raise
                            # A held descendant may disappear while its
                            # directory stream is being read; root errors
                            # are never handled by this descendant path.
                        after = os.fstat(child_fd)
                        require(_tmpdir_directory_signature(after) ==
                                _tmpdir_directory_signature(opened),
                                "member TMPDIR directory identity or mode changed during accounting")
                        try:
                            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except OSError as error:
                            if allow_descendant_enoent and error.errno == errno.ENOENT:
                                continue
                            raise
                        require(_tmpdir_directory_signature(named_after) ==
                                _tmpdir_directory_signature(opened),
                                "member TMPDIR directory name changed during accounting")
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    require(info.st_nlink in ((0, 1) if allow_descendant_enoent else (1,)) and
                            info.st_size >= 0,
                            "member TMPDIR contains a hard link or invalid regular file")
                    try:
                        file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                    except OSError as error:
                        if allow_descendant_enoent and error.errno == errno.ENOENT:
                            total_bytes += info.st_size
                            require(total_bytes <= byte_limit,
                                    "member TMPDIR exceeded its frozen byte bound")
                            continue
                        raise
                    try:
                        opened = os.fstat(file_fd)
                        require((opened.st_dev, opened.st_ino, opened.st_uid,
                                 stat.S_IFMT(opened.st_mode)) ==
                                (info.st_dev, info.st_ino, info.st_uid,
                                 stat.S_IFMT(info.st_mode)) and
                                stat.S_ISREG(opened.st_mode) and
                                opened.st_nlink in ((0, 1) if allow_descendant_enoent else (1,)) and
                                opened.st_size >= 0,
                                "member TMPDIR file changed between stat and open or is hard-linked")
                        after = os.fstat(file_fd)
                        require((after.st_dev, after.st_ino, after.st_uid,
                                 stat.S_IFMT(after.st_mode)) ==
                                (opened.st_dev, opened.st_ino, opened.st_uid,
                                 stat.S_IFMT(opened.st_mode)) and
                                after.st_nlink in ((0, 1) if allow_descendant_enoent else (1,)) and
                                after.st_size >= 0,
                                "member TMPDIR file identity changed during accounting")
                        try:
                            named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except OSError as error:
                            if allow_descendant_enoent and error.errno == errno.ENOENT:
                                total_bytes += max(info.st_size, opened.st_size, after.st_size)
                                require(total_bytes <= byte_limit,
                                        "member TMPDIR exceeded its frozen byte bound")
                                continue
                            raise
                        require((named_after.st_dev, named_after.st_ino, named_after.st_uid,
                                 stat.S_IFMT(named_after.st_mode)) ==
                                (opened.st_dev, opened.st_ino, opened.st_uid,
                                 stat.S_IFMT(opened.st_mode)) and
                                stat.S_ISREG(named_after.st_mode) and
                                named_after.st_nlink in ((0, 1) if allow_descendant_enoent else (1,)) and
                                named_after.st_size >= 0,
                                "member TMPDIR file name changed during accounting")
                        total_bytes += max(
                            info.st_size, opened.st_size, after.st_size, named_after.st_size,
                        )
                    finally:
                        os.close(file_fd)
                    require(total_bytes <= byte_limit,
                            "member TMPDIR exceeded its frozen byte bound")
                else:
                    raise FixedPairError("member TMPDIR contains a special file")

        visit(root_fd, 0)
        root_after = os.fstat(root_fd)
        require(_tmpdir_directory_signature(root_after) == root_signature,
                "member TMPDIR root owner/mode/device/inode changed during accounting")
        named_root_fd = _open_tmpdir_absolute_directory(path)
        try:
            named_root = os.fstat(named_root_fd)
            require(_tmpdir_directory_signature(named_root) == root_signature,
                    "member TMPDIR named root changed during accounting")
        finally:
            os.close(named_root_fd)
    finally:
        os.close(root_fd)
    return {"bytes_used": total_bytes, "inode_count": inode_count}


def _tmpdir_exceeded(
    path: Path, byte_limit: int, inode_limit: int,
    expected_root_identity: tuple[int, int] | None = None,
) -> bool:
    try:
        usage = _tmpdir_usage_snapshot(
            path, byte_limit, inode_limit, expected_root_identity,
            allow_descendant_enoent=True,
        )
    except (FixedPairError, OSError):
        return True
    return usage["bytes_used"] > byte_limit or usage["inode_count"] > inode_limit


def _bounded_tmpdir_monitor(
    path: Path, byte_limit: int, inode_limit: int,
    expected_root: dict[str, Any] | None = None,
) -> Callable[[], bool]:
    root_fd = _open_tmpdir_absolute_directory(path)
    try:
        root_info = os.fstat(root_fd)
        _validate_tmpdir_directory(root_info, root_info.st_dev, "member TMPDIR root")
        root_identity = (root_info.st_dev, root_info.st_ino)
        if expected_root is not None:
            require(root_identity == (expected_root.get("device"), expected_root.get("inode")) and
                    expected_root.get("mode") == 0o700,
                    "member TMPDIR differs from its prepared root identity")
    finally:
        os.close(root_fd)
    last_scan = [0.0]
    high_water_bytes = [0]
    high_water_inodes = [0]

    def monitor() -> bool:
        now = time.monotonic()
        if now - last_scan[0] < 0.05:
            return False
        last_scan[0] = now
        try:
            usage = _tmpdir_usage_snapshot(
                path, byte_limit, inode_limit, root_identity,
                allow_descendant_enoent=True,
            )
        except (FixedPairError, OSError):
            return True
        high_water_bytes[0] = max(high_water_bytes[0], usage["bytes_used"])
        high_water_inodes[0] = max(high_water_inodes[0], usage["inode_count"])
        return high_water_bytes[0] > byte_limit or high_water_inodes[0] > inode_limit

    return monitor


def _ensure_private_directory(path: Path) -> None:
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    require(not path.is_symlink() and path.is_dir(), f"private output subdirectory is missing or aliased: {path}")
    info = path.stat(follow_symlinks=False)
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, f"private output subdirectory is not owned mode 0700: {path}")


def _probe_feedback_policy(
    reader: types.ModuleType, source: dict[str, Any], probe: dict[str, Any], identity: dict[str, Any],
) -> dict[str, Any]:
    projector = getattr(reader, "_source_v5_base_feedback_policy", None)
    require(callable(projector), "pinned SourceV5 feedback reader has no V4 base-policy projection")
    try:
        policy, projected_algorithm, workers = projector({"identity": identity}, source, probe)
    except Exception as error:
        raise FixedPairError(f"pinned SourceV5 feedback reader could not project the uncalibrated V4 policy: {error}") from error
    rust_context = probe["rust_control_context"]
    observed_sources = exact(rust_context["required_byte_sources"], {"disk", "download"}, "uncalibrated APP required byte sources")
    expected_sources = {
        "disk": identity["workload"] in ("disk", "mixed"),
        "download": identity["workload"] in ("http", "mixed"),
    }
    require(observed_sources == expected_sources, "uncalibrated APP required-byte-source observations differ from its original workload")
    require(projected_algorithm == rust_context["algorithm"], "SourceV5 base projection changed actual APP feedback algorithm observations")
    require(workers == (2 if identity["profile"] == "oversubscribed" else 4), "SourceV5 base projection worker count differs from the original profile")
    # V4 `capacity_sources` means that calibrated denominators were supplied;
    # the probe's `required_byte_sources` separately reports constructed sensors.
    require(policy["capacity_sources"] == {"disk": False, "download": False}, "uncalibrated probe expectation supplied a capacity calibration")
    require(policy["collector"]["expected_global_control_baseline"] == source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"], "uncalibrated probe Control baseline differs from SourceV5 calibration")
    require(callable(getattr(reader, "validate_construction_probe", None)), "pinned SourceV5 feedback reader has no construction-probe validator")
    return policy


def _run_construction_probe(
    context: dict[str, Any], member: dict[str, Any], overlay_sha256: str,
) -> dict[str, Any]:
    job = context["job"]
    source = context["source"]
    helper = context["loaded_modules"]["launch_identity_helper"]
    reader = context["loaded_modules"]["feedback_reader"]
    binary = Path(member["binary"]["path"])
    outputs = member["outputs"]
    probe_stdout = Path(outputs["probe_stdout"])
    probe_stderr = Path(outputs["probe_stderr"])
    replay_stdout = Path(outputs["probe_replay_stdout"])
    replay_stderr = Path(outputs["probe_replay_stderr"])
    probe_tmpdir = Path(outputs["probe_tmpdir"])
    _ensure_private_directory(probe_stdout.parent)
    _ensure_private_directory(probe_tmpdir.parent)
    tmp_initial = _prepare_member_tmpdir(probe_tmpdir, context["output_root"], _artifact_budgets())
    probe_environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": str(probe_tmpdir),
    }
    probe_argv = [str(binary), "--emit-feedback-policy-only", "--workload", job["workload"], "--profile", job["profile"]]
    expected_network_inode = context["observed_host"]["network_namespace_inode"]
    first = _run_direct_process(
        probe_argv, binary, member["binary"]["sha256"], context["source_root"], probe_environment,
        member["affinity"]["cpus"], probe_stdout, probe_stderr, MAX_PROBE_STDOUT_BYTES,
        MAX_PROBE_STDERR_BYTES, PROBE_TIMEOUT_SECONDS, helper,
        expected_tmpdir=probe_tmpdir, expected_network_inode=expected_network_inode,
        capture_identity=False,
        resource_monitor=_bounded_tmpdir_monitor(
            probe_tmpdir, MAX_TMPDIR_BYTES, MAX_TMPDIR_INODES, tmp_initial,
        ),
    )
    require(first["status"] == 0 and first["supervision"]["cleanup_status"] == "verified", "actual SourceV5 APP construction probe failed or left an owned process")
    first_raw, first_sha, _first_info = read_stable(probe_stdout, "actual APP construction probe stdout", MAX_PROBE_STDOUT_BYTES)
    first_err, first_err_sha, _err_info = read_stable(probe_stderr, "actual APP construction probe stderr", MAX_PROBE_STDERR_BYTES)
    require(not first_err, "actual APP construction probe wrote stderr")
    try:
        probe_value = json.loads(first_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"actual APP construction probe is not bounded JSON: {error}") from error
    require(type(probe_value) is dict and probe_value.get("schema") == "allocatbelt.application-feedback-policy-probe.v1", "actual APP construction probe has an unsupported schema")
    require(probe_value.get("context") == {
        "workload": job["workload"], "profile": job["profile"],
        "workers": 2 if job["profile"] == "oversubscribed" else 4,
    }, "actual APP construction probe workload/profile/workers differ from the original PlanV3 job")

    replay = _run_direct_process(
        probe_argv, binary, member["binary"]["sha256"], context["source_root"], probe_environment,
        member["affinity"]["cpus"], replay_stdout, replay_stderr, MAX_PROBE_STDOUT_BYTES,
        MAX_PROBE_STDERR_BYTES, PROBE_TIMEOUT_SECONDS, helper,
        expected_tmpdir=probe_tmpdir, expected_network_inode=expected_network_inode,
        capture_identity=False,
        resource_monitor=_bounded_tmpdir_monitor(
            probe_tmpdir, MAX_TMPDIR_BYTES, MAX_TMPDIR_INODES, tmp_initial,
        ),
    )
    require(replay["status"] == 0 and replay["supervision"]["cleanup_status"] == "verified", "repeated APP construction probe failed or left an owned process")
    replay_raw, replay_sha, _replay_info = read_stable(replay_stdout, "repeated APP construction probe stdout", MAX_PROBE_STDOUT_BYTES)
    replay_err, replay_err_sha, _replay_err_info = read_stable(replay_stderr, "repeated APP construction probe stderr", MAX_PROBE_STDERR_BYTES)
    require(not replay_err and replay_raw == first_raw and replay_sha == first_sha, "repeated APP construction probe differs from its original exact stdout")

    binding = member["runtime_recipe"]["value"]
    identity = {
        "host_id": context["host_id"],
        "run_id": job["run_id"],
        "report_nonce": binding["identity"]["report_nonce"],
        "process_id": first["start"]["pid"],
        "allocator": member["descriptor"]["allocator"],
        "executor": EXECUTOR_LABELS[member["descriptor"]["executor"]],
        "workload": job["workload"],
        "profile": job["profile"],
        "mode": "capacity_calibration",
        "source_sha256": source["source"]["source_tree_sha256"],
        "binary_sha256": member["binary"]["sha256"],
        "pressure_qualification": False,
    }
    manifest_pin = context["source_manifest_records"][context["host_id"]]["pin"]
    construction_pin = {
        "path": str(probe_stdout),
        "raw_sha256": first_sha,
        "allocator": member["descriptor"]["allocator"],
        "binary_sha256": member["binary"]["sha256"],
    }
    recipe = {
        "schema": reader.EXPECTATION_SCHEMA_V4,
        "mode": "capacity_calibration",
        "identity": identity,
        "policy": _probe_feedback_policy(reader, source, probe_value, identity),
        "app_capacity_artifact_sha256": None,
        "construction_probe": construction_pin,
        "host_binding": {"path": manifest_pin["path"], "raw_sha256": manifest_pin["sha256"]},
        "external_pressure_proof": None,
        "final_runtime_binding": None,
        "minimum_production_seconds": 1,
        "minimum_pressure_overlap_seconds": 0,
    }
    try:
        reader.validate_construction_probe(recipe, source)
    except Exception as error:
        raise FixedPairError(f"pinned SourceV5 feedback reader rejected the actual APP construction probe: {error}") from error
    tmp_final = _tmpdir_usage(probe_tmpdir, {"bytes_limit": MAX_TMPDIR_BYTES, "inode_limit": MAX_TMPDIR_INODES})
    require(tmp_final["mount"] == tmp_initial["mount"], "construction-probe TMPDIR mount identity changed during execution")
    return {
        "schema": PROBE_SCHEMA,
        "role": "uncalibrated_construction_only",
        "overlay_sha256": overlay_sha256,
        "member_ordinal": member["ordinal"],
        "descriptor": member["descriptor"],
        "binary": member["binary"],
        "argv": probe_argv,
        "environment": probe_environment,
        "cwd": str(context["source_root"]),
        "pid": first["start"]["pid"],
        "start_ticks": first["start"]["start_ticks"],
        "binary_device": first["binary_device"],
        "binary_inode": first["binary_inode"],
        "stdout": {"path": str(probe_stdout), "sha256": first_sha, "bytes": len(first_raw)},
        "stderr": {"path": str(probe_stderr), "sha256": first_err_sha, "bytes": 0},
        "replay": {
            "pid": replay["start"]["pid"],
            "start_ticks": replay["start"]["start_ticks"],
            "stdout": {"path": str(replay_stdout), "sha256": replay_sha, "bytes": len(replay_raw)},
            "stderr": {"path": str(replay_stderr), "sha256": replay_err_sha, "bytes": 0},
            "byte_equal": True,
            "cleanup": replay["supervision"],
        },
        "cleanup": first["supervision"],
        "reader": {
            "path": "scripts/application-feedback-readback.py",
            "sha256": context["modules"]["feedback_reader"]["sha256"],
            "validated": True,
            "probe_sha256": first_sha,
            "policy_sha256": source["feedback_policy"]["policy_sha256"],
            "fixed_global_control_baseline": source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"],
        },
        "reader_expectation": recipe,
        "tmpdir_initial": tmp_initial,
        "tmpdir_final": tmp_final,
    }


def _snapshot_source_inputs(context: dict[str, Any]) -> dict[str, Any]:
    controller = context["controller"]
    source = context["source"]
    root = context["source_root"]
    try:
        controller.verify_source_manifest(source, source_root=root, verify_artifacts=True)
        tree = context["inventory_module"].verify_source_tree(
            root, source["source"]["source_tree_sha256"], source["source"]["files"],
        )
        current_commit = controller.run_checked(["git", "rev-parse", "HEAD"], root, 120.0).decode().strip()
    except Exception as error:
        raise FixedPairError(f"post-run SourceV5 verification failed: {error}") from error
    require(tree.get("entries") == source["source"]["files"] and current_commit == source["source"]["git_commit"], "post-run Git source identity differs from the selected SourceV5 snapshot")
    spec_raw, spec_sha, _spec_info = read_stable(context["spec_path"], "original SpecV3 after execution", MAX_SPEC_BYTES)
    plan_raw, plan_sha, _plan_info = read_stable(context["plan_path"], "original PlanV3 after execution", MAX_PLAN_BYTES)
    require(spec_raw == context["spec_raw"] and plan_raw == context["plan_raw"], "original SpecV3 or PlanV3 bytes changed during fixed-pair execution")
    manifests: dict[str, str] = {}
    for host, value in context["source_manifest_records"].items():
        path = Path(value["pin"]["path"])
        _raw, actual, _info = read_stable(path, f"SourceV5 manifest {host} after execution", MAX_MANIFEST_BYTES)
        require(actual == value["pin"]["sha256"], f"SourceV5 manifest raw pin changed after execution: {host}")
        manifests[host] = actual
    modules: dict[str, str] = {}
    for name, pin in context["modules"].items():
        path = _safe_child(root, pin["path"], f"execution module {name} after execution")
        actual = _hash_regular_file(path, MAX_SOURCE_BYTES, f"execution module {name} after execution")
        require(actual == pin["sha256"], f"execution module changed after execution: {name}")
        modules[name] = actual
    binaries: dict[str, str] = {}
    for allocator in ALLOCATORS:
        pin = source["artifacts"][allocator]
        path = _safe_child(root, pin["path"], f"SourceV5 {allocator} APP after execution")
        actual = _hash_regular_file(path, MAX_BINARY_BYTES, f"SourceV5 {allocator} APP after execution")
        require(actual == pin["sha256"], f"SourceV5 APP binary changed after execution: {allocator}")
        binaries[allocator] = actual
    oracles: dict[str, str] = {}
    for member in context["members"]:
        oracle = member["oracle"]
        if oracle is None:
            continue
        path = Path(oracle["artifact"]["path"])
        actual = _hash_regular_file(path, MAX_ORACLE_BYTES, "original APP oracle after execution")
        require(actual == oracle["artifact"]["sha256"] == oracle["entry"]["sha256"], "original PlanV3 oracle changed after execution")
        oracles[str(path)] = actual
    host_raw, host_sha, _host_info = read_stable(Path(context["host_pin"]["path"]), "observed host contract after execution", MAX_MANIFEST_BYTES)
    require(host_sha == context["host_pin"]["sha256"], "observed host contract changed after execution")
    runtime_path = context["output_root"] / ".fixed-pair-runtime-bindings.json"
    runtime_raw, runtime_sha = _read_pair_artifact(runtime_path, "original runtime bindings after execution", MAX_RUNTIME_BYTES, context.get("artifact_view"))
    expected_runtime = context["runtime_bindings_raw"]
    require(runtime_raw == expected_runtime and runtime_sha == context["runtime_bindings_sha256"], "original runtime binding manifest changed after execution")
    return {
        "spec_raw_sha256": spec_sha,
        "plan_raw_sha256": plan_sha,
        "spec_semantic_sha256": context["spec_semantic_sha256"],
        "plan_semantic_sha256": context["plan_semantic_sha256"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
        "source_git_commit": current_commit,
        "source_manifest_pins": manifests,
        "module_pins": modules,
        "binary_pins": binaries,
        "oracle_pins": oracles,
        "observed_host_sha256": host_sha,
        "runtime_bindings_sha256": runtime_sha,
        "typed_inventory_sha256": context["inventory_module"].digest_records(source["source"]["files"]),
    }


def _hash_output_tree(
    overlay: dict[str, Any], *, artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> dict[str, Any]:
    if artifact_view is not None:
        return artifact_view.output_tree()
    root = Path(overlay["output_root"])
    temporary_roots = [
        Path(item["tmpdir"]["path"]) for item in overlay["members"]
    ] + [Path(item["outputs"]["probe_tmpdir"]) for item in overlay["members"]]
    files: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    file_count = 0
    directory_count = 0
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = os.scandir(current)
        except OSError as error:
            raise FixedPairError(f"cannot enumerate fixed-pair output directory {current}: {error}") from error
        try:
            for entry in entries:
                path = Path(entry.path)
                require(not entry.is_symlink(), f"output tree contains a symlink: {path}")
                if any(path == tmp or tmp in path.parents for tmp in temporary_roots):
                    if entry.is_dir(follow_symlinks=False):
                        continue
                    continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    directory_count += 1
                    require(directory_count <= MAX_OUTPUT_DIRECTORIES, "fixed-pair output tree exceeds its finite directory bound")
                    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, f"output directory is not privately owned mode 0700: {path}")
                    pending.append(path)
                    continue
                require(stat.S_ISREG(info.st_mode), f"output tree contains a special file: {path}")
                if path == root / "fixed-pair-execution-receipt.json":
                    continue
                file_count += 1
                require(file_count <= MAX_OUTPUT_FILES, "fixed-pair output tree exceeds its finite file bound")
                raw, checksum, stable_info = read_stable(path, "fixed-pair output artifact", MAX_PAIR_OUTPUT_BYTES)
                total_bytes += len(raw)
                require(total_bytes <= MAX_PAIR_OUTPUT_BYTES, "fixed-pair output artifacts exceed their aggregate byte bound")
                relative = path.relative_to(root).as_posix()
                files[relative] = {
                    "sha256": checksum,
                    "size": len(raw),
                    "device": stable_info.st_dev,
                    "inode": stable_info.st_ino,
                    "mode": stat.S_IMODE(stable_info.st_mode),
                }
        finally:
            entries.close()
    return {"files": files, "total_bytes": total_bytes, "maximum_bytes": MAX_PAIR_OUTPUT_BYTES}


def _validate_runtime_v2(
    context: dict[str, Any], member: dict[str, Any],
) -> tuple[dict[str, Any], str, str, bytes]:
    reader = context["loaded_modules"]["runtime_reader"]
    controller = context["controller"]
    outputs = member["outputs"]
    receipt_path = Path(outputs["runtime_readback"])
    expectation_path = Path(outputs["runtime_expectation"])
    validation_path = Path(outputs["runtime_validation"])
    view = context.get("artifact_view")
    raw, receipt_sha = _read_pair_artifact(receipt_path, "APP runtime binding receipt", MAX_RUNTIME_BYTES, view)
    if view is None:
        require(expectation_path.is_file() and not expectation_path.is_symlink(), "fixed APP runtime expectation is missing")
    else:
        require(view.has_file(expectation_path), "captured fixed APP runtime expectation is missing")
    expected_raw, expected_sha = _read_pair_artifact(expectation_path, "fixed APP runtime expectation", MAX_RUNTIME_BYTES, view)
    expected = member["runtime_expectation"]["value"]
    require(expected_raw == reader.canonical_bytes(expected) and expected_sha == member["runtime_expectation"]["sha256"], "stored fixed APP expectation differs from the original runtime recipe")
    try:
        receipt_schema, fields = reader.read_receipt_versioned(_BytesArtifactPath(raw))
    except Exception as error:
        raise FixedPairError(f"pinned runtime reader rejected APP receipt framing: {error}") from error
    require(receipt_schema == "allocatbelt.application-runtime-binding.v2", "fixed SourceV5 pair requires an explicit runtime-binding.v2 receipt")
    try:
        validation = reader.validate_runtime_readback(fields, expected, receipt_schema)
        snapshot = controller.numeric_runtime_snapshot(fields, expected, context["source"]["runtime_readback_validator"]["sha256"])
        controller.validate_numeric_runtime_snapshot(
            snapshot, expected, context["source"]["resource_domain_calibration"]["record"],
            context["source"]["runtime_readback_validator"]["sha256"], require_final_usage=True,
        )
    except Exception as error:
        raise FixedPairError(f"runtime-v2 owner-release proof failed independent numeric validation: {error}") from error
    baseline = context["source"]["resource_domain_calibration"]["record"]["fixed_global_control_baseline"]
    after_release = snapshot["after_release"]
    require(after_release["global_live_tenants"] == 0, "runtime-v2 receipt retains a live tenant")
    require(after_release["global_used_control"] == baseline and after_release["expected_global_control_baseline"] == baseline, "runtime-v2 Control release differs from the source-calibrated baseline")
    require(after_release["global_used_application"] == {name: 0 for name in reader.APP_DIMENSIONS}, "runtime-v2 receipt retains final global CPU/memory/disk/network/Task usage")
    validation_raw = reader.canonical_bytes(validation)
    if _pair_artifact_exists(validation_path, view):
        stored_validation, stored_sha = _read_pair_artifact(validation_path, "fixed APP runtime validation", MAX_RUNTIME_BYTES, view)
        require(stored_validation == validation_raw, "fixed APP runtime validation output differs from the pinned reader")
    else:
        require(view is None, "captured replay refuses to create a missing runtime validation receipt")
        stored_sha = write_exclusive(validation_path, validation_raw, "fixed APP runtime validation")
    expected_validation = {
        "schema": reader.EXPECTATION_SCHEMA,
        "validated": True,
        "expectation_sha256": expected_sha,
        "field_count": len(fields),
    }
    require(validation == expected_validation, "pinned runtime reader returned an unexpected v2 validation record")
    return snapshot, receipt_sha, stored_sha, raw


class _BytesArtifactPath:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def open(self, mode: str = "rb") -> io.BytesIO:
        require(mode == "rb", "runtime receipt memory adapter is read-only")
        return io.BytesIO(self._raw)


def _existing_output_hash(path_value: str, maximum: int, label: str) -> tuple[str, int] | None:
    path = Path(path_value)
    if not path.exists() and not path.is_symlink():
        return None
    raw, checksum, _info = read_stable(path, label, maximum)
    return checksum, len(raw)


def _launch_member(
    overlay: dict[str, Any], context: dict[str, Any], member: dict[str, Any], overlay_sha256: str,
    outer_deadline: float, on_app_started: Callable[[dict[str, Any]], None],
    on_app_terminal: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    output_root = context["output_root"]
    outputs = member["outputs"]
    _ensure_private_directory(output_root / "tmp")
    tmpdir = Path(member["tmpdir"]["path"])
    initial_storage = _prepare_member_tmpdir(tmpdir, output_root, overlay["artifact_budgets"])
    expected = member["runtime_expectation"]["value"]
    runtime_expectation_raw = context["loaded_modules"]["runtime_reader"].canonical_bytes(expected)
    require(sha256_bytes(runtime_expectation_raw) == member["runtime_expectation"]["sha256"], "runtime expectation changed before the original APP launch")
    write_exclusive(Path(outputs["runtime_expectation"]), runtime_expectation_raw, "fixed APP runtime expectation")
    for key, maximum in (
        ("stdout", MAX_STDOUT_BYTES), ("stderr", MAX_STDERR_BYTES), ("time_report", MAX_TIME_BYTES),
        ("ids", MAX_ID_BYTES), ("shutdown", MAX_RUNTIME_BYTES), ("capacity_families", MAX_RUNTIME_BYTES),
        ("runtime_readback", MAX_RUNTIME_BYTES), ("runtime_validation", MAX_RUNTIME_BYTES),
    ):
        path = Path(outputs[key])
        require(not path.exists() and not path.is_symlink(), f"refusing to replace original APP output {key}")
    require(member["environment"]["TMPDIR"] == str(tmpdir), "original APP TMPDIR differs from the exact private member path")
    remaining_outer = outer_deadline - time.monotonic()
    require(remaining_outer > 0, "original pair outer deadline elapsed before APP launch")
    app_timeout = min(float(context["spec"]["deadlines"]["process_seconds"]), remaining_outer)
    require(app_timeout > 0, "original pair has no remaining process deadline")
    start_events: list[dict[str, Any]] = []

    def started_callback(proof: dict[str, Any]) -> None:
        event = {
            "schema": APP_STARTED_SCHEMA,
            "overlay_sha256": overlay_sha256,
            "campaign_id": overlay["campaign_id"],
            "host_id": overlay["host_id"],
            "run_id": overlay["job"]["value"]["run_id"],
            "member_ordinal": member["ordinal"],
            "descriptor": member["descriptor"],
            "role": "fixed_application_member",
            "proof": proof,
        }
        start_events.append(event)
        on_app_started(event)

    attempt: dict[str, Any]
    try:
        direct = _run_direct_process(
            member["argv"], Path(member["binary"]["path"]), member["binary"]["sha256"],
            Path(member["cwd"]), member["environment"], member["affinity"]["cpus"],
            Path(outputs["stdout"]), Path(outputs["stderr"]), MAX_STDOUT_BYTES,
            MAX_STDERR_BYTES, app_timeout, context["loaded_modules"]["launch_identity_helper"],
            expected_tmpdir=tmpdir, expected_network_inode=member["network_namespace_inode"],
            on_started=started_callback,
            resource_monitor=_bounded_tmpdir_monitor(
                tmpdir, member["tmpdir"]["bytes_limit"], member["tmpdir"]["inode_limit"],
                initial_storage,
            ),
        )
        final_storage = _tmpdir_usage(tmpdir, member["tmpdir"])
        require(final_storage["mount"] == initial_storage["mount"], "normal APP TMPDIR mount identity changed during execution")
        timing_raw = canonical_bytes(direct["timing"])
        require(len(timing_raw) <= MAX_TIME_BYTES, "direct APP timing record exceeds its finite output bound")
        timing_sha = write_exclusive(Path(outputs["time_report"]), timing_raw, "direct APP timing record")
        runtime_snapshot = None
        runtime_readback_sha = None
        runtime_validation_sha = None
        runtime_error = None
        if direct["status"] == 0 and direct["supervision"]["cleanup_status"] == "verified":
            try:
                runtime_snapshot, runtime_readback_sha, runtime_validation_sha, _receipt_raw = _validate_runtime_v2(context, member)
            except Exception as error:
                runtime_error = f"{type(error).__name__}: {error}"
        attempt = {
            "ordinal": member["ordinal"],
            "descriptor": member["descriptor"],
            "attempted": True,
            "status": direct["status"],
            "child_return_code": direct["child_return_code"],
            "start": direct["start"],
            "start_events": start_events,
            "supervision": direct["supervision"],
            "timing": direct["timing"],
            "time_report_sha256": timing_sha,
            "runtime_snapshot": runtime_snapshot,
            "runtime_readback_sha256": runtime_readback_sha,
            "runtime_validation_sha256": runtime_validation_sha,
            "runtime_validation_error": runtime_error,
            "tmpdir_initial": initial_storage,
            "tmpdir_final": final_storage,
            "supervision_timeout_seconds": app_timeout,
            "error": None,
        }
    except BaseException as error:
        timing_path = Path(outputs["time_report"])
        time_record = {
            "schema": DIRECT_TIME_SCHEMA,
            "time_source": "monotonic_direct_supervisor",
            "exit_code": 125,
            "supervision_error": f"{type(error).__name__}: {error}",
            "started_monotonic_ns": None,
            "ended_monotonic_ns": time.monotonic_ns(),
            "cleanup_status": "unverified" if not start_events else "see_terminal_event",
        }
        timing_sha = None
        if not timing_path.exists() and not timing_path.is_symlink():
            timing_sha = write_exclusive(timing_path, canonical_bytes(time_record), "failed direct APP timing record")
        attempt = {
            "ordinal": member["ordinal"],
            "descriptor": member["descriptor"],
            "attempted": True,
            "status": 125,
            "child_return_code": None,
            "start": start_events[-1]["proof"] if start_events else None,
            "start_events": start_events,
            "supervision": {"cleanup_status": "unverified", "leader_reaped": False, "group_signal_after_leader_reap_count": 0, "cleanup_errors": [str(error)]},
            "timing": time_record,
            "time_report_sha256": timing_sha,
            "runtime_snapshot": None,
            "runtime_readback_sha256": None,
            "runtime_validation_sha256": None,
            "runtime_validation_error": str(error),
            "tmpdir_initial": initial_storage,
            "tmpdir_final": None,
            "supervision_timeout_seconds": app_timeout,
            "error": f"{type(error).__name__}: {error}",
        }

    terminal_event = {
        "schema": APP_TERMINAL_SCHEMA,
        "overlay_sha256": overlay_sha256,
        "campaign_id": overlay["campaign_id"],
        "host_id": overlay["host_id"],
        "run_id": overlay["job"]["value"]["run_id"],
        "member_ordinal": member["ordinal"],
        "descriptor": member["descriptor"],
        "pid": None if attempt["start"] is None else attempt["start"]["pid"],
        "status": attempt["status"],
        "cleanup": attempt["supervision"],
        "terminal_monotonic_ns": time.monotonic_ns(),
    }
    attempt["terminal_event"] = terminal_event
    try:
        on_app_terminal(terminal_event)
    except BaseException as error:
        attempt["terminal_callback_error"] = f"{type(error).__name__}: {error}"
        attempt["error"] = attempt["terminal_callback_error"]
    return attempt


def _process_row(
    context: dict[str, Any], member: dict[str, Any], attempt: dict[str, Any],
) -> dict[str, str]:
    outputs = member["outputs"]
    binding = member["runtime_binding"]
    descriptor = member["descriptor"]
    job = context["job"]
    def checksum(field: str, maximum: int, required: bool = False) -> str:
        found = _existing_output_hash(outputs[field], maximum, f"APP {field}")
        if found is None:
            require(not required, f"APP output is missing: {field}")
            return "unavailable"
        return found[0]

    stdout_sha = checksum("stdout", MAX_STDOUT_BYTES)
    runtime_sha = checksum("runtime_readback", MAX_RUNTIME_BYTES)
    expectation_sha = checksum("runtime_expectation", MAX_RUNTIME_BYTES)
    validation_sha = checksum("runtime_validation", MAX_RUNTIME_BYTES)
    shutdown_sha = checksum("shutdown", MAX_RUNTIME_BYTES)
    if job["mode"] == "open_loop":
        ids_sha = checksum("ids", MAX_ID_BYTES)
    else:
        ids_sha = "not_applicable"
    if job["mode"] == "capacity" and job["workload"] == "mixed":
        family_sha = checksum("capacity_families", MAX_RUNTIME_BYTES)
    else:
        family_sha = "not_applicable"
    time_path = Path(outputs["time_report"])
    time_name = time_path.name if time_path.exists() and not time_path.is_symlink() else time_path.name
    argv_json = json.dumps(member["argv"], separators=(",", ":"), ensure_ascii=True)
    return {
        "pair": descriptor["pair"],
        "executor": descriptor["executor"],
        "allocator": descriptor["allocator"],
        "exit_code": str(attempt["status"]),
        "row_validation": "pending",
        "p99_qualification": "eligible" if job["mode"] == "open_loop" else "not_applicable",
        "argv": argv_json,
        "stdout": Path(outputs["stdout"]).name,
        "time_report": time_name,
        "ids_sha256": ids_sha,
        "shutdown_sha256": shutdown_sha,
        "capacity_family_sha256": family_sha,
        "stdout_sha256": stdout_sha,
        "runtime_readback": Path(outputs["runtime_readback"]).name,
        "runtime_readback_sha256": runtime_sha,
        "runtime_expectation": Path(outputs["runtime_expectation"]).name,
        "runtime_expectation_sha256": expectation_sha,
        "runtime_validation": Path(outputs["runtime_validation"]).name,
        "runtime_validation_sha256": validation_sha,
        "runtime_recipe_sha256": binding["recipe_sha256"],
        "resource_ceiling_sha256": binding["resource_ceiling_sha256"],
        "policy_sha256": binding["policy_sha256"],
        "fixed_global_control_baseline": str(binding["fixed_global_control_baseline"]),
        "validator_sha256": context["source"]["runtime_readback_validator"]["sha256"],
        "source_manifest_sha256": context["source"]["manifest_sha256"],
        "calibration_binary_sha256": context["source"]["resource_domain_calibration"]["binary"]["sha256"],
        "calibration_output_sha256": context["source"]["resource_domain_calibration"]["output"]["sha256"],
    }


def _failure_process_row(context: dict[str, Any], member: dict[str, Any], attempt: dict[str, Any]) -> dict[str, str]:
    """Retain a scheduled process row even if artifact inspection itself fails."""
    descriptor = member["descriptor"]
    binding = member["runtime_binding"]
    outputs = member["outputs"]
    job = context["job"]
    argv_json = json.dumps(member["argv"], separators=(",", ":"), ensure_ascii=True)
    return {
        "pair": descriptor["pair"],
        "executor": descriptor["executor"],
        "allocator": descriptor["allocator"],
        "exit_code": str(attempt.get("status", 125)),
        "row_validation": "invalid",
        "p99_qualification": "invalid",
        "argv": argv_json,
        "stdout": Path(outputs["stdout"]).name,
        "time_report": Path(outputs["time_report"]).name,
        "ids_sha256": "unavailable" if job["mode"] == "open_loop" else "not_applicable",
        "shutdown_sha256": "unavailable",
        "capacity_family_sha256": "unavailable" if job["mode"] == "capacity" and job["workload"] == "mixed" else "not_applicable",
        "stdout_sha256": "unavailable",
        "runtime_readback": Path(outputs["runtime_readback"]).name,
        "runtime_readback_sha256": "unavailable",
        "runtime_expectation": Path(outputs["runtime_expectation"]).name,
        "runtime_expectation_sha256": member["runtime_expectation"]["sha256"],
        "runtime_validation": Path(outputs["runtime_validation"]).name,
        "runtime_validation_sha256": "unavailable",
        "runtime_recipe_sha256": binding["recipe_sha256"],
        "resource_ceiling_sha256": binding["resource_ceiling_sha256"],
        "policy_sha256": binding["policy_sha256"],
        "fixed_global_control_baseline": str(binding["fixed_global_control_baseline"]),
        "validator_sha256": context["source"]["runtime_readback_validator"]["sha256"],
        "source_manifest_sha256": context["source"]["manifest_sha256"],
        "calibration_binary_sha256": context["source"]["resource_domain_calibration"]["binary"]["sha256"],
        "calibration_output_sha256": context["source"]["resource_domain_calibration"]["output"]["sha256"],
    }


def _write_pair_metadata(context: dict[str, Any], attempts: list[dict[str, Any]]) -> str:
    values: dict[str, str] = {
        "execution_scope": "qualification",
        "comparison_family": context["job"]["comparison_family"],
        "fixed_pair_execution_status": EXECUTION_STATUS,
    }
    for member, attempt in zip(context["members"], attempts, strict=False):
        descriptor = member["descriptor"]
        binding = member["runtime_binding"]
        suffix = f"{descriptor['pair']}_{descriptor['executor']}"
        values[f"report_nonce_{suffix}"] = binding["report_nonce"]
        values[f"policy_sha256_{suffix}"] = binding["policy_sha256"]
        values[f"resource_ceiling_sha256_{suffix}"] = binding["resource_ceiling_sha256"]
        values[f"fixed_global_control_baseline_{suffix}"] = str(binding["fixed_global_control_baseline"])
        values[f"execution_scope_{suffix}"] = "qualification"
        values[f"oracle_sha256_{suffix}"] = "" if member["oracle"] is None else member["oracle"]["artifact"]["sha256"]
        try:
            shutdown = _existing_output_hash(member["outputs"]["shutdown"], MAX_RUNTIME_BYTES, "APP shutdown sidecar")
        except Exception:
            shutdown = None
        if shutdown is not None:
            values[f"shutdown_report_{suffix}"] = Path(member["outputs"]["shutdown"]).name
        try:
            ids = _existing_output_hash(member["outputs"]["ids"], MAX_ID_BYTES, "APP ID trace")
        except Exception:
            ids = None
        if ids is not None:
            values[f"ids_sha256_{suffix}"] = ids[0]
    rows = [[key, values[key]] for key in sorted(values)]
    return _write_tsv(context["output_root"] / "metadata.tsv", ["key", "value"], rows, "fixed-pair metadata")


def _validate_attempt_row(
    context: dict[str, Any], member: dict[str, Any], attempt: dict[str, Any], row: dict[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    if attempt.get("error") is not None:
        return None, attempt["error"]
    if attempt["status"] != 0:
        return None, "normal APP exited with a nonzero direct-launch status"
    if attempt["supervision"].get("cleanup_status") != "verified":
        return None, "normal APP owner cleanup was not verified"
    stderr = _existing_output_hash(member["outputs"]["stderr"], MAX_STDERR_BYTES, "normal APP stderr")
    if stderr is None or stderr[1] != 0:
        return None, "normal APP wrote stderr or its stderr artifact is missing"
    try:
        if attempt.get("runtime_snapshot") is None:
            snapshot, receipt_sha, validation_sha, _raw = _validate_runtime_v2(context, member)
            attempt["runtime_snapshot"] = snapshot
            attempt["runtime_readback_sha256"] = receipt_sha
            attempt["runtime_validation_sha256"] = validation_sha
        readback, _artifact = context["controller"].validate_runtime_process_artifacts(
            context["output_root"], row, context["job"], context["source"], context["spec"],
        )
        require(readback["numeric_snapshot"] == attempt["runtime_snapshot"], "runtime artifact adapter and strict v2 owner-release proof differ")
        require(readback["numeric_snapshot"]["schema"] == "allocatbelt.application-runtime-numeric-snapshot.v2", "fixed pair runtime artifact adapter downgraded its numeric snapshot")
        context["controller"].validate_numeric_runtime_snapshot(
            readback["numeric_snapshot"], member["runtime_expectation"]["value"],
            context["source"]["resource_domain_calibration"]["record"],
            context["source"]["runtime_readback_validator"]["sha256"], require_final_usage=True,
        )
        metrics = context["controller"].extract_process_metrics(
            context["output_root"], row, context["job"], context["source"], context["spec"],
            context["campaign_artifacts_root"],
        )
        if context["job"]["mode"] == "open_loop":
            minimum = context["spec"]["protocol"]["mixed_min_successes"] if context["job"]["workload"] == "mixed" else context["spec"]["protocol"]["standalone_min_successes"]
            require(metrics["completed"] >= minimum, "original open-loop success minimum was missed; evidence is invalid")
            require(metrics["completed"] == context["job"]["arrivals"], "original open-loop arrival count was not fully observed")
        return metrics, None
    except Exception as error:
        return None, f"{type(error).__name__}: {error}"


def _launch_root_is_unused(overlay: dict[str, Any]) -> None:
    root = Path(overlay["output_root"])
    expected = {
        "fixed-pair-execution-overlay.json",
        Path(overlay["runtime_bindings"]["pin"]["path"]).name,
    }
    actual = set()
    for entry in os.scandir(root):
        require(not entry.is_symlink(), f"fixed-pair output root contains a symlink before launch: {entry.name}")
        actual.add(entry.name)
    require(actual == expected, "fixed-pair output root contains prior or colliding execution artifacts")


def _allowed_output_paths(overlay: dict[str, Any]) -> set[str]:
    root = Path(overlay["output_root"])
    allowed = {
        "fixed-pair-execution-overlay.json",
        Path(overlay["runtime_bindings"]["pin"]["path"]).name,
        "processes.tsv",
        "metadata.tsv",
        "app-events.jsonl",
        "fixed-pair-execution-receipt.json",
    }
    for member in overlay["members"]:
        for name, value in member["outputs"].items():
            if name in ("root", "tmpdir", "probe_tmpdir"):
                continue
            path = Path(value)
            require(path.parent == root or root in path.parents, f"overlay output escaped its private root: {name}")
            allowed.add(path.relative_to(root).as_posix())
    return allowed


def _verify_output_allowlist(
    overlay: dict[str, Any], *, artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> None:
    output_tree = _hash_output_tree(overlay, artifact_view=artifact_view)
    allowed = _allowed_output_paths(overlay)
    unexpected = set(output_tree["files"]) - allowed
    require(not unexpected, f"fixed-pair output tree contains unbound files: {sorted(unexpected)}")


def _receipt_body(
    overlay: dict[str, Any], overlay_sha256: str, status: str, errors: list[str],
    source_before: dict[str, Any] | None, source_after: dict[str, Any] | None,
    probes: list[dict[str, Any]], attempts: list[dict[str, Any]], rows: list[dict[str, str]],
    metrics: list[dict[str, Any] | None], row_errors: list[str | None],
    metadata_sha256: str | None, process_sha256: str | None, output_tree: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "overlay_sha256": overlay_sha256,
        "campaign_id": overlay["campaign_id"],
        "host_id": overlay["host_id"],
        "run_id": overlay["job"]["value"]["run_id"],
        "component_status": EXECUTION_STATUS,
        "qualification_eligible": False,
        "execution_ready": False,
        "campaign_chronology_complete": False,
        "status": status,
        "historical_runner_sha256": overlay["sources"]["historical_runner_sha256"],
        "execution_modules": overlay["modules"],
        "execution_source": overlay["execution_source"],
        "source_pins_before": source_before,
        "source_pins_after": source_after,
        "inputs_unchanged": source_before is not None and source_before == source_after,
        "construction_probes": probes,
        "member_attempts": attempts,
        "process_header": PAIR_PROCESS_HEADER_FALLBACK,
        "processes_sha256": process_sha256,
        "metadata_sha256": metadata_sha256,
        "process_rows": rows,
        "process_metrics": metrics,
        "process_validation_errors": row_errors,
        "output_artifacts": output_tree,
        "errors": errors,
    }


def _write_receipt(root: Path, body: dict[str, Any]) -> dict[str, str]:
    receipt = dict(body)
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(body))
    raw = canonical_bytes(receipt)
    require(len(raw) <= MAX_RECEIPT_BYTES, "fixed-pair execution receipt exceeds its finite size bound")
    path = root / "fixed-pair-execution-receipt.json"
    checksum = write_exclusive(path, raw, "fixed-pair execution receipt")
    return {"path": str(path), "sha256": checksum}


def run_fixed_pair_overlay(
    overlay_pin: dict[str, Any], on_app_started: Callable[[dict[str, Any]], None],
    on_app_terminal: Callable[[dict[str, Any]], None],
) -> dict[str, str]:
    """Execute exactly the two original APP descriptors under one immutable overlay."""
    require(callable(on_app_started) and callable(on_app_terminal), "fixed-pair lifecycle callbacks are required")
    overlay, _overlay_raw, overlay_sha, context, _reconstructed = _read_overlay(overlay_pin)
    _launch_root_is_unused(overlay)
    context["members"] = overlay["members"]
    context["runtime_bindings_raw"] = read_stable(
        Path(overlay["runtime_bindings"]["pin"]["path"]), "original runtime binding manifest", MAX_RUNTIME_BYTES,
    )[0]
    context["runtime_bindings_sha256"] = overlay["runtime_bindings"]["pin"]["sha256"]
    errors: list[str] = []
    probes: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    rows: list[dict[str, str]] = []
    metrics: list[dict[str, Any] | None] = []
    row_errors: list[str | None] = []
    source_before: dict[str, Any] | None = None
    source_after: dict[str, Any] | None = None
    metadata_sha: str | None = None
    process_sha: str | None = None
    output_tree = {"files": {}, "total_bytes": 0, "maximum_bytes": MAX_PAIR_OUTPUT_BYTES}
    outer_deadline = time.monotonic() + overlay["deadlines"]["outer_seconds"]
    try:
        source_before = _snapshot_source_inputs(context)
    except Exception as error:
        errors.append(f"preflight source snapshot: {type(error).__name__}: {error}")
    probes_ok = source_before is not None
    if probes_ok:
        _ensure_private_directory(Path(overlay["output_root"]) / "probes")
        _ensure_private_directory(Path(overlay["output_root"]) / "probes" / "tmp")
        for member in overlay["members"]:
            try:
                probes.append(_run_construction_probe(context, member, overlay_sha))
            except Exception as error:
                probes_ok = False
                failure = {
                    "schema": PROBE_SCHEMA,
                    "role": "uncalibrated_construction_only",
                    "overlay_sha256": overlay_sha,
                    "member_ordinal": member["ordinal"],
                    "descriptor": member["descriptor"],
                    "validated": False,
                    "error": f"{type(error).__name__}: {error}",
                }
                probes.append(failure)
                errors.append(f"construction probe member {member['ordinal']}: {failure['error']}")
                break

    fatal_cleanup = False
    if probes_ok:
        for member in overlay["members"]:
            if time.monotonic() >= outer_deadline:
                errors.append("original pair outer deadline elapsed before the next exact member")
                break
            try:
                attempt = _launch_member(
                    overlay, context, member, overlay_sha, outer_deadline,
                    on_app_started, on_app_terminal,
                )
            except Exception as error:
                attempt = {
                    "ordinal": member["ordinal"],
                    "descriptor": member["descriptor"],
                    "attempted": True,
                    "status": 125,
                    "child_return_code": None,
                    "start": None,
                    "supervision": {"cleanup_status": "unverified", "leader_reaped": False, "group_signal_after_leader_reap_count": 0, "cleanup_errors": [f"{type(error).__name__}: {error}"]},
                    "runtime_snapshot": None,
                    "error": f"{type(error).__name__}: {error}",
                }
                errors.append(f"APP member {member['ordinal']}: {attempt['error']}")
            attempts.append(attempt)
            if attempt.get("error"):
                errors.append(f"APP member {member['ordinal']} lifecycle: {attempt['error']}")
            if attempt.get("terminal_callback_error"):
                fatal_cleanup = True
                errors.append(f"APP member {member['ordinal']} terminal callback failed; later original members were not launched")
                break
            if attempt.get("supervision", {}).get("cleanup_status") != "verified":
                fatal_cleanup = True
                errors.append(f"APP member {member['ordinal']} owner cleanup was not verified; later original members were not launched")
                break
            if attempt.get("supervision", {}).get("received_signal") is not None:
                errors.append(f"APP member {member['ordinal']} supervisor received an external signal")
                break

    metadata_rows = []
    for member, attempt in zip(overlay["members"], attempts, strict=False):
        try:
            row = _process_row(context, member, attempt)
        except Exception as error:
            detail = f"{type(error).__name__}: {error}"
            attempt["row_construction_error"] = detail
            errors.append(f"APP member {member['ordinal']} process row: {detail}")
            row = _failure_process_row(context, member, attempt)
        rows.append(row)
        metadata_rows.append((member, attempt))
    try:
        metadata_sha = _write_pair_metadata(context, attempts)
    except Exception as error:
        errors.append(f"pair metadata: {type(error).__name__}: {error}")
    header = PAIR_PROCESS_HEADER_FALLBACK
    try:
        captured_header = context["controller"].PAIR_PROCESS_HEADER
        require(captured_header == PAIR_PROCESS_HEADER_FALLBACK, "captured controller PAIR_PROCESS_HEADER changed after overlay build")
        header = captured_header
    except Exception as error:
        # A controller/header mismatch invalidates the pair, but must not erase
        # the terminal attempt ledger or prevent a bounded failure receipt.
        errors.append(f"process header: {type(error).__name__}: {error}")
    for index, row in enumerate(rows):
        member = overlay["members"][index]
        attempt = attempts[index]
        row_construction_error = attempt.get("row_construction_error")
        if row_construction_error is not None:
            # A fallback row records the failed attempt for audit; it cannot
            # be promoted by an adapter that reports unrelated valid metrics.
            validation_metrics = None
            validation_error = f"process row construction failed: {row_construction_error}"
        else:
            validation_metrics, validation_error = _validate_attempt_row(context, member, attempt, row)
        if validation_metrics is None:
            row["row_validation"] = "invalid"
            row["p99_qualification"] = "invalid"
            errors.append(f"APP member {member['ordinal']} artifact validation: {validation_error}")
        else:
            row["row_validation"] = "valid"
            row["p99_qualification"] = "eligible" if overlay["job"]["value"]["mode"] == "open_loop" else "not_applicable"
        metrics.append(validation_metrics)
        row_errors.append(validation_error)
    try:
        process_sha = _write_tsv(
            Path(overlay["output_root"]) / "processes.tsv", header,
            [[row[field] for field in header] for row in rows], "fixed-pair process ledger",
        )
    except Exception as error:
        errors.append(f"process ledger: {type(error).__name__}: {error}")
    try:
        source_after = _snapshot_source_inputs(context)
        if source_before is not None:
            require(source_after == source_before, "source/spec/plan/binary/oracle/module pins changed during the pair")
    except Exception as error:
        errors.append(f"postflight source snapshot: {type(error).__name__}: {error}")
    try:
        _verify_output_allowlist(overlay)
        output_tree = _hash_output_tree(overlay)
    except Exception as error:
        errors.append(f"output artifact bounds/allowlist: {type(error).__name__}: {error}")
    if time.monotonic() > outer_deadline:
        errors.append("original pair outer deadline elapsed before fixed-pair terminal evidence was sealed")
    pair_valid = (
        probes_ok and len(probes) == 2 and all(item.get("reader", {}).get("validated") is True for item in probes)
        and len(attempts) == 2 and len(rows) == 2 and all(row["exit_code"] == "0" and row["row_validation"] == "valid" for row in rows)
        and all(
            type(item.get("start")) is dict
            and item["start"].get("schema") == APP_STARTED_SCHEMA
            and item["start"].get("role") == "fixed_application_member"
            and type(item["start"].get("pid")) is int and item["start"]["pid"] > 0
            and type(item["start"].get("start_ticks")) is int and item["start"]["start_ticks"] > 0
            and type(item.get("terminal_event")) is dict
            and item["terminal_event"].get("schema") == APP_TERMINAL_SCHEMA
            and item["terminal_event"].get("pid") == item["start"]["pid"]
            and type(item.get("tmpdir_initial")) is dict and type(item.get("tmpdir_final")) is dict
            and item["tmpdir_final"].get("path") == overlay["members"][item["ordinal"]]["tmpdir"]["path"]
            for item in attempts
        )
        and len(metrics) == 2 and all(item is not None for item in metrics)
        and source_before is not None and source_after == source_before
        and metadata_sha is not None and process_sha is not None
        and not errors and not fatal_cleanup
    )
    status = "valid_pair" if pair_valid else "failed_or_invalid"
    receipt_body = _receipt_body(
        overlay, overlay_sha, status, errors, source_before, source_after,
        probes, attempts, rows, metrics, row_errors, metadata_sha, process_sha, output_tree,
    )
    receipt_pin = _write_receipt(Path(overlay["output_root"]), receipt_body)
    return receipt_pin


def _verify_cleanup_record(cleanup: dict[str, Any], label: str, *, require_success: bool) -> None:
    require(type(cleanup) is dict, f"{label} cleanup proof is malformed")
    require(cleanup.get("group_signal_after_leader_reap_count") == 0, f"{label} signaled a numeric process group after leader reap")
    signals = cleanup.get("signals", [])
    require(type(signals) is list, f"{label} cleanup signal ledger is malformed")
    require(all(type(item) is dict and item.get("group_signal", {}).get("leader_unreaped") is True for item in signals), f"{label} cleanup signal lacks the WNOWAIT leader ownership boundary")
    if require_success:
        require(cleanup.get("leader_reaped") is True and cleanup.get("remaining_session_members") == [] and cleanup.get("cleanup_status") == "verified" and cleanup.get("cleanup_errors") == [], f"{label} owner-release cleanup was not completely verified")


def _verify_start_proof(
    overlay: dict[str, Any], member: dict[str, Any], attempt: dict[str, Any], overlay_sha256: str,
    *, require_success: bool, offline_facts: dict[str, Any] | None = None,
) -> None:
    proof = attempt.get("start")
    require(type(proof) is dict, "attempted APP member lacks its actual start proof")
    body = dict(proof)
    claimed = body.pop("identity_sha256", None)
    require(claimed == sha256_bytes(canonical_bytes(body)), "APP start identity digest is invalid")
    require(proof.get("schema") == APP_STARTED_SCHEMA and proof.get("role") == "fixed_application_member", "APP start proof has the wrong direct-execution role")
    require(type(proof.get("pid")) is int and proof["pid"] > 0 and type(proof.get("start_ticks")) is int and proof["start_ticks"] > 0, "APP start proof lacks a positive PID/start-ticks identity")
    require(proof.get("executable_path") == member["binary"]["path"] and proof.get("executable_sha256") == member["binary"]["sha256"], "APP start proof executable differs from the source-pinned normal binary")
    binary_info = Path(member["binary"]["path"]).stat(follow_symlinks=False)
    if offline_facts is None:
        require((proof.get("executable_device"), proof.get("executable_inode"), proof.get("executable_size")) == (binary_info.st_dev, binary_info.st_ino, binary_info.st_size), "APP start proof descriptor device/inode/size differs from the pinned normal binary")
    else:
        require(type(proof.get("executable_device")) is int and proof["executable_device"] >= 0 and
                type(proof.get("executable_inode")) is int and proof["executable_inode"] > 0 and
                proof.get("executable_size") == binary_info.st_size,
                "peer APP start proof device/inode/size fields are malformed or differ from the source-pinned binary size")
    require(proof.get("requested_argv") == member["argv"] == proof.get("executed_argv"), "APP requested/executed argv differs from the exact original normal command")
    require(proof.get("requested_argv_sha256") == proof.get("executed_argv_sha256") == sha256_bytes(canonical_bytes(member["argv"])), "APP argv digest differs from the original normal command")
    require(proof.get("environment") == member["environment"] and proof.get("environment_sha256") == sha256_bytes(canonical_bytes(member["environment"])), "APP observed full environment differs from the exact identity allowlist")
    require(proof.get("cwd") == member["cwd"] and proof.get("tmpdir") == member["tmpdir"]["path"], "APP observed cwd/TMPDIR differs from the pinned member paths")
    require(proof.get("cpu_affinity") == member["affinity"]["cpus"], "APP observed affinity differs from the exact host CPU set")
    require(proof.get("network_namespace_inode") == member["network_namespace_inode"], "APP observed network namespace differs from the host pin")
    if attempt.get("tmpdir_final") is not None:
        if offline_facts is None:
            _verify_tmpdir_storage(
                attempt.get("tmpdir_initial"), attempt["tmpdir_final"], member["tmpdir"]["path"],
                member["tmpdir"]["bytes_limit"], member["tmpdir"]["inode_limit"],
                f"APP member {member['ordinal']}",
            )
        else:
            _verify_tmpdir_storage_offline(
                attempt.get("tmpdir_initial"), attempt["tmpdir_final"], member["tmpdir"]["path"],
                member["tmpdir"]["bytes_limit"], member["tmpdir"]["inode_limit"],
                offline_facts["host_verification"]["output_mount"], f"APP member {member['ordinal']}",
            )
    else:
        require(not require_success, "valid APP member has no final TMPDIR mount/storage proof")
    events = attempt.get("start_events")
    require(type(events) is list and len(events) == 1, "APP attempt does not contain one lifecycle start callback event")
    event = events[0]
    require(event.get("schema") == APP_STARTED_SCHEMA and event.get("role") == "fixed_application_member" and event.get("overlay_sha256") == overlay_sha256, "APP start callback event has the wrong role or overlay binding")
    require(event.get("campaign_id") == overlay["campaign_id"] and event.get("host_id") == overlay["host_id"] and event.get("run_id") == overlay["job"]["value"]["run_id"], "APP start callback event differs from its original campaign/job")
    require(event.get("member_ordinal") == member["ordinal"] and event.get("descriptor") == member["descriptor"] and event.get("proof") == proof, "APP start callback event differs from its exact member proof")
    terminal = attempt.get("terminal_event")
    require(type(terminal) is dict and terminal.get("schema") == APP_TERMINAL_SCHEMA, "APP attempt has no terminal lifecycle callback proof")
    require(terminal.get("overlay_sha256") == event.get("overlay_sha256") and terminal.get("pid") == proof["pid"] and terminal.get("descriptor") == member["descriptor"], "APP terminal event is not joined to the actual started PID/member")
    require(terminal.get("cleanup") == attempt.get("supervision") and terminal.get("status") == attempt.get("status"), "APP terminal event differs from direct supervisor cleanup/status")
    _verify_cleanup_record(
        attempt["supervision"], f"APP member {member['ordinal']}",
        require_success=attempt.get("supervision", {}).get("cleanup_status") == "verified",
    )


def _verify_construction_probe(
    context: dict[str, Any], overlay: dict[str, Any], member: dict[str, Any], probe: dict[str, Any], overlay_sha256: str,
    *, offline_facts: dict[str, Any] | None = None,
) -> None:
    view = context.get("artifact_view")
    require(probe.get("schema") == PROBE_SCHEMA and probe.get("role") == "uncalibrated_construction_only", "construction probe receipt role is malformed")
    require(probe.get("overlay_sha256") == overlay_sha256 and probe.get("member_ordinal") == member["ordinal"] and probe.get("descriptor") == member["descriptor"], "construction probe receipt differs from its frozen member")
    require(probe.get("binary") == member["binary"], "construction probe executable differs from the selected normal APP")
    expected_argv = [member["binary"]["path"], "--emit-feedback-policy-only", "--workload", overlay["job"]["value"]["workload"], "--profile", overlay["job"]["value"]["profile"]]
    require(probe.get("argv") == expected_argv, "construction probe argv differs from the pinned uncalibrated probe CLI")
    require(type(probe.get("pid")) is int and probe["pid"] > 0 and type(probe.get("start_ticks")) is int and probe["start_ticks"] > 0, "construction probe receipt lacks its actual positive PID/start-ticks")
    replay = exact(probe["replay"], {"pid", "start_ticks", "stdout", "stderr", "byte_equal", "cleanup"}, "construction probe replay")
    require(type(replay["pid"]) is int and replay["pid"] > 0 and replay["pid"] != probe["pid"] and type(replay["start_ticks"]) is int and replay["start_ticks"] > 0, "construction probe replay lacks an independent process identity")
    require(replay["byte_equal"] is True, "construction probe replay was not byte-equal")
    _verify_cleanup_record(probe["cleanup"], "construction probe", require_success=True)
    _verify_cleanup_record(replay["cleanup"], "construction probe replay", require_success=True)
    for label in ("stdout", "stderr"):
        artifact = exact(probe[label], {"path", "sha256", "bytes"}, f"construction probe {label} pin")
        raw, actual = _read_pair_artifact(Path(artifact["path"]), f"construction probe {label}", MAX_PROBE_STDOUT_BYTES if label == "stdout" else MAX_PROBE_STDERR_BYTES, view)
        require(actual == artifact["sha256"] and len(raw) == artifact["bytes"], f"construction probe {label} differs from its raw output pin")
        require(label != "stderr" or len(raw) == 0, "construction probe wrote stderr")
    for label in ("stdout", "stderr"):
        artifact = exact(replay[label], {"path", "sha256", "bytes"}, f"construction probe replay {label} pin")
        raw, actual = _read_pair_artifact(Path(artifact["path"]), f"construction probe replay {label}", MAX_PROBE_STDOUT_BYTES if label == "stdout" else MAX_PROBE_STDERR_BYTES, view)
        require(actual == artifact["sha256"] and len(raw) == artifact["bytes"], f"construction probe replay {label} differs from its raw output pin")
        require(label != "stderr" or len(raw) == 0, "construction probe replay wrote stderr")
    first_raw, first_sha = _read_pair_artifact(Path(probe["stdout"]["path"]), "actual construction probe JSON", MAX_PROBE_STDOUT_BYTES, view)
    replay_raw, replay_sha = _read_pair_artifact(Path(replay["stdout"]["path"]), "repeated construction probe JSON", MAX_PROBE_STDOUT_BYTES, view)
    require(first_raw == replay_raw and first_sha == replay_sha and replay["byte_equal"] is True, "construction probe rerun is not byte-equal")
    try:
        probe_value = json.loads(first_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"actual construction probe is not bounded JSON: {error}") from error
    require(first_raw == canonical_bytes(probe_value), "actual construction probe bytes are not canonical")
    recipe = exact(probe["reader_expectation"], {
        "schema", "mode", "identity", "policy", "app_capacity_artifact_sha256", "construction_probe",
        "host_binding", "external_pressure_proof", "final_runtime_binding", "minimum_production_seconds",
        "minimum_pressure_overlap_seconds",
    }, "uncalibrated feedback reader expectation")
    require(recipe["schema"] == context["loaded_modules"]["feedback_reader"].EXPECTATION_SCHEMA_V4 and recipe["mode"] == "capacity_calibration", "construction probe expectation is not the source-pinned uncalibrated v4 role")
    require(recipe["app_capacity_artifact_sha256"] is None and recipe["external_pressure_proof"] is None and recipe["final_runtime_binding"] is None, "construction probe expectation contains an unrelated calibration or pressure quartet")
    require(recipe["identity"]["process_id"] == probe["pid"] and recipe["construction_probe"]["raw_sha256"] == first_sha, "feedback reader expectation is not bound to the actual construction-probe PID/stdout")
    try:
        reader = context["loaded_modules"]["feedback_reader"]
        if view is None:
            actual_probe_sha = reader.validate_construction_probe(recipe, context["source"])
        else:
            actual_probe_sha = reader.validate_construction_probe(
                recipe, context["source"], artifact_reader=view.read,
            )
    except Exception as error:
        raise FixedPairError(f"pinned SourceV5 feedback reader rejected offline construction-probe replay: {error}") from error
    require(actual_probe_sha == first_sha, "pinned feedback reader returned a different construction-probe digest")
    require(probe["reader"].get("validated") is True and probe["reader"].get("probe_sha256") == first_sha, "construction probe reader receipt is incomplete")
    require(probe["reader"].get("sha256") == context["modules"]["feedback_reader"]["sha256"], "construction probe reader module pin changed")
    if offline_facts is None:
        _verify_tmpdir_storage(
            probe.get("tmpdir_initial"), probe.get("tmpdir_final"), member["outputs"]["probe_tmpdir"],
            MAX_TMPDIR_BYTES, MAX_TMPDIR_INODES, f"construction probe member {member['ordinal']}",
        )
    else:
        _verify_tmpdir_storage_offline(
            probe.get("tmpdir_initial"), probe.get("tmpdir_final"), member["outputs"]["probe_tmpdir"],
            MAX_TMPDIR_BYTES, MAX_TMPDIR_INODES, offline_facts["host_verification"]["output_mount"],
            f"construction probe member {member['ordinal']}",
        )


def _verify_fixed_pair_overlay_replay(
    overlay_pin: dict[str, Any], receipt_pin: dict[str, Any],
    offline_facts: dict[str, Any] | None = None,
    *, artifact_view: CapturedFixedPairArtifactsV1 | None = None,
) -> dict[str, Any]:
    """Shared raw artifact replay; host mode comes only from its caller."""
    require(artifact_view is None or offline_facts is not None,
            "captured fixed replay requires original strict-host receipt facts")
    if offline_facts is None:
        overlay, _overlay_raw, overlay_sha, context, _reconstructed = _read_overlay(overlay_pin)
    else:
        overlay, _overlay_raw, overlay_sha, context, _reconstructed = _read_overlay_with_host_facts(
            overlay_pin, offline_facts, artifact_view=artifact_view,
        )
    pin = exact(receipt_pin, {"path", "sha256"}, "fixed-pair receipt raw pin")
    receipt_path = (_safe_absolute(pin["path"], "fixed-pair receipt path")
                    if artifact_view is None else
                    _captured_origin_path(pin["path"], "fixed-pair receipt origin"))
    require(receipt_path == Path(overlay["output_root"]) / "fixed-pair-execution-receipt.json", "fixed-pair receipt path differs from its private output root")
    if artifact_view is None:
        raw, actual_receipt_sha, receipt_info = read_stable(receipt_path, "fixed-pair execution receipt", MAX_RECEIPT_BYTES)
        require(receipt_info.st_uid == os.getuid() and stat.S_IMODE(receipt_info.st_mode) == 0o600, "fixed-pair execution receipt permissions are not private")
    else:
        raw, actual_receipt_sha = artifact_view.read(receipt_path, "fixed-pair execution receipt", MAX_RECEIPT_BYTES)
    require(is_sha(pin["sha256"]) and actual_receipt_sha == pin["sha256"], "fixed-pair receipt differs from its raw pin")
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"fixed-pair receipt is not bounded JSON: {error}") from error
    expected_receipt_keys = {
        "schema", "overlay_sha256", "campaign_id", "host_id", "run_id", "component_status",
        "qualification_eligible", "execution_ready", "campaign_chronology_complete", "status",
        "historical_runner_sha256", "execution_modules", "execution_source",
        "source_pins_before", "source_pins_after", "inputs_unchanged", "construction_probes", "member_attempts",
        "process_header", "processes_sha256", "metadata_sha256", "process_rows", "process_metrics",
        "process_validation_errors", "output_artifacts", "errors", "receipt_sha256",
    }
    exact(receipt, expected_receipt_keys, "fixed-pair execution receipt")
    require(raw == canonical_bytes(receipt), "fixed-pair execution receipt is not canonical JSON")
    material = dict(receipt)
    claimed = material.pop("receipt_sha256")
    require(is_sha(claimed) and claimed == sha256_bytes(canonical_bytes(material)), "fixed-pair receipt self digest is invalid")
    require(receipt["schema"] == RECEIPT_SCHEMA and receipt["overlay_sha256"] == overlay_sha and receipt["campaign_id"] == overlay["campaign_id"] and receipt["host_id"] == overlay["host_id"] and receipt["run_id"] == overlay["job"]["value"]["run_id"], "fixed-pair receipt identity differs from the reconstructed overlay")
    require(receipt["component_status"] == EXECUTION_STATUS and receipt["qualification_eligible"] is False, "fixed-pair component receipt made a campaign qualification claim")
    require(receipt["execution_ready"] is False and receipt["campaign_chronology_complete"] is False, "fixed-pair component receipt made an execution-readiness or campaign-chronology claim")
    require(receipt["historical_runner_sha256"] == overlay["sources"]["historical_runner_sha256"] and receipt["execution_modules"] == overlay["modules"] and receipt["execution_source"] == overlay["execution_source"], "executor sidecar relabeled the historical runner or changed its new module pins")
    require(receipt["status"] in ("valid_pair", "failed_or_invalid"), "fixed-pair receipt has an unknown terminal status")
    current_snapshot = _snapshot_source_inputs(context)
    if receipt["source_pins_after"] is not None:
        require(receipt["source_pins_after"] == current_snapshot, "post-run SourceV5/spec/plan/binary/oracle/module pins differ during offline replay")
    else:
        require(receipt["status"] == "failed_or_invalid", "successful fixed pair omitted its post-run immutable input snapshot")
    require(receipt["inputs_unchanged"] is (receipt["source_pins_before"] is not None and receipt["source_pins_before"] == receipt["source_pins_after"]), "fixed-pair immutable-input status differs from its source snapshots")
    require(receipt["process_header"] == context["controller"].PAIR_PROCESS_HEADER == PAIR_PROCESS_HEADER_FALLBACK, "fixed-pair process header differs from the unchanged original schema")
    require(type(receipt["construction_probes"]) is list and type(receipt["member_attempts"]) is list and type(receipt["errors"]) is list, "fixed-pair receipt lists are malformed")
    require(type(receipt["process_rows"]) is list and type(receipt["process_metrics"]) is list and type(receipt["process_validation_errors"]) is list, "fixed-pair process replay records are malformed")
    require(len(receipt["member_attempts"]) <= 2 and len(receipt["process_rows"]) == len(receipt["member_attempts"]), "fixed-pair receipt has a process row without one attempted original member")
    _verify_output_allowlist(overlay, artifact_view=artifact_view)
    output_tree = _hash_output_tree(overlay, artifact_view=artifact_view)
    require(receipt["output_artifacts"] == output_tree, "fixed-pair output artifact tree differs from its receipt hashes/bounds")
    if offline_facts is not None and receipt["status"] == "valid_pair":
        for member in overlay["members"]:
            validation_path = Path(member["outputs"]["runtime_validation"])
            require((validation_path.is_file() and not validation_path.is_symlink())
                    if artifact_view is None else artifact_view.has_file(validation_path),
                    "offline fixed-pair replay refuses to create a missing runtime validation receipt")

    if receipt["status"] == "valid_pair":
        require(receipt["inputs_unchanged"] is True and receipt["source_pins_before"] == receipt["source_pins_after"], "valid fixed pair has changed source inputs")
        require(len(receipt["construction_probes"]) == len(receipt["member_attempts"]) == len(receipt["process_rows"]) == 2, "valid fixed pair does not contain exactly two source-pinned probes and APP members")
        require(all(item.get("reader", {}).get("validated") is True for item in receipt["construction_probes"]), "valid fixed pair contains an unvalidated construction probe")
        require(receipt["errors"] == [] and receipt["process_validation_errors"] == [None, None], "valid fixed pair retained a validation error")
    probes_by_ordinal = {item.get("member_ordinal"): item for item in receipt["construction_probes"] if type(item) is dict}
    for member in overlay["members"]:
        probe = probes_by_ordinal.get(member["ordinal"])
        if probe is not None and probe.get("validated") is not False:
            _verify_construction_probe(context, overlay, member, probe, overlay_sha,
                                       offline_facts=offline_facts)
    attempts_by_ordinal = {item.get("ordinal"): item for item in receipt["member_attempts"] if type(item) is dict}
    for member in overlay["members"]:
        attempt = attempts_by_ordinal.get(member["ordinal"])
        if attempt is None:
            continue
        require(attempt.get("descriptor") == member["descriptor"] and attempt.get("attempted") is True, "attempted APP member differs from the exact original descriptor")
        if attempt.get("start") is not None:
            _verify_start_proof(
                overlay, member, attempt, overlay_sha,
                require_success=receipt["status"] == "valid_pair", offline_facts=offline_facts,
            )
        else:
            _verify_cleanup_record(attempt.get("supervision", {}), f"failed APP launch {member['ordinal']}", require_success=False)

    process_path = Path(overlay["output_root"]) / "processes.tsv"
    if receipt["processes_sha256"] is not None:
        header, parsed_rows, _process_raw, actual_process_sha = _read_tsv(process_path, "fixed-pair process ledger", MAX_RUNTIME_BYTES, artifact_view=artifact_view)
        require(actual_process_sha == receipt["processes_sha256"] and header == receipt["process_header"], "fixed-pair process ledger raw pin or closed header differs")
        require(parsed_rows == receipt["process_rows"], "fixed-pair process rows differ from the immutable sidecar representation")
    else:
        parsed_rows = []
        require(not _pair_artifact_exists(process_path, artifact_view), "fixed-pair receipt omitted an existing process ledger pin")
    if receipt["metadata_sha256"] is not None:
        metadata_raw, metadata_sha = _read_pair_artifact(Path(overlay["output_root"]) / "metadata.tsv", "fixed-pair metadata", MAX_RUNTIME_BYTES, artifact_view)
        require(metadata_sha == receipt["metadata_sha256"], "fixed-pair metadata raw pin differs")
        require(metadata_raw.startswith(b"key\tvalue\n"), "fixed-pair metadata schema differs")
    else:
        metadata_path = Path(overlay["output_root"]) / "metadata.tsv"
        require(not metadata_path.exists() if artifact_view is None else
                not artifact_view.has_file(metadata_path),
                "fixed-pair receipt omitted an existing metadata pin")

    recomputed_metrics: list[dict[str, Any] | None] = []
    recomputed_errors: list[str | None] = []
    if receipt["status"] == "valid_pair":
        try:
            context["controller"].require_exact_pair_process_rows(parsed_rows, overlay["job"]["value"])
        except Exception as error:
            raise FixedPairError(f"fixed-pair original process descriptors did not revalidate: {error}") from error
        require(all(row["exit_code"] == "0" and row["row_validation"] == "valid" for row in parsed_rows), "valid fixed pair contains a failed process row")
        expected_order = [
            (member["descriptor"]["pair"], member["descriptor"]["executor"], member["descriptor"]["allocator"])
            for member in overlay["members"]
        ]
        observed_order = [(row["pair"], row["executor"], row["allocator"]) for row in parsed_rows]
        require(observed_order == expected_order, "process rows changed original ordinal-parity member order")
        for row in parsed_rows:
            members = [item for item in overlay["members"] if (item["descriptor"]["pair"], item["descriptor"]["executor"], item["descriptor"]["allocator"]) == (row["pair"], row["executor"], row["allocator"])]
            require(len(members) == 1, "process row does not identify one original member")
            member = members[0]
            try:
                argv_value = json.loads(row["argv"])
            except (TypeError, json.JSONDecodeError) as error:
                raise FixedPairError(f"process argv row is not JSON: {error}") from error
            require(argv_value == member["argv"], "process row argv differs from the exact original APP command")
            expected_p99 = "eligible" if overlay["job"]["value"]["mode"] == "open_loop" else "not_applicable"
            require(row["p99_qualification"] == expected_p99, "process row p99 label differs from validated original-mode eligibility")
            time_raw, _time_sha = _read_pair_artifact(Path(overlay["output_root"]) / row["time_report"], "direct APP time report", MAX_TIME_BYTES, artifact_view)
            timing = json.loads(time_raw.decode("utf-8"))
            require(time_raw == canonical_bytes(timing) and timing.get("schema") == DIRECT_TIME_SCHEMA and timing.get("time_source") == "monotonic_direct_supervisor", "direct APP time report is not the separately named/versioned monotonic record")
            attempt = attempts_by_ordinal[member["ordinal"]]
            require(timing.get("pid") == attempt["start"]["pid"] and timing.get("exit_code") == 0, "direct APP time report differs from actual process identity/status")
            snapshot, _receipt_sha, _validation_sha, _runtime_raw = _validate_runtime_v2(context, member)
            require(snapshot == attempt["runtime_snapshot"], "offline runtime-v2 snapshot differs from the captured APP owner-release proof")
            metric_arguments = (context["output_root"], row, overlay["job"]["value"], context["source"],
                                context["spec"], context["campaign_artifacts_root"])
            if artifact_view is None:
                metrics = context["controller"].extract_process_metrics(*metric_arguments)
            else:
                metrics = context["controller"].extract_process_metrics(
                    *metric_arguments, artifact_view=artifact_view,
                )
            recomputed_metrics.append(metrics)
            recomputed_errors.append(None)
        require(receipt["process_metrics"] == recomputed_metrics and receipt["process_validation_errors"] == recomputed_errors, "stored process metrics differ from independent SourceV5 artifact replay")
        require(receipt["processes_sha256"] is not None and receipt["metadata_sha256"] is not None, "valid fixed pair omitted its closed process/metadata ledgers")
    else:
        require(all(type(value) in (dict, type(None)) for value in receipt["process_metrics"]), "failed fixed pair process metrics are malformed")

    return {
        "schema": RECEIPT_SCHEMA,
        "verified": True,
        "status": receipt["status"],
        "qualification_eligible": False,
        "receipt_sha256": actual_receipt_sha,
        "overlay_sha256": overlay_sha,
        "run_id": receipt["run_id"],
    }


def verify_fixed_pair_overlay_offline(
    overlay_pin: object, receipt_pin: object, host_verification_pin: object,
    evidence_path_map: object,
) -> dict[str, Any]:
    """Replay one peer pair from identity-mapped bytes and its strict host receipt."""
    overlay_pin = exact(overlay_pin, {"path", "sha256"}, "offline fixed-pair overlay pin")
    receipt_pin = exact(receipt_pin, {"path", "sha256"}, "offline fixed-pair execution receipt pin")
    host_pin = exact(host_verification_pin, {
        "path", "raw_sha256", "host_verification_sha256",
    }, "offline fixed-pair host-verification pin")
    overlay, overlay_raw, overlay_sha, overlay_path = _read_overlay_raw(overlay_pin)
    roots = _validate_fixed_pair_evidence_path_map(
        evidence_path_map, overlay, _safe_absolute(host_pin["path"], "host-verification receipt path"),
    )
    receipt_path = _safe_absolute(receipt_pin["path"], "offline fixed-pair execution receipt path")
    require(str(receipt_path) in roots or any(str(receipt_path).startswith(root + "/") for root in roots),
            "fixed-pair evidence map omits its raw execution receipt")
    receipt_raw, receipt_raw_sha, _receipt_info = read_stable(
        receipt_path, "offline fixed-pair execution receipt", MAX_RECEIPT_BYTES,
    )
    require(receipt_raw_sha == receipt_pin["sha256"], "offline fixed-pair receipt bytes differ from the supplied raw pin")
    try:
        receipt_value = json.loads(receipt_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"offline fixed-pair execution receipt is not bounded JSON: {error}") from error
    require(type(receipt_value) is dict and receipt_raw == canonical_bytes(receipt_value),
            "offline fixed-pair execution receipt is not canonical")

    host_receipt_path = _safe_absolute(host_pin["path"], "strict fixed-pair host-verification receipt path")
    host_raw, host_raw_sha, host_info = read_stable(
        host_receipt_path, "strict fixed-pair host-verification receipt", MAX_RECEIPT_BYTES,
    )
    require(host_info.st_uid == os.getuid() and stat.S_IMODE(host_info.st_mode) == 0o600 and
            host_raw_sha == host_pin["raw_sha256"],
            "strict fixed-pair host-verification receipt mode/owner/raw pin differs")
    try:
        host_value = json.loads(host_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"strict fixed-pair host-verification receipt is not bounded JSON: {error}") from error
    require(type(host_value) is dict and host_raw == canonical_bytes(host_value),
            "strict fixed-pair host-verification receipt is not canonical")
    host_value = _validate_host_verification_receipt(
        host_value, host_pin, overlay, overlay_sha, receipt_raw_sha, receipt_value,
    )
    spec_binding = exact(overlay["spec"], {"pin", "semantic_sha256"}, "offline fixed-pair SpecV3 binding")
    _spec_path, spec_value, _spec_raw, _spec_raw_sha = read_json_pin(
        spec_binding["pin"], "offline fixed-pair SpecV3", MAX_SPEC_BYTES,
    )
    require(sha256_bytes(canonical_bytes(spec_value)) == spec_binding["semantic_sha256"],
            "offline fixed-pair SpecV3 semantic digest differs from its original pin")
    observed_binding = exact(overlay["sources"]["observed_host"], {
        "pin", "host_fingerprint_sha256", "controls_sha256", "process_affinity",
        "network_namespace_inode",
    }, "offline fixed-pair observed-host binding")
    facts = {
        "schema": host_value["schema"],
        "host_verification": host_value["host_verification"],
    }
    _offline_host_observation(
        facts, observed_binding["pin"], spec_value, overlay["host_id"],
    )
    result = _verify_fixed_pair_overlay_replay(overlay_pin, receipt_pin, facts)
    require(result["overlay_sha256"] == overlay_sha and result["receipt_sha256"] == receipt_raw_sha and
            result["run_id"] == overlay["job"]["value"]["run_id"] and result["status"] == host_value["status"],
            "fixed-pair peer replay differs from its strict host receipt and original scheduled job")
    return {**result, "host_verification_sha256": host_value["receipt_sha256"]}


def verify_fixed_pair_overlay(overlay_pin: dict[str, Any], receipt_pin: dict[str, Any]) -> dict[str, Any]:
    """Preserve the strict host-local v1 overlay verifier API."""
    return _verify_fixed_pair_overlay_replay(overlay_pin, receipt_pin, None)


def _host_verification_body(
    overlay: dict[str, Any], overlay_sha: str, receipt_value: dict[str, Any],
    receipt_raw_sha: str, host_value: dict[str, Any], output_mount: dict[str, Any],
) -> dict[str, Any]:
    nested = {
        "schema": HOST_VERIFICATION_IDENTITY_SCHEMA,
        "host_id": overlay["host_id"],
        "observed_host_raw_sha256": host_value["pin"]["sha256"],
        "process_affinity": host_value["process_affinity"],
        "network_namespace_inode": host_value["network_namespace_inode"],
        "output_mount": output_mount,
    }
    host_verification = {**nested, "host_verification_sha256": sha256_bytes(canonical_bytes(nested))}
    body = {
        "schema": HOST_VERIFICATION_SCHEMA,
        "strict_verified": True,
        "qualification_eligible": False,
        "execution_ready": False,
        "campaign_chronology_complete": False,
        "overlay_raw_sha256": overlay_sha,
        "execution_receipt_raw_sha256": receipt_raw_sha,
        "execution_receipt_sha256": receipt_value["receipt_sha256"],
        "status": receipt_value["status"],
        "run_id": receipt_value["run_id"],
        "host_verification": host_verification,
    }
    return {**body, "receipt_sha256": sha256_bytes(canonical_bytes(body))}


def verify_fixed_pair_overlay_with_host_receipt(
    overlay_pin: dict[str, Any], receipt_pin: dict[str, Any], host_verification_path: Path,
) -> dict[str, Any]:
    """Strictly verify one pair on its origin host and preserve a host receipt."""
    overlay, _overlay_raw, overlay_sha, context, _reconstructed = _read_overlay(overlay_pin)
    output_mount = _mount_identity(context["output_root"])
    require(_mount_static(output_mount) == overlay["sources"]["output_mount"] and
            output_mount["available_bytes"] >= MAX_PAIR_OUTPUT_BYTES + 2 * MAX_TMPDIR_BYTES and
            output_mount["available_inodes"] >= 2 * MAX_TMPDIR_INODES + 64,
            "strict fixed-pair host verification cannot reproduce its original output-storage allowance")
    strict_result = verify_fixed_pair_overlay(overlay_pin, receipt_pin)
    affinity_after = sorted(os.sched_getaffinity(0))
    network_after = _live_network_namespace_inode()
    output_mount_after = _mount_identity(context["output_root"])
    require(affinity_after == context["observed_host"]["process_affinity"] and
            network_after == context["observed_host"]["network_namespace_inode"] and
            _mount_static(output_mount_after) == _mount_static(output_mount),
            "strict fixed-pair host identity changed during its independent replay")
    receipt_path = _safe_absolute(receipt_pin["path"], "strict fixed-pair execution receipt path")
    receipt_raw, receipt_raw_sha, _receipt_info = read_stable(receipt_path, "strict fixed-pair execution receipt", MAX_RECEIPT_BYTES)
    require(receipt_raw_sha == receipt_pin["sha256"], "strict fixed-pair receipt changed after replay")
    receipt_value = json.loads(receipt_raw.decode("utf-8"))
    require(_mount_static(output_mount) == overlay["sources"]["output_mount"],
            "strict fixed-pair output mount differs from the frozen overlay")
    body = _host_verification_body(
        overlay, overlay_sha, receipt_value, receipt_raw_sha,
        context["observed_host"], output_mount,
    )
    path = Path(host_verification_path)
    try:
        path.relative_to(Path(overlay["output_root"]))
        in_pair_tree = True
    except ValueError:
        in_pair_tree = False
    require(path.is_absolute() and not in_pair_tree,
            "fixed-pair host-verification receipt must be separate from the immutable pair output tree")
    try:
        parent_info = path.parent.lstat()
        require(stat.S_ISDIR(parent_info.st_mode) and path.parent.resolve(strict=True) == path.parent and
                stat.S_IMODE(parent_info.st_mode) == 0o700 and parent_info.st_uid == os.getuid(),
                "fixed-pair host-verification parent must be an owned real mode-0700 directory")
    except OSError as error:
        raise FixedPairError(f"fixed-pair host-verification parent is unavailable: {error}") from error
    receipt_bytes = canonical_bytes(body)
    receipt_sha = write_exclusive(path, receipt_bytes, "fixed-pair strict host-verification receipt")
    return {
        "path": str(path), "raw_sha256": receipt_sha,
        "host_verification_sha256": body["receipt_sha256"],
        "status": strict_result["status"], "overlay_sha256": overlay_sha,
    }


def _validate_host_verification_receipt(
    value: object, pin_value: object, overlay: dict[str, Any], overlay_sha: str,
    execution_receipt_raw_sha: str, execution_receipt: dict[str, Any],
) -> dict[str, Any]:
    pin = exact(pin_value, {"path", "raw_sha256", "host_verification_sha256"},
                "strict fixed-pair host-verification receipt pin")
    receipt = exact(value, {
        "schema", "strict_verified", "qualification_eligible", "execution_ready",
        "campaign_chronology_complete", "overlay_raw_sha256", "execution_receipt_raw_sha256",
        "execution_receipt_sha256", "status", "run_id", "host_verification", "receipt_sha256",
    }, "strict fixed-pair host-verification receipt")
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    require(receipt["schema"] == HOST_VERIFICATION_SCHEMA and receipt["strict_verified"] is True and
            receipt["qualification_eligible"] is False and receipt["execution_ready"] is False and
            receipt["campaign_chronology_complete"] is False and
            receipt["receipt_sha256"] == pin["host_verification_sha256"] == sha256_bytes(canonical_bytes(body)),
            "strict fixed-pair host-verification receipt schema/digest/flags are invalid")
    require(receipt["overlay_raw_sha256"] == overlay_sha and
            receipt["execution_receipt_raw_sha256"] == execution_receipt_raw_sha and
            receipt["execution_receipt_sha256"] == execution_receipt["receipt_sha256"] and
            receipt["status"] == execution_receipt["status"] and
            receipt["run_id"] == overlay["job"]["value"]["run_id"],
            "strict fixed-pair host-verification receipt names different original raw evidence")
    host = exact(receipt["host_verification"], {
        "schema", "host_id", "observed_host_raw_sha256", "process_affinity",
        "network_namespace_inode", "output_mount", "host_verification_sha256",
    }, "strict fixed-pair host identity receipt")
    host_body = {key: item for key, item in host.items() if key != "host_verification_sha256"}
    require(host["schema"] == HOST_VERIFICATION_IDENTITY_SCHEMA and
            host["host_verification_sha256"] == sha256_bytes(canonical_bytes(host_body)) and
            host["host_id"] == overlay["host_id"] and
            host["observed_host_raw_sha256"] == overlay["sources"]["observed_host"]["pin"]["sha256"],
            "strict fixed-pair host identity receipt differs from the frozen overlay")
    affinity = host["process_affinity"]
    require(type(affinity) is list and affinity and
            affinity == sorted(set(item for item in affinity if type(item) is int and 0 <= item <= 65535)),
            "strict fixed-pair host affinity receipt is malformed")
    require(type(host["network_namespace_inode"]) is int and host["network_namespace_inode"] > 0 and
            affinity == overlay["sources"]["observed_host"]["process_affinity"] and
            host["network_namespace_inode"] == overlay["sources"]["observed_host"]["network_namespace_inode"],
            "strict fixed-pair host facts differ from the original overlay observation")
    return receipt


def _captured_origin_path(value: object, label: str) -> Path:
    """Validate an origin name without resolving or statting the origin host."""
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096 and
            "\\" not in value and not any(ord(item) < 32 or ord(item) == 127 for item in value),
            f"{label} is not bounded path text")
    pure = PurePosixPath(value)
    require(pure.anchor == "/" and pure.as_posix() == value and
            all(part not in (".", "..") for part in pure.parts),
            f"{label} is not a normalized absolute origin name")
    return Path(value)


class CapturedFixedPairArtifactsV1:
    """Read exact0400 capture references without inventing origin stat facts.

    References are supplied by the caller's signed-manifest readback boundary.
    The replay preparer subsequently restricts access to the original pair's
    receipt-bound inventory. Physical metadata always describes the capture.
    """

    def __init__(self, references: object, stage_root: Path):
        root = _safe_absolute(str(stage_root), "fixed capture stage root")
        require(root.resolve(strict=True) == root,
                "fixed capture stage root traverses an alias")
        info = root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700,
                "fixed capture stage root is not an owned0700 directory")
        require(type(references) is dict and
                0 < len(references) <= MAX_OUTPUT_FILES + 64,
                "fixed capture references exceed the finite file count")
        self._references = {}
        local_paths = set()
        for origin, value in references.items():
            origin_path = _captured_origin_path(origin, "fixed capture origin")
            row = exact(value, {
                "origin_path", "path", "role", "host_id", "raw_sha256",
                "semantic_sha256", "byte_count", "maximum_bytes",
            }, "fixed capture reference")
            path = _safe_absolute(row["path"], "fixed capture local path")
            require(row["origin_path"] == str(origin_path) and
                    path.parent == root and path != origin_path and
                    str(path) not in local_paths and is_sha(row["raw_sha256"]) and
                    type(row["role"]) is str and 0 < len(row["role"]) <= 128 and
                    type(row["host_id"]) is str and 0 < len(row["host_id"]) <= 128 and
                    (row["semantic_sha256"] is None or is_sha(row["semantic_sha256"])) and
                    type(row["byte_count"]) is int and 0 <= row["byte_count"] <= (1 << 64) - 1 and
                    type(row["maximum_bytes"]) is int and
                    row["byte_count"] <= row["maximum_bytes"] <= (1 << 64) - 1,
                    "fixed capture reference has an alias or malformed byte pin")
            local_paths.add(str(path))
            self._references[str(origin_path)] = dict(row)
        self.stage_root = root
        self._stage_identity = self._local_identity(info)
        self._admitted = set(self._references)
        self._origin_files = None
        self._output_root = None
        self._directories = set()

    @staticmethod
    def _local_identity(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    @contextmanager
    def open_snapshot(self, origin: object, label: str, maximum: int):
        origin_text = str(_captured_origin_path(str(origin), f"{label} capture origin"))
        require(origin_text in self._admitted,
                f"{label} is absent from the exact admitted capture")
        row = self._references[origin_text]
        require(type(maximum) is int and 0 <= row["byte_count"] <= maximum,
                f"{label} exceeds its original reader byte ceiling")
        path = Path(row["path"])
        root_descriptor = os.open(self.stage_root, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptor = None
        stream = None
        try:
            require(self._stage_identity == self._local_identity(os.fstat(root_descriptor)) ==
                    self._local_identity(self.stage_root.lstat()),
                    f"{label} capture stage root changed")
            before_path = os.stat(path.name, dir_fd=root_descriptor, follow_symlinks=False)
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_descriptor)
            before = os.fstat(descriptor)
            require(self._local_identity(before) == self._local_identity(before_path) and
                    stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                    stat.S_IMODE(before.st_mode) == 0o400 and before.st_nlink == 1 and
                    before.st_size == row["byte_count"],
                    f"{label} capture is not its exact owned0400 regular file")
            digest = hashlib.sha256()
            remaining = row["byte_count"]
            while remaining:
                block = os.read(descriptor, min(1024 * 1024, remaining))
                require(bool(block), f"{label} capture was shortened")
                remaining -= len(block)
                digest.update(block)
            require(os.read(descriptor, 1) == b"" and
                    digest.hexdigest() == row["raw_sha256"],
                    f"{label} capture raw bytes differ from their exact pin")
            os.lseek(descriptor, 0, os.SEEK_SET)
            stream = os.fdopen(os.dup(descriptor), "rb")
            yield stream, digest.hexdigest(), row["byte_count"]
            require(self._local_identity(before) ==
                    self._local_identity(os.fstat(descriptor)) ==
                    self._local_identity(os.stat(path.name, dir_fd=root_descriptor,
                                                 follow_symlinks=False)) and
                    self._stage_identity == self._local_identity(os.fstat(root_descriptor)) ==
                    self._local_identity(self.stage_root.lstat()),
                    f"{label} capture changed during replay")
        finally:
            if stream is not None:
                stream.close()
            if descriptor is not None:
                os.close(descriptor)
            os.close(root_descriptor)

    def read(self, origin: object, label: str, maximum: int) -> tuple[bytes, str]:
        with self.open_snapshot(origin, label, maximum) as (stream, digest, size):
            raw = stream.read(maximum + 1)
            require(len(raw) == size <= maximum,
                    f"{label} capture read changed its exact byte count")
            return raw, digest

    def has_file(self, origin: object) -> bool:
        """Membership is manifest/receipt authority, never ambient origin IO."""
        return str(_captured_origin_path(str(origin), "captured artifact name")) in self._admitted

    def bind_output_inventory(
        self, overlay: dict[str, Any], receipt: dict[str, Any],
        host_receipt_path: str,
    ) -> None:
        output_root = _captured_origin_path(overlay["output_root"], "captured pair output root")
        inventory = exact(receipt["output_artifacts"], {
            "files", "total_bytes", "maximum_bytes",
        }, "captured origin output inventory")
        require(type(inventory["files"]) is dict and
                len(inventory["files"]) <= MAX_OUTPUT_FILES and
                inventory["maximum_bytes"] == MAX_PAIR_OUTPUT_BYTES,
                "captured origin output inventory exceeds the unchanged owner bounds")
        allowed = _allowed_output_paths(overlay)
        expected = set()
        directories = {str(output_root)}
        original = {}
        total = 0
        for relative, value in inventory["files"].items():
            relative = _safe_relative(relative, "captured origin output name")
            require(relative in allowed, "captured origin inventory has an undeclared output")
            fact = exact(value, {"sha256", "size", "device", "inode", "mode"},
                         "captured origin output facts")
            require(is_sha(fact["sha256"]) and type(fact["size"]) is int and
                    0 <= fact["size"] <= MAX_PAIR_OUTPUT_BYTES and
                    type(fact["device"]) is int and 0 <= fact["device"] < 1 << 64 and
                    type(fact["inode"]) is int and 0 < fact["inode"] < 1 << 64 and
                    type(fact["mode"]) is int and fact["mode"] == 0o600,
                    "captured origin output facts are malformed")
            origin = str(output_root / relative)
            row = self._references.get(origin)
            require(row is not None and row["raw_sha256"] == fact["sha256"] and
                    row["byte_count"] == fact["size"],
                    "capture does not contain its exact origin inventory row")
            total += fact["size"]
            require(total <= MAX_PAIR_OUTPUT_BYTES,
                    "captured origin inventory exceeds its aggregate owner cap")
            expected.add(origin)
            original[relative] = dict(fact)
            parent = (output_root / relative).parent
            while parent == output_root or output_root in parent.parents:
                directories.add(str(parent))
                if parent == output_root:
                    break
                parent = parent.parent
        require(type(inventory["total_bytes"]) is int and inventory["total_bytes"] == total,
                "captured origin inventory byte sum differs")
        expected.add(str(output_root / "fixed-pair-execution-receipt.json"))
        host_origin = _captured_origin_path(host_receipt_path, "captured strict host receipt")
        require(host_origin != output_root and output_root not in host_origin.parents,
                "captured strict host receipt must be outside the immutable pair output tree")
        expected.add(str(host_origin))
        require(expected <= set(self._references) and not any(
                    origin not in expected and
                    (Path(origin) == output_root or output_root in Path(origin).parents)
                    for origin in self._references
                ), "capture has missing or unexpected pair output members")
        require(all(self._references[origin]["host_id"] == overlay["host_id"]
                    for origin in expected),
                "capture member belongs to a different original host")
        self._admitted = expected
        self._origin_files = original
        self._output_root = output_root
        self._directories = directories

    def output_tree(self) -> dict[str, Any]:
        require(type(self._origin_files) is dict and self._output_root is not None,
                "capture has not bound its original output inventory")
        files = {}
        total = 0
        for relative, fact in self._origin_files.items():
            raw, digest = self.read(self._output_root / relative,
                                    "captured pair output", MAX_PAIR_OUTPUT_BYTES)
            require(digest == fact["sha256"] and len(raw) == fact["size"],
                    "captured output differs from its original receipt bytes")
            # device/inode/mode are authenticated ORIGIN facts, never claimed
            # to be the metadata of the separate physical0400 capture.
            files[relative] = {**fact, "sha256": digest, "size": len(raw)}
            total += len(raw)
        return {"files": files, "total_bytes": total,
                "maximum_bytes": MAX_PAIR_OUTPUT_BYTES}


def prepare_captured_fixed_pair_replay_v1(
    overlay_pin: object, receipt_pin: object, host_verification_pin: object,
    references: object, stage_root: Path,
) -> dict[str, Any]:
    """Validate captured envelopes/host facts; full numeric replay is separate."""
    overlay_pin = exact(overlay_pin, {"path", "sha256"}, "captured overlay pin")
    receipt_pin = exact(receipt_pin, {"path", "sha256"}, "captured execution receipt pin")
    host_pin = exact(host_verification_pin, {
        "path", "raw_sha256", "host_verification_sha256",
    }, "captured strict host receipt pin")
    require(type(references) is dict, "captured fixed references must be an exact origin map")
    bootstrap_origins = {
        str(_captured_origin_path(pin["path"], "captured fixed envelope origin"))
        for pin in (overlay_pin, receipt_pin, host_pin)
    }
    require(bootstrap_origins <= references.keys(), "capture omits an exact fixed envelope")
    view = CapturedFixedPairArtifactsV1(
        {origin: references[origin] for origin in bootstrap_origins}, stage_root,
    )

    def document(pin, digest_field, label, maximum):
        require(is_sha(pin[digest_field]), f"{label} raw pin is malformed")
        raw, digest = view.read(pin["path"], label, maximum)
        require(digest == pin[digest_field], f"{label} raw pin differs")
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise FixedPairError(f"{label} is not bounded canonical JSON") from error
        require(type(value) is dict and raw == canonical_bytes(value),
                f"{label} is not canonical JSON")
        return value, raw, digest

    overlay, _overlay_raw, overlay_sha = document(
        overlay_pin, "sha256", "captured fixed overlay", MAX_PLAN_BYTES,
    )
    receipt, _receipt_raw, receipt_sha = document(
        receipt_pin, "sha256", "captured fixed receipt", MAX_RECEIPT_BYTES,
    )
    host, _host_raw, _host_sha = document(
        host_pin, "raw_sha256", "captured strict host receipt", MAX_RECEIPT_BYTES,
    )
    require(overlay.get("schema") == OVERLAY_SCHEMA and
            receipt.get("schema") == RECEIPT_SCHEMA and
            receipt.get("campaign_id") == overlay.get("campaign_id") and
            receipt.get("host_id") == overlay.get("host_id") and
            receipt.get("run_id") == overlay["job"]["value"]["run_id"] and
            overlay_pin["path"] == str(Path(overlay["output_root"]) /
                                       "fixed-pair-execution-overlay.json") and
            receipt_pin["path"] == str(Path(overlay["output_root"]) /
                                       "fixed-pair-execution-receipt.json") and
            receipt.get("overlay_sha256") == overlay_sha and
            receipt.get("receipt_sha256") == sha256_bytes(canonical_bytes({
                key: value for key, value in receipt.items() if key != "receipt_sha256"
            })), "captured fixed envelopes differ from their original identity or self pin")
    host = _validate_host_verification_receipt(
        host, host_pin, overlay, overlay_sha, receipt_sha, receipt,
    )
    mount = _validate_output_mount_attestation(
        host["host_verification"]["output_mount"], Path(overlay["output_root"]),
    )
    require(_mount_static(mount) == overlay["sources"]["output_mount"] and
            mount["available_bytes"] >= MAX_PAIR_OUTPUT_BYTES + 2 * MAX_TMPDIR_BYTES and
            mount["available_inodes"] >= 2 * MAX_TMPDIR_INODES + 64,
            "captured strict host mount differs from the original bounded output facts")
    spec_pin = exact(overlay["spec"], {"pin", "semantic_sha256"},
                     "captured fixed SpecV3 binding")
    _path, spec, _raw, _sha = read_json_pin(spec_pin["pin"],
                                         "resident original SpecV3", MAX_SPEC_BYTES)
    require(sha256_bytes(canonical_bytes(spec)) == spec_pin["semantic_sha256"],
            "captured fixed SpecV3 semantic pin differs")
    facts = {"schema": host["schema"],
             "host_verification": host["host_verification"]}
    _offline_host_observation(facts, overlay["sources"]["observed_host"]["pin"],
                              spec, overlay["host_id"])
    inventory = exact(receipt["output_artifacts"], {
        "files", "total_bytes", "maximum_bytes",
    }, "captured fixed receipt inventory")
    require(type(inventory["files"]) is dict and len(inventory["files"]) <= MAX_OUTPUT_FILES,
            "captured fixed receipt inventory exceeds its finite file count")
    output_root = _captured_origin_path(overlay["output_root"], "captured fixed output origin")
    origins = bootstrap_origins | {
        str(output_root / _safe_relative(name, "captured fixed inventory name"))
        for name in inventory["files"]
    }
    require(origins <= references.keys(), "capture omits an exact fixed inventory member")
    require(not any(
        (candidate := _captured_origin_path(origin, "whole-job capture origin")) == output_root or
        (output_root in candidate.parents and origin not in origins)
        for origin in references
    ), "whole-job capture contains an undeclared member under the fixed output root")
    # A whole-job read view may additionally contain unrelated ProbeV2 objects.
    # Only the genuine strict receipt's exact fixed subset enters this view.
    view = CapturedFixedPairArtifactsV1(
        {origin: references[origin] for origin in origins}, stage_root,
    )
    view.bind_output_inventory(overlay, receipt, host_pin["path"])
    return {"schema": CAPTURED_REPLAY_CONTEXT_SCHEMA_V1,
            "artifact_view": view, "overlay": overlay,
            "execution_receipt": receipt, "host_verification_receipt": host,
            "host_verification_pin": dict(host_pin), "offline_facts": facts,
            "envelope_verified": True, "full_replay_verified": False,
            "qualification_eligible": False}


def verify_fixed_pair_overlay_captured_v1(
    overlay_pin: object, receipt_pin: object, host_verification_pin: object,
    references: object, stage_root: Path,
) -> dict[str, Any]:
    """Replay exact captured bytes using genuine original strict-host facts.

    The caller authenticates references against its signed archive manifest.
    Resident immutable Source/Spec/Plan/binaries/oracles and the retained empty
    owned TMP directories are verified independently. The original component
    verification projection remains byte-for-byte compatible with live replay.
    """
    prepared = prepare_captured_fixed_pair_replay_v1(
        overlay_pin, receipt_pin, host_verification_pin, references, stage_root,
    )
    view = prepared["artifact_view"]
    verification = _verify_fixed_pair_overlay_replay(
        overlay_pin, receipt_pin, prepared["offline_facts"], artifact_view=view,
    )
    return {"schema": CAPTURED_REPLAY_CONTEXT_SCHEMA_V1,
            "verification": verification, "overlay": prepared["overlay"],
            "execution_receipt": prepared["execution_receipt"],
            "host_verification_pin": prepared["host_verification_pin"],
            "full_replay_verified": True, "qualification_eligible": False}


def _load_cli_input(path: Path, label: str) -> dict[str, Any]:
    raw, _checksum, _info = read_stable(path, label, MAX_PLAN_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixedPairError(f"{label} is not bounded JSON: {error}") from error
    require(type(value) is dict, f"{label} must be one JSON object")
    return value


def _cli_event_callbacks(root: Path) -> tuple[Callable[[dict[str, Any]], None], Callable[[dict[str, Any]], None], Callable[[], None]]:
    path = root / "app-events.jsonl"
    descriptor: list[int | None] = [None]

    def append(event: dict[str, Any]) -> None:
        if descriptor[0] is None:
            require(not path.exists() and not path.is_symlink(), "fixed-pair lifecycle event journal already exists")
            descriptor[0] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        raw = canonical_bytes(event)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor[0], raw[offset:])
            require(count > 0, "short write to fixed-pair lifecycle event journal")
            offset += count
        os.fsync(descriptor[0])

    def close() -> None:
        if descriptor[0] is not None:
            os.close(descriptor[0])
            descriptor[0] = None

    return append, append, close


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="verify SourceV5/SpecV3/PlanV3 pins and write an immutable fixed-pair overlay")
    build.add_argument("--input", required=True, type=Path)
    launch = commands.add_parser("launch", help="launch the exact fixed APP pair described by a pinned overlay")
    launch.add_argument("--overlay", required=True, type=Path)
    launch.add_argument("--sha256", required=True)
    verify = commands.add_parser("verify", help="independently replay a fixed-pair overlay and execution receipt")
    verify.add_argument("--overlay", required=True, type=Path)
    verify.add_argument("--overlay-sha256", required=True)
    verify.add_argument("--receipt", required=True, type=Path)
    verify.add_argument("--receipt-sha256", required=True)
    verify.add_argument("--host-verification-receipt", type=Path)
    offline = commands.add_parser("verify-offline", help="replay a peer fixed pair using its strict host receipt and identity path map")
    offline.add_argument("--overlay", required=True, type=Path)
    offline.add_argument("--overlay-sha256", required=True)
    offline.add_argument("--receipt", required=True, type=Path)
    offline.add_argument("--receipt-sha256", required=True)
    offline.add_argument("--host-verification-receipt", required=True, type=Path)
    offline.add_argument("--host-verification-raw-sha256", required=True)
    offline.add_argument("--host-verification-sha256", required=True)
    offline.add_argument("--evidence-path-map", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            body = _load_cli_input(args.input, "fixed-pair build input")
            exact(body, {"original_pins", "execution_pins", "exact_job", "observed_host_pin", "output_root"}, "fixed-pair build input")
            result = build_fixed_pair_overlay(
                body["original_pins"], body["execution_pins"], body["exact_job"],
                body["observed_host_pin"], body["output_root"],
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "launch":
            overlay_pin = {"path": str(args.overlay.resolve(strict=True)), "sha256": args.sha256}
            overlay, _raw, _sha, _context, _value = _read_overlay(overlay_pin)
            started, terminal, close = _cli_event_callbacks(Path(overlay["output_root"]))
            try:
                receipt_pin = run_fixed_pair_overlay(overlay_pin, started, terminal)
            finally:
                close()
            outcome = verify_fixed_pair_overlay(overlay_pin, receipt_pin)
            print(json.dumps({**outcome, "receipt_pin": receipt_pin}, sort_keys=True, separators=(",", ":")))
            return 0 if outcome["status"] == "valid_pair" else 1
        overlay_pin = {"path": str(args.overlay.resolve(strict=True)), "sha256": args.overlay_sha256}
        receipt_pin = {"path": str(args.receipt.resolve(strict=True)), "sha256": args.receipt_sha256}
        if args.command == "verify-offline":
            evidence_map_path = args.evidence_path_map.resolve(strict=True)
            evidence_path_map = _load_cli_input(evidence_map_path, "fixed-pair evidence path map")
            evidence_map_raw, _evidence_map_sha, _evidence_map_info = read_stable(
                evidence_map_path, "fixed-pair evidence path map", MAX_MANIFEST_BYTES,
            )
            require(evidence_map_raw == canonical_bytes(evidence_path_map),
                    "fixed-pair evidence path map must be canonical JSON")
            outcome = verify_fixed_pair_overlay_offline(
                overlay_pin, receipt_pin,
                {
                    "path": str(args.host_verification_receipt.resolve(strict=True)),
                    "raw_sha256": args.host_verification_raw_sha256,
                    "host_verification_sha256": args.host_verification_sha256,
                },
                evidence_path_map,
            )
            print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
            return 0 if outcome["status"] == "valid_pair" else 1
        if args.host_verification_receipt is not None:
            outcome = verify_fixed_pair_overlay_with_host_receipt(
                overlay_pin, receipt_pin, args.host_verification_receipt,
            )
            print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
            return 0 if outcome["status"] == "valid_pair" else 1
        outcome = verify_fixed_pair_overlay(overlay_pin, receipt_pin)
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
        return 0 if outcome["status"] == "valid_pair" else 1
    except (FixedPairError, OSError, TypeError, ValueError, KeyError) as error:
        parser.exit(1, f"application-fixed-pair refused: {error}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
