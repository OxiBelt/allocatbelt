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
    "allocatbelt.application-source5-campaign-execution.v5",
}
TWO_KVM_QUALIFICATION_PROFILE = "two_kvm_hosts_v1"
SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE = \
    "source5_prepared_exploration_reuse_v1"
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
MAX_ARCHIVE_JSON_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_READ_METADATA_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 1 << 48
ARCHIVE_ESCAPED_MAX_PATH = "/" + "\u00e9" * ((MAX_PATH_BYTES - 1) // 2)
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
FIXED_CHECKPOINT_REQUEST_SCHEMA_V3 = (
    "allocatbelt.application-source5-evidence-checkpoint-request.v3"
)
FIXED_CHECKPOINT_SCHEMA_V3 = (
    "allocatbelt.application-source5-evidence-job-checkpoint.v3"
)
SUCCESS_EMPTY_TMP_TREE_ROLES = frozenset({"normal_app_output"})
ARCHIVE_SIGNATURE_QUOTA_BYTES = 4096
ACK_BUNDLE_ALTERNATIVE_ROLES = frozenset({
    "source5_ack_bundle", "source5_ack_bundle_incoming",
})
TRANSIENT_JOB_EVIDENCE_ROLES = frozenset({
    "source5_transfer_packet", *ACK_BUNDLE_ALTERNATIVE_ROLES,
})
SOURCE5_ARCHIVE_READ_CONTROL_ROLE = "source5_archive_read_control_ledger"
SOURCE5_ANALYZER_SPOOL_ROLE = "source5_analyzer_spool"
SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES = frozenset({
    "source5_archive_read_request_slot",
    "source5_archive_read_response_slot",
    "source5_archive_read_response_incoming",
    "source5_archive_read_bundle",
    "source5_archive_read_bundle_incoming",
    "source5_archive_read_stage",
})
SOURCE5_NON_INDEX_TRANSIENT_ROLES = frozenset({
    *SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES,
    SOURCE5_ANALYZER_SPOOL_ROLE,
})
SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES = frozenset({
    "source5_archive_read_response_slot",
    "source5_archive_read_response_incoming",
})
SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES = frozenset({
    "source5_archive_read_bundle",
    "source5_archive_read_bundle_incoming",
})
SOURCE5_CLEANUP_SIDECAR_ROLE = "source5_cleanup_sidecar"
SOURCE5_CLEANUP_SIDECAR_REFUSAL_ROLE = "source5_cleanup_sidecar_refusal"
SOURCE5_CLEANUP_ERROR_TEXT_BYTES = 8192
SOURCE5_CLEANUP_SIGNAL_SNAPSHOT_COUNT = 5
SOURCE5_CLEANUP_ERROR_ENTRY_COUNT = 1348
SOURCE5_CLEANUP_REFUSAL_BYTES = 65_536
SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT = 262_144
SOURCE5_CLEANUP_TERM_GRACE_SECONDS = 3.0
SOURCE5_CLEANUP_KILL_REAP_SECONDS = 1.0
SOURCE5_CLEANUP_POLL_INTERVAL_SECONDS = 0.01
CLEANUP_SIDECAR_ALTERNATIVE_ROLES = frozenset({
    SOURCE5_CLEANUP_SIDECAR_ROLE,
    SOURCE5_CLEANUP_SIDECAR_REFUSAL_ROLE,
})
FAILURE_WINDOW_ONLY_ROLES = frozenset({
    "source5_job_disposition", *CLEANUP_SIDECAR_ALTERNATIVE_ROLES,
})
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
HOST_BUDGET_SCHEMA_V3 = "allocatbelt.application-source5-host-evidence-budget.v3"
HOST_BUDGET_SCHEMA_V4 = "allocatbelt.application-source5-host-evidence-budget.v4"
PREPARATORY_BUDGET_SCHEMA = (
    "allocatbelt.application-source5-preparatory-exploration-budget.v1"
)
PREPARATORY_EXECUTION_SCHEMA = (
    "allocatbelt.application-source5-preparatory-exploration-execution.v1"
)
EXECUTION_SCHEMA_V5 = "allocatbelt.application-source5-campaign-execution.v5"
SOURCE5_V3_ADMISSION_PROFILE = "source5_width_v4_captured_replay_v1"
SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2 = \
    "allocatbelt.application-source5-journal-width-contract.v2"
STORAGE_RESERVATION_SCHEMA_V1 = "allocatbelt.application-source5-evidence-storage-reservation.v1"
JOURNAL_WIDTH_CONTRACT_SCHEMA = \
    "allocatbelt.application-source5-journal-width-contract.v1"
MAX_JOURNAL_WIDTH_CONTRACT_BYTES = 16 * 1024 * 1024


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


def _cleanup_sidecar_source_bound(maximum_session_members: int) -> int:
    """Compute a raw cleanup-object bound without materializing huge arrays."""
    _uint(maximum_session_members,
          "Source5 cleanup session-member source bound", positive=True)
    normal_polls = int((SOURCE5_CLEANUP_TERM_GRACE_SECONDS +
                        SOURCE5_CLEANUP_KILL_REAP_SECONDS) /
                       SOURCE5_CLEANUP_POLL_INTERVAL_SECONDS) + 4
    emergency_polls = int(SOURCE5_CLEANUP_KILL_REAP_SECONDS /
                          SOURCE5_CLEANUP_POLL_INTERVAL_SECONDS) + 4
    _require(3 * normal_polls + emergency_polls + 32 ==
             SOURCE5_CLEANUP_ERROR_ENTRY_COUNT,
             "Source5 cleanup error-entry contract differs from the fixed-owner bounded poll formula")
    maximum_u64 = MAX_U64
    maximum_pid = (1 << 31) - 1
    error_text = "\x01" * SOURCE5_CLEANUP_ERROR_TEXT_BYTES

    def array_bytes(item_bytes: int, count: int) -> int:
        return 2 + item_bytes * count + max(0, count - 1)

    member = {
        "pid": maximum_pid, "state": "Z",
        "parent_pid": maximum_pid, "process_group": maximum_pid,
        "session_id": maximum_pid, "start_ticks": maximum_u64,
    }
    pidfd_signal = {
        "pid": maximum_pid, "start_ticks": maximum_u64,
        "signal": 255, "sent": False,
    }
    signal_row = {
        "group_signal": {
            "signal": 255, "leader_pid": maximum_pid,
            "leader_start_ticks": maximum_u64, "leader_unreaped": True,
        },
        "group_error": error_text, "pidfd_signals": [],
        "scan_error": error_text, "members": [],
    }
    signal_row_bytes = len(_canonical(signal_row)) - 1
    signal_row_bytes += (
        array_bytes(len(_canonical(pidfd_signal)) - 1,
                    maximum_session_members) - 2
    )
    signal_row_bytes += (
        array_bytes(len(_canonical(member)) - 1,
                    maximum_session_members) - 2
    )
    cleanup = {
        "leader_info": {"si_code": 255, "si_status": 255,
                        "si_pid": maximum_pid},
        "child_return_code": -255, "timed_out": False,
        "artifact_budget_exceeded": False, "received_signal": None,
        "term_grace_seconds": SOURCE5_CLEANUP_TERM_GRACE_SECONDS,
        "kill_reap_seconds": SOURCE5_CLEANUP_KILL_REAP_SECONDS,
        "signals": [], "leader_unreaped_during_group_signals": False,
        "group_signal_after_leader_reap_count":
            SOURCE5_CLEANUP_SIGNAL_SNAPSHOT_COUNT,
        "leader_reaped": False, "remaining_session_members": [],
        "cleanup_errors": [], "cleanup_status": "not_started",
    }
    result = len(_canonical(cleanup)) - 1
    result += array_bytes(signal_row_bytes,
                          SOURCE5_CLEANUP_SIGNAL_SNAPSHOT_COUNT) - 2
    result += array_bytes(len(_canonical(member)) - 1,
                          maximum_session_members) - 2
    result += array_bytes(len(_canonical(error_text)) - 1,
                          SOURCE5_CLEANUP_ERROR_ENTRY_COUNT) - 2
    return result + 1  # canonical trailing LF


def _cleanup_source_shape(maximum_session_members: int) -> dict[str, Any]:
    source_bytes = _cleanup_sidecar_source_bound(maximum_session_members)
    refusal_window = 2 * SOURCE5_CLEANUP_REFUSAL_BYTES
    return {
        "maximum_session_members_per_snapshot": maximum_session_members,
        "maximum_pidfd_signal_entries_per_snapshot": maximum_session_members,
        "maximum_signal_snapshots": SOURCE5_CLEANUP_SIGNAL_SNAPSHOT_COUNT,
        "maximum_cleanup_errors": SOURCE5_CLEANUP_ERROR_ENTRY_COUNT,
        "maximum_error_text_bytes": SOURCE5_CLEANUP_ERROR_TEXT_BYTES,
        "normal_cleanup_poll_count": int((
            SOURCE5_CLEANUP_TERM_GRACE_SECONDS +
            SOURCE5_CLEANUP_KILL_REAP_SECONDS
        ) / SOURCE5_CLEANUP_POLL_INTERVAL_SECONDS) + 4,
        "emergency_cleanup_poll_count": int(
            SOURCE5_CLEANUP_KILL_REAP_SECONDS /
            SOURCE5_CLEANUP_POLL_INTERVAL_SECONDS
        ) + 4,
        "term_grace_seconds": SOURCE5_CLEANUP_TERM_GRACE_SECONDS,
        "kill_reap_seconds": SOURCE5_CLEANUP_KILL_REAP_SECONDS,
        "cleanup_poll_interval_seconds": SOURCE5_CLEANUP_POLL_INTERVAL_SECONDS,
        "source_maximum_bytes": source_bytes,
        "admission_maximum_bytes": source_bytes,
        "maximum_window_bytes": 2 * source_bytes,
        "refusal_file_bytes": SOURCE5_CLEANUP_REFUSAL_BYTES,
        "maximum_refusal_window_bytes": refusal_window,
    }


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


def _validated_spec_host_ids(spec: dict[str, Any]) -> list[str]:
    """Bind the explicit profile and venue matrix before deriving host maps."""
    _require(type(spec) is dict and spec.get("schema") == SPEC_SCHEMA,
             "host matrix requires the original SpecV3")
    if "qualification_profile" in spec:
        _require(type(spec["qualification_profile"]) is str and
                 spec["qualification_profile"] == TWO_KVM_QUALIFICATION_PROFILE,
                 "SpecV3 qualification profile is unknown")
        expected_count = 2
    else:
        expected_count = 3
    hosts = spec.get("hosts")
    _require(type(hosts) is list and len(hosts) == expected_count and
             all(type(host) is dict for host in hosts),
             "SpecV3 host rows do not match the selected qualification profile")
    host_ids = [_token(host.get("host_id"), "SpecV3 host ID") for host in hosts]
    venues = [host.get("venue") for host in hosts]
    _require(len(set(host_ids)) == expected_count and
             ((expected_count == 2 and venues == ["kvm_guest", "kvm_guest"]) or
              (expected_count == 3 and venues.count("bare_metal") == 1 and
               venues.count("kvm_guest") == 2)),
             "SpecV3 host IDs or profile venue matrix differs")
    return host_ids


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


def _raw_origin_pin(value: Any, label: str) -> dict[str, str]:
    """Validate the exact two-field raw pin used by captured lineage reads."""
    pin = _exact(value, {"path", "raw_sha256"}, label)
    path = pin["path"]
    _require(type(path) is str and path.startswith("/") and
             len(path.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             PurePosixPath(path).as_posix() == path and
             ".." not in PurePosixPath(path).parts and
             "." not in PurePosixPath(path).parts and path != "/" and
             not path.endswith("/") and "\\" not in path and "\x00" not in path,
             f"{label} path is not a normalized absolute origin")
    _digest(pin["raw_sha256"], f"{label} raw SHA-256")
    return pin


def _prepared_lineage_catalogue_role_matches(
    expected_role: str, actual_role: str,
) -> bool:
    """Allow only the exact old-to-current role projections used by V5."""
    if expected_role == "evidence_index":
        return actual_role in {"preparation", "evidence_index"}
    if expected_role == "fixed_spec_host":
        return actual_role == "observed_host"
    if expected_role == "journal_width_contract":
        return actual_role in {
            "journal_width_contract",
            "preparatory_journal_width_contract",
        }
    return actual_role == expected_role


def _prepared_lineage_catalogue_rows_for_host(
    expected_rows: dict[str, dict[str, Any]], host_id: str,
) -> dict[str, dict[str, Any]]:
    """Select origins expected in this old catalogue, apart from storage host."""
    return {
        path: row for path, row in expected_rows.items()
        if row["role"] != "source5_job_row_catalogue" and
        host_id in row["catalogue_hosts"]
    }


def _source5_indexed_raw_pin_projection(value: object, label: str) -> dict[str, str]:
    """Validate a Source-issued raw, semantic, or signer pin for indexed binding."""
    allowed = {"path", "raw_sha256", "semantic_sha256", "signer_fingerprint"}
    _require(type(value) is dict and {"path", "raw_sha256"} <= set(value) and
             set(value) <= allowed,
             f"{label} contains unknown fields or lacks its raw pin")
    pin = _raw_origin_pin({
        "path": value["path"], "raw_sha256": value["raw_sha256"],
    }, label)
    if "semantic_sha256" in value:
        _digest(value["semantic_sha256"], f"{label} semantic digest")
    if "signer_fingerprint" in value:
        _require(type(value["signer_fingerprint"]) is str and
                 re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}",
                              value["signer_fingerprint"]) is not None,
                 f"{label} signer fingerprint is malformed")
    return pin


def source5_indexed_reservation_binding_v1(
    index_row: object, pin_value: object, role: str, job: object, *,
    initial_output_root: str, campaign_id: str, selected_host: str,
    old_rows: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], dict[str, Any]]:
    """Join one validated Source5 index pin to its exact old reservation row.

    Durable ACK/signature paths remain their raw origin identity. Only their
    old-catalogue lookup uses the exact host-local H6 reservation leaf.
    """
    roles = {
        "source5_job_record", "source5_checkpoint_request",
        "source5_checkpoint", "source5_object_manifest",
        "source5_archive_ack", "source5_archive_signature",
    }
    _require(role in roles, "prepared capture indexed role is unsupported")
    _require(type(index_row) is dict and type(job) is dict and
             job.get("phase") == "exploration" and
             job.get("host_id") == selected_host,
             "prepared capture indexed reservation job join is malformed")
    run_id = _token(job.get("run_id"), "prepared capture indexed run ID")
    ordinal = _uint(job.get("ordinal"),
                    "prepared capture indexed job ordinal", positive=True)
    job_sha = _digest(index_row.get("job_sha256"),
                      "prepared capture indexed job digest")
    _require(type(initial_output_root) is str and
             initial_output_root.startswith("/") and
             PurePosixPath(initial_output_root).as_posix() == initial_output_root and
             "\\" not in initial_output_root and "\x00" not in initial_output_root and
             ".." not in PurePosixPath(initial_output_root).parts and
             "." not in PurePosixPath(initial_output_root).parts and
             not initial_output_root.endswith("/"),
             "prepared capture initial output root is not normalized")
    campaign_id = _token(campaign_id, "prepared capture campaign ID")
    selected_host = _token(selected_host, "prepared capture selected host ID")
    pin = _source5_indexed_raw_pin_projection(
        pin_value, f"prepared capture indexed {role} origin pin",
    )
    leaf = f"{ordinal:06d}-{job_sha}"
    metadata_root = str(PurePosixPath(initial_output_root) / campaign_id /
                        "chronology" / selected_host /
                        "evidence-checkpoints" / "exploration")
    if role == "source5_job_record":
        reservation_path = str(
            PurePosixPath(initial_output_root) / campaign_id / "source5" /
            selected_host / "exploration" / "job-records" / f"{run_id}.json",
        )
        _require(pin["path"] == reservation_path,
                 "prepared capture job-record pin differs from its canonical H6 path")
    else:
        suffixes = {
            "source5_checkpoint_request": f"{leaf}.request.json",
            "source5_checkpoint": f"{leaf}.checkpoint.json",
            "source5_object_manifest": f"{leaf}.object-manifest.json",
            "source5_archive_ack": f"{leaf}.ack.json",
            "source5_archive_signature": f"{leaf}.ack.sig",
        }
        reservation_path = str(PurePosixPath(metadata_root) / suffixes[role])
        if role in {"source5_archive_ack", "source5_archive_signature"}:
            archive = index_row.get("archive_pins")
            _require(type(archive) is dict,
                     "prepared capture indexed ACK/signature pins are malformed")
            ack = _source5_indexed_raw_pin_projection(
                archive.get("ack_pin"), "prepared capture durable ACK pin",
            )
            signature = _source5_indexed_raw_pin_projection(
                archive.get("signature_pin"),
                "prepared capture durable signature pin",
            )
            ack_path = PurePosixPath(ack["path"])
            signature_path = PurePosixPath(signature["path"])
            _require(ack_path.name == f"{leaf}.json" and
                     ack_path.parent.name == "exploration" and
                     ack_path.parent.parent.name == "acks" and
                     signature_path.name == f"{leaf}.sig" and
                     signature_path.parent.name == "exploration" and
                     signature_path.parent.parent.name == "signatures" and
                     signature_path.parent.parent.parent.name == "acks" and
                     ack_path.parent.parent == signature_path.parent.parent.parent,
                     "prepared capture durable ACK/signature leaf or Root hierarchy differs")
            expected_durable_pin = (
                ack if role == "source5_archive_ack" else signature
            )
            _require(pin == expected_durable_pin,
                     f"prepared capture indexed {role} identity differs from its durable pin")
        else:
            _require(pin["path"] == reservation_path,
                     f"prepared capture indexed {role} pin differs from its canonical H6 path")

    row = old_rows.get(reservation_path)
    _require(type(row) is dict and row.get("kind") == "file" and
             row.get("path") == reservation_path and row.get("role") == role and
             row.get("host_id") == selected_host and
             row.get("phase") == "exploration" and
             row.get("run_id") == run_id and
             type(row.get("max_file_bytes")) is int and
             row["max_file_bytes"] > 0,
             f"prepared capture {role} differs from its exact old Source reservation")
    origin = row.get("origin_pin")
    if origin is not None:
        origin = _exact(origin, {"raw_sha256", "semantic_sha256"},
                        f"prepared capture {role} old Source origin")
        _digest(origin["raw_sha256"],
                f"prepared capture {role} old Source raw origin")
        _require(origin["raw_sha256"] == pin["raw_sha256"] and
                 (type(pin_value) is not dict or
                  "semantic_sha256" not in pin_value or
                  origin["semantic_sha256"] is None or
                  origin["semantic_sha256"] == pin_value["semantic_sha256"]),
                 f"prepared capture {role} differs from its old Source origin pin")
    return pin, row


def source5_preparatory_shared_originals_v1(
    cohort_values: object,
) -> dict[str, Any]:
    """Verify the exact shared SourceH preparation/generation inputs for a cohort."""
    _require(type(cohort_values) is list and len(cohort_values) in (2, 3),
             "prepared capture shared SourceH inputs require the exact host cohort")
    host_ids = []
    shared_by_host = {}
    execution_host_orders = []
    for index, value in enumerate(cohort_values):
        item = _exact(value, {
            "host_id", "original_pins", "execution_manifest", "header",
        }, f"prepared capture shared SourceH cohort input[{index}]")
        host = _token(item["host_id"],
                      f"prepared capture shared SourceH host[{index}]")
        _require(host not in host_ids,
                 "prepared capture shared SourceH cohort repeats a host")
        host_ids.append(host)
        original = _exact(item["original_pins"], {
            "preparation", "capacity_generation", "initial_spec", "initial_plan",
            "source_manifests", "observed_hosts", "typed_modules",
            "archive_signer_context", "capacity_registration",
            "execution_basis_sha256",
        }, f"prepared capture {host} SourceH original pins")
        preparation_pin = _raw_origin_pin(
            original["preparation"],
            f"prepared capture {host} original preparation pin",
        )
        capacity_generation = _exact(original["capacity_generation"], {
            "path", "raw_sha256", "semantic_sha256", "provenance",
        }, f"prepared capture {host} original capacity-generation pin")
        generation_pin = _pin({key: capacity_generation[key] for key in (
            "path", "raw_sha256", "semantic_sha256",
        )}, f"prepared capture {host} original capacity-generation pin")
        generation_provenance = _exact(capacity_generation["provenance"], {
            "schema", "preparation_pin", "initial_spec_pin", "initial_plan_pin",
        }, f"prepared capture {host} original capacity-generation provenance")
        execution_manifest = item["execution_manifest"]
        _require(type(execution_manifest) is dict and
                 execution_manifest.get("schema") == PREPARATORY_EXECUTION_SCHEMA and
                 execution_manifest.get("host_id") == host and
                 type(execution_manifest.get("campaign_id")) is str,
                 f"prepared capture {host} SourceH execution manifest is malformed")
        execution_hosts = execution_manifest.get("hosts")
        _require(type(execution_hosts) is list and len(execution_hosts) ==
                 len(cohort_values),
                 f"prepared capture {host} execution host cohort is malformed")
        execution_hosts = [
            _token(peer_host,
                   f"prepared capture {host} execution host[{peer_index}]")
            for peer_index, peer_host in enumerate(execution_hosts)
        ]
        _require(len(set(execution_hosts)) == len(execution_hosts) and
                 host in execution_hosts,
                 f"prepared capture {host} execution host cohort is malformed")
        execution_host_orders.append(execution_hosts)
        manifest_generation = _exact(
            execution_manifest.get("preparatory_capacity_generation"),
            {"completion", "provenance"},
            f"prepared capture {host} execution capacity generation",
        )
        manifest_generation_pin = _pin(
            manifest_generation["completion"],
            f"prepared capture {host} execution capacity-generation pin",
        )
        provenance_preparation_pin = _raw_origin_pin(
            generation_provenance["preparation_pin"],
            f"prepared capture {host} generation preparation provenance pin",
        )
        _require(generation_provenance["schema"] ==
                 "allocatbelt.application-source5-preparatory-capacity-provenance.v1" and
                 generation_pin == manifest_generation_pin and
                 generation_provenance == manifest_generation["provenance"] and
                 preparation_pin == provenance_preparation_pin,
                 f"prepared capture {host} SourceH preparation/generation join differs")
        header = item["header"]
        _require(type(header) is dict and header.get("host_id") == host and
                 header.get("campaign_id") == execution_manifest["campaign_id"] and
                 type(header.get("initial")) is dict and
                 header["initial"].get("capacity_generation_sha256") ==
                    generation_pin["semantic_sha256"],
                 f"prepared capture {host} header generation identity differs")
        source_rows = header["initial"].get("source_manifest_pins")
        _require(type(source_rows) is list and
                 [row.get("host_id") for row in source_rows if type(row) is dict] ==
                    execution_hosts,
                 f"prepared capture {host} header Source cohort order differs")
        for original_name, header_name, provenance_name in (
            ("initial_spec", "spec_pin", "initial_spec_pin"),
            ("initial_plan", "plan_pin", "initial_plan_pin"),
        ):
            original_pin = _pin(
                original[original_name],
                f"prepared capture {host} original {original_name} pin",
            )
            provenance_pin = _raw_origin_pin(
                generation_provenance[provenance_name],
                f"prepared capture {host} generation {provenance_name}",
            )
            header_pin = _pin(
                header["initial"][header_name],
                f"prepared capture {host} header initial {original_name} pin",
            )
            _require({key: original_pin[key] for key in ("path", "raw_sha256")} ==
                     provenance_pin and original_pin == header_pin,
                     f"prepared capture {host} generation {provenance_name} differs")
        shared_by_host[host] = {
            "preparation": preparation_pin,
            "capacity_generation": {
                **generation_pin, "provenance": generation_provenance,
            },
        }
    shared_values = list(shared_by_host.values())
    shared = shared_values[0]
    _require(all(order == execution_host_orders[0]
                 for order in execution_host_orders[1:]) and
             execution_host_orders[0] == host_ids and
             all(value == shared for value in shared_values[1:]),
             "prepared capture shared SourceH preparation/generation pins differ across the cohort")
    return shared


def _source5_prepared_lineage_indexed_rows_v4(
    expected_rows: dict[str, dict[str, Any]],
    index_rows: list[dict[str, Any]], old_rows: dict[str, dict[str, Any]], *,
    initial_output_root: str, campaign_id: str, selected_host: str,
) -> dict[str, dict[str, Any]]:
    """Re-key durable indexed pins to exact old H6 reservation paths for V4."""
    _require(type(expected_rows) is dict and type(index_rows) is list and
             len(index_rows) == 360 and type(old_rows) is dict,
             "Source5 v4 indexed old-reservation inputs are malformed")
    needed = _prepared_lineage_catalogue_rows_for_host(
        expected_rows, selected_host,
    )
    phase_roles = {
        "source5_job_record", "source5_checkpoint_request",
        "source5_checkpoint", "source5_object_manifest",
        "source5_archive_ack", "source5_archive_signature",
    }
    for row_index, index_row in enumerate(index_rows):
        _require(type(index_row) is dict and
                 index_row.get("row_index") == row_index and
                 type(index_row.get("job")) is dict,
                 f"Source5 v4 indexed row[{row_index}] is malformed")
        job = index_row["job"]
        _require(job.get("host_id") == selected_host and
                 job.get("phase") == "exploration" and
                 index_row.get("job_sha256") == _sha(_canonical(job)),
                 f"Source5 v4 indexed row[{row_index}] changed its exact job join")
        archive = _exact(index_row.get("archive_pins"), {
            "request_pin", "checkpoint_pin", "object_manifest_pin",
            "ack_pin", "signature_pin",
        }, f"Source5 v4 indexed row[{row_index}] archive pins")
        entries = (
            (index_row.get("job_record_pin"), "source5_job_record"),
            *((archive[name], role) for name, role in (
                ("request_pin", "source5_checkpoint_request"),
                ("checkpoint_pin", "source5_checkpoint"),
                ("object_manifest_pin", "source5_object_manifest"),
                ("ack_pin", "source5_archive_ack"),
                ("signature_pin", "source5_archive_signature"),
            )),
        )
        seen_roles = set()
        for pin_value, role in entries:
            pin, reservation = source5_indexed_reservation_binding_v1(
                index_row, pin_value, role, job,
                initial_output_root=initial_output_root,
                campaign_id=campaign_id, selected_host=selected_host,
                old_rows=old_rows,
            )
            expected = expected_rows.get(pin["path"])
            _require(role in phase_roles and role not in seen_roles and
                     type(expected) is dict and
                     expected.get("raw_sha256") == pin["raw_sha256"] and
                     expected.get("role") == role and
                     expected.get("host_id") == selected_host and
                     expected.get("phase") == "exploration" and
                     expected.get("run_id") == job["run_id"] and
                     selected_host in expected.get("catalogue_hosts", set()) and
                     type(expected.get("byte_count")) is int and
                     expected["byte_count"] > 0 and
                     reservation["max_file_bytes"] >= expected["byte_count"],
                     f"Source5 v4 indexed {role} differs from its exact captured row/cap")
            previous = needed.pop(pin["path"], None)
            _require(previous == expected,
                     f"Source5 v4 indexed {role} is absent from its selected host catalogue closure")
            reservation_path = reservation["path"]
            _require(reservation_path not in needed,
                     f"Source5 v4 indexed {role} aliases another old reservation")
            needed[reservation_path] = expected
            seen_roles.add(role)
        _require(seen_roles == phase_roles,
                 f"Source5 v4 indexed row[{row_index}] omits an exact reservation role")
    return needed


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
    host_ids = _validated_spec_host_ids(spec)
    _require(host_id in host_ids and
             plan.get("host_ids") == host_ids and
             execution_manifest.get("hosts") == host_ids and
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

    prepared_reuse = execution_manifest.get("schema") == \
        "allocatbelt.application-source5-campaign-execution.v5"
    pin_fields = {
        "spec", "plan", "execution_manifest", "source_manifests",
    } | ({"prepared_exploration"} if prepared_reuse else set())
    pins = _exact(pins_value, pin_fields, "original budget pins")
    spec_pin = _pin(pins["spec"], "original SpecV3 pin")
    plan_pin = _pin(pins["plan"], "original PlanV3 pin")
    execution_pin = _pin(pins["execution_manifest"],
                         "original execution-manifest pin")
    execution_schema = execution_manifest["schema"]
    prepared_exploration = None
    if prepared_reuse:
        prepared_exploration = _exact(
            pins["prepared_exploration"], set(host_ids),
            "prepared exploration original host pins",
        )
        for selected_host in host_ids:
            lineage = _exact(prepared_exploration[selected_host], {
                "bridge_header", "record_index",
            }, f"prepared exploration {selected_host} raw pins")
            for role in ("bridge_header", "record_index"):
                pin = _exact(lineage[role], {"path", "raw_sha256"},
                             f"prepared exploration {selected_host} {role} pin")
                _require(type(pin["path"]) is str and pin["path"].startswith("/"),
                         f"prepared exploration {selected_host} {role} path is malformed")
                _digest(pin["raw_sha256"],
                        f"prepared exploration {selected_host} {role} raw digest")
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
    if prepared_reuse:
        current_paired_jobs = counts["aa"] + counts["confirmation"] + counts["pressure"]
        maximum_callbacks = 1 + 6 + 6 * current_paired_jobs + 4 * counts["soak"]
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
            **({"prepared_exploration": prepared_exploration}
               if prepared_reuse else {}),
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


def _archive_empty_tmp_proof_bounds(
    phase: str, *, archive_v2: bool, fixed_v3: bool = False,
) -> list[dict[str, Any]]:
    maximum_path = ARCHIVE_ESCAPED_MAX_PATH
    base = [{
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
    if fixed_v3:
        _require(phase in {"exploration", "aa", "confirmation"},
                 "fixed checkpoint v3 proofs are limited to original fixed phases")
        probe = [{**item, "domain": "probe_tmpdir"} for item in base]
        return sorted([*base, *probe],
                      key=lambda item: (item["role"],
                                        item["member_ordinal"],
                                        item.get("domain", "")))
    if not archive_v2:
        return base
    if phase in {"exploration", "aa", "confirmation"}:
        probe = [{**item, "domain": "probe_tmpdir"} for item in base]
        return sorted([*base, *probe],
                      key=lambda item: (item["role"],
                                        item["member_ordinal"],
                                        item.get("domain", "")))
    if phase == "pressure":
        return base
    if phase == "soak":
        return [{
            "role": "x" * 96, "path": maximum_path,
            "owner_receipt_pin": {
                "path": maximum_path, "raw_sha256": "f" * 64,
                "semantic_sha256": "f" * 64,
            },
            "member_ordinal": 0, "domain": "application_tmpdir",
            "bytes_used": 0, "inode_count": 0,
            "inventory_sha256": "f" * 64,
        }]
    raise BudgetPlanError("archive TMP proof phase is outside the original Source5 schedule")


def _archive_fixed_request_value(
    phase: str, receipt_roles: Iterable[str], *, archive_v2: bool = False,
    tree_inventory_count: int = 0, fixed_v3: bool = False,
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
    body = {
        "schema": (FIXED_CHECKPOINT_REQUEST_SCHEMA_V3 if fixed_v3 else
                   "allocatbelt.application-source5-evidence-checkpoint-request.v2"
                   if archive_v2 else
                   "allocatbelt.application-source5-evidence-checkpoint-request.v1"),
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
        "empty_tmp_proofs": _archive_empty_tmp_proof_bounds(
            phase, archive_v2=archive_v2, fixed_v3=fixed_v3,
        ),
        "entries": [], "request_sha256": "f" * 64,
    }
    if archive_v2 and not fixed_v3:
        body["tree_inventories"] = []
    return body


def _archive_fixed_request_bound(
    phase: str, receipt_roles: Iterable[str], *, archive_v2: bool = False,
    tree_inventory_bytes: int = 0, tree_inventory_count: int = 0,
    fixed_v3: bool = False,
) -> int:
    _require(archive_v2 or fixed_v3 or
             (tree_inventory_bytes == 0 and tree_inventory_count == 0),
             "Source5 v1 request cannot carry typed tree inventory rows")
    body_bytes = len(_canonical(_archive_fixed_request_value(
        phase, receipt_roles, archive_v2=archive_v2,
        tree_inventory_count=tree_inventory_count,
        fixed_v3=fixed_v3,
    )))
    return (body_bytes + (0 if fixed_v3 else tree_inventory_bytes) +
            (0 if fixed_v3 else max(0, tree_inventory_count - 1)))


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


def _archive_dynamic_tree_file_bounds(
    tree: dict[str, Any],
) -> tuple[bytes, bytes, bytes, int, int, int]:
    """Bound every possible ProbeV2 file descendant from its exact owner caps."""
    child_count = tree["max_inodes"] - 1
    maximum_object = tree["max_file_bytes"]
    row = {
        "path": ARCHIVE_ESCAPED_MAX_PATH,
        "role": "opaque_trace",
        "max_file_bytes": maximum_object,
    }
    request_entry = _archive_request_entry_bound(row) * child_count
    manifest_entry = _archive_manifest_entry_bound(row) * child_count
    stage_entry = _archive_stage_entry_bound(row) * child_count
    readback_descriptor = len(_canonical({
        "owner_job_sha256": "f" * 64,
        "origin_path": ARCHIVE_ESCAPED_MAX_PATH,
        "raw_sha256": "f" * 64,
        "byte_count": maximum_object,
    })) * child_count
    return (
        request_entry, manifest_entry, stage_entry,
        readback_descriptor, child_count,
        tree["max_bytes"] + child_count * 1023,
    )


def _archive_tree_inventory_entry_bound(
    tree: dict[str, Any], inventory_byte_cap: int,
) -> int:
    """Bound one v2 typed-tree proof using its pinned inventory file ceiling."""
    maximum_pin = _archive_pin_bound(ARCHIVE_ESCAPED_MAX_PATH)
    row = {
        "owner_job_sha256": "f" * 64,
        "root_path": ARCHIVE_ESCAPED_MAX_PATH,
        "role": "opaque_trace",
        "owner_receipt_pin": maximum_pin,
        "inventory_pin": maximum_pin,
        "inventory_sha256": "f" * 64,
        "entry_count": MAX_U64,
        "byte_count": MAX_U64,
        "entries": [],
    }
    return len(_canonical(row)) - 2 + inventory_byte_cap


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
    checkpoint_entry_bytes: int, manifest_entry_bytes: int, *,
    archive_v2: bool = False, tree_inventory_bytes: int = 0,
    tree_inventory_count: int = 0, fixed_v3: bool = False,
) -> dict[str, int]:
    """Bound each canonical response member and the four-file PAX envelope."""
    maximum_pin = _archive_pin_bound()
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    request_pin = maximum_pin
    checkpoint = {
        "schema": (FIXED_CHECKPOINT_SCHEMA_V3 if fixed_v3 else
                   "allocatbelt.application-source5-evidence-job-checkpoint.v2"
                   if archive_v2 else
                   "allocatbelt.application-source5-evidence-job-checkpoint.v1"),
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
        "empty_tmp_proofs": _archive_empty_tmp_proof_bounds(
            phase, archive_v2=archive_v2, fixed_v3=fixed_v3,
        ),
        "object_manifest_pin": maximum_pin,
        "entries": [], "checkpoint_sha256": "f" * 64,
    }
    if archive_v2 and not fixed_v3:
        checkpoint["tree_inventories"] = []
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
                        max(0, entry_count - 1) +
                        (0 if fixed_v3 else tree_inventory_bytes) +
                        (0 if fixed_v3 else max(0, tree_inventory_count - 1)))
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
    if row["role"] in (NON_EXPORTABLE_JOB_RECORD_ROLES |
                        FAILURE_WINDOW_ONLY_ROLES):
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
                "payload_bytes": 0,
                "readback_descriptor_bytes": 0,
                "readback_payload_bytes": 0,
                "readback_member_tar_bytes": 0,
                "readback_maximum_object_bytes": 0,
                "dynamic_tree_rows": [],
                "probe_inventory_caps": {},
                "archive_v2": False,
                "validation_record_count": 0,
                "validation_record_tar_bytes": 0,
                "receipt_roles": set(),
            })
            stats["validation_record_count"] += 1
            stats["validation_record_bytes"] = row["max_file_bytes"]
            stats["validation_record_tar_bytes"] += _archive_tar_member_size(
                row["max_file_bytes"],
            )
        elif row["role"] in CLEANUP_SIDECAR_ALTERNATIVE_ROLES:
            if row["phase"] is not None and row["run_id"] is not None:
                groups.setdefault((row["phase"], row["run_id"]), {
                    "phase": row["phase"], "file_count": 0,
                    "request_entry_bytes": 0, "manifest_entry_bytes": 0,
                    "stage_entry_bytes": 0, "packet_members_tar_bytes": 0,
                    "payload_bytes": 0, "readback_descriptor_bytes": 0,
                    "readback_payload_bytes": 0,
                    "readback_member_tar_bytes": 0,
                    "readback_maximum_object_bytes": 0,
                    "dynamic_tree_rows": [], "probe_inventory_caps": {},
                    "archive_v2": False,
                    "validation_record_count": 0,
                    "validation_record_tar_bytes": 0,
                    "validation_record_bytes": 0, "receipt_roles": set(),
                })
        return
    if (row["phase"] is None or row["run_id"] is None or
            row["role"] in (ALWAYS_LOCAL_EVIDENCE_ROLES |
                            {"journal_width_contract"}) or
            row["role"] in TRANSIENT_JOB_EVIDENCE_ROLES or
            row["role"] in ARCHIVE_LOCAL_METADATA_ROLES):
        return
    group_key = (row["phase"], row["run_id"])
    if row["kind"] == "tree":
        if row["role"] in SUCCESS_EMPTY_TMP_TREE_ROLES:
            return
        _require(row["role"] == "opaque_trace" and
                 row["max_inodes"] > 1 and row["max_bytes"] > 0 and
                 row["max_file_bytes"] > 0,
                 "Source5 archive cannot project an unsupported dynamic tree role")
        stats = groups.setdefault(group_key, {
            "phase": row["phase"], "file_count": 0,
            "request_entry_bytes": 0, "manifest_entry_bytes": 0,
            "stage_entry_bytes": 0, "packet_members_tar_bytes": 0,
            "payload_bytes": 0,
            "readback_descriptor_bytes": 0,
            "readback_payload_bytes": 0,
            "readback_member_tar_bytes": 0,
            "readback_maximum_object_bytes": 0,
            "dynamic_tree_rows": [], "probe_inventory_caps": {},
            "archive_v2": False,
            "validation_record_count": 0, "validation_record_tar_bytes": 0,
            "validation_record_bytes": 0,
            "receipt_roles": set(),
        })
        member_index = row["member_index"]
        _require((type(member_index) is int and member_index in {0, 1}) or
                 (row["phase"] == "soak" and member_index is None),
                 "Source5 dynamic ProbeV2 tree lacks its exact original member index")
        _require(not any(item["member_index"] == member_index
                         for item in stats["dynamic_tree_rows"]),
                 f"Source5 {group_key} repeats a ProbeV2 dynamic tree member")
        stats["dynamic_tree_rows"].append({
            "path": row["path"], "member_index": member_index,
            "max_bytes": row["max_bytes"],
            "max_file_bytes": row["max_file_bytes"],
            "max_inodes": row["max_inodes"],
        })
        stats["archive_v2"] = True
        return
    if row["kind"] != "file":
        return
    stats = groups.setdefault(group_key, {
        "phase": row["phase"], "file_count": 0,
        "request_entry_bytes": 0, "manifest_entry_bytes": 0,
        "stage_entry_bytes": 0, "packet_members_tar_bytes": 0,
        "payload_bytes": 0,
        "readback_descriptor_bytes": 0,
        "readback_payload_bytes": 0,
        "readback_member_tar_bytes": 0,
        "readback_maximum_object_bytes": 0,
        "dynamic_tree_rows": [], "probe_inventory_caps": {},
        "archive_v2": False,
        "validation_record_count": 0, "validation_record_tar_bytes": 0,
        "validation_record_bytes": 0,
        "receipt_roles": set(),
    })
    if row["role"] in {"component_receipt", "fixed_pair_host_receipt"}:
        if row["owner"] == "fixed_pair":
            stats.setdefault("fixed_pair_receipt_roles", set()).add(row["role"])
        elif row["role"] == "fixed_pair_host_receipt":
            stats["invalid_fixed_pair_host_owner"] = True
    stats["file_count"] += 1
    stats["request_entry_bytes"] += len(_archive_request_entry_bound(row))
    stats["manifest_entry_bytes"] += len(_archive_manifest_entry_bound(row))
    stats["stage_entry_bytes"] += len(_archive_stage_entry_bound(row))
    stats["packet_members_tar_bytes"] += _archive_tar_member_size(
        row["max_file_bytes"],
    )
    stats["payload_bytes"] += row["max_file_bytes"]
    stats["readback_descriptor_bytes"] += len(_canonical({
        "owner_job_sha256": "f" * 64,
        "origin_path": row["path"],
        "raw_sha256": "f" * 64,
        "byte_count": row["max_file_bytes"],
    }))
    stats["readback_payload_bytes"] += row["max_file_bytes"]
    stats["readback_member_tar_bytes"] += _archive_tar_member_size(
        row["max_file_bytes"],
    )
    stats["readback_maximum_object_bytes"] = max(
        stats["readback_maximum_object_bytes"], row["max_file_bytes"],
    )
    if row["role"].startswith("probe_capture_inventory"):
        member_index = row["member_index"]
        valid_member = ((type(member_index) is int and member_index in {0, 1}) or
                        (row["phase"] == "soak" and member_index is None))
        _require(valid_member and
                 member_index not in stats["probe_inventory_caps"],
                 f"Source5 {group_key} ProbeV2 inventory role has a duplicate or unknown member")
        stats["probe_inventory_caps"][member_index] = row["max_file_bytes"]
        stats["archive_v2"] = True
    if "receipt" in row["role"].lower():
        _require(row["role"] not in stats["receipt_roles"],
                 "Source5 job has duplicate owner receipt roles")
        stats["receipt_roles"].add(row["role"])


def _archive_caps_from_stats(
    groups: dict[tuple[str, str], dict[str, Any]],
    *, prepared_source5_profile: bool = False,
) -> dict[tuple[str, str], dict[str, int]]:
    result: dict[tuple[str, str], dict[str, int]] = {}
    fixed_groups: set[tuple[str, str]] = set()
    if prepared_source5_profile:
        fixed_roles = {"component_receipt", "fixed_pair_host_receipt"}
        for group, stats in groups.items():
            _require(not stats.get("invalid_fixed_pair_host_owner", False),
                     "fixed-pair host receipt is not owned by the fixed-pair producer")
            roles = stats.get("fixed_pair_receipt_roles", set())
            _require(not roles or roles == fixed_roles,
                     f"Source5 fixed group {group} lacks its exact paired owner receipts")
            if roles:
                _require(stats["phase"] in {"exploration", "aa", "confirmation"} and
                         not stats.get("dynamic_tree_rows") and
                         not stats.get("probe_inventory_caps") and
                         not stats.get("archive_v2"),
                         f"Source5 fixed group {group} is outside the tree-free fixed v3 profile")
                fixed_groups.add(group)
    for group, stats in groups.items():
        _require(stats["validation_record_count"] <= 1,
                 f"Source5 {group} has duplicate always-local validation records")
        fixed_v3 = group in fixed_groups
        archive_v2 = (not fixed_v3 and bool(stats.get("archive_v2") or
                                            stats["dynamic_tree_rows"]))
        request_entry_bytes = stats["request_entry_bytes"]
        manifest_entry_bytes = stats["manifest_entry_bytes"]
        stage_entry_bytes = stats["stage_entry_bytes"]
        readback_descriptor_bytes = stats["readback_descriptor_bytes"]
        readback_payload_bytes = stats["readback_payload_bytes"]
        readback_member_tar_bytes = stats["readback_member_tar_bytes"]
        readback_maximum_object_bytes = stats["readback_maximum_object_bytes"]
        packet_members_tar_bytes = stats["packet_members_tar_bytes"]
        payload_bytes = stats["payload_bytes"]
        file_count = stats["file_count"]
        dynamic_tree_rows = sorted(
            stats["dynamic_tree_rows"], key=lambda item: item["path"],
        )
        tree_inventory_bytes = 0
        if dynamic_tree_rows:
            members = {row["member_index"] for row in dynamic_tree_rows}
            _require(set(stats["probe_inventory_caps"]) == members and
                     len(members) == len(dynamic_tree_rows),
                     f"Source5 {group} ProbeV2 tree and inventory role rows do not close")
            for tree in dynamic_tree_rows:
                inventory_cap = stats["probe_inventory_caps"][tree["member_index"]]
                _require(0 < inventory_cap <= MAX_ARCHIVE_JSON_BYTES,
                         f"Source5 {group} ProbeV2 inventory cap exceeds its closed owner parser bound")
                tree_inventory_bytes += _archive_tree_inventory_entry_bound(
                    tree, inventory_cap,
                )
                (request_extra, manifest_extra, stage_extra,
                 readback_extra, child_count, member_tar_extra) = \
                    _archive_dynamic_tree_file_bounds(tree)
                request_entry_bytes += len(request_extra)
                manifest_entry_bytes += len(manifest_extra)
                stage_entry_bytes += len(stage_extra)
                readback_descriptor_bytes += readback_extra
                readback_payload_bytes += tree["max_bytes"]
                readback_member_tar_bytes += member_tar_extra
                readback_maximum_object_bytes = max(
                    readback_maximum_object_bytes, tree["max_file_bytes"],
                )
                packet_members_tar_bytes += member_tar_extra
                payload_bytes += tree["max_bytes"]
                file_count += child_count
        else:
            _require(not stats["probe_inventory_caps"],
                     f"Source5 {group} has a ProbeV2 inventory without its dynamic tree")
        _require(file_count > 0 and payload_bytes <= MAX_ARCHIVE_TOTAL_BYTES and
                 request_entry_bytes >= stats["request_entry_bytes"],
                 f"Source5 {group} archive closure exceeds its finite entry or payload budget")
        request_bytes = (_archive_fixed_request_bound(
            stats["phase"], stats["receipt_roles"], archive_v2=archive_v2,
            fixed_v3=fixed_v3,
            tree_inventory_bytes=tree_inventory_bytes,
            tree_inventory_count=len(dynamic_tree_rows),
        ) + request_entry_bytes + max(0, file_count - 1))
        # The source-pinned PAX encoder adds a 512-byte header and 512-byte
        # block padding per member, a size extension for files beyond USTAR,
        # and its fixed trailer. Use exact path/role row widths plus the exact
        # raw owner byte ceilings for this original job.
        packet_content = (_archive_tar_member_size(request_bytes) +
                          packet_members_tar_bytes +
                          stats["validation_record_tar_bytes"])
        packet_size = ((packet_content + 1024 + 10239) // 10240) * 10240
        metadata_caps = _archive_ack_bundle_bounds(
            stats["phase"], group[1], stats["receipt_roles"],
            file_count, request_entry_bytes, manifest_entry_bytes,
            archive_v2=archive_v2,
            fixed_v3=fixed_v3,
            tree_inventory_bytes=tree_inventory_bytes,
            tree_inventory_count=len(dynamic_tree_rows),
        )
        stage_map_bytes = (
            stage_entry_bytes + max(0, file_count - 1) +
            len(_canonical({
            "schema": "allocatbelt.application-source5-evidence-stage-map.v1",
            "checkpoint_pin": _archive_pin_bound(),
            "object_manifest_pin": _archive_pin_bound(),
            "rows": [], "stage_map_sha256": "f" * 64,
        })))
        maximum_path = ARCHIVE_ESCAPED_MAX_PATH
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
        request_checkpoint_limit = (
            MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES
            if archive_v2 else MAX_ARCHIVE_JSON_BYTES
        )
        _require(
            request_bytes <= request_checkpoint_limit and
            metadata_caps["checkpoint_bytes"] <= request_checkpoint_limit and
            metadata_caps["object_manifest_bytes"] <= MAX_ARCHIVE_JSON_BYTES and
            metadata_caps["archive_ack_bytes"] <= MAX_ARCHIVE_JSON_BYTES and
            stage_map_bytes <= MAX_ARCHIVE_JSON_BYTES and
            offer_bytes <= MAX_ARCHIVE_JSON_BYTES and
            packet_size <= MAX_ARCHIVE_TOTAL_BYTES,
            f"Source5 {group} archive metadata exceeds its exact parser or transport ceiling",
        )
        result[group] = {
            "checkpoint_request_bytes": request_bytes,
            "transfer_packet_bytes": packet_size,
            "validation_record_bytes": stats["validation_record_bytes"],
            "archive_v2": int(archive_v2),
            "file_count": file_count,
            "payload_bytes": payload_bytes,
            **metadata_caps,
            "stage_map_bytes": stage_map_bytes,
            "transfer_offer_bytes": offer_bytes,
        }
        result[group]["readback_request_bytes"] = (
            len(_canonical({
                "schema": "allocatbelt.application-source5-archive-read-request.v1",
                "campaign_id": "x" * 96, "host_id": "x" * 96,
                "analysis_phase": "host_evidence_finalization",
                "request_ordinal": MAX_U64, "objects": [],
                "maximum_response_bytes": MAX_U64,
                "request_sha256": "f" * 64,
            })) - 2 + readback_descriptor_bytes + max(0, file_count - 1)
        )
        result[group]["readback_response_bytes"] = (
            len(_canonical({
                "schema": "allocatbelt.application-source5-archive-read-response.v1",
                "campaign_id": "x" * 96, "host_id": "x" * 96,
                "analysis_phase": "host_evidence_finalization",
                "request_ordinal": MAX_U64,
                "request_pin": {"raw_sha256": "f" * 64,
                                "semantic_sha256": "f" * 64},
                "objects": [],
                "body_tar_pin": {"raw_sha256": "f" * 64,
                                 "byte_count": MAX_U64},
                "response_sha256": "f" * 64,
            })) - 2 + readback_descriptor_bytes + max(0, file_count - 1)
        )
        bundle_content_bytes = readback_member_tar_bytes
        result[group]["readback_bundle_bytes"] = (
            (bundle_content_bytes + 1024 + 10239) // 10240
        ) * 10240
        result[group]["readback_stage_bytes"] = readback_payload_bytes
        result[group]["readback_stage_inodes"] = file_count + 1
        result[group]["readback_object_count"] = file_count
        result[group]["readback_maximum_object_bytes"] = readback_maximum_object_bytes
        result[group]["readback_window_bytes"] = sum(result[group][key] for key in (
            "readback_request_bytes", "readback_response_bytes",
            "readback_bundle_bytes", "readback_stage_bytes",
        ))
        result[group]["readback_window_inodes"] = file_count + 4
    return result


def project_archive_job_caps(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    """Derive the exact nine transport rows for each original job."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        _archive_job_stats_add(groups, row)
    projected = _archive_caps_from_stats(groups)
    public_fields = (
        "checkpoint_request_bytes", "transfer_packet_bytes",
        "checkpoint_bytes", "object_manifest_bytes", "archive_ack_bytes",
        "signature_bytes", "ack_bundle_bytes", "stage_map_bytes",
        "transfer_offer_bytes",
    )
    return {
        group: {field: caps[field] for field in public_fields}
        for group, caps in projected.items()
    }


def _project_prepared_source5_archive_caps(
    rows: Iterable[dict[str, Any]], *, readback: bool,
) -> dict[tuple[str, str], dict[str, int]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        _archive_job_stats_add(groups, _catalogue_row(
            row, "prepared Source5 archive projection row",
        ))
    _require(bool(groups),
             "prepared Source5 archive projection has no original jobs")
    projected = _archive_caps_from_stats(
        groups, prepared_source5_profile=True,
    )
    if readback:
        return _archive_readback_projection(projected)
    public_fields = (
        "checkpoint_request_bytes", "transfer_packet_bytes",
        "checkpoint_bytes", "object_manifest_bytes", "archive_ack_bytes",
        "signature_bytes", "ack_bundle_bytes", "stage_map_bytes",
        "transfer_offer_bytes",
    )
    return {group: {field: caps[field] for field in public_fields}
            for group, caps in projected.items()}


def project_archive_readback_caps(
    rows: Iterable[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, int]]:
    """Derive reusable readback request, response, tar and stage ceilings."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        _archive_job_stats_add(groups, row)
    _require(bool(groups),
             "Source5 archive readback has no exact per-job owner objects")
    projected = _archive_caps_from_stats(groups)
    return _archive_readback_projection(projected)


def _archive_readback_projection(
    projected: dict[tuple[str, str], dict[str, int]],
) -> dict[tuple[str, str], dict[str, int]]:
    _require(bool(projected),
             "Source5 archive readback has no exact per-job owner objects")
    result: dict[tuple[str, str], dict[str, int]] = {}
    maximum_request_bytes = 0
    maximum_response_bytes = 0
    maximum_bundle_bytes = 0
    maximum_stage_bytes = 0
    maximum_stage_inodes = 0
    maximum_object_count = 0
    maximum_object_bytes = 0
    maximum_live_window_bytes = 0
    maximum_live_window_inodes = 0
    for key, caps in projected.items():
        request_bytes = caps["readback_request_bytes"]
        response_bytes = caps["readback_response_bytes"]
        bundle_bytes = caps["readback_bundle_bytes"]
        stage_bytes = caps["readback_stage_bytes"]
        stage_inodes = caps["readback_stage_inodes"]
        object_count = caps["readback_object_count"]
        per_job_maximum_object_bytes = caps["readback_maximum_object_bytes"]
        live_window_bytes = caps["readback_window_bytes"]
        live_window_inodes = caps["readback_window_inodes"]
        _require(request_bytes <= MAX_ARCHIVE_READ_METADATA_BYTES and
                 response_bytes <= MAX_ARCHIVE_READ_METADATA_BYTES and
                 bundle_bytes <= MAX_ARCHIVE_TOTAL_BYTES and
                 stage_bytes <= MAX_ARCHIVE_TOTAL_BYTES,
                 f"Source5 readback {key} exceeds the closed transfer bounds")
        result[key] = {
            "request_bytes": request_bytes,
            "response_bytes": response_bytes,
            "bundle_bytes": bundle_bytes,
            "stage_bytes": stage_bytes,
            "stage_inodes": stage_inodes,
            "object_count": object_count,
            "maximum_object_bytes": per_job_maximum_object_bytes,
            "live_window_bytes": live_window_bytes,
            "live_window_inodes": live_window_inodes,
        }
        maximum_request_bytes = max(maximum_request_bytes, request_bytes)
        maximum_response_bytes = max(maximum_response_bytes, response_bytes)
        maximum_bundle_bytes = max(maximum_bundle_bytes, bundle_bytes)
        maximum_stage_bytes = max(maximum_stage_bytes, stage_bytes)
        maximum_stage_inodes = max(maximum_stage_inodes, stage_inodes)
        maximum_object_count = max(maximum_object_count, object_count)
        maximum_object_bytes = max(
            maximum_object_bytes, per_job_maximum_object_bytes,
        )
        maximum_live_window_bytes = max(maximum_live_window_bytes,
                                        live_window_bytes)
        maximum_live_window_inodes = max(maximum_live_window_inodes,
                                         live_window_inodes)
    for key, caps in result.items():
        caps["maximum_request_bytes"] = maximum_request_bytes
        caps["maximum_response_bytes"] = maximum_response_bytes
        caps["maximum_bundle_bytes"] = maximum_bundle_bytes
        caps["maximum_stage_bytes"] = maximum_stage_bytes
        caps["maximum_stage_inodes"] = maximum_stage_inodes
        caps["maximum_object_count"] = maximum_object_count
        caps["maximum_object_bytes"] = maximum_object_bytes
        caps["maximum_live_window_bytes"] = maximum_live_window_bytes
        caps["maximum_live_window_inodes"] = maximum_live_window_inodes
    return result


def project_prepared_source5_archive_job_caps(
    rows: Iterable[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, int]]:
    """Project fixed checkpoint-v3 and dynamic Source5 job caps by exact rows."""
    return _project_prepared_source5_archive_caps(rows, readback=False)


def project_prepared_source5_archive_readback_caps(
    rows: Iterable[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, int]]:
    """Project readback caps for the prepared Source5 fixed/dynamic profile."""
    return _project_prepared_source5_archive_caps(rows, readback=True)


def _fixed_pair_groups(
    rows: Iterable[dict[str, Any]],
) -> set[tuple[str, str]]:
    receipt_counts: dict[tuple[str, str], dict[str, int]] = {}
    for row_value in rows:
        row = _catalogue_row(row_value, "fixed Source5 archive profile row")
        if row["role"] not in {"component_receipt", "fixed_pair_host_receipt"}:
            continue
        if row["owner"] != "fixed_pair":
            _require(row["role"] != "fixed_pair_host_receipt",
                     "fixed-pair host receipt has another owner")
            continue
        _require(row["phase"] in {"exploration", "aa", "confirmation"} and
                 row["run_id"] is not None and row["kind"] == "file",
                 "fixed-pair receipt is outside an exact fixed job row")
        group = (row["phase"], row["run_id"])
        roles = receipt_counts.setdefault(group, {})
        roles[row["role"]] = roles.get(row["role"], 0) + 1
        _require(roles[row["role"]] == 1,
                 f"fixed-pair group {group} repeats owner receipt role {row['role']}")
    expected = {"component_receipt", "fixed_pair_host_receipt"}
    for group, roles in receipt_counts.items():
        _require(set(roles) == expected,
                 f"fixed-pair group {group} lacks its exact paired owner receipts")
    return set(receipt_counts)


def project_fixed_pair_archive_job_caps(
    rows: Iterable[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, int]]:
    materialized = [_catalogue_row(row, "fixed Source5 archive row")
                    for row in rows]
    groups = _fixed_pair_groups(materialized)
    _require(bool(groups), "fixed Source5 archive projection has no fixed jobs")
    projected = project_prepared_source5_archive_job_caps(materialized)
    return {group: projected[group] for group in groups}


def project_fixed_pair_archive_readback_caps(
    rows: Iterable[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, int]]:
    materialized = [_catalogue_row(row, "fixed Source5 archive row")
                    for row in rows]
    projected = project_prepared_source5_archive_readback_caps(materialized)
    # The fixed profile has no dynamic-tree contribution and is confined to
    # the three original fixed-pair phases. Selection is derived from exact
    # fixed owner receipt rows below.
    groups = _fixed_pair_groups(materialized)
    _require(bool(groups), "fixed Source5 readback projection has no fixed jobs")
    return {group: projected[group] for group in groups}


def _retention_projection(
    rows: Iterable[dict[str, Any]], *, prepared_source5_profile: bool = False,
) -> dict[str, Any]:
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
    cleanup_sidecar_alternatives: dict[
        tuple[tuple[str, str], int], dict[str, tuple[int, int, str]]
    ] = {}
    fixed_job_record_groups: set[tuple[str, str]] = set()
    has_journal_width_contract = False
    has_archive_read_control = False
    has_analyzer_scratch = False
    analyzer_scratch_root: str | None = None
    archive_read_window_bytes: dict[str, int] = {}
    archive_read_window_inodes: dict[str, int] = {}
    archive_read_roles_seen: set[str] = set()
    archive_read_slot_roots: set[str | None] = set()
    archive_read_alternative_rows: dict[
        str, dict[str, tuple[int, int, str | None]]
    ] = {"response": {}, "bundle": {}}
    files = 0
    file_index_data_bytes = 0
    non_tmp_tree_entries = 0
    non_tmp_tree_data_bytes = 0
    for row in rows:
        root = row["storage_root"]
        if row["role"] == "journal_width_contract":
            has_journal_width_contract = True
        if row["role"] == SOURCE5_ARCHIVE_READ_CONTROL_ROLE:
            has_archive_read_control = True
        is_archive_read_transient = (
            row["role"] in SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES
        )
        is_analyzer_scratch = row["role"] == SOURCE5_ANALYZER_SPOOL_ROLE
        if is_analyzer_scratch:
            _require(not has_analyzer_scratch and row["kind"] == "tree" and
                     row["phase"] is None and row["run_id"] is None and
                     row["member_index"] is None and
                     row["aggregate_id"] is None and
                     row["host_id"] is not None and
                     row["owner"] == "source5_controller" and
                     row["max_bytes"] > 0 and
                     row["max_file_bytes"] > 0 and
                     row["max_inodes"] > 1 and
                     row["storage_root"] is not None,
                     "Source5 analyzer scratch is not one bounded global v4 tree")
            has_analyzer_scratch = True
            analyzer_scratch_root = row["storage_root"]
        if row["role"] in SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES | {
                SOURCE5_ARCHIVE_READ_CONTROL_ROLE}:
            _require(row["role"] not in archive_read_roles_seen and
                     row["phase"] is None and row["run_id"] is None and
                     row["member_index"] is None and
                     row["aggregate_id"] is None,
                     "Source5 archive readback path is duplicated or has job-group identity")
            archive_read_roles_seen.add(row["role"])
            _require(row["host_id"] is not None and row["owner"] ==
                     "source5_controller",
                     "Source5 archive readback path lost its exact host/controller owner")
            if is_archive_read_transient:
                expected_kind = ("tree" if row["role"] ==
                                 "source5_archive_read_stage" else "file")
                _require(row["kind"] == expected_kind and
                         (row["kind"] != "file" or row["max_inodes"] == 1) and
                         row["max_bytes"] > 0,
                         "Source5 archive readback slot type or finite ceiling differs")
                archive_read_slot_roots.add(row["storage_root"])
            else:
                _require(row["kind"] == "file" and row["max_inodes"] == 1 and
                         row["max_bytes"] > 0,
                         "Source5 archive read-control ledger is not one bounded regular file")
        failure_suffix = (
            row["role"] in FAILURE_WINDOW_ONLY_ROLES and
            row["phase"] is not None and row["run_id"] is None
        )
        always_local = ALWAYS_LOCAL_EVIDENCE_ROLES | {
            "journal_width_contract", SOURCE5_ARCHIVE_READ_CONTROL_ROLE,
        }
        group = ((row["phase"], row["run_id"])
                 if row["phase"] is not None and row["run_id"] is not None and
                 row["role"] not in always_local
                 else None)
        if row["role"] in CLEANUP_SIDECAR_ALTERNATIVE_ROLES:
            _require(group is not None and row["kind"] == "file" and
                     row["phase"] in {"exploration", "aa", "confirmation"} and
                     row["member_index"] in {0, 1},
                     "Source5 cleanup sidecar alternative lacks one original fixed job/member")
            member_key = (group, row["member_index"])
            alternatives = cleanup_sidecar_alternatives.setdefault(
                member_key, {},
            )
            _require(row["role"] not in alternatives,
                     "Source5 cleanup sidecar/refusal alternative repeats a role")
            alternatives[row["role"]] = (
                row["max_file_bytes"], row["max_inodes"], root,
            )
        if root is not None:
            roots.add(root)
            if is_analyzer_scratch:
                archive_read_window_bytes[root] = (
                    archive_read_window_bytes.get(root, 0) + row["max_bytes"]
                )
                archive_read_window_inodes[root] = (
                    archive_read_window_inodes.get(root, 0) + row["max_inodes"]
                )
            elif is_archive_read_transient:
                _require(row["phase"] is None and row["run_id"] is None,
                         "Source5 archive readback slot must be one reusable host window")
                if row["role"] in SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES:
                    archive_read_alternative_rows["response"][row["role"]] = (
                        row["max_bytes"], row["max_inodes"], root,
                    )
                elif row["role"] in SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES:
                    archive_read_alternative_rows["bundle"][row["role"]] = (
                        row["max_bytes"], row["max_inodes"], root,
                    )
                else:
                    archive_read_window_bytes[root] = (
                        archive_read_window_bytes.get(root, 0) + row["max_bytes"]
                    )
                    archive_read_window_inodes[root] = (
                        archive_read_window_inodes.get(root, 0) + row["max_inodes"]
                    )
            elif failure_suffix:
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
            elif (group is not None and
                  row["role"] in CLEANUP_SIDECAR_ALTERNATIVE_ROLES):
                pass  # one of the two same-member alternatives is retained
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
            if row["phase"] in {"exploration", "aa", "confirmation"}:
                fixed_job_record_groups.add(key)
        if row["kind"] == "file":
            is_transient = (row["role"] in TRANSIENT_JOB_EVIDENCE_ROLES or
                            is_archive_read_transient)
            is_success_indexed = row["role"] not in (
                TRANSIENT_JOB_EVIDENCE_ROLES | FAILURE_WINDOW_ONLY_ROLES |
                SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES
            )
            if is_success_indexed:
                files += 1
                file_index_data_bytes += _index_row_bound(row)
            if group is not None and is_success_indexed:
                window_index_entries[group] = window_index_entries.get(group, 0) + 1
                window_index_data_bytes[group] = (
                    window_index_data_bytes.get(group, 0) + _index_row_bound(row)
                )
            if (row["role"] == "source5_job_disposition" and
                    row["run_id"] is not None):
                failure_job_bytes_by_phase[row["phase"]] = max(
                    failure_job_bytes_by_phase.get(row["phase"], 0),
                    row["max_bytes"],
                )
            _archive_job_stats_add(archive_job_stats, row)
            continue
        if is_analyzer_scratch:
            continue
        if is_archive_read_transient:
            _require(row["kind"] == "tree" and
                     row["role"] == "source5_archive_read_stage",
                     "Source5 archive readback stage is not a bounded private tree")
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
    expected_cleanup_roles = CLEANUP_SIDECAR_ALTERNATIVE_ROLES
    cleanup_shape = _cleanup_source_shape(SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT)
    sidecar_source_max = cleanup_shape["source_maximum_bytes"]
    cleanup_group_members: dict[tuple[str, str], set[int]] = {}
    for (group, member_index), alternatives in cleanup_sidecar_alternatives.items():
        _require(set(alternatives) == expected_cleanup_roles,
                 f"Source5 {group}/member{member_index} cleanup alternatives are incomplete")
        sidecar_cap = alternatives[SOURCE5_CLEANUP_SIDECAR_ROLE]
        refusal_cap = alternatives[SOURCE5_CLEANUP_SIDECAR_REFUSAL_ROLE]
        _require(sidecar_cap == (sidecar_source_max, 1, sidecar_cap[2]) and
                 refusal_cap == (SOURCE5_CLEANUP_REFUSAL_BYTES, 1,
                                 refusal_cap[2]) and
                 sidecar_cap[2] == refusal_cap[2],
                 f"Source5 {group}/member{member_index} cleanup cap/root differs from the source-derived contract")
        cleanup_group_members.setdefault(group, set()).add(member_index)
        root = sidecar_cap[2]
        byte_rows = group_bytes.setdefault(group, {})
        inode_rows = group_inodes.setdefault(group, {})
        byte_rows[root] = byte_rows.get(root, 0) + max(
            sidecar_cap[0], refusal_cap[0],
        )
        inode_rows[root] = inode_rows.get(root, 0) + max(
            sidecar_cap[1], refusal_cap[1],
        )
    _require(all(members == {0, 1} for members in cleanup_group_members.values()),
             "Source5 cleanup sidecar alternatives do not cover both exact fixed members")
    if cleanup_sidecar_alternatives:
        _require(set(cleanup_group_members) == fixed_job_record_groups,
                 "Source5 cleanup sidecar/refusal alternatives do not cover every original fixed job")
    if has_archive_read_control or archive_read_roles_seen:
        _require(has_archive_read_control and archive_read_roles_seen ==
                 (SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES |
                  {SOURCE5_ARCHIVE_READ_CONTROL_ROLE}),
                 "Source5 archive readback catalogue does not close every reusable slot and control ledger")
        for family, roles in (
            ("response", SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES),
            ("bundle", SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES),
        ):
            alternatives = archive_read_alternative_rows[family]
            _require(set(alternatives) == roles and
                     len(set(alternatives.values())) == 1,
                     f"Source5 archive read {family} incoming/final slots are not exact same-filesystem alternatives")
            amount, inodes, root = next(iter(alternatives.values()))
            _require(root is not None,
                     f"Source5 archive read {family} alternatives have no reserved storage root")
            archive_read_window_bytes[root] = (
                archive_read_window_bytes.get(root, 0) + amount
            )
            archive_read_window_inodes[root] = (
                archive_read_window_inodes.get(root, 0) + inodes
            )
        _require(len(archive_read_slot_roots) == 1 and
                 None not in archive_read_slot_roots,
                 "Source5 archive readback slots do not share one caller-reserved storage root")
    _require(has_analyzer_scratch == has_journal_width_contract,
             "Source5 v4 journal-width contract and analyzer scratch tree do not close together")
    if has_analyzer_scratch:
        _require(has_archive_read_control and archive_read_roles_seen ==
                 SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES | {
                     SOURCE5_ARCHIVE_READ_CONTROL_ROLE,
                 } and analyzer_scratch_root in archive_read_slot_roots,
                 "Source5 analyzer scratch does not share the v4 archive-readback window root")
    for root in roots:
        byte_peaks = [(values.get(root, 0), group)
                      for group, values in group_bytes.items()]
        inode_peaks = [(values.get(root, 0), group)
                       for group, values in group_inodes.items()]
        peak_bytes, _ = max(byte_peaks, default=(0, None))
        peak_inodes, _ = max(inode_peaks, default=(0, None))
        window_bytes[root] = max(
            peak_bytes, archive_read_window_bytes.get(root, 0),
        )
        window_inodes[root] = max(
            peak_inodes, archive_read_window_inodes.get(root, 0),
        )
        live_bytes[root] = base_bytes.get(root, 0) + window_bytes[root]
        live_inodes[root] = base_inodes.get(root, 0) + window_inodes[root]
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
    archive_caps = _archive_caps_from_stats(
        archive_job_stats,
        prepared_source5_profile=prepared_source5_profile,
    )
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
    maximum_job_window_bytes = max(
        (sum(amounts.values()) for amounts in group_bytes.values()), default=0,
    )
    maximum_job_window_inodes = max(
        (sum(amounts.values()) for amounts in group_inodes.values()), default=0,
    )
    if has_analyzer_scratch:
        maximum_window_total_bytes = max(
            maximum_job_window_bytes, sum(archive_read_window_bytes.values()),
        )
        maximum_window_total_inodes = max(
            maximum_job_window_inodes, sum(archive_read_window_inodes.values()),
        )
    else:
        maximum_window_total_bytes = maximum_job_window_bytes
        maximum_window_total_inodes = maximum_job_window_inodes
    maximum_window_index_entries = max(window_index_entries.values(), default=0)
    maximum_window_index_data_bytes = max(
        window_index_data_bytes.values(), default=0,
    )
    maximum_transfer_packet_bytes = maximum_archive_caps["transfer_packet_bytes"]
    retention = {
        "schema": RETENTION_POLICY_SCHEMA_V2,
        "mode": RETENTION_POLICY_MODE_V2,
        "success_empty_tree_roles": sorted(SUCCESS_EMPTY_TMP_TREE_ROLES),
        "always_local_roles": sorted(
            ALWAYS_LOCAL_EVIDENCE_ROLES |
            ({"journal_width_contract"} if has_journal_width_contract else set()) |
            ({SOURCE5_ARCHIVE_READ_CONTROL_ROLE}
             if has_archive_read_control else set())
        ),
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
    if cleanup_sidecar_alternatives:
        retention.update({
            "cleanup_source_shape": cleanup_shape,
            "maximum_cleanup_sidecar_source_bytes":
                cleanup_shape["source_maximum_bytes"],
            "maximum_cleanup_sidecar_bytes":
                cleanup_shape["admission_maximum_bytes"],
            "maximum_failed_cleanup_window_bytes":
                cleanup_shape["maximum_window_bytes"],
            "maximum_failed_cleanup_window_inodes": 2,
            "maximum_cleanup_sidecar_refusal_bytes":
                cleanup_shape["refusal_file_bytes"],
            "maximum_failed_cleanup_refusal_window_bytes":
                cleanup_shape["maximum_refusal_window_bytes"],
            "maximum_failed_cleanup_refusal_window_inodes": 2,
        })
    return retention


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


def _write_path_catalogue_chunks(
    records: Iterable[object], output_directory_value: object,
    *, scratch_directory_value: object | None = None,
    prepared_source5_profile: bool = False,
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
            elif row["role"] == SOURCE5_ANALYZER_SPOOL_ROLE:
                # Analyzer spools are controller scratch. Their bytes and
                # inodes are charged to the live scratch window above, but
                # these files are not source evidence or archive payload.
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

    retention = _retention_projection(
        catalogue_rows_from_chunks(),
        prepared_source5_profile=prepared_source5_profile,
    )
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


def write_path_catalogue_chunks(
    records: Iterable[object], output_directory_value: object,
    *, scratch_directory_value: object | None = None,
) -> dict[str, Any]:
    """Write the unchanged legacy v1/v2 archive-profile catalogue."""
    return _write_path_catalogue_chunks(
        records, output_directory_value,
        scratch_directory_value=scratch_directory_value,
    )


def write_fixed_pair_v3_path_catalogue_chunks(
    records: Iterable[object], output_directory_value: object,
    *, scratch_directory_value: object | None = None,
) -> dict[str, Any]:
    """Write the Source-owned fixed-v3 plus dynamic-Source5 catalogue profile."""
    return _write_path_catalogue_chunks(
        records, output_directory_value,
        scratch_directory_value=scratch_directory_value,
        prepared_source5_profile=True,
    )


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
    retention_base_fields = {
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
    }
    cleanup_policy_fields = {
        "cleanup_source_shape", "maximum_cleanup_sidecar_source_bytes",
        "maximum_cleanup_sidecar_bytes",
        "maximum_failed_cleanup_window_bytes",
        "maximum_failed_cleanup_window_inodes",
        "maximum_cleanup_sidecar_refusal_bytes",
        "maximum_failed_cleanup_refusal_window_bytes",
        "maximum_failed_cleanup_refusal_window_inodes",
    }
    _require(type(manifest["retention_policy"]) is dict,
             "Source5 path catalogue retention policy is not an object")
    retention_has_cleanup = (
        set(manifest["retention_policy"]) ==
        retention_base_fields | cleanup_policy_fields
    )
    _require(retention_has_cleanup or
             set(manifest["retention_policy"]) == retention_base_fields,
             "Source5 path catalogue retention policy field set differs")
    retention = _exact(
        manifest["retention_policy"],
        retention_base_fields | (cleanup_policy_fields
                                 if retention_has_cleanup else set()),
        "Source5 path catalogue between-pair retention policy",
    )
    _require(type(manifest["role_byte_bounds"]) is dict,
             "Source5 path catalogue role-byte projection is malformed")
    expected_always_local_roles = ALWAYS_LOCAL_EVIDENCE_ROLES
    if "journal_width_contract" in manifest["role_byte_bounds"]:
        expected_always_local_roles |= {"journal_width_contract"}
    if SOURCE5_ARCHIVE_READ_CONTROL_ROLE in manifest["role_byte_bounds"]:
        expected_always_local_roles |= {SOURCE5_ARCHIVE_READ_CONTROL_ROLE}
    _require(retention["schema"] == RETENTION_POLICY_SCHEMA_V2 and
             retention["mode"] == RETENTION_POLICY_MODE_V2 and
             retention["success_empty_tree_roles"] ==
                sorted(SUCCESS_EMPTY_TMP_TREE_ROLES) and
             retention["always_local_roles"] ==
                 sorted(expected_always_local_roles) and
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
    if retention_has_cleanup:
        _require(retention["cleanup_source_shape"] ==
                    _cleanup_source_shape(SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT) and
                 retention["maximum_cleanup_sidecar_source_bytes"] ==
                    retention["cleanup_source_shape"]["source_maximum_bytes"] and
                 retention["maximum_cleanup_sidecar_bytes"] ==
                    retention["cleanup_source_shape"]["admission_maximum_bytes"] and
                 retention["maximum_failed_cleanup_window_bytes"] ==
                    retention["cleanup_source_shape"]["maximum_window_bytes"] and
                 retention["maximum_failed_cleanup_window_inodes"] == 2 and
                 retention["maximum_cleanup_sidecar_refusal_bytes"] ==
                    retention["cleanup_source_shape"]["refusal_file_bytes"] and
                 retention["maximum_failed_cleanup_refusal_window_bytes"] ==
                    retention["cleanup_source_shape"]["maximum_refusal_window_bytes"] and
                 retention["maximum_failed_cleanup_refusal_window_inodes"] == 2,
                 "Source5 cleanup sidecar retention bounds differ from the source contract")
    _uint(retention["job_group_count"],
          "Source5 retention original phase/run group count")
    if retention_has_cleanup:
        cleanup_shape = retention["cleanup_source_shape"]
        _exact(cleanup_shape, {
            "maximum_session_members_per_snapshot",
            "maximum_pidfd_signal_entries_per_snapshot",
            "maximum_signal_snapshots", "maximum_cleanup_errors",
            "maximum_error_text_bytes", "normal_cleanup_poll_count",
            "emergency_cleanup_poll_count", "term_grace_seconds",
            "kill_reap_seconds", "cleanup_poll_interval_seconds",
            "source_maximum_bytes", "admission_maximum_bytes",
            "maximum_window_bytes", "refusal_file_bytes",
            "maximum_refusal_window_bytes",
        }, "Source5 retention cleanup source shape")
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
    if retention_has_cleanup:
        for field in (
            "maximum_cleanup_sidecar_source_bytes",
            "maximum_cleanup_sidecar_bytes",
            "maximum_failed_cleanup_window_bytes",
            "maximum_failed_cleanup_window_inodes",
            "maximum_cleanup_sidecar_refusal_bytes",
            "maximum_failed_cleanup_refusal_window_bytes",
            "maximum_failed_cleanup_refusal_window_inodes",
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
    *, prepared_source5_profile: bool = False,
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
        elif row["role"] == SOURCE5_ANALYZER_SPOOL_ROLE:
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
        elif row["role"] != SOURCE5_ANALYZER_SPOOL_ROLE:
            trees += 1
            maximum_index_entries += row["max_inodes"] - 1
            maximum_index_data_bytes += (
                row["max_inodes"] - 1
            ) * _index_row_bound(row, path_length=MAX_PATH_BYTES)
        else:
            trees += 1
    grouped_bytes = 0
    for aggregate, amount in aggregate_bytes.items():
        maximum, root = aggregate_limits[aggregate]
        grouped_bytes += min(amount, maximum)
        if root is not None:
            root_bytes[root] -= amount - min(amount, maximum)
    retention = _retention_projection(
        retention_rows,
        prepared_source5_profile=prepared_source5_profile,
    )
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


def verify_fixed_pair_v3_path_catalogue_chunks(value: object) -> dict[str, Any]:
    """Verify a Source fixed-v3 catalogue from its original pinned paths."""
    manifest = validate_fixed_pair_v3_path_catalogue_manifest(value)
    derived = _catalogue_derived_bounds(
        manifest, iter_path_catalogue_rows(manifest),
        iter_path_catalogue_rows(manifest),
        prepared_source5_profile=True,
    )
    for name, amount in derived.items():
        _require(manifest[name] == amount,
                 f"fixed-v3 Source5 catalogue {name} differs from its exact row projection")
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


def validate_fixed_pair_v3_path_catalogue_manifest(
    value: object,
) -> dict[str, Any]:
    """Validate the unchanged manifest wire shape for Source fixed-v3 rows."""
    return validate_path_catalogue_manifest(value)


def iter_fixed_pair_v3_path_catalogue_rows_with_reader(
    value: object, reader,
) -> Iterator[dict[str, Any]]:
    """Stream raw-pinned rows for the Source fixed-v3 catalogue profile."""
    yield from iter_path_catalogue_rows_with_reader(value, reader)


def verify_fixed_pair_v3_path_catalogue_chunks_with_reader(
    value: object, reader,
) -> dict[str, Any]:
    """Verify exact catalogue rows with fixed-v3 and dynamic Source5 caps."""
    manifest = validate_fixed_pair_v3_path_catalogue_manifest(value)
    derived = _catalogue_derived_bounds(
        manifest,
        iter_fixed_pair_v3_path_catalogue_rows_with_reader(manifest, reader),
        iter_fixed_pair_v3_path_catalogue_rows_with_reader(manifest, reader),
        prepared_source5_profile=True,
    )
    for name, amount in derived.items():
        _require(manifest[name] == amount,
                 f"fixed-v3 Source5 catalogue {name} differs from its exact row projection")
    return manifest


def verify_prepared_source5_path_catalogue_chunks_with_reader(
    value: object, reader,
) -> dict[str, Any]:
    """Verify V5 fixed-v3 rows and pressure/Soak dynamic-tree rows together."""
    return verify_fixed_pair_v3_path_catalogue_chunks_with_reader(value, reader)


def verify_prepared_source5_path_catalogue_chunks(
    value: object,
) -> dict[str, Any]:
    """Verify a V5 fixed-v3 plus pressure/Soak dynamic profile from disk."""
    return verify_fixed_pair_v3_path_catalogue_chunks(value)


def iter_prepared_source5_path_catalogue_rows_with_reader(
    value: object, reader,
) -> Iterator[dict[str, Any]]:
    """Stream rows after the caller authenticates the prepared Source5 profile."""
    yield from iter_fixed_pair_v3_path_catalogue_rows_with_reader(value, reader)


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


def _verify_captured_journal_width_contract(
    pin_value: object, raw_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    pin = _exact(pin_value, {"path", "raw_sha256", "semantic_sha256"},
                 "Source5 journal-width contract pin")
    path_text = pin["path"]
    _require(type(path_text) is str and path_text.startswith("/") and
             len(path_text.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             PurePosixPath(path_text).as_posix() == path_text and
             ".." not in PurePosixPath(path_text).parts,
             "Source5 journal-width contract path is not normalized")
    _digest(pin["raw_sha256"], "Source5 journal-width contract raw digest")
    _digest(pin["semantic_sha256"],
            "Source5 journal-width contract semantic digest")
    _require(type(raw_value) is bytes and
             0 < len(raw_value) <= MAX_JOURNAL_WIDTH_CONTRACT_BYTES,
             "Source5 journal-width contract captured bytes are not bounded")
    raw = raw_value
    _require(_sha(raw) == pin["raw_sha256"],
             "Source5 journal-width contract raw pin differs")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise BudgetPlanError("Source5 journal-width contract is malformed") from error
    _require(type(value) is dict and raw == _canonical(value) and
             value.get("schema") == JOURNAL_WIDTH_CONTRACT_SCHEMA and
             type(value.get("contract_sha256")) is str and
             value["contract_sha256"] == pin["semantic_sha256"] ==
                 _sha(_canonical({key: item for key, item in value.items()
                                  if key != "contract_sha256"})),
             "Source5 journal-width contract canonical/semantic pin differs")
    return value, raw, pin


def _validate_journal_width_contract_summary(
    contract_value: object, audit: dict[str, Any], owner_contract: dict[str, Any],
) -> tuple[dict[str, Any], int, int]:
    contract = _exact(contract_value, {
        "schema", "campaign_id", "host_id", "original_pins_sha256",
        "plan_pin", "source_manifest_pin", "owner_pins", "job_rows",
        "phase_totals", "fixed_event_widths", "total_event_count",
        "total_event_bytes", "failed_owner_window", "contract_sha256",
    }, "Source5 journal-width contract")
    body = {key: item for key, item in contract.items()
            if key != "contract_sha256"}
    host_id = audit["host_id"]
    original = audit["original_pins"]
    catalogue_owner_pins = owner_contract.get("owner_source_pins")
    catalogue_owner_roles = {
        "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
        "soak_reader", "offline_dispatcher", "chronology",
        "evidence_transport",
    }
    audit_owner_pins = audit.get("producer_catalogue", {}).get(
        "owner_schema_pins",
    )
    audit_owner_roles = {
        "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
        "soak_reader", "feedback_composer", "feedback_reader",
        "pressure_reader", "evidence_transport",
    }
    _require(type(catalogue_owner_pins) is dict and
             set(catalogue_owner_pins) == catalogue_owner_roles and
             (audit_owner_pins is None or
              (type(audit_owner_pins) is dict and
               set(audit_owner_pins) == audit_owner_roles)),
             "Source5 width owner profiles do not match their exact catalogue/budget role sets")
    expected_owner_pins: dict[str, dict[str, Any]] = {}
    for role, row_value in catalogue_owner_pins.items():
        row = _exact(row_value, {"path", "raw_sha256", "byte_count"},
                     f"Source5 catalogue width owner pin {role}")
        _require(type(row["path"]) is str and bool(row["path"]) and
                 _digest(row["raw_sha256"],
                         f"Source5 catalogue width owner pin {role} raw SHA-256") ==
                     row["raw_sha256"] and
                 type(row["byte_count"]) is int and row["byte_count"] > 0,
                 f"Source5 catalogue width owner pin {role} is malformed")
        expected_owner_pins[role] = dict(row)
    expected_roles = catalogue_owner_roles | audit_owner_roles
    contract_owner_pins = _exact(
        contract["owner_pins"], expected_roles,
        "Source5 journal-width union owner pins",
    )
    if audit_owner_pins is None:
        # The persisted host budget intentionally retains the catalogue's
        # eight-role pin profile, not a second copy of the budget audit's
        # nine-role profile. At replay, only the catalogue profile can be
        # independently reconstructed here; the controller and chronology
        # compare all eleven contract pins against the captured typed Source.
        for role in sorted(audit_owner_roles - catalogue_owner_roles):
            row = _exact(
                contract_owner_pins[role],
                {"path", "raw_sha256", "byte_count"},
                f"Source5 journal-width budget-only owner pin {role}",
            )
            _require(type(row["path"]) is str and bool(row["path"]) and
                     _digest(row["raw_sha256"],
                             f"Source5 budget width owner pin {role} raw SHA-256") ==
                         row["raw_sha256"] and
                     type(row["byte_count"]) is int and row["byte_count"] > 0,
                     f"Source5 journal-width budget-only owner pin {role} is malformed")
            expected_owner_pins[role] = dict(row)
    else:
        for role, row_value in audit_owner_pins.items():
            row = _exact(row_value, {"path", "mode", "sha256", "size"},
                         f"Source5 budget width owner pin {role}")
            normalized = {
                "path": row["path"], "raw_sha256": row["sha256"],
                "byte_count": row["size"],
            }
            _require(type(normalized["path"]) is str and bool(normalized["path"]) and
                     _digest(normalized["raw_sha256"],
                             f"Source5 budget width owner pin {role} raw SHA-256") ==
                         normalized["raw_sha256"] and
                     type(normalized["byte_count"]) is int and
                     normalized["byte_count"] > 0 and
                     row["mode"] in {"100644", "100755"},
                     f"Source5 budget width owner pin {role} is malformed")
            prior = expected_owner_pins.get(role)
            _require(prior is None or prior == normalized,
                     f"Source5 shared width owner role {role} has divergent source pins")
            expected_owner_pins[role] = normalized
    _require(set(expected_owner_pins) == expected_roles and
             len(expected_owner_pins) == 11,
             "Source5 width owner pin union does not close over eleven source roles")
    expected_owner_pins = {
        role: expected_owner_pins[role] for role in sorted(expected_owner_pins)
    }
    _require(contract["schema"] == JOURNAL_WIDTH_CONTRACT_SCHEMA and
             contract["campaign_id"] == audit["campaign_id"] and
             contract["host_id"] == host_id and
             type(contract["original_pins_sha256"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", contract["original_pins_sha256"]) and
             contract["contract_sha256"] == _sha(_canonical(body)) and
             contract["plan_pin"] == original["plan"] and
             contract["source_manifest_pin"] == original["source_manifests"][host_id] and
             contract_owner_pins == expected_owner_pins,
             "Source5 journal-width contract changed its exact campaign/host/input/source pins")
    phases = PHASES
    counts = audit["schedule"]["job_counts"]
    _require(type(contract["job_rows"]) is list and
             type(contract["phase_totals"]) is list and
             type(contract["fixed_event_widths"]) is list,
             "Source5 journal-width contract rows/totals are malformed")
    event_names = (
        "source5_authorized", "source5_app_started",
        "source5_app_terminal", "source5_job_terminal",
    )
    row_fields = {
        "phase", "job_index", "ordinal", "run_id", "job_sha256",
        "event_counts", "maximum_event_bytes_by_kind",
        "failed_event_counts", "failed_event_bytes_by_kind",
        "success_job_bytes", "failed_window_bytes", "failed_event_count",
        "failed_event_count_uplift", "byte_uplift",
    }
    expected_row_count = sum(counts[phase] for phase in phases)
    _require(len(contract["job_rows"]) == expected_row_count and
             len(contract["phase_totals"]) == len(phases),
             "Source5 journal-width contract does not contain every original job row")
    row_position = 0
    phase_totals = []
    successful_count = 0
    successful_bytes = 0
    winner = None
    for phase in phases:
        phase_count = 0
        phase_bytes = 0
        member_count = 1 if phase == "soak" else 2
        expected_counts = {
            "source5_authorized": 1,
            "source5_app_started": member_count,
            "source5_app_terminal": member_count,
            "source5_job_terminal": 1,
        }
        for job_index in range(counts[phase]):
            row = _exact(contract["job_rows"][row_position], row_fields,
                         f"Source5 journal-width {phase} row[{job_index}]")
            row_position += 1
            _require(row["phase"] == phase and row["job_index"] == job_index and
                     type(row["ordinal"]) is int and row["ordinal"] > 0 and
                     type(row["run_id"]) is str and bool(row["run_id"]) and
                     type(row["job_sha256"]) is str and
                     re.fullmatch(r"[0-9a-f]{64}", row["job_sha256"]) and
                     row["event_counts"] == expected_counts and
                     row["failed_event_counts"] == expected_counts,
                     f"Source5 journal-width {phase} row changed original ordinal/index/callback shape")
            success_widths = _exact(row["maximum_event_bytes_by_kind"],
                                    set(event_names),
                                    "Source5 journal-width success line widths")
            failed_widths = _exact(row["failed_event_bytes_by_kind"],
                                   set(event_names),
                                   "Source5 journal-width failed line widths")
            for event in event_names:
                _uint(success_widths[event],
                      f"Source5 journal-width {phase}.{event} success width",
                      positive=True)
                _uint(failed_widths[event],
                      f"Source5 journal-width {phase}.{event} failed width",
                      positive=True)
                _require(success_widths[event] <= MAX_EVENT_BYTES and
                         failed_widths[event] <= MAX_EVENT_BYTES,
                         "Source5 journal-width event line exceeds its source ceiling")
            success_job_bytes = sum(
                expected_counts[event] * success_widths[event]
                for event in event_names
            )
            failed_window_bytes = sum(
                expected_counts[event] * failed_widths[event]
                for event in event_names
            )
            failed_event_count = sum(expected_counts.values())
            _require(row["success_job_bytes"] == success_job_bytes and
                     row["failed_window_bytes"] == failed_window_bytes and
                     row["failed_event_count"] == failed_event_count and
                     row["failed_event_count_uplift"] == 0 and
                     row["byte_uplift"] ==
                         max(0, failed_window_bytes - success_job_bytes),
                     f"Source5 journal-width {phase} row bytes/counts do not close")
            phase_count += failed_event_count
            phase_bytes += success_job_bytes
            candidate = {
                "phase": phase, "job_index": job_index,
                "ordinal": row["ordinal"], "run_id": row["run_id"],
                "job_sha256": row["job_sha256"],
                "failed_event_count": row["failed_event_count"],
                "failed_event_count_uplift": row["failed_event_count_uplift"],
                "failed_window_bytes": row["failed_window_bytes"],
                "success_job_bytes": row["success_job_bytes"],
                "byte_uplift": row["byte_uplift"],
            }
            if (winner is None or
                    (candidate["byte_uplift"],
                     candidate["failed_event_count_uplift"]) >
                    (winner["byte_uplift"],
                     winner["failed_event_count_uplift"])):
                winner = candidate
        phase_totals.append({
            "phase": phase, "job_count": counts[phase],
            "event_count": phase_count,
            "success_event_bytes": phase_bytes,
        })
        successful_count += phase_count
        successful_bytes += phase_bytes
    _require(contract["phase_totals"] == phase_totals,
             "Source5 journal-width contract phase totals differ from original job rows")
    expected_fixed = [
        ("source5_prepared_capacity_registered", "registration"),
        *(("source5_analysis", phase) for phase in (
            "exploration", "aa", "fixed_analysis", "pressure_analysis",
            "soak", "final_analysis",
        )),
    ]
    _require(len(contract["fixed_event_widths"]) == len(expected_fixed),
             "Source5 journal-width contract fixed events omit an original event")
    fixed_count = 0
    fixed_bytes = 0
    maximum_line_bytes = 0
    for index, (row_value, identity) in enumerate(zip(
        contract["fixed_event_widths"], expected_fixed, strict=True,
    )):
        row = _exact(row_value, {
            "event", "phase", "count", "maximum_line_bytes",
        }, f"Source5 journal-width fixed row[{index}]")
        _uint(row["maximum_line_bytes"],
              f"Source5 journal-width fixed line[{index}]", positive=True)
        _require((row["event"], row["phase"]) == identity and
                 row["count"] == 1 and row["maximum_line_bytes"] <= MAX_EVENT_BYTES,
                 "Source5 journal-width fixed event identity/width differs")
        fixed_count += row["count"]
        fixed_bytes += row["count"] * row["maximum_line_bytes"]
        maximum_line_bytes = max(maximum_line_bytes, row["maximum_line_bytes"])
    for row in contract["job_rows"]:
        maximum_line_bytes = max(
            maximum_line_bytes,
            *row["maximum_event_bytes_by_kind"].values(),
            *row["failed_event_bytes_by_kind"].values(),
        )
    expected_total_count = fixed_count + successful_count
    expected_total_bytes = fixed_bytes + successful_bytes + max(
        0, winner["byte_uplift"] if winner is not None else 0,
    )
    _require(winner is not None and
             contract["failed_owner_window"] == winner and
             contract["total_event_count"] == expected_total_count ==
                audit["schedule"]["maximum_callback_events"] and
             contract["total_event_bytes"] == expected_total_bytes,
             "Source5 journal-width contract winner or campaign totals differ")
    _uint(contract["total_event_bytes"],
          "Source5 journal-width total journal bytes", positive=True)
    return contract, expected_total_count, maximum_line_bytes


def _verify_captured_prepared_width_contract_v2(
    pin_value: object, raw_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    pin = _exact(pin_value, {"path", "raw_sha256", "semantic_sha256"},
                 "Source5 v5 journal-width contract pin")
    _pin(pin, "Source5 v5 journal-width contract pin")
    _require(type(raw_value) is bytes and
             0 < len(raw_value) <= MAX_JOURNAL_WIDTH_CONTRACT_BYTES and
             _sha(raw_value) == pin["raw_sha256"],
             "Source5 v5 journal-width contract captured bytes differ from their raw pin")
    try:
        value = json.loads(raw_value)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise BudgetPlanError("Source5 v5 journal-width contract is malformed") from error
    _require(type(value) is dict and raw_value == _canonical(value) and
             value.get("schema") == SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2 and
             value.get("contract_sha256") == pin["semantic_sha256"] ==
                 _sha(_canonical({key: item for key, item in value.items()
                                  if key != "contract_sha256"})),
             "Source5 v5 width-v2 canonical/raw/semantic identities differ")
    return value, raw_value, pin


def _validate_prepared_width_v2_summary(
    contract_value: object, audit: dict[str, Any], owner_contract_value: object,
) -> tuple[dict[str, Any], int, int]:
    """Check v2 current-only widths and full logical schedule accounting."""
    fields = {
        "schema", "campaign_id", "host_id", "original_pins_sha256",
        "plan_pin", "source_manifest_pin", "owner_pins", "job_rows",
        "phase_totals", "fixed_event_widths", "total_event_count",
        "total_event_bytes", "failed_owner_window", "contract_sha256",
        "admission_profile", "ancestor",
    }
    contract = _exact(contract_value, fields, "Source5 prepared width-v2 contract")
    body = {key: value for key, value in contract.items()
            if key != "contract_sha256"}
    original = audit["original_pins"]
    host_id = audit["host_id"]
    source_pins = original.get("source_manifests")
    _require(contract["schema"] == SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2 and
             contract["admission_profile"] == SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE and
             contract["campaign_id"] == audit["campaign_id"] and
             contract["host_id"] == host_id and
             _digest(contract["contract_sha256"], "Source5 v5 width digest") ==
                 _sha(_canonical(body)) and
             contract["plan_pin"] == original["plan"] and
             type(source_pins) is dict and
             contract["source_manifest_pin"] == source_pins[host_id],
             "Source5 v5 width campaign/host/Plan/Source identity differs")
    _digest(contract["original_pins_sha256"],
            "Source5 v5 width original-pin digest")

    catalogue_owner_pins = (owner_contract_value.get("owner_source_pins")
                            if type(owner_contract_value) is dict else None)
    audit_owner_pins = audit.get("producer_catalogue", {}).get("owner_schema_pins")
    catalogue_roles = {
        "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
        "soak_reader", "offline_dispatcher", "chronology", "evidence_transport",
    }
    audit_roles = {
        "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
        "soak_reader", "feedback_composer", "feedback_reader",
        "pressure_reader", "evidence_transport",
    }
    _require(type(catalogue_owner_pins) is dict and
             set(catalogue_owner_pins) == catalogue_roles and
             (audit_owner_pins is None or
              (type(audit_owner_pins) is dict and set(audit_owner_pins) == audit_roles)),
             "Source5 v5 width audit lacks its exact owner source profiles")
    expected_owner_pins: dict[str, dict[str, Any]] = {}
    for role, pin_value in catalogue_owner_pins.items():
        row = _exact(pin_value, {"path", "raw_sha256", "byte_count"},
                     f"Source5 v5 catalogue owner pin {role}")
        _require(type(row["path"]) is str and bool(row["path"]) and
                 _digest(row["raw_sha256"], f"Source5 v5 owner {role} digest") ==
                     row["raw_sha256"],
                 f"Source5 v5 catalogue owner pin {role} is malformed")
        _uint(row["byte_count"], f"Source5 v5 owner {role} byte count", positive=True)
        expected_owner_pins[role] = dict(row)
    width_owner = _exact(contract["owner_pins"], catalogue_roles | audit_roles,
                         "Source5 v5 width owner pin map")
    if audit_owner_pins is not None:
        for role, row_value in audit_owner_pins.items():
            row = _exact(row_value, {"path", "mode", "sha256", "size"},
                         f"Source5 v5 audit owner pin {role}")
            normalized = {"path": row["path"], "raw_sha256": row["sha256"],
                          "byte_count": row["size"]}
            _require(row["mode"] in {"100644", "100755"} and
                     _digest(normalized["raw_sha256"], f"Source5 v5 audit owner {role} digest") ==
                         normalized["raw_sha256"],
                     f"Source5 v5 audit owner pin {role} is malformed")
            _uint(normalized["byte_count"], f"Source5 v5 audit owner {role} bytes", positive=True)
            prior = expected_owner_pins.get(role)
            _require(prior is None or prior == normalized,
                     f"Source5 v5 width owner {role} differs between selected Source profiles")
            expected_owner_pins[role] = normalized
    else:
        for role in audit_roles - catalogue_roles:
            row = _exact(width_owner[role], {"path", "raw_sha256", "byte_count"},
                         f"Source5 v5 budget-only width owner pin {role}")
            _require(type(row["path"]) is str and bool(row["path"]),
                     f"Source5 v5 budget-only width owner pin {role} path is malformed")
            _digest(row["raw_sha256"], f"Source5 v5 budget-only owner {role} digest")
            _uint(row["byte_count"], f"Source5 v5 budget-only owner {role} bytes", positive=True)
            expected_owner_pins[role] = dict(row)
    _require(set(expected_owner_pins) == set(width_owner) and
             width_owner == expected_owner_pins,
             "Source5 v5 width owner pins differ from the exact selected Source")

    prepared = _exact(original.get("prepared_exploration"), set(source_pins),
                      "Source5 v5 prepared-exploration host pins")
    ancestor = _exact(contract["ancestor"], {
        "bridge_header_pin", "record_index_pin", "header_byte_count",
        "index_byte_count", "job_list_sha256", "journal", "phase_ledger",
    }, "Source5 v5 width ancestor")
    for pin_name, label in (("bridge_header_pin", "bridge header"),
                            ("record_index_pin", "record index")):
        pin = _exact(ancestor[pin_name], {"path", "raw_sha256"},
                     f"Source5 v5 ancestor {label} pin")
        _raw_origin_pin(pin, f"Source5 v5 ancestor {label} pin")
    _uint(ancestor["header_byte_count"], "Source5 v5 header byte count", positive=True)
    _uint(ancestor["index_byte_count"], "Source5 v5 index byte count", positive=True)
    _digest(ancestor["job_list_sha256"], "Source5 v5 ancestor job-list digest")
    lineage_pin = _exact(prepared[host_id], {"bridge_header", "record_index"},
                         "Source5 v5 selected provenance pins")
    _require(ancestor["bridge_header_pin"] == lineage_pin["bridge_header"] and
             ancestor["record_index_pin"] == lineage_pin["record_index"],
             "Source5 v5 width ancestor differs from the full provenance-v2 host map")
    journal = _exact(ancestor["journal"], {
        "pin", "byte_count", "record_count", "head",
    }, "Source5 v5 ancestor journal")
    _raw_origin_pin(journal["pin"], "Source5 v5 ancestor journal pin")
    _require(_uint(journal["byte_count"], "Source5 v5 journal byte count", positive=True) > 0 and
             journal["record_count"] == 2161 and type(journal["record_count"]) is int,
             "Source5 v5 ancestor journal count differs from the exact initial horizon")
    _digest(journal["head"], "Source5 v5 ancestor journal head")
    ledger = _exact(ancestor["phase_ledger"], {
        "pin", "byte_count", "row_count",
    }, "Source5 v5 ancestor phase ledger")
    _raw_origin_pin(ledger["pin"], "Source5 v5 ancestor phase-ledger pin")
    _uint(ledger["byte_count"], "Source5 v5 phase-ledger byte count", positive=True)
    _require(ledger["row_count"] == 360 and type(ledger["row_count"]) is int,
             "Source5 v5 ancestor phase ledger row count differs")

    counts = {"exploration": 0, "aa": 48, "confirmation": 8100,
              "pressure": 8100, "soak": 1}
    expected_events = {"exploration": 0, "aa": 288,
                       "confirmation": 48600, "pressure": 48600, "soak": 4}
    _require(type(contract["phase_totals"]) is list and
             len(contract["phase_totals"]) == len(PHASES) and
             type(contract["job_rows"]) is list and
             len(contract["job_rows"]) == 16249,
             "Source5 v5 width rows do not close over current jobs only")
    phase_totals = []
    winner = None
    maximum_line = 0
    successful_event_count = 0
    successful_event_bytes = 0
    position = 0
    run_ids = set()
    row_fields = {
        "phase", "job_index", "ordinal", "run_id", "job_sha256",
        "event_counts", "maximum_event_bytes_by_kind", "failed_event_counts",
        "failed_event_bytes_by_kind", "success_job_bytes", "failed_window_bytes",
        "failed_event_count", "failed_event_count_uplift", "byte_uplift",
    }
    event_names = ("source5_authorized", "source5_app_started",
                   "source5_app_terminal", "source5_job_terminal")
    for phase in PHASES:
        if phase == "exploration":
            phase_totals.append({"phase": phase, "job_count": 0,
                                 "event_count": 0, "success_event_bytes": 0})
            continue
        phase_count = 0
        phase_bytes = 0
        member_count = 1 if phase == "soak" else 2
        event_counts = {
            "source5_authorized": 1,
            "source5_app_started": member_count,
            "source5_app_terminal": member_count,
            "source5_job_terminal": 1,
        }
        _require(sum(event_counts.values()) * counts[phase] == expected_events[phase],
                 "Source5 v5 current phase callback shape differs")
        for index in range(counts[phase]):
            row = _exact(contract["job_rows"][position], row_fields,
                         f"Source5 v5 width {phase} row[{index}]")
            position += 1
            _require(row["phase"] == phase and row["job_index"] == index and
                     type(row["ordinal"]) is int and row["ordinal"] > 0 and
                     type(row["run_id"]) is str and bool(row["run_id"]) and
                     row["run_id"] not in run_ids and
                     _digest(row["job_sha256"], f"Source5 v5 {phase} job digest") ==
                         row["job_sha256"] and row["event_counts"] == event_counts and
                     row["failed_event_counts"] == event_counts,
                     f"Source5 v5 width {phase} row order/identity/callbacks differ")
            run_ids.add(row["run_id"])
            success = _exact(row["maximum_event_bytes_by_kind"], set(event_names),
                             "Source5 v5 success event widths")
            failed = _exact(row["failed_event_bytes_by_kind"], set(event_names),
                            "Source5 v5 failed event widths")
            for name in event_names:
                _uint(success[name], f"Source5 v5 {phase}.{name} success", positive=True)
                _uint(failed[name], f"Source5 v5 {phase}.{name} failed", positive=True)
                _require(success[name] <= MAX_EVENT_BYTES and failed[name] <= MAX_EVENT_BYTES,
                         "Source5 v5 event width exceeds its finite ceiling")
                maximum_line = max(maximum_line, success[name], failed[name])
            success_bytes = sum(event_counts[name] * success[name] for name in event_names)
            failed_bytes = sum(event_counts[name] * failed[name] for name in event_names)
            event_count = sum(event_counts.values())
            _require(row["success_job_bytes"] == success_bytes and
                     row["failed_window_bytes"] == failed_bytes and
                     row["failed_event_count"] == event_count and
                     row["failed_event_count_uplift"] == 0 and
                     row["byte_uplift"] == max(0, failed_bytes - success_bytes),
                     f"Source5 v5 width {phase} byte/event arithmetic differs")
            phase_count += event_count
            phase_bytes += success_bytes
            candidate = {key: row[key] for key in (
                "phase", "job_index", "ordinal", "run_id", "job_sha256",
                "failed_event_count", "failed_event_count_uplift",
                "failed_window_bytes", "success_job_bytes", "byte_uplift",
            )}
            if winner is None or (candidate["byte_uplift"],
                                  candidate["failed_event_count_uplift"]) > (
                                      winner["byte_uplift"],
                                      winner["failed_event_count_uplift"]):
                winner = candidate
        phase_totals.append({"phase": phase, "job_count": counts[phase],
                             "event_count": phase_count,
                             "success_event_bytes": phase_bytes})
        successful_event_count += phase_count
        successful_event_bytes += phase_bytes
    _require(position == len(contract["job_rows"]) and
             contract["phase_totals"] == phase_totals and
             successful_event_count == 97492,
             "Source5 v5 width current phase totals differ")
    fixed_expected = [
        ("source5_prepared_capacity_registered", "registration"),
        *(('source5_analysis', phase) for phase in (
            "exploration", "aa", "fixed_analysis", "pressure_analysis",
            "soak", "final_analysis",
        )),
    ]
    _require(type(contract["fixed_event_widths"]) is list and
             len(contract["fixed_event_widths"]) == len(fixed_expected),
             "Source5 v5 fixed event widths omit registration/analysis events")
    fixed_count = 0
    fixed_bytes = 0
    for index, (row_value, identity) in enumerate(zip(
            contract["fixed_event_widths"], fixed_expected, strict=True)):
        row = _exact(row_value, {
            "event", "phase", "count", "maximum_line_bytes",
        }, f"Source5 v5 fixed event[{index}]")
        width = _uint(row["maximum_line_bytes"],
                      f"Source5 v5 fixed event[{index}] width", positive=True)
        _require((row["event"], row["phase"]) == identity and
                 row["count"] == 1 and width <= MAX_EVENT_BYTES,
                 f"Source5 v5 fixed event[{index}] identity/width differs")
        fixed_count += 1
        fixed_bytes += width
        maximum_line = max(maximum_line, width)
    _require(winner is not None and contract["failed_owner_window"] == winner and
             contract["total_event_count"] == fixed_count + successful_event_count == 97499 and
             contract["total_event_bytes"] ==
                 fixed_bytes + successful_event_bytes + max(0, winner["byte_uplift"]),
             "Source5 v5 current event/failure-window totals differ")
    _require(audit["schedule"].get("total_job_count") == 16609 and
             audit["schedule"].get("job_counts") == {
                 "exploration": 360, "aa": 48, "confirmation": 8100,
                 "pressure": 8100, "soak": 1,
             },
             "Source5 v5 width is not bound to the full 16,609-job logical Plan")
    return contract, contract["total_event_count"], maximum_line


def _build_host_evidence_budget_projection(
    audit_value: object, contract_value: object,
    catalogue_value: object, reservation_value: object,
    reservation_pin_value: object, *,
    journal_width_contract_value: object | None = None,
    journal_width_contract_pin_value: object | None = None,
    journal_width_contract_raw: bytes | None = None,
    budget_schema: str = HOST_BUDGET_SCHEMA_V2,
    admission_profile: str | None = None,
) -> dict[str, Any]:
    """Build the shared source-derived body, then size one closed schema."""
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
    if budget_schema == HOST_BUDGET_SCHEMA_V4:
        catalogue = verify_fixed_pair_v3_path_catalogue_chunks(catalogue)
    else:
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
    cleanup_policy_bound = "cleanup_source_shape" in retention
    if cleanup_policy_bound:
        owner_cleanup_fields = {
            "maximum_session_members_per_snapshot",
            "maximum_pidfd_signal_entries_per_snapshot",
            "maximum_signal_snapshots", "maximum_cleanup_errors",
            "maximum_error_text_bytes", "normal_cleanup_poll_count",
            "emergency_cleanup_poll_count", "term_grace_seconds",
            "kill_reap_seconds", "cleanup_poll_interval_seconds",
        }
        owner_cleanup_shape = _exact(
            contract.get("cleanup_source_shape"), owner_cleanup_fields,
            "Source5 source-pinned cleanup limits",
        )
        expected_cleanup_shape = _cleanup_source_shape(
            SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
        )
        _require(owner_cleanup_shape == {
            key: expected_cleanup_shape[key] for key in owner_cleanup_fields
        }, "Source5 cleanup limits differ from their pinned owner-source profile")
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
    execution_schema = audit.get("execution_manifest_schema")
    width_inputs = (
        journal_width_contract_value is not None,
        journal_width_contract_pin_value is not None,
        journal_width_contract_raw is not None,
    )
    _require(len(set(width_inputs)) == 1 and
             (execution_schema in {
                  "allocatbelt.application-source5-campaign-execution.v4",
                  "allocatbelt.application-source5-campaign-execution.v5",
              } or
              not any(width_inputs)),
             "Source5 journal-width contract inputs are partial or outside bounded execution")
    width_contract_bound = all(width_inputs)
    _require(budget_schema in {HOST_BUDGET_SCHEMA_V2, HOST_BUDGET_SCHEMA_V3,
                               HOST_BUDGET_SCHEMA_V4},
             "Source5 budget projection schema is unsupported")
    if budget_schema == HOST_BUDGET_SCHEMA_V2:
        _require(admission_profile is None,
                 "legacy Source5 v2 budget cannot carry an admission profile")
    elif budget_schema == HOST_BUDGET_SCHEMA_V3:
        _require(admission_profile == SOURCE5_V3_ADMISSION_PROFILE and
                 execution_schema ==
                    "allocatbelt.application-source5-campaign-execution.v4" and
                 width_contract_bound,
                 "Source5 ready v3 requires its exact v4 admission profile and width contract")
    else:
        _require(admission_profile == SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE and
                 execution_schema ==
                    "allocatbelt.application-source5-campaign-execution.v5" and
                 width_contract_bound,
                 "Source5 ready v4 requires its exact V5 profile and width contract")
    if width_contract_bound:
        _require(cleanup_policy_bound,
                 "Source5 v4 catalogue omits exact failed-cleanup retention rows")
    _require(execution_schema in EXECUTION_SCHEMAS,
             "Source5 v2 budget lacks its exact execution-manifest schema")
    schedule = dict(audit["schedule"])
    journal_width_contract_pin = None
    journal_width_contract = None
    if width_contract_bound:
        if budget_schema == HOST_BUDGET_SCHEMA_V4:
            journal_width_contract, width_event_count, maximum_line_bytes = \
                _validate_prepared_width_v2_summary(
                    journal_width_contract_value, audit, contract,
                )
        else:
            journal_width_contract, width_event_count, maximum_line_bytes = \
                _validate_journal_width_contract_summary(
                    journal_width_contract_value, audit, contract,
                )
        journal_width_contract_pin = _exact(
            journal_width_contract_pin_value,
            {"path", "raw_sha256", "semantic_sha256"},
            "Source5 journal-width contract raw/semantic pin",
        )
        _pin(journal_width_contract_pin,
             "Source5 journal-width contract raw/semantic pin")
        if budget_schema == HOST_BUDGET_SCHEMA_V4:
            pinned_contract, _width_raw, _width_pin = \
                _verify_captured_prepared_width_contract_v2(
                    journal_width_contract_pin, journal_width_contract_raw,
                )
        else:
            pinned_contract, _width_raw, _width_pin = \
                _verify_captured_journal_width_contract(
                    journal_width_contract_pin, journal_width_contract_raw,
                )
        _require(pinned_contract == journal_width_contract and
                 journal_width_contract_pin["semantic_sha256"] ==
                    journal_width_contract["contract_sha256"] and
                 width_event_count == schedule["maximum_callback_events"],
                 "Source5 bounded journal-width contract body/pin differs from the source audit")
        schedule["maximum_callback_events"] = width_event_count
        schedule["maximum_callback_event_bytes"] = maximum_line_bytes
        schedule["worst_case_journal_bytes"] = \
            journal_width_contract["total_event_bytes"]
    else:
        _require(not any(width_inputs),
                 "Source5 legacy budget cannot bind a partial journal-width contract")
    event_count = _uint(schedule["maximum_callback_events"],
                         "Source5 v2 callback event bound", positive=True)
    event_bytes = _uint(schedule["maximum_callback_event_bytes"],
                         "Source5 v2 callback event width", positive=True)
    if journal_width_contract is None:
        _require(schedule["worst_case_journal_bytes"] == min(
                     CORE_ROLE_BYTES_CAP, event_count * event_bytes,
                 ),
                 "Source5 legacy v2 journal audit formula differs from its original Plan projection")
    else:
        _require(schedule["maximum_callback_events"] ==
                    journal_width_contract["total_event_count"] and
                 schedule["worst_case_journal_bytes"] ==
                    journal_width_contract["total_event_bytes"],
                 "Source5 v4 journal reservation differs from the complete width contract")
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
    body_projection = {
        "schema": budget_schema,
        "campaign_id": audit["campaign_id"], "host_id": audit["host_id"],
        "original_pins": audit["original_pins"], "schedule": schedule,
        "owner_contract": contract, "path_catalogue": catalogue,
        "storage_reservation": {
            "pin": reservation_pin, "roots": roots,
            "required_bytes_by_root": base_required_bytes,
            "required_inodes_by_root": required_inodes,
        },
        "role_byte_reservations": catalogue["role_byte_bounds"],
        "transport": transport,
    }
    if budget_schema == HOST_BUDGET_SCHEMA_V2:
        body_projection["execution_blockers"] = ([
            "source_derived_journal_width_not_bound",
            "verified_between_pair_archive_ack_reclaim_not_integrated",
        ] if journal_width_contract_pin is None else [
            "verified_between_pair_archive_ack_reclaim_not_integrated",
        ])
        body_projection["readiness"] = {
            "budget_complete": False, "execution_ready": False,
            "component_gate_ready": False, "qualification_eligible": False,
        }
    else:
        body_projection["admission_profile"] = admission_profile
        body_projection["execution_blockers"] = []
        body_projection["readiness"] = {
            "budget_complete": True, "execution_ready": True,
            "component_gate_ready": False, "qualification_eligible": False,
        }
    if journal_width_contract_pin is not None:
        body_projection["execution_manifest_schema"] = execution_schema
        body_projection["journal_width_contract_pin"] = journal_width_contract_pin
    if budget_schema in {HOST_BUDGET_SCHEMA_V3, HOST_BUDGET_SCHEMA_V4}:
        expected_counts = {
            "exploration": 360, "aa": 48, "confirmation": 8100,
            "pressure": 8100, "soak": 1,
        }
        expected_phase_events = {
            "exploration": (360, 2160), "aa": (48, 288),
            "confirmation": (8100, 48600), "pressure": (8100, 48600),
            "soak": (1, 4),
        }
        expected_callback_count = 99659 if budget_schema == HOST_BUDGET_SCHEMA_V3 else 97499
        expected_width_rows = 16609 if budget_schema == HOST_BUDGET_SCHEMA_V3 else 16249
        _require(schedule["job_counts"] == expected_counts and
                 schedule["total_job_count"] == 16609 and
                 schedule["maximum_callback_events"] == expected_callback_count and
                 journal_width_contract is not None and
                 journal_width_contract["total_event_count"] == expected_callback_count and
                 len(journal_width_contract["job_rows"]) == expected_width_rows and
                 type(journal_width_contract["phase_totals"]) is list and
                 [(row.get("phase"), row.get("job_count"), row.get("event_count"))
                  for row in journal_width_contract["phase_totals"]] ==
                    ([(phase, *expected_phase_events[phase])
                      for phase in PHASES] if budget_schema == HOST_BUDGET_SCHEMA_V3 else
                     [("exploration", 0, 0), ("aa", 48, 288),
                      ("confirmation", 8100, 48600),
                      ("pressure", 8100, 48600), ("soak", 1, 4)]),
                 "Source5 ready budget requires the exact logical/current callback domains")
        all_counts = schedule.get("all_host_job_counts")
        audit_pins = audit.get("original_pins")
        original_source_pins = (
            audit_pins.get("source_manifests") if type(audit_pins) is dict else None
        )
        expected_host_ids = set(original_source_pins) if type(original_source_pins) is dict else set()
        _require(len(expected_host_ids) in (2, 3) and
                 type(all_counts) is dict and set(all_counts) == expected_host_ids and
                 all(type(row) is dict and
                     {phase: row.get(phase) for phase in PHASES} == expected_counts
                     for row in all_counts.values()),
                 "Source5 ready v3 requires the exact host map of complete original Plan schedules")
    budget_bytes = 0
    result: dict[str, Any] = {}
    for _ in range(32):
        required_bytes = dict(base_required_bytes)
        for path, role in roles.items():
            if role in {"artifact", "evidence_store"}:
                required_bytes[path] += budget_bytes
        body = dict(body_projection)
        storage = dict(body_projection["storage_reservation"])
        storage["required_bytes_by_root"] = required_bytes
        storage["required_inodes_by_root"] = required_inodes
        body["storage_reservation"] = storage
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



def build_host_evidence_budget_v2(
    audit_value: object, contract_value: object,
    catalogue_value: object, reservation_value: object,
    reservation_pin_value: object, *,
    journal_width_contract_value: object | None = None,
    journal_width_contract_pin_value: object | None = None,
    journal_width_contract_raw: bytes | None = None,
) -> dict[str, Any]:
    """Build the legacy non-ready v2 budget with its original exact fields."""
    return _build_host_evidence_budget_projection(
        audit_value, contract_value, catalogue_value, reservation_value,
        reservation_pin_value,
        journal_width_contract_value=journal_width_contract_value,
        journal_width_contract_pin_value=journal_width_contract_pin_value,
        journal_width_contract_raw=journal_width_contract_raw,
        budget_schema=HOST_BUDGET_SCHEMA_V2,
    )


def build_host_evidence_budget_v3(
    audit_value: object, contract_value: object,
    catalogue_value: object, reservation_value: object,
    reservation_pin_value: object, *,
    journal_width_contract_value: object,
    journal_width_contract_pin_value: object,
    journal_width_contract_raw: bytes,
) -> dict[str, Any]:
    """Build the SourceH-admitted ready budget for a complete original v4 plan."""
    _require(type(audit_value) is dict and
             audit_value.get("execution_manifest_schema") ==
                "allocatbelt.application-source5-campaign-execution.v4",
             "Source5 ready v3 accepts only an execution-v4 source-owned audit")
    _require(type(journal_width_contract_value) is dict and
             type(journal_width_contract_pin_value) is dict and
             type(journal_width_contract_raw) is bytes,
             "Source5 ready v3 requires the exact raw-pinned width contract")
    return _build_host_evidence_budget_projection(
        audit_value, contract_value, catalogue_value, reservation_value,
        reservation_pin_value,
        journal_width_contract_value=journal_width_contract_value,
        journal_width_contract_pin_value=journal_width_contract_pin_value,
        journal_width_contract_raw=journal_width_contract_raw,
        budget_schema=HOST_BUDGET_SCHEMA_V3,
        admission_profile=SOURCE5_V3_ADMISSION_PROFILE,
    )


def build_host_evidence_budget_v4(
    audit_value: object, contract_value: object,
    catalogue_value: object, reservation_value: object,
    reservation_pin_value: object, *,
    journal_width_contract_value: object,
    journal_width_contract_pin_value: object,
    journal_width_contract_raw: bytes,
    final_spec_raw: bytes,
    lineage_artifact_reader,
    catalogue_row_reader=None,
) -> dict[str, Any]:
    """Build the V5 current-journal budget over the full logical Plan."""
    _require(type(audit_value) is dict and
             audit_value.get("execution_manifest_schema") ==
                "allocatbelt.application-source5-campaign-execution.v5" and
             type(journal_width_contract_value) is dict and
             type(journal_width_contract_pin_value) is dict and
             type(journal_width_contract_raw) is bytes and
             type(final_spec_raw) is bytes and callable(lineage_artifact_reader),
             "Source5 v4 budget requires exact V5 inputs, width-v2 bytes, and a closed lineage reader")
    result = _build_host_evidence_budget_projection(
        audit_value, contract_value, catalogue_value, reservation_value,
        reservation_pin_value,
        journal_width_contract_value=journal_width_contract_value,
        journal_width_contract_pin_value=journal_width_contract_pin_value,
        journal_width_contract_raw=journal_width_contract_raw,
        budget_schema=HOST_BUDGET_SCHEMA_V4,
        admission_profile=SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE,
    )
    return validate_host_evidence_budget_v4(
        result,
        journal_width_contract_raw=journal_width_contract_raw,
        final_spec_raw=final_spec_raw,
        lineage_artifact_reader=lineage_artifact_reader,
        catalogue_row_reader=catalogue_row_reader,
    )


def _validate_source5_v3_ready_state(value: object) -> None:
    """Require literal JSON booleans in the ready-but-unqualified v3 flags."""
    readiness = _exact(value, {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "Source5 v3 readiness")
    expected = {
        "budget_complete": True, "execution_ready": True,
        "component_gate_ready": False, "qualification_eligible": False,
    }
    _require(all(type(readiness[field]) is bool and
                 readiness[field] is expected[field]
                 for field in expected),
             "Source5 v3 readiness flags are not the exact literal ready/unqualified booleans")


def _read_lineage_pin_v4(
    artifact_reader, pin_value: object, maximum: int, label: str,
) -> bytes:
    pin = _raw_origin_pin(pin_value, f"{label} raw pin")
    try:
        raw = artifact_reader(dict(pin), maximum)
    except Exception as error:
        raise BudgetPlanError(
            f"{label} is unavailable from the closed lineage capture store",
        ) from error
    _require(type(raw) is bytes and 0 < len(raw) <= maximum and
             _sha(raw) == pin["raw_sha256"],
             f"{label} captured bytes differ from their exact raw pin/cap")
    return raw


def _validate_prepared_journal_chain_v4(
    raw: bytes, campaign_id: str, host_id: str, expected_head: str,
) -> None:
    """Check the raw predecessor chain and terminal head for 2,161 rows."""
    lines = raw.splitlines(keepends=True)
    _require(len(lines) == 2161 and all(
        line.endswith(b"\n") and b"\r" not in line for line in lines
    ), "Source5 v4 ancestor journal framing/count differs")
    previous = "0" * 64
    for sequence, line in enumerate(lines, start=1):
        try:
            envelope = json.loads(line)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise BudgetPlanError(
                f"Source5 v4 ancestor journal row[{sequence - 1}] is malformed",
            ) from error
        _require(type(envelope) is dict and line == _canonical(envelope),
                 f"Source5 v4 ancestor journal row[{sequence - 1}] is noncanonical")
        envelope = _exact(envelope, {
            "previous_sha256", "record", "record_sha256",
        }, f"Source5 v4 ancestor journal row[{sequence - 1}]")
        record = envelope["record"]
        _require(type(record) is dict and
                 record.get("sequence") == sequence and
                 record.get("campaign_id") == campaign_id and
                 record.get("host_id") == host_id and
                 envelope["previous_sha256"] == previous,
                 f"Source5 v4 ancestor journal row[{sequence - 1}] identity/chain differs")
        digest = _sha(_canonical({"previous_sha256": previous, "record": record}))
        _require(envelope["record_sha256"] == digest,
                 f"Source5 v4 ancestor journal row[{sequence - 1}] digest differs")
        previous = digest
    _require(previous == expected_head,
             "Source5 v4 ancestor journal terminal head differs from its header/width pins")


def _validate_prepared_lineage_budget_v4(
    budget: dict[str, Any], width: dict[str, Any], final_spec_raw: bytes,
    lineage_artifact_reader, catalogue: dict[str, Any], *, catalogue_row_reader=None,
) -> None:
    """Bind captured ancestor bytes and current catalogue to the exact profile."""
    try:
        spec = json.loads(final_spec_raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise BudgetPlanError("Source5 v4 final Spec bytes are malformed") from error
    _require(type(spec) is dict and final_spec_raw == _canonical(spec) and
             spec.get("schema") == SPEC_SCHEMA and
             spec.get("campaign_id") == budget["campaign_id"],
             "Source5 v4 final Spec bytes are not the selected canonical SpecV3")
    spec_pin = _pin(budget["original_pins"].get("spec"),
                    "Source5 v4 actual final Spec pin")
    _require(_sha(final_spec_raw) == spec_pin["raw_sha256"] and
             _sha(_canonical(spec)) == spec_pin["semantic_sha256"],
             "Source5 v4 final Spec raw/semantic bytes differ from budget original pins")
    host_ids = _validated_spec_host_ids(spec)
    _require(len(host_ids) == 2 and budget["host_id"] in host_ids and
             set(budget["original_pins"]["source_manifests"]) == set(host_ids),
             "Source5 v4 requires the complete explicit two-KVM host profile")
    prepared = _exact(budget["original_pins"].get("prepared_exploration"),
                      set(host_ids), "Source5 v4 prepared-exploration host pins")
    ancestor = _exact(width["ancestor"], {
        "bridge_header_pin", "record_index_pin", "header_byte_count",
        "index_byte_count", "job_list_sha256", "journal", "phase_ledger",
    }, "Source5 v4 selected ancestor width DTO")
    selected = budget["host_id"]
    _require(ancestor["bridge_header_pin"] == prepared[selected]["bridge_header"] and
             ancestor["record_index_pin"] == prepared[selected]["record_index"],
             "Source5 v4 width ancestor differs from its exact provenance-v2 host pins")
    current_rows = (iter_path_catalogue_rows(catalogue)
                    if catalogue_row_reader is None else
                    iter_path_catalogue_rows_with_reader(
                        catalogue, catalogue_row_reader,
                    ))
    retained_roles = {
        "preparation", "evidence_index", "journal", "source5_phase_ledger",
        "source_manifest", "spec_v3", "plan_v3", "execution_manifest",
        "observed_host", "host_evidence_budget", "journal_width_contract",
        "fixed_spec_host",
        "preparatory_journal_width_contract", "capacity_artifact",
        "capacity_completion", "capacity_host_receipt", "capacity_ledger",
        "source5_archive_signer_context", "source5_archive_signer_keyring",
        "source5_archive_signer_gpgv", "source5_job_row_catalogue",
        "source5_job_record", *ARCHIVE_LOCAL_METADATA_ROLES,
    }
    captured_rows: dict[str, dict[str, Any]] = {}
    for row in current_rows:
        if row["role"] not in retained_roles:
            continue
        _require(row["path"] not in captured_rows,
                 f"Source5 v4 retained catalogue repeats {row['path']}")
        captured_rows[row["path"]] = row

    def captured_cap(pin: dict[str, str], label: str) -> int:
        row = captured_rows.get(pin["path"])
        _require(type(row) is dict and row["kind"] == "file" and
                 (row["origin_pin"] is None or
                  row["origin_pin"].get("raw_sha256") == pin["raw_sha256"]),
                 f"{label} has no matching authenticated current catalogue row")
        return row["max_bytes"]

    expected_catalogue_rows: dict[str, dict[str, Any]] = {}
    catalogue_owner_host: str | None = None

    def expect_catalogue_row(
        pin: dict[str, str], byte_count: int, role: str | None,
        host: str, phase: str | None = None, run_id: str | None = None,
    ) -> None:
        _require(catalogue_owner_host in host_ids,
                 "Source5 v4 retained origin has no old-catalogue owner")
        prior = expected_catalogue_rows.get(pin["path"])
        expected = {"raw_sha256": pin["raw_sha256"], "byte_count": byte_count,
                    "role": role, "host_id": host, "phase": phase,
                    "run_id": run_id}
        if prior is None:
            expected["catalogue_hosts"] = {catalogue_owner_host}
            expected_catalogue_rows[pin["path"]] = expected
        else:
            _require(all(prior.get(field) == expected[field] for field in expected),
                     f"Source5 v4 captured origin {pin['path']} has conflicting Source descriptors")
            prior["catalogue_hosts"].add(catalogue_owner_host)

    index_jobs_by_host = {}
    index_rows_by_host = {}
    headers_by_host = {}
    old_budgets_by_host = {}
    execution_manifests_by_host = {}
    for host in host_ids:
        catalogue_owner_host = host
        host_pins = _exact(prepared[host], {"bridge_header", "record_index"},
                           f"Source5 v4 {host} provenance-v2 pins")
        header_raw = _read_lineage_pin_v4(
            lineage_artifact_reader, host_pins["bridge_header"],
            captured_cap(host_pins["bridge_header"], f"{host} bridge header"),
            f"Source5 v4 {host} bridge header",
        )
        if host == selected:
            _require(len(header_raw) == ancestor["header_byte_count"],
                     "Source5 v4 width header byte count differs from captured header")
        expect_catalogue_row(host_pins["bridge_header"], len(header_raw),
                             "preparation", host)
        try:
            header = json.loads(header_raw)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise BudgetPlanError(f"Source5 v4 {host} bridge header is malformed") from error
        _require(type(header) is dict and header_raw == _canonical(header) and
                 header.get("schema") ==
                    "allocatbelt.application-source5-prepared-exploration-bridge-header.v1" and
                 header.get("campaign_id") == budget["campaign_id"] and
                 header.get("host_id") == host and header.get("scope") == "initial_only" and
                 header.get("qualification_eligible") is False,
                 f"Source5 v4 {host} bridge header identity/scope differs")
        initial = header.get("initial")
        _require(type(initial) is dict,
                 f"Source5 v4 {host} bridge header has no original context")
        headers_by_host[host] = header
        old_budget_full_pin = _pin(
            initial["host_budget_pin"],
            f"Source5 v4 {host} old host-budget full pin",
        )
        old_budget_raw_pin = {
            "path": old_budget_full_pin["path"],
            "raw_sha256": old_budget_full_pin["raw_sha256"],
        }
        old_budget_raw = _read_lineage_pin_v4(
            lineage_artifact_reader, old_budget_raw_pin,
            captured_cap(old_budget_raw_pin, f"{host} old host budget"),
            f"Source5 v4 {host} old host budget",
        )
        try:
            old_budget = json.loads(old_budget_raw)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise BudgetPlanError(
                f"Source5 v4 {host} old host budget is malformed",
            ) from error
        _require(old_budget_raw == _canonical(old_budget) and
                 old_budget.get("budget_sha256") ==
                    old_budget_full_pin["semantic_sha256"] ==
                    _sha(_canonical({key: value for key, value in old_budget.items()
                                     if key != "budget_sha256"})) and
                 old_budget.get("schema") == PREPARATORY_BUDGET_SCHEMA and
                 old_budget.get("campaign_id") == budget["campaign_id"] and
                 old_budget.get("host_id") == host,
                 f"Source5 v4 {host} old budget canonical/semantic pin differs")
        old_budgets_by_host[host] = old_budget
        global_pins = (
            (header["journal"]["pin"], "journal", host),
            (header["phase_ledger"]["pin"], "source5_phase_ledger", host),
            (initial["execution_manifest_pin"], "execution_manifest", None),
            (initial["spec_pin"], "spec_v3", None),
            (initial["plan_pin"], "plan_v3", None),
            (initial["observed_host_pin"], "observed_host", host),
            (initial["host_budget_pin"], "host_evidence_budget", host),
            (initial["journal_width_pin"], "journal_width_contract", host),
            (initial["fixed_spec_host_pin"], "fixed_spec_host", host),
            (initial["signer_context_pin"], "source5_archive_signer_context", host),
            (header["pilot"]["pin"], "capacity_artifact", host),
        )
        for pin_value, role, pin_host in global_pins:
            pin = {"path": pin_value["path"],
                   "raw_sha256": pin_value["raw_sha256"]}
            raw = (old_budget_raw if role == "host_evidence_budget" else
                   _read_lineage_pin_v4(
                       lineage_artifact_reader, pin,
                       captured_cap(pin, f"{host} {role}"),
                       f"Source5 v4 {host} {role}",
                   ))
            if role == "execution_manifest":
                execution_full_pin = _pin(
                    pin_value,
                    f"Source5 v4 {host} execution-manifest full pin",
                )
                try:
                    execution_manifest = json.loads(raw)
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise BudgetPlanError(
                        f"Source5 v4 {host} execution manifest is malformed",
                    ) from error
                _require(type(execution_manifest) is dict and
                         raw == _canonical(execution_manifest) and
                         execution_manifest.get("schema") == PREPARATORY_EXECUTION_SCHEMA and
                         execution_manifest.get("campaign_id") == budget["campaign_id"] and
                         execution_manifest.get("host_id") == host and
                         execution_manifest.get("manifest_sha256") ==
                            execution_full_pin["semantic_sha256"] ==
                            _sha(_canonical({key: value for key, value in
                                             execution_manifest.items()
                                             if key != "manifest_sha256"})),
                         f"Source5 v4 {host} execution manifest pin/schema differs")
                execution_manifests_by_host[host] = execution_manifest
            if role == "journal":
                _require(len(raw) == header["journal"]["byte_count"] and
                         len(raw.splitlines()) == 2161 and
                         header["journal"]["record_count"] == 2161,
                         f"Source5 v4 {host} captured initial journal count/bytes differ")
            elif role == "source5_phase_ledger":
                _require(len(raw.splitlines()) == 360 and
                         header["phase_ledger"]["row_count"] == 360,
                         f"Source5 v4 {host} captured initial phase ledger row count differs")
            expect_catalogue_row(pin, len(raw), role, pin_host)
        source_rows = initial.get("source_manifest_pins")
        _require(type(source_rows) is list and len(source_rows) == len(host_ids) and
                 {row.get("host_id") for row in source_rows if type(row) is dict} ==
                    set(host_ids),
                 f"Source5 v4 {host} header Source cohort differs")
        for row in source_rows:
            source_pin = budget["original_pins"]["source_manifests"].get(row["host_id"])
            _require(type(source_pin) is dict and all(
                row.get(field) == source_pin.get(field)
                for field in ("path", "raw_sha256", "semantic_sha256")
            ), f"Source5 v4 {host} header changed {row.get('host_id')} Source pins")
            raw_pin_value = {"path": row["path"],
                             "raw_sha256": row["raw_sha256"]}
            source_raw = _read_lineage_pin_v4(
                lineage_artifact_reader, raw_pin_value,
                captured_cap(raw_pin_value, f"{row['host_id']} source manifest"),
                f"Source5 v4 {row['host_id']} source manifest",
            )
            expect_catalogue_row(raw_pin_value, len(source_raw),
                                 "source_manifest", row["host_id"])
        header_index = header.get("record_index")
        _require(type(header_index) is dict and
                 header_index.get("pin") == host_pins["record_index"] and
                 header_index.get("row_count") == 360,
                 f"Source5 v4 {host} header/index pin or row count differs")
        index_raw = _read_lineage_pin_v4(
            lineage_artifact_reader, host_pins["record_index"],
            captured_cap(host_pins["record_index"], f"{host} record index"),
            f"Source5 v4 {host} record index",
        )
        expect_catalogue_row(host_pins["record_index"], len(index_raw),
                             "evidence_index", host)
        lines = index_raw.splitlines(keepends=True)
        _require(len(lines) == 360 and all(
            line.endswith(b"\n") and b"\r" not in line for line in lines
        ), f"Source5 v4 {host} index does not contain 360 canonical rows")
        jobs = []
        indexed_rows = []
        run_ids = set()
        for index, line in enumerate(lines):
            try:
                row = json.loads(line)
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise BudgetPlanError(
                    f"Source5 v4 {host} index row[{index}] is malformed",
                ) from error
            _require(type(row) is dict and line == _canonical(row) and
                     row.get("schema") ==
                         "allocatbelt.application-source5-prepared-exploration-index-row.v1" and
                     row.get("row_index") == index and type(row.get("job")) is dict and
                     row["job"].get("host_id") == host and
                     row["job"].get("phase") == "exploration" and
                     row.get("job_sha256") == _sha(_canonical(row["job"])) and
                     row["job"].get("run_id") not in run_ids,
                     f"Source5 v4 {host} index row[{index}] changed original job identity/order")
            run_ids.add(row["job"]["run_id"])
            jobs.append(row["job"])
            indexed_rows.append(row)
            archive = row.get("archive_pins")
            _require(type(archive) is dict,
                     f"Source5 v4 {host} index row[{index}] archive pins are malformed")
            pin_roles = ((row.get("job_record_pin"), "source5_job_record"),) + tuple(
                (archive.get(name), role) for name, role in (
                    ("request_pin", "source5_checkpoint_request"),
                    ("checkpoint_pin", "source5_checkpoint"),
                    ("object_manifest_pin", "source5_object_manifest"),
                    ("ack_pin", "source5_archive_ack"),
                    ("signature_pin", "source5_archive_signature"),
                )
            )
            for pin_value, expected_role in pin_roles:
                pin = _exact(pin_value, {"path", "raw_sha256"} |
                             ({"semantic_sha256", "signer_fingerprint"} &
                              (set(pin_value) if type(pin_value) is dict else set())),
                             f"Source5 v4 {host} index row[{index}] raw object pin")
                raw = _read_lineage_pin_v4(
                    lineage_artifact_reader,
                    {"path": pin["path"], "raw_sha256": pin["raw_sha256"]},
                    captured_cap({"path": pin["path"],
                                  "raw_sha256": pin["raw_sha256"]},
                                 f"{host} indexed {expected_role}"),
                    f"Source5 v4 {host} indexed archive object",
                )
                expect_catalogue_row(
                    {"path": pin["path"], "raw_sha256": pin["raw_sha256"]},
                    len(raw), expected_role, host, "exploration",
                    row["job"]["run_id"],
                )
        index_jobs_by_host[host] = jobs
        index_rows_by_host[host] = indexed_rows
        if host == selected:
            _require(_sha(_canonical(jobs)) == ancestor["job_list_sha256"] and
                     len(index_raw) == ancestor["index_byte_count"],
                     "Source5 v4 width ancestor differs from the exact captured record index")
            journal = _exact(header.get("journal"), {
                "pin", "byte_count", "record_count", "head",
            }, "Source5 v4 selected initial journal")
            ledger = _exact(header.get("phase_ledger"), {
                "pin", "row_count",
            }, "Source5 v4 selected phase ledger")
            _require(journal["pin"] == ancestor["journal"]["pin"] and
                     journal["byte_count"] == ancestor["journal"]["byte_count"] and
                     journal["head"] == ancestor["journal"]["head"] and
                     journal["record_count"] == 2161 and
                     ledger["pin"] == ancestor["phase_ledger"]["pin"] and
                     ledger["row_count"] == 360,
                     "Source5 v4 selected header/journal/ledger differs from width ancestor")
            journal_raw = _read_lineage_pin_v4(
                lineage_artifact_reader, journal["pin"],
                captured_cap(journal["pin"], "selected ancestor journal"),
                "Source5 v4 selected ancestor journal",
            )
            ledger_raw = _read_lineage_pin_v4(
                lineage_artifact_reader, ledger["pin"],
                captured_cap(ledger["pin"], "selected ancestor phase ledger"),
                "Source5 v4 selected ancestor phase ledger",
            )
            expect_catalogue_row(journal["pin"], len(journal_raw), "journal", host)
            expect_catalogue_row(ledger["pin"], len(ledger_raw),
                                 "source5_phase_ledger", host)
            _require(len(journal_raw) == ancestor["journal"]["byte_count"] and
                     len(journal_raw.splitlines()) == 2161 and
                     len(ledger_raw) == ancestor["phase_ledger"]["byte_count"] and
                     len(ledger_raw.splitlines()) == 360,
                     "Source5 v4 selected ancestor journal/ledger actual counts differ")
            _validate_prepared_journal_chain_v4(
                journal_raw, budget["campaign_id"], selected,
                ancestor["journal"]["head"],
            )

    shared_originals = source5_preparatory_shared_originals_v1([
        {
            "host_id": host,
            "original_pins": old_budgets_by_host[host]["original_pins"],
            "execution_manifest": execution_manifests_by_host[host],
            "header": headers_by_host[host],
        }
        for host in host_ids
    ])

    # Existing old catalogue chunks are part of retained ancestry. Their caps
    # and raw sizes come from the old signed budget manifest, then the closed
    # reader proves the actual bytes before the current catalogue may reserve
    # them.
    for host in host_ids:
        catalogue_owner_host = host
        header = headers_by_host[host]
        old_budget = old_budgets_by_host[host]
        old_catalogue = old_budget.get("path_catalogue")
        _require(type(old_catalogue) is dict,
                 f"Source5 v4 {host} old budget lacks its path catalogue")
        chunk_pins = {chunk["path"]: chunk for chunk in old_catalogue["chunks"]}
        def read_old_catalogue_chunk(path: str, maximum: int) -> bytes:
            chunk = chunk_pins.get(path)
            _require(type(chunk) is dict and maximum == chunk["byte_count"],
                     "Source5 v4 old catalogue requested an undeclared chunk")
            return _read_lineage_pin_v4(
                lineage_artifact_reader,
                {"path": path, "raw_sha256": chunk["raw_sha256"]},
                captured_cap({"path": path, "raw_sha256": chunk["raw_sha256"]},
                             f"{host} old catalogue chunk"),
                "Source5 v4 old catalogue chunk",
            )
        old_verified = verify_fixed_pair_v3_path_catalogue_chunks_with_reader(
            old_catalogue, read_old_catalogue_chunk,
        )
        for chunk in old_verified["chunks"]:
            raw = read_old_catalogue_chunk(chunk["path"], chunk["byte_count"])
            expect_catalogue_row(
                {"path": chunk["path"], "raw_sha256": chunk["raw_sha256"]},
                len(raw), "source5_job_row_catalogue", host,
            )
        old_indexed_rows = {}
        indexed_roles = {
            "source5_job_record", "source5_checkpoint_request",
            "source5_checkpoint", "source5_object_manifest",
            "source5_archive_ack", "source5_archive_signature",
        }
        for source_row in iter_fixed_pair_v3_path_catalogue_rows_with_reader(
                old_verified, read_old_catalogue_chunk):
            if source_row["kind"] != "file" or source_row["role"] not in indexed_roles:
                continue
            _require(source_row["path"] not in old_indexed_rows,
                     f"Source5 v4 {host} old indexed reservation path is duplicated")
            old_indexed_rows[source_row["path"]] = source_row
        needed = _source5_prepared_lineage_indexed_rows_v4(
            expected_catalogue_rows, index_rows_by_host[host], old_indexed_rows,
            initial_output_root=headers_by_host[host]["initial_output_root"],
            campaign_id=budget["campaign_id"], selected_host=host,
        )
        source_proven_unpinned_roles = {
            "preparation", "evidence_index", "journal",
            "source5_phase_ledger", "capacity_artifact",
            "host_evidence_budget", "execution_manifest",
        }
        source_rows_seen = set()
        retained_global_roles = {
            "preparation", "source_manifest", "spec_v3", "plan_v3",
            "execution_manifest", "observed_host", "host_evidence_budget",
            "journal_width_contract", "preparatory_journal_width_contract",
            "capacity_completion", "capacity_host_receipt", "capacity_ledger",
            "source5_archive_signer_context", "source5_archive_signer_keyring",
            "source5_archive_signer_gpgv",
        }
        shared_rows = {
            shared_originals["preparation"]["path"]: (
                "preparation", shared_originals["preparation"]["raw_sha256"], None,
            ),
            shared_originals["capacity_generation"]["path"]: (
                "capacity_completion",
                shared_originals["capacity_generation"]["raw_sha256"],
                shared_originals["capacity_generation"]["semantic_sha256"],
            ),
        }
        shared_rows_seen = set()
        for source_row in iter_fixed_pair_v3_path_catalogue_rows_with_reader(
                old_verified, read_old_catalogue_chunk):
            expected = needed.get(source_row["path"])
            if expected is not None:
                expected_role = expected["role"]
                role_matches = _prepared_lineage_catalogue_role_matches(
                    expected_role, source_row["role"],
                )
                pin = source_row.get("origin_pin")
                if source_row["path"] in shared_rows:
                    source_host_matches = source_row["host_id"] == host
                elif expected["host_id"] is None:
                    source_host_matches = source_row["host_id"] in {None, host}
                else:
                    source_host_matches = source_row["host_id"] == expected["host_id"]
                origin_matches = (
                    (pin is not None and
                     pin.get("raw_sha256") == expected["raw_sha256"]) or
                    (pin is None and expected_role in
                     (indexed_roles | source_proven_unpinned_roles))
                )
                _require(role_matches and
                         origin_matches and
                         source_row["max_file_bytes"] >= expected["byte_count"] and
                         source_host_matches and
                         (expected["phase"] is None or
                          source_row["phase"] == expected["phase"]) and
                         (expected["run_id"] is None or
                          source_row["run_id"] == expected["run_id"]),
                         f"Source5 v4 {host} retained origin differs from its old Source catalogue")
                source_rows_seen.add(source_row["path"])
            role = source_row["role"]
            origin_pin = source_row.get("origin_pin")
            expected_owner = expected_catalogue_rows.get(source_row["path"])
            shared_row = shared_rows.get(source_row["path"])
            if (source_row["kind"] != "file" or
                    source_row["phase"] is not None or
                    role not in retained_global_roles or
                    (expected_owner is not None and
                     host in expected_owner["catalogue_hosts"] and
                     shared_row is None) or
                    type(origin_pin) is not dict or
                    type(origin_pin.get("raw_sha256")) is not str):
                if shared_row is not None and (
                        type(origin_pin) is not dict or
                        type(origin_pin.get("raw_sha256")) is not str):
                    _require(False,
                             f"Source5 v4 {host} shared SourceH row lacks its exact raw origin")
                continue
            descriptor_role = ("journal_width_contract"
                               if role == "preparatory_journal_width_contract" else
                               role)
            descriptor_host = source_row["host_id"]
            if shared_row is not None:
                shared_role, shared_raw, shared_semantic = shared_row
                _require(role == shared_role and source_row["host_id"] == host and
                         source_row["owner"] == {
                             "preparation": "inputs",
                             "capacity_completion": "capacity_stage",
                         }[shared_role] and
                         source_row["run_id"] is None and
                         origin_pin["raw_sha256"] == shared_raw and
                         origin_pin.get("semantic_sha256") == shared_semantic,
                         f"Source5 v4 {host} shared SourceH row differs from exact provenance")
                descriptor_host = None
                shared_rows_seen.add(shared_role)
            elif descriptor_role in {
                "spec_v3", "plan_v3", "execution_manifest",
                "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
            }:
                descriptor_host = None
            source_pin = {"path": source_row["path"],
                          "raw_sha256": origin_pin["raw_sha256"]}
            raw = _read_lineage_pin_v4(
                lineage_artifact_reader, source_pin,
                captured_cap(source_pin, f"{host} retained {descriptor_role}"),
                f"Source5 v4 {host} retained {descriptor_role}",
            )
            expect_catalogue_row(
                source_pin, len(raw), descriptor_role, descriptor_host,
            )
        _require(set(needed) <= source_rows_seen,
                 f"Source5 v4 {host} old Source catalogue omits retained origins")
        _require(shared_rows_seen == {"preparation", "capacity_completion"},
                 f"Source5 v4 {host} old catalogue omits its provenance-checked shared inputs")

    current_rows = (iter_path_catalogue_rows(catalogue)
                    if catalogue_row_reader is None else
                    iter_path_catalogue_rows_with_reader(
                        catalogue, catalogue_row_reader,
                    ))
    current_seen = set()
    for row in current_rows:
        expected = expected_catalogue_rows.get(row["path"])
        if expected is None:
            continue
        _require(row["path"] not in current_seen and
                 row["role"] == expected["role"] and
                 row["host_id"] == expected["host_id"] and
                 row["phase"] == expected["phase"] and
                 row["run_id"] == expected["run_id"] and
                 row["max_bytes"] == expected["byte_count"] and
                 row["max_file_bytes"] == expected["byte_count"] and
                 type(row["origin_pin"]) is dict and
                 row["origin_pin"].get("raw_sha256") == expected["raw_sha256"],
                 f"Source5 v4 current catalogue changes captured origin {row['path']}")
        current_seen.add(row["path"])
    _require(set(expected_catalogue_rows) == current_seen,
             "Source5 v4 current catalogue omits captured lineage origins")
    current_rows = (iter_path_catalogue_rows(catalogue)
                    if catalogue_row_reader is None else
                    iter_path_catalogue_rows_with_reader(
                        catalogue, catalogue_row_reader,
                    ))
    seen_current = set()
    for row in current_rows:
        expected = expected_catalogue_rows.get(row["path"])
        if expected is None:
            continue
        _require(row["path"] not in seen_current and
                 row["role"] == expected["role"] and
                 row["host_id"] == expected["host_id"] and
                 row["phase"] == expected["phase"] and
                 row["run_id"] == expected["run_id"] and
                 row["max_bytes"] == expected["byte_count"] and
                 row["max_file_bytes"] == expected["byte_count"] and
                 type(row["origin_pin"]) is dict and
                 row["origin_pin"].get("raw_sha256") == expected["raw_sha256"],
                 f"Source5 v4 current catalogue changes captured origin {row['path']}")
        seen_current.add(row["path"])
    _require(set(expected_catalogue_rows) == seen_current,
             "Source5 v4 current catalogue omits exact captured lineage origins")


def _validate_host_evidence_budget_common(
    value: object, *, expected_schema: str,
    journal_width_contract_raw: bytes | None = None,
    catalogue_row_reader=None,
    final_spec_raw: bytes | None = None,
    lineage_artifact_reader=None,
) -> dict[str, Any]:
    """Validate either closed budget version without changing its body."""
    legacy_fields = {
        "schema", "campaign_id", "host_id", "original_pins", "schedule",
        "owner_contract", "path_catalogue", "storage_reservation",
        "role_byte_reservations", "transport", "execution_blockers",
        "readiness", "budget_sha256",
    }
    v4_fields = legacy_fields | {
        "execution_manifest_schema", "journal_width_contract_pin",
    }
    ready_v3_fields = v4_fields | {"admission_profile"}
    _require(type(value) is dict,
             "Source5 host evidence budget is not an object")
    if expected_schema == HOST_BUDGET_SCHEMA_V2:
        if set(value) == v4_fields:
            budget = _exact(value, v4_fields,
                            "Source5 v4 host evidence budget v2")
            width_is_bound = True
            _require(budget["execution_manifest_schema"] ==
                     "allocatbelt.application-source5-campaign-execution.v4",
                     "Source5 extended v2 budget is not bound to execution v4")
        else:
            budget = _exact(value, legacy_fields,
                            "legacy Source5 host evidence budget v2")
            width_is_bound = False
            _require(journal_width_contract_raw is None,
                     "legacy Source5 v2 budget cannot consume v4 width-contract bytes")
        expected_blockers = ([
            "verified_between_pair_archive_ack_reclaim_not_integrated",
        ] if width_is_bound else [
            "source_derived_journal_width_not_bound",
            "verified_between_pair_archive_ack_reclaim_not_integrated",
        ])
        expected_readiness = {
            "budget_complete": False, "execution_ready": False,
            "component_gate_ready": False, "qualification_eligible": False,
        }
        _require(budget["schema"] == HOST_BUDGET_SCHEMA_V2 and
                 budget["execution_blockers"] == expected_blockers and
                 budget["readiness"] == expected_readiness,
                 "Source5 v2 budget readiness differs from the pre-execution state")
    elif expected_schema in {HOST_BUDGET_SCHEMA_V3, HOST_BUDGET_SCHEMA_V4}:
        budget = _exact(value, ready_v3_fields,
                        "Source5 ready host evidence budget")
        width_is_bound = True
        _validate_source5_v3_ready_state(budget.get("readiness"))
        expected_profile = (SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE
                            if expected_schema == HOST_BUDGET_SCHEMA_V4 else
                            SOURCE5_V3_ADMISSION_PROFILE)
        expected_execution = ("allocatbelt.application-source5-campaign-execution.v5"
                              if expected_schema == HOST_BUDGET_SCHEMA_V4 else
                              "allocatbelt.application-source5-campaign-execution.v4")
        _require(budget["schema"] == expected_schema and
                 budget["admission_profile"] == expected_profile and
                 budget["execution_manifest_schema"] == expected_execution and
                 budget["execution_blockers"] == [] and
                 journal_width_contract_raw is not None and
                 (expected_schema != HOST_BUDGET_SCHEMA_V4 or
                  (type(final_spec_raw) is bytes and
                   callable(lineage_artifact_reader))),
                 "Source5 ready admission profile or ready-but-unqualified state differs")
    else:
        raise BudgetPlanError("unsupported Source5 host evidence budget validator")

    _token(budget["campaign_id"], "Source5 v2 campaign ID")
    _token(budget["host_id"], "Source5 v2 host ID")
    _require(type(budget["original_pins"]) is dict and
             type(budget["schedule"]) is dict,
             "Source5 v2 provenance or schedule is malformed")
    original_source_pins = budget["original_pins"].get("source_manifests")
    expected_host_ids = set(original_source_pins) if type(original_source_pins) is dict else set()
    _require(len(expected_host_ids) in (2, 3) and budget["host_id"] in expected_host_ids,
             "Source5 budget original pins do not bind a complete supported host map")
    if expected_schema == HOST_BUDGET_SCHEMA_V4:
        _exact(budget["original_pins"], {
            "spec", "plan", "execution_manifest", "source_manifests",
            "source_tree_sha256", "prepared_exploration",
        }, "Source5 v4 six-key original pins")
        _exact(budget["original_pins"]["prepared_exploration"],
               expected_host_ids, "Source5 v4 prepared host lineage pins")
    catalogue = validate_path_catalogue_manifest(budget["path_catalogue"])
    if width_is_bound:
        if expected_schema == HOST_BUDGET_SCHEMA_V4:
            if catalogue_row_reader is None:
                catalogue = verify_prepared_source5_path_catalogue_chunks(catalogue)
            else:
                catalogue = verify_prepared_source5_path_catalogue_chunks_with_reader(
                    catalogue, catalogue_row_reader,
                )
        elif catalogue_row_reader is None:
            catalogue = verify_path_catalogue_chunks(catalogue)
        else:
            catalogue = verify_path_catalogue_chunks_with_reader(
                catalogue, catalogue_row_reader,
            )
    width_pin_value = budget.get("journal_width_contract_pin")
    if width_is_bound:
        width_pin = _exact(width_pin_value, {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 v2 journal-width contract pin")
        if expected_schema == HOST_BUDGET_SCHEMA_V4:
            width_contract, width_raw, _width_pin = \
                _verify_captured_prepared_width_contract_v2(
                    width_pin, journal_width_contract_raw,
                )
        else:
            width_contract, width_raw, _width_pin = \
                _verify_captured_journal_width_contract(
                    width_pin, journal_width_contract_raw,
                )
        audit_projection = {
            "campaign_id": budget["campaign_id"],
            "host_id": budget["host_id"],
            "original_pins": budget["original_pins"],
            "schedule": budget["schedule"],
        }
        if expected_schema == HOST_BUDGET_SCHEMA_V4:
            width_contract, width_event_count, width_maximum_line = \
                _validate_prepared_width_v2_summary(
                    width_contract, audit_projection, budget["owner_contract"],
                )
            _validate_prepared_lineage_budget_v4(
                budget, width_contract, final_spec_raw,
                lineage_artifact_reader, catalogue,
                catalogue_row_reader=catalogue_row_reader,
            )
        else:
            width_contract, width_event_count, width_maximum_line = \
                _validate_journal_width_contract_summary(
                    width_contract, audit_projection, budget["owner_contract"],
                )
        _require(budget["schedule"].get("maximum_callback_events") ==
                    width_event_count and
                 budget["schedule"].get("maximum_callback_event_bytes") ==
                    width_maximum_line and
                 budget["schedule"].get("worst_case_journal_bytes") ==
                    width_contract["total_event_bytes"],
                 "Source5 v4 schedule does not consume its pinned exact width contract")
        if expected_schema == HOST_BUDGET_SCHEMA_V3:
            expected_counts = {
                "exploration": 360, "aa": 48, "confirmation": 8100,
                "pressure": 8100, "soak": 1,
            }
            expected_phase_events = {
                "exploration": (360, 2160), "aa": (48, 288),
                "confirmation": (8100, 48600), "pressure": (8100, 48600),
                "soak": (1, 4),
            }
            counts = budget["schedule"].get("job_counts")
            all_counts = budget["schedule"].get("all_host_job_counts")
            _require(counts == expected_counts and
                     budget["schedule"].get("total_job_count") == 16609 and
                     width_event_count == 99659 and
                     len(width_contract["job_rows"]) == 16609 and
                     type(width_contract.get("phase_totals")) is list and
                     [(row.get("phase"), row.get("job_count"), row.get("event_count"))
                      for row in width_contract["phase_totals"]] ==
                        [(phase, *expected_phase_events[phase])
                         for phase in PHASES] and
                     type(all_counts) is dict and set(all_counts) == expected_host_ids and
                     all(type(row) is dict and
                         {phase: row.get(phase) for phase in PHASES} == expected_counts
                         for row in all_counts.values()),
                     "Source5 v3 does not preserve the exact complete original host schedule map")
        elif expected_schema == HOST_BUDGET_SCHEMA_V4:
            expected_counts = {
                "exploration": 360, "aa": 48, "confirmation": 8100,
                "pressure": 8100, "soak": 1,
            }
            counts = budget["schedule"].get("job_counts")
            all_counts = budget["schedule"].get("all_host_job_counts")
            _require(counts == expected_counts and
                     budget["schedule"].get("total_job_count") == 16609 and
                     budget["schedule"].get("maximum_callback_events") == 97499 and
                     width_event_count == 97499 and
                     len(width_contract["job_rows"]) == 16249 and
                     type(width_contract.get("phase_totals")) is list and
                     [(row.get("phase"), row.get("job_count"), row.get("event_count"))
                      for row in width_contract["phase_totals"]] == [
                          ("exploration", 0, 0), ("aa", 48, 288),
                          ("confirmation", 8100, 48600),
                          ("pressure", 8100, 48600), ("soak", 1, 4),
                      ] and type(all_counts) is dict and
                     set(all_counts) == expected_host_ids and
                     all(type(row) is dict and
                         {phase: row.get(phase) for phase in PHASES} == expected_counts
                         for row in all_counts.values()),
                     "Source5 v4 schedule does not preserve logical 16,609 jobs/current 97,499 events")
        width_row = None
        width_row_count = 0
        rows = (iter_path_catalogue_rows(catalogue)
                if catalogue_row_reader is None else
                iter_path_catalogue_rows_with_reader(catalogue, catalogue_row_reader))
        for row in rows:
            if row["path"] == width_pin["path"]:
                width_row = row
                width_row_count += 1
        _require(width_row_count == 1 and width_row is not None and
                 width_row["role"] == "journal_width_contract" and
                 width_row["kind"] == "file" and
                 width_row["phase"] is None and
                 width_row["run_id"] is None and
                 width_row["member_index"] is None and
                 width_row["origin_pin"] == {
                     "raw_sha256": width_pin["raw_sha256"],
                     "semantic_sha256": width_pin["semantic_sha256"],
                 } and width_row["max_file_bytes"] >= len(width_raw),
                 "Source5 v2 path catalogue omits its raw-pinned journal-width contract")
    else:
        _require(width_pin_value is None,
                 "legacy Source5 budget carries an unregistered v4 journal-width pin")
        legacy_schedule = budget["schedule"]
        _require(legacy_schedule.get("worst_case_journal_bytes") == min(
                     CORE_ROLE_BYTES_CAP,
                     legacy_schedule.get("maximum_callback_events", 0) *
                     legacy_schedule.get("maximum_callback_event_bytes", 0),
                 ), "legacy Source5 v2 schedule journal formula differs")
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


def validate_host_evidence_budget_v2(
    value: object, *, journal_width_contract_raw: bytes | None = None,
    catalogue_row_reader=None,
) -> dict[str, Any]:
    """Validate legacy false-ready v2 bytes with their frozen exact field sets."""
    return _validate_host_evidence_budget_common(
        value, expected_schema=HOST_BUDGET_SCHEMA_V2,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_row_reader=catalogue_row_reader,
    )


def validate_host_evidence_budget_v3(
    value: object, *, journal_width_contract_raw: bytes,
    catalogue_row_reader=None,
) -> dict[str, Any]:
    """Validate SourceH's exact ready-but-unqualified v3 admission bytes."""
    return _validate_host_evidence_budget_common(
        value, expected_schema=HOST_BUDGET_SCHEMA_V3,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_row_reader=catalogue_row_reader,
    )


def validate_host_evidence_budget_v4(
    value: object, *, journal_width_contract_raw: bytes,
    final_spec_raw: bytes, lineage_artifact_reader,
    catalogue_row_reader=None,
) -> dict[str, Any]:
    """Validate V5 budget.v4 with separate logical/current horizons and captured ancestry."""
    _require(type(journal_width_contract_raw) is bytes and
             type(final_spec_raw) is bytes and callable(lineage_artifact_reader),
             "Source5 v4 requires exact width bytes, final Spec bytes, and a closed lineage reader")
    return _validate_host_evidence_budget_common(
        value, expected_schema=HOST_BUDGET_SCHEMA_V4,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_row_reader=catalogue_row_reader,
        final_spec_raw=final_spec_raw,
        lineage_artifact_reader=lineage_artifact_reader,
    )


def required_archive_request_schema_v1(
    budget_value: object, execution_manifest_value: object,
    context_value: object,
) -> str | None:
    """Select the request wire schema from the validated Source5 profile.

    This selector is called only after the execution, budget, and archive
    context have been validated against their typed Source pins.  A missing
    result preserves the existing V1/V2 request API for legacy profiles.
    """
    _require(type(budget_value) is dict,
             "Source5 request-schema selected budget is not an object")
    budget = budget_value
    execution = execution_manifest_value
    _require(type(execution) is dict and
             type(execution.get("schema")) is str and
             type(context_value) is dict,
             "Source5 request-schema selector inputs are malformed")
    context = _exact(context_value, {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "source_manifest_pin", "execution_manifest_pin", "plan_pin",
        "resource_budget_pin", "predecessor_ack_pin",
        "authorized_signer_fingerprint",
    }, "Source5 request-schema archive context")
    _require(context["schema"] ==
             "allocatbelt.application-source5-evidence-archive-context.v1" and
             type(context["campaign_id"]) is str and
             type(context["host_id"]) is str and
             context["phase"] in PHASES and
             type(context["job_index"]) is int and
             context["job_index"] >= 0,
             "Source5 request-schema archive context identity is malformed")
    budget_schema = budget.get("schema")
    execution_schema = execution.get("schema")
    if budget_schema == HOST_BUDGET_SCHEMA_V4:
        _require(execution_schema == EXECUTION_SCHEMA_V5,
                 "Source5 budget.v4 is not bound to execution.v5")
    elif execution_schema == EXECUTION_SCHEMA_V5:
        _require(budget_schema == HOST_BUDGET_SCHEMA_V4,
                 "Source5 execution.v5 requires its exact budget.v4")
    elif (budget_schema == PREPARATORY_BUDGET_SCHEMA or
          execution_schema == PREPARATORY_EXECUTION_SCHEMA):
        _require(budget_schema == PREPARATORY_BUDGET_SCHEMA and
                 execution_schema == PREPARATORY_EXECUTION_SCHEMA,
                 "Source5 preparatory execution and budget schemas disagree")
    else:
        known_legacy_budgets = {
            HOST_BUDGET_SCHEMA_V2, HOST_BUDGET_SCHEMA_V3,
            "allocatbelt.application-source5-host-evidence-budget.v1",
        }
        known_legacy_executions = {
            "allocatbelt.application-source5-campaign-execution.v2",
            "allocatbelt.application-source5-campaign-execution.v3",
            "allocatbelt.application-source5-campaign-execution.v4",
        }
        _require(budget_schema in known_legacy_budgets and
                 execution_schema in known_legacy_executions,
                 "Source5 request-schema selector received an unsupported profile pair")
        return None
    require_profile = budget_schema in {
        HOST_BUDGET_SCHEMA_V4, PREPARATORY_BUDGET_SCHEMA,
    }
    if not require_profile:
        return None
    _require(budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"] and
             type(budget.get("budget_sha256")) is str and
             _digest(budget["budget_sha256"],
                     "Source5 request-schema budget digest") ==
                 budget["budget_sha256"],
             "Source5 request-schema budget does not bind the archive context")
    budget_pin = _pin(context["resource_budget_pin"],
                      "Source5 request-schema budget pin")
    _require(budget_pin["semantic_sha256"] == budget["budget_sha256"],
             "Source5 request-schema budget pin has another semantic body")
    execution_pin = _pin(context["execution_manifest_pin"],
                         "Source5 request-schema execution pin")
    _require(execution.get("campaign_id") == context["campaign_id"] and
             execution.get("manifest_sha256") ==
                 execution_pin["semantic_sha256"],
             "Source5 request-schema execution identity differs from the archive context")
    execution_hosts = execution.get("hosts")
    _require(type(execution_hosts) is list and len(execution_hosts) == 2 and
             all(type(host) is str and host for host in execution_hosts) and
             len(set(execution_hosts)) == 2,
             "Source5 fixed-v3 request requires an exact two-host execution map")
    pins = budget.get("original_pins")
    source_manifests = pins.get("source_manifests") if type(pins) is dict else None
    _require(type(source_manifests) is dict and
             len(source_manifests) == 2 and
             set(source_manifests) == set(execution_hosts) and
             context["host_id"] in source_manifests,
             "Source5 fixed-v3 request requires the explicit two-KVM host map")
    if budget_schema == HOST_BUDGET_SCHEMA_V4:
        original_execution = pins.get("execution_manifest")
        host_counts = budget.get("schedule", {}).get("all_host_job_counts")
        host_schedule = host_counts.get(context["host_id"]) if type(host_counts) is dict else None
        current_count = host_schedule.get(context["phase"]) if type(host_schedule) is dict else None
        if context["phase"] == "exploration":
            raise BudgetPlanError(
                "Source5 V5 exploration reuses its captured predecessor and cannot launch a new request",
            )
        _require(execution_schema == EXECUTION_SCHEMA_V5 and
                 context["phase"] in {"aa", "confirmation", "pressure", "soak"} and
                 type(current_count) is int and 0 <= context["job_index"] < current_count and
                 _pin(original_execution,
                      "Source5 request-schema original execution pin") == execution_pin,
                 "Source5 V5 request phase or execution pin is outside its admitted current horizon")
        if context["phase"] in {"aa", "confirmation"}:
            return FIXED_CHECKPOINT_REQUEST_SCHEMA_V3
        return None
    _require(execution_schema == PREPARATORY_EXECUTION_SCHEMA and
             context["phase"] == "exploration" and
             budget.get("profile") == "preparatory_exploration_360_v1",
             "Source5 preparatory fixed-v3 requests are limited to its exact exploration profile")
    schedule = budget.get("read_schedule")
    _require(type(schedule) is list and len(schedule) == 360 and
             0 <= context["job_index"] < len(schedule) and
             type(schedule[context["job_index"]]) is dict,
             "Source5 preparatory v3 request index is outside its exact 360-job budget")
    selected = schedule[context["job_index"]]
    selected_job = selected.get("job") if type(selected) is dict else None
    _require(selected.get("job_index") == context["job_index"] and
             selected.get("request_ordinal") == context["job_index"] and
             selected.get("analysis_phase") == "exploration" and
             type(selected_job) is dict and
             selected_job.get("host_id") == context["host_id"] and
             selected_job.get("comparison_family") == "fixed_policy" and
             selected.get("job_sha256") == _sha(_canonical(selected_job)),
             "Source5 preparatory v3 request does not select its exact original fixed job row")
    return FIXED_CHECKPOINT_REQUEST_SCHEMA_V3


def validate_host_evidence_budget(
    value: object, *, journal_width_contract_raw: bytes | None = None,
    catalogue_row_reader=None, final_spec_raw: bytes | None = None,
    lineage_artifact_reader=None,
) -> dict[str, Any]:
    """Closed-version dispatch for SourceH, archive and packet consumers."""
    _require(type(value) is dict,
             "Source5 host evidence budget is not an object")
    if value.get("schema") == HOST_BUDGET_SCHEMA_V2:
        return validate_host_evidence_budget_v2(
            value, journal_width_contract_raw=journal_width_contract_raw,
            catalogue_row_reader=catalogue_row_reader,
        )
    if value.get("schema") == HOST_BUDGET_SCHEMA_V3:
        return validate_host_evidence_budget_v3(
            value, journal_width_contract_raw=journal_width_contract_raw,
            catalogue_row_reader=catalogue_row_reader,
        )
    if value.get("schema") == HOST_BUDGET_SCHEMA_V4:
        return validate_host_evidence_budget_v4(
            value, journal_width_contract_raw=journal_width_contract_raw,
            final_spec_raw=final_spec_raw,
            lineage_artifact_reader=lineage_artifact_reader,
            catalogue_row_reader=catalogue_row_reader,
        )
    raise BudgetPlanError("unsupported Source5 host evidence budget schema")
