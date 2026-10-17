#!/usr/bin/env python3
"""One bounded, no-link tar packet per completed Source5 job.

The host sends an immutable checkpoint request plus its exact raw-pinned row
bytes. The private coordinator verifies the whole archive before extracting any
member, then copies objects into its private content-addressed staging tree.
Final checkpoints and signed ACKs are produced only after coordinator-side
object fsync and independent reopen.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable


REQUEST_SCHEMA = "allocatbelt.application-source5-evidence-checkpoint-request.v1"
REQUEST_SCHEMA_V2 = "allocatbelt.application-source5-evidence-checkpoint-request.v2"
REQUEST_SCHEMA_V3 = "allocatbelt.application-source5-evidence-checkpoint-request.v3"
CHECKPOINT_SCHEMA = "allocatbelt.application-source5-evidence-job-checkpoint.v1"
CHECKPOINT_SCHEMA_V2 = "allocatbelt.application-source5-evidence-job-checkpoint.v2"
CHECKPOINT_SCHEMA_V3 = "allocatbelt.application-source5-evidence-job-checkpoint.v3"
PROBE_TMPDIR_INVENTORY_SCHEMA_V1 = \
    "allocatbelt.application-feedback-probe-tmpdir-inventory.v1"
PACKET_PIN_SCHEMA = "allocatbelt.application-source5-evidence-transfer-packet-pin.v1"
HOST_BUDGET_SCHEMA = "allocatbelt.application-source5-host-evidence-budget.v2"
HOST_BUDGET_SCHEMA_V3 = "allocatbelt.application-source5-host-evidence-budget.v3"
HOST_BUDGET_SCHEMA_V4 = "allocatbelt.application-source5-host-evidence-budget.v4"
PREPARED_EXPLORATION_ADMISSION_PROFILE = "source5_prepared_exploration_reuse_v1"
PREPARED_EXPLORATION_EXECUTION_SCHEMA = "allocatbelt.application-source5-campaign-execution.v5"
PREPARED_EXPLORATION_SCOPE = "final_prepared_exploration_reuse"
HOST_BUDGET_V3_ADMISSION_PROFILE = "source5_width_v4_captured_replay_v1"
SOURCE5_BUDGET_VALIDATOR_PATH = "scripts/application-source5-evidence-budget.py"
PREPARATORY_EXECUTION_SCHEMA_V1 = (
    "allocatbelt.application-source5-preparatory-exploration-execution.v1"
)
PREPARATORY_BUDGET_SCHEMA_V1 = (
    "allocatbelt.application-source5-preparatory-exploration-budget.v1"
)
PREPARATORY_PROFILE_V1 = "preparatory_exploration_360_v1"
PREPARATORY_ARCHIVE_VALIDATOR_PATH = (
    "scripts/application-source5-evidence-archive.py"
)
PREPARATORY_EXECUTION_FIELDS_V1 = {
    "schema", "campaign_id", "host_id", "hosts", "original_inputs",
    "execution_sources", "modules", "observed_hosts", "artifact_root",
    "output_root", "scope", "phase_order", "protocol_sha256",
    "preparatory_capacity_generation", "preparatory_capacity_registration",
    "preparatory_journal_width_contracts", "preparatory_host_budgets",
    "archive_signer_contexts", "preparatory_execution_basis_sha256",
    "qualification_eligible", "manifest_sha256",
}
PREPARATORY_BUDGET_FIELDS_V1 = {
    "schema", "campaign_id", "host_id", "profile",
    "execution_basis_sha256", "original_pins", "owner_contract", "schedule",
    "read_schedule", "journal_width_contract_pin", "path_catalogue",
    "archive_transport", "retention_policy", "storage_reservation",
    "readiness", "budget_sha256",
}
PREPARATORY_MAX_BUDGET_BYTES = 128 * 1024 * 1024
PREPARATORY_MAX_WIDTH_BYTES = 16 * 1024 * 1024
PREPARATORY_MAX_SPEC_BYTES = 16 * 1024 * 1024
SOURCE_MANIFEST_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
SOURCE_INVENTORY_SCHEMA_V1 = "allocatbelt.application-source-inventory.v1"
HOST_BUDGET_FIELDS_LEGACY = {
    "schema", "campaign_id", "host_id", "original_pins", "schedule",
    "owner_contract", "path_catalogue", "storage_reservation",
    "role_byte_reservations", "transport", "execution_blockers",
    "readiness", "budget_sha256",
}
HOST_BUDGET_FIELDS_R6 = HOST_BUDGET_FIELDS_LEGACY | {
    "execution_manifest_schema", "journal_width_contract_pin",
}
HOST_BUDGET_FIELDS_V3 = HOST_BUDGET_FIELDS_R6 | {"admission_profile"}
HOST_BUDGET_FIELDS = HOST_BUDGET_FIELDS_LEGACY
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
SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES = frozenset({
    "source5_archive_read_response_slot",
    "source5_archive_read_response_incoming",
})
SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES = frozenset({
    "source5_archive_read_bundle",
    "source5_archive_read_bundle_incoming",
})
SOURCE5_ARCHIVE_READ_ROLES = (
    SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES |
    {SOURCE5_ARCHIVE_READ_CONTROL_ROLE}
)
SOURCE5_PATH_CATALOGUE_FIELDS = {
    "schema", "entry_count", "file_count", "tree_count", "chunk_bytes",
    "sort_input_row_count", "sort_input_byte_count", "chunks",
    "maximum_payload_bytes", "maximum_inode_count",
    "maximum_live_inode_count", "retention_policy", "root_byte_bounds",
    "root_inode_bounds", "maximum_index_entries", "maximum_index_bytes",
    "maximum_index_chunks", "maximum_index_manifest_pages",
    "maximum_index_manifest_bytes", "maximum_sort_scratch_bytes",
    "maximum_sort_scratch_inodes", "maximum_index_sort_scratch_bytes",
    "maximum_index_sort_scratch_inodes", "role_byte_bounds",
    "semantic_sha256",
}
SOURCE5_RETENTION_POLICY_FIELDS = {
    "schema", "mode", "success_empty_tree_roles", "always_local_roles",
    "max_live_job_windows", "max_retained_failure_windows",
    "stop_before_next_authorization_on", "reclaim_after", "archive_io_lane",
    "job_group_count", "persistent_root_byte_bounds",
    "persistent_root_inode_bounds",
    "persistent_archive_metadata_root_byte_bounds",
    "persistent_archive_metadata_root_inode_bounds",
    "persistent_archive_metadata_bytes", "persistent_archive_metadata_inodes",
    "persistent_local_job_record_count",
    "persistent_archive_metadata_byte_bounds_by_role",
    "maximum_window_root_byte_bounds", "maximum_window_root_inode_bounds",
    "maximum_live_root_byte_bounds", "maximum_live_root_inode_bounds",
    "maximum_failure_window_tmp_payload_bytes",
    "maximum_failure_window_disposition_bytes", "maximum_window_total_bytes",
    "maximum_window_total_inodes", "maximum_window_index_entries",
    "maximum_window_index_data_bytes", "maximum_checkpoint_request_bytes",
    "maximum_checkpoint_bytes", "maximum_validation_record_bytes",
    "maximum_job_record_bytes", "maximum_object_manifest_bytes",
    "maximum_archive_ack_bytes", "maximum_signature_bytes",
    "maximum_ack_bundle_bytes", "maximum_stage_map_bytes",
    "maximum_transfer_offer_bytes", "archive_metadata_job_group_count",
    "maximum_transfer_packet_bytes", "maximum_transfer_packet_inodes",
    "maximum_failure_window_tmp_index_entries",
    "maximum_failure_window_tmp_index_data_bytes",
    "maximum_full_index_entries", "maximum_full_index_data_bytes",
}
SOURCE5_CLEANUP_RETENTION_FIELDS = {
    "cleanup_source_shape", "maximum_cleanup_sidecar_source_bytes",
    "maximum_cleanup_sidecar_bytes", "maximum_failed_cleanup_window_bytes",
    "maximum_failed_cleanup_window_inodes",
    "maximum_cleanup_sidecar_refusal_bytes",
    "maximum_failed_cleanup_refusal_window_bytes",
    "maximum_failed_cleanup_refusal_window_inodes",
}
ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY = frozenset({
    "directory_node", "source5_phase_ledger", "journal", "evidence_index",
    "evidence_index_data_chunk", "evidence_index_manifest_page",
    "origin_receipt", "host_evidence_budget", "host_evidence_budget_chunk",
    "source5_job_record", "source5_archive_signer_context",
    "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
    "source5_job_row_catalogue", "source5_checkpoint_request",
    "source5_transfer_offer", "source5_checkpoint",
    "source5_object_manifest", "source5_archive_ack",
    "source5_archive_signature", "source5_stage_map",
})
EXECUTION_SCHEMA_V2 = "allocatbelt.application-source5-campaign-execution.v2"
EXECUTION_SCHEMA_V3 = "allocatbelt.application-source5-campaign-execution.v3"
EXECUTION_SCHEMA_V4 = "allocatbelt.application-source5-campaign-execution.v4"
JOURNAL_WIDTH_CONTRACT_SCHEMA = \
    "allocatbelt.application-source5-journal-width-contract.v1"
JOURNAL_WIDTH_CONTRACT_FIELDS = {
    "schema", "campaign_id", "host_id", "original_pins_sha256",
    "plan_pin", "source_manifest_pin", "owner_pins", "job_rows",
    "phase_totals", "fixed_event_widths", "total_event_count",
    "total_event_bytes", "failed_owner_window", "contract_sha256",
}
CATALOGUE_LOCAL_MAP_SCHEMA = "allocatbelt.application-source5-host-catalogue-local-map.v1"
DEPENDENCY_LOCAL_MAP_SCHEMA = "allocatbelt.application-source5-dependency-local-map.v1"
ARCHIVE_SIGNER_CONTEXT_SCHEMA = "allocatbelt.application-source5-archive-signer-context.v1"
NON_EXPORTABLE_JOB_ROLES = frozenset({
    "source5_job_record", "source5_job_disposition",
    SOURCE5_ANALYZER_SPOOL_ROLE,
})
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES = 128 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BUDGET_MODULE_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_WIDTH_CONTRACT_BYTES = 16 * 1024 * 1024
MAX_GPG_OUTPUT_BYTES = 1 << 20
MAX_PATH_BYTES = 4096
# One escaped path plus the fixed digest/count fields of a plain pin.
MAX_INLINE_PIN_BYTES = 6 * MAX_PATH_BYTES + 512
MAX_ROWS = 1_000_000
MAX_OBJECT_BYTES = (1 << 64) - 1
MAX_ARCHIVE_OBJECT_BYTES = 1 << 40
MAX_TOTAL_BYTES = 1 << 48
MAX_ARCHIVE_READ_METADATA_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_READ_OBJECTS = 262_144
MIN_ARCHIVE_READ_BUNDLE_BYTES = 10 * 1024
MAX_U64 = (1 << 64) - 1
BLOCK_BYTES = 1024 * 1024
TAR_BLOCK_BYTES = 512
TAR_RECORD_BYTES = 10240
USTAR_MAX_SIZE = (1 << 33) - 1
MAX_PAX_HEADER_BYTES = 4096
MAX_CATALOGUE_CHUNK_BYTES = 8 * 1024 * 1024
MAX_PROBE_TMPDIR_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_PROBE_CAPTURE_RECEIPT_BYTES = 16 * 1024 * 1024
RENAME_NOREPLACE = 1
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class TransferPacketError(ValueError):
    """A packet, budget pin, source file, or extracted object is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TransferPacketError(message)


def _profile_required_request_schema(profile: object) -> str | None:
    """Return the requirement from the fully checked Source archive profile."""
    if profile is None:
        return None
    _require(type(profile) is dict,
             "selected Source archive profile is not an object")
    if "required_request_schema" not in profile:
        # An older, exactly pinned Source archive has no Fixed profile hook.
        return None
    required = profile["required_request_schema"]
    _require(required is None or
             (type(required) is str and required == REQUEST_SCHEMA_V3),
             "selected Source archive profile returned an unknown request schema")
    return required


def _require_profile_request_schema(
    profile: object, actual_request_schema: object,
) -> None:
    required = _profile_required_request_schema(profile)
    if required is not None:
        _require(type(actual_request_schema) is str and
                 actual_request_schema == required,
                 "actual checkpoint request schema differs from its selected Source profile")


def _request_schema_for_checkpoint_schema(checkpoint_schema: object) -> str:
    paired = {
        CHECKPOINT_SCHEMA: REQUEST_SCHEMA,
        CHECKPOINT_SCHEMA_V2: REQUEST_SCHEMA_V2,
        CHECKPOINT_SCHEMA_V3: REQUEST_SCHEMA_V3,
    }
    _require(type(checkpoint_schema) is str and checkpoint_schema in paired,
             "checkpoint schema has no exact request-schema pairing")
    return paired[checkpoint_schema]


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _canonical(value: Any, *, maximum_bytes: int = MAX_JSON_BYTES) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise TransferPacketError(
            f"{type(value).__name__} is not canonical JSON: {error}"
        ) from error
    _require(len(raw) <= maximum_bytes,
             "packet metadata exceeds its finite byte ceiling")
    return raw


def _budget_body_semantic_sha256(value: object) -> str:
    """Hash a budget body under its exact schema-specific byte ceiling."""
    _require(type(value) is dict,
             "host evidence budget body is not an object")
    maximum = (PREPARATORY_MAX_BUDGET_BYTES
               if value.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1
               else MAX_JSON_BYTES)
    body = {key: item for key, item in value.items()
            if key != "budget_sha256"}
    return _sha(_canonical(body, maximum_bytes=maximum))


def _checkpoint_metadata_limit(value: object) -> int:
    if type(value) is dict and value.get("schema") in {
            REQUEST_SCHEMA_V2,
            "allocatbelt.application-source5-evidence-job-checkpoint.v2",
    }:
        return MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES
    return MAX_JSON_BYTES


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= (1 << 64) - 1 and
             (not positive or value > 0),
             f"{label} is outside its finite integer bound")
    return value


def _path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("/") and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             "\x00" not in value and
             not any(ord(ch) < 32 or ord(ch) == 127 for ch in value),
             f"{label} is not a bounded absolute path")
    pure = PurePosixPath(value)
    _require(".." not in pure.parts and pure.as_posix() == value,
             f"{label} is not normalized")
    return value


def _token(value: object, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None,
             f"{label} is malformed")
    return value


def _is_owner_receipt_role(role: str) -> bool:
    return "receipt" in role.lower() and not role.startswith(
        "probe_capture_inventory_",
    )


def _run_id(value: object, label: str) -> str:
    _require(type(value) is str and
             0 < len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             not any(ord(char) < 32 or ord(char) == 127 for char in value),
             f"{label} is not bounded original run-ID text")
    return value


def _pin(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    return {
        "path": _path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw digest"),
        "semantic_sha256": _digest(row["semantic_sha256"],
                                   f"{label} semantic digest"),
    }


def _pin_raw(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256"}, label)
    return {
        "path": _path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw digest"),
    }


def _tree_contains(root: str, child: str) -> bool:
    prefix = "/" if root == "/" else root + "/"
    return child.startswith(prefix) and child != root


def _validate_tree_inventories(
    value: object, entries: list[dict[str, Any]],
    owner_receipt_pins: dict[str, Any],
) -> tuple[list[dict[str, Any]], set[str]]:
    _require(type(value) is list and len(value) <= MAX_ROWS,
             "tree inventory rows exceed their finite count bound")
    by_origin = {row["origin_path"]: row for row in entries}
    owner_by_pin = {}
    for role, pin_value in owner_receipt_pins.items():
        pin = _pin(pin_value, f"tree owner receipt {role}")
        owner_by_pin[(pin["path"], pin["raw_sha256"],
                      pin["semantic_sha256"])] = role
    checked = []
    prior_root = ""
    file_paths: set[str] = set()
    receipt_paths: set[str] = set()
    total_entries = 0
    for index, value_row in enumerate(value):
        row = _exact(value_row, {
            "owner_job_sha256", "root_path", "role", "owner_receipt_pin",
            "inventory_pin", "inventory_sha256", "entry_count", "byte_count",
            "entries",
        }, f"request tree inventory[{index}]")
        _digest(row["owner_job_sha256"],
                f"tree inventory[{index}] owner job digest")
        root = _path(row["root_path"], f"tree inventory[{index}] root")
        role = _token(row["role"], f"tree inventory[{index}] role")
        _require(role == "opaque_trace" and root > prior_root and
                 not any(_tree_contains(prior["root_path"], root) or
                         _tree_contains(root, prior["root_path"])
                         for prior in checked),
                 "tree roots are not sorted, unique, disjoint opaque-trace declarations")
        prior_root = root
        owner_pin = _pin(row["owner_receipt_pin"],
                         f"tree inventory[{index}] owner receipt")
        owner_role = owner_by_pin.get((owner_pin["path"],
                                       owner_pin["raw_sha256"],
                                       owner_pin["semantic_sha256"]))
        _require(owner_role is not None and
                 re.fullmatch(r"probe_capture_receipt(?:_member[0-9]+)?",
                              owner_role) is not None and
                 not _tree_contains(root, owner_pin["path"]) and
                 owner_pin["path"] not in receipt_paths,
                 "tree inventory does not bind one unique ProbeV2 capture receipt")
        receipt_paths.add(owner_pin["path"])
        inventory_pin = _pin(row["inventory_pin"],
                             f"tree inventory[{index}] inventory object")
        inventory_sha = _digest(row["inventory_sha256"],
                                f"tree inventory[{index}] inventory digest")
        inventory_row = by_origin.get(inventory_pin["path"])
        _require(inventory_pin["semantic_sha256"] == inventory_sha and
                 inventory_row is not None and
                 re.fullmatch(r"probe_capture_inventory(?:_member[0-9]+)?",
                              inventory_row["role"]) is not None and
                 inventory_row["raw_sha256"] == inventory_pin["raw_sha256"] and
                 inventory_row["semantic_sha256"] == inventory_sha and
                 inventory_pin["path"] != root and
                 not _tree_contains(root, inventory_pin["path"]),
                 "tree inventory object does not match its exact request pin")
        _require(all(inventory_pin["path"] != prior["inventory_pin"]["path"]
                     for prior in checked),
                 "one ProbeV2 inventory object cannot describe multiple TMP roots")
        raw_entries = row["entries"]
        _require(type(raw_entries) is list and len(raw_entries) <= MAX_ROWS,
                 "tree inventory entries exceed their finite row count")
        total_entries += len(raw_entries)
        _require(total_entries <= MAX_ROWS,
                 "request tree inventories exceed their shared finite row count")
        checked_entries = []
        prior_path = ""
        byte_count = 0
        for item_index, item_value in enumerate(raw_entries):
            item = _exact(item_value, {
                "path", "kind", "uid", "mode", "size", "raw_sha256",
            }, f"tree inventory[{index}] entry[{item_index}]")
            path = _path(item["path"],
                         f"tree inventory[{index}] entry[{item_index}] path")
            uid = _uint(item["uid"], "tree inventory uid")
            mode = _uint(item["mode"], "tree inventory mode")
            _require(path > prior_path and _tree_contains(root, path) and
                     mode <= 0o7777 and path not in file_paths and
                     path not in {tree["root_path"] for tree in checked},
                     "tree inventory path is unordered, duplicated, or outside its exact root")
            prior_path = path
            if item["kind"] == "directory":
                _require(item["size"] is None and item["raw_sha256"] is None,
                         "tree directory row carries object payload facts")
            elif item["kind"] == "file":
                size = _uint(item["size"], "tree inventory file size")
                raw_sha = _digest(item["raw_sha256"],
                                  "tree inventory file raw digest")
                request_row = by_origin.get(path)
                _require(request_row is not None and
                         request_row["role"] == role and
                         request_row["byte_count"] == size and
                         request_row["raw_sha256"] == raw_sha and
                         request_row["semantic_sha256"] is None,
                         "tree file differs from its exact request object row")
                file_paths.add(path)
                byte_count += size
            else:
                raise TransferPacketError(
                    "ProbeV2 inventory admits only regular files and directories",
                )
            checked_entries.append({
                "path": path, "kind": item["kind"], "uid": uid,
                "mode": mode, "size": item["size"],
                "raw_sha256": item["raw_sha256"],
            })
        declared_entries = _uint(row["entry_count"],
                                 "tree inventory entry count")
        declared_bytes = _uint(row["byte_count"],
                               "tree inventory byte count")
        _require(byte_count <= MAX_U64,
                 "tree inventory payload byte sum exceeds its finite arithmetic bound")
        inventory_paths = {entry["path"]: entry for entry in checked_entries}
        for entry in checked_entries:
            parent_path = PurePosixPath(entry["path"]).parent.as_posix()
            _require(parent_path == root or
                     (parent_path in inventory_paths and
                      inventory_paths[parent_path]["kind"] == "directory"),
                     "tree inventory omits a parent directory or places a child under a file")
        inventory_body = {
            "schema": PROBE_TMPDIR_INVENTORY_SCHEMA_V1,
            "entries": checked_entries,
        }
        expected_sha = _sha(_canonical(inventory_body))
        inventory_raw = _canonical({
            **inventory_body, "inventory_sha256": expected_sha,
        })
        _require(len(inventory_raw) <= MAX_PROBE_TMPDIR_INVENTORY_BYTES and
                 declared_entries == len(checked_entries) and
                 declared_bytes == byte_count and
                 inventory_sha == expected_sha and
                 inventory_pin["raw_sha256"] == _sha(inventory_raw) and
                 inventory_row["byte_count"] == len(inventory_raw),
                 "tree inventory digest/count/byte projection differs")
        checked.append({
            "owner_job_sha256": row["owner_job_sha256"],
            "root_path": root, "role": role,
            "owner_receipt_pin": owner_pin, "inventory_pin": inventory_pin,
            "inventory_sha256": inventory_sha,
            "entry_count": declared_entries, "byte_count": declared_bytes,
            "entries": checked_entries,
        })
    for row in entries:
        _require(all(row["origin_path"] != tree["root_path"]
                     for tree in checked),
                 "opaque-trace root itself cannot be an object row")
        if any(_tree_contains(tree["root_path"], row["origin_path"])
               for tree in checked):
            _require(row["origin_path"] in file_paths,
                     "request contains a directory or undeclared tree descendant payload")
    capture_paths = {
        pin["path"] for role, pin in owner_receipt_pins.items()
        if role.startswith("probe_capture_receipt")
    }
    _require(receipt_paths == capture_paths,
             "tree inventories do not close over the exact ProbeV2 capture receipt set")
    return checked, file_paths


def _validate_probe_capture_tree_receipt(
    tree: dict[str, Any], receipt: dict[str, Any],
) -> None:
    _require(receipt.get("schema") ==
             "allocatbelt.application-feedback-probe-capture.v2" and
             receipt.get("output_matches_probe") is True and
             receipt.get("stderr_empty") is True and
             receipt.get("exit_status") == 0 and
             receipt.get("qualification_eligible") is False and
             receipt.get("execution_ready") is False and
             receipt.get("controller_chronology_proven") is False,
             "tree capture receipt is not a successful nonready ProbeV2 receipt")
    pin = _exact(receipt.get("tmpdir_inventory_pin"), {
        "path", "raw_sha256", "inventory_sha256",
    }, "ProbeV2 receipt TMPDIR inventory pin")
    inventory_pin = tree["inventory_pin"]
    _require(pin == {
        "path": inventory_pin["path"], "raw_sha256": inventory_pin["raw_sha256"],
        "inventory_sha256": tree["inventory_sha256"],
    }, "ProbeV2 capture receipt differs from its exact tree inventory pin")
    initial = _exact(receipt.get("tmpdir_initial"), {
        "path", "device", "inode", "mode", "mount", "available_bytes",
        "available_inodes", "bytes_limit", "inode_limit",
    }, "ProbeV2 initial TMPDIR identity")
    final = _exact(receipt.get("tmpdir_final"), {
        "path", "device", "inode", "mode", "mount", "bytes_used",
        "file_count", "directory_count", "bytes_limit", "inode_limit",
        "available_bytes", "available_inodes",
    }, "ProbeV2 final TMPDIR usage")
    for label, facts in (("initial", initial), ("final", final)):
        _path(facts["path"], f"ProbeV2 {label} TMPDIR path")
        for field in ("device", "inode", "mode", "available_bytes",
                      "available_inodes", "bytes_limit", "inode_limit"):
            _uint(facts[field], f"ProbeV2 {label} TMPDIR {field}")
        mount = _exact(facts["mount"], {
            "mount_id", "major_minor", "mount_root", "mount_point",
            "filesystem_type", "mount_source", "device",
        }, f"ProbeV2 {label} TMPDIR mount")
        _uint(mount["mount_id"], f"ProbeV2 {label} mount ID", positive=True)
        _uint(mount["device"], f"ProbeV2 {label} mount device")
        _require(type(mount["major_minor"]) is str and
                 re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
                 type(mount["mount_root"]) is str and mount["mount_root"].startswith("/") and
                 type(mount["mount_point"]) is str and mount["mount_point"].startswith("/") and
                 type(mount["filesystem_type"]) is str and
                 mount["filesystem_type"] not in {"tmpfs", "ramfs", "devtmpfs"} and
                 type(mount["mount_source"]) is str and
                 mount["device"] == facts["device"],
                 f"ProbeV2 {label} TMPDIR mount identity is malformed")
    for field in ("bytes_used", "file_count", "directory_count"):
        _uint(final[field], f"ProbeV2 final TMPDIR {field}")
    budget = _exact(receipt.get("storage_budget"), {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes",
        "receipt_bytes", "output_inodes",
    }, "ProbeV2 receipt storage budget")
    byte_limit = _uint(budget["tmpdir_bytes"],
                       "ProbeV2 TMPDIR byte cap", positive=True)
    inode_limit = _uint(budget["tmpdir_inodes"],
                        "ProbeV2 TMPDIR inode cap", positive=True)
    files = sum(item["kind"] == "file" for item in tree["entries"])
    directories = sum(item["kind"] == "directory" for item in tree["entries"])
    _require(initial["path"] == final["path"] == tree["root_path"] and
             initial["device"] == final["device"] and
             initial["inode"] == final["inode"] > 0 and
             initial["mode"] == final["mode"] == 0o700 and
             initial["mount"] == final["mount"] and
             initial["bytes_limit"] == final["bytes_limit"] == byte_limit and
             initial["inode_limit"] == final["inode_limit"] == inode_limit and
             final["bytes_used"] == tree["byte_count"] and
             final["file_count"] == files and
             final["directory_count"] == directories and
             tree["entry_count"] == files + directories and
             tree["byte_count"] <= byte_limit and tree["entry_count"] <= inode_limit,
             "ProbeV2 TMPDIR owner counters differ from its exact tree proof")


def _validate_packet_tree_inventory_payloads(
    fd: int, request: dict[str, Any],
    locations: list[dict[str, Any]],
) -> None:
    trees = request.get("tree_inventories")
    if trees is None:
        return
    entries = {row["origin_path"]: row for row in request["entries"]}
    by_location = {row["origin_path"]: row for row in locations}
    receipt_pins = request["owner_receipt_pins"]
    for index, tree in enumerate(trees):
        for pin, label, schema in (
            (tree["inventory_pin"], "inventory", PROBE_TMPDIR_INVENTORY_SCHEMA_V1),
            (tree["owner_receipt_pin"], "capture receipt",
             "allocatbelt.application-feedback-probe-capture.v2"),
        ):
            row = entries[pin["path"]]
            location = by_location.get(pin["path"])
            _require(location is not None,
                     f"tree {label}[{index}] has no packet object member")
            maximum = (MAX_PROBE_TMPDIR_INVENTORY_BYTES if label == "inventory"
                       else MAX_PROBE_CAPTURE_RECEIPT_BYTES)
            raw = _read_tar_bytes(
                fd, location["offset"], location["byte_count"], maximum,
                f"packet tree {label}[{index}] object",
            )
            _require(len(raw) == row["byte_count"] and
                     _sha(raw) == row["raw_sha256"] == pin["raw_sha256"],
                     f"packet tree {label}[{index}] bytes differ from their exact row pin")
            if label == "inventory":
                document = _exact(
                    _parse_canonical(raw, f"packet tree inventory[{index}]",
                                     maximum_bytes=MAX_PROBE_TMPDIR_INVENTORY_BYTES),
                    {"schema", "entries", "inventory_sha256"},
                    f"packet tree inventory[{index}] document",
                )
                body = {key: item for key, item in document.items()
                        if key != "inventory_sha256"}
                _require(document["schema"] == schema and
                         document["entries"] == tree["entries"] and
                         document["inventory_sha256"] == tree["inventory_sha256"] ==
                            _sha(_canonical(body)) == pin["semantic_sha256"],
                         "packet inventory object differs from its sealed tree inventory")
            else:
                receipt, semantic = _document_self_digest(
                    raw, "receipt_sha256", f"packet tree capture receipt[{index}]",
                )
                expected_pin = receipt_pins.get(row["role"])
                _require(row["role"].startswith("probe_capture_receipt") and
                         expected_pin == pin and semantic == pin["semantic_sha256"],
                         "packet capture receipt is not its exact owner pin")
                _validate_probe_capture_tree_receipt(tree, receipt)


def _exact_host_budget(value: object, label: str) -> tuple[dict[str, Any], bool]:
    """Accept only schema-correlated legacy-v2, width-v2, or admitted-v3 shapes."""
    if type(value) is dict and set(value) == HOST_BUDGET_FIELDS_LEGACY:
        parsed = _exact(value, HOST_BUDGET_FIELDS_LEGACY, label)
        _require(parsed.get("schema") == HOST_BUDGET_SCHEMA,
                 f"{label} schema does not match its legacy-v2 field set")
        return parsed, False
    if type(value) is dict and set(value) == HOST_BUDGET_FIELDS_R6:
        parsed = _exact(value, HOST_BUDGET_FIELDS_R6, label)
        _require(parsed.get("schema") == HOST_BUDGET_SCHEMA,
                 f"{label} schema does not match its width-v2 field set")
        return parsed, True
    if type(value) is dict and set(value) == HOST_BUDGET_FIELDS_V3:
        parsed = _exact(value, HOST_BUDGET_FIELDS_V3, label)
        _require(parsed.get("schema") == HOST_BUDGET_SCHEMA_V3 and
                 parsed.get("admission_profile") ==
                    HOST_BUDGET_V3_ADMISSION_PROFILE,
                 f"{label} schema/profile does not match its v3 field set")
        return parsed, True
    _exact(value, HOST_BUDGET_FIELDS_LEGACY, label)
    raise TransferPacketError(f"{label} has an unsupported exact field set")


def _validate_v4_width_contract_bytes(
    raw: bytes, pin_value: object, context: dict[str, Any],
) -> dict[str, Any]:
    pin = _pin(pin_value, "R6 v4 journal-width contract pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "journal-width contract bytes differ from their budget raw pin")
    value = _exact(_parse_canonical(raw, "pinned journal-width contract"),
                   JOURNAL_WIDTH_CONTRACT_FIELDS,
                   "Source5 v4 journal-width contract")
    body = {key: item for key, item in value.items()
            if key != "contract_sha256"}
    plan_pin = _pin(value["plan_pin"], "journal-width PlanV3 pin")
    source_pin = _pin(value["source_manifest_pin"],
                       "journal-width source-manifest pin")
    _require(value["schema"] == JOURNAL_WIDTH_CONTRACT_SCHEMA and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             plan_pin == context["plan_pin"] and
             source_pin == context["source_manifest_pin"] and
             value["contract_sha256"] == _sha(_canonical(body)) ==
                 pin["semantic_sha256"],
             "journal-width contract schema, identity, original pins or semantic digest differs")
    return value


def _read_source_budget_module(
    source_manifest_raw: bytes, context: dict[str, Any],
    execution_manifest_raw: bytes,
) -> dict[str, Any]:
    """Load exactly the v3 validator selected by this pinned SourceV5."""
    source_pin = _pin(context["source_manifest_pin"],
                      "selected SourceV5 manifest pin")
    _require(type(source_manifest_raw) is bytes and
             _sha(source_manifest_raw) == source_pin["raw_sha256"],
             "selected SourceV5 bytes differ from their exact raw pin")
    source = _parse_canonical(
        source_manifest_raw, "selected SourceV5 manifest",
        maximum_bytes=MAX_SOURCE_MANIFEST_BYTES,
    )
    source_body = {key: item for key, item in source.items()
                   if key != "manifest_sha256"}
    inventory = source.get("source")
    _require(source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5 and
             source.get("manifest_sha256") == source_pin["semantic_sha256"] and
             type(inventory) is dict and type(inventory.get("files")) is list,
             "selected SourceV5 schema or semantic pin differs")
    files = inventory["files"]
    _require(source["manifest_sha256"] ==
             _sha(_canonical(source_body,
                             maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)) and
             inventory.get("source_tree_sha256") == _sha(_canonical({
                "schema": SOURCE_INVENTORY_SCHEMA_V1, "entries": files,
             }, maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)),
             "selected SourceV5 typed inventory differs from its tree digest")
    matches = [row for row in files
               if type(row) is dict and
               row.get("path") == SOURCE5_BUDGET_VALIDATOR_PATH]
    _require(len(matches) == 1,
             "selected SourceV5 has no unique budget-validator typed row")
    module_row = _exact(matches[0], {
        "path", "kind", "mode", "sha256", "size",
    }, "selected SourceV5 budget-validator row")
    module_sha = _digest(module_row["sha256"],
                         "selected budget-validator raw source digest")
    module_size = _uint(module_row["size"],
                         "selected budget-validator source size")
    _require(module_row["kind"] == "file" and
             module_row["mode"] in {"100644", "100755"} and
             0 < module_size <= MAX_SOURCE_BUDGET_MODULE_BYTES,
             "selected SourceV5 budget validator is not a bounded regular file")
    execution_pin = _pin(context["execution_manifest_pin"],
                         "selected execution-manifest pin")
    _require(type(execution_manifest_raw) is bytes and
             _sha(execution_manifest_raw) == execution_pin["raw_sha256"],
             "selected execution-manifest bytes differ from their raw pin")
    execution = _parse_canonical(
        execution_manifest_raw, "selected Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    execution_body = {key: item for key, item in execution.items()
                      if key != "manifest_sha256"}
    hosts = execution.get("hosts")
    _require(execution.get("schema") == EXECUTION_SCHEMA_V4 and
             execution.get("campaign_id") == context["campaign_id"] and
             type(hosts) is list and context["host_id"] in hosts and
             execution.get("manifest_sha256") == execution_pin["semantic_sha256"] ==
                 _sha(_canonical(execution_body,
                                 maximum_bytes=MAX_PLAN_BYTES)),
             "selected execution manifest does not bind the Source5 v3 context")
    original = execution.get("original_inputs")
    _require(type(original) is dict and
             type(original.get("source_manifests")) is dict and
             context["host_id"] in original["source_manifests"],
             "selected execution manifest omits the selected SourceV5 raw pin")
    wrapper = _exact(original["source_manifests"][context["host_id"]],
                     {"artifact", "semantic_sha256"},
                     "execution-manifest SourceV5 wrapper")
    artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                       "execution-manifest SourceV5 artifact")
    _require(artifact == {"path": source_pin["path"],
                          "raw_sha256": source_pin["raw_sha256"]} and
             wrapper["semantic_sha256"] == source_pin["semantic_sha256"],
             "selected SourceV5 differs from the execution-manifest original pin")
    execution_sources = execution.get("execution_sources")
    _require(type(execution_sources) is dict and
             context["host_id"] in execution_sources,
             "selected execution manifest omits its SourceV5 source snapshot")
    snapshot = _exact(execution_sources[context["host_id"]], {
        "source_root", "git_commit", "source_tree_sha256", "build_sha256",
    }, "execution-manifest selected SourceV5 snapshot")
    build = source.get("build")
    _require(type(build) is dict and
             snapshot["git_commit"] == inventory.get("git_commit") and
             snapshot["source_tree_sha256"] == inventory["source_tree_sha256"] and
             snapshot["build_sha256"] == _sha(_canonical(build)),
             "execution-manifest source snapshot differs from SourceV5")
    modules = execution.get("modules")
    _require(type(modules) is dict and context["host_id"] in modules and
             type(modules[context["host_id"]]) is dict,
             "selected execution manifest omits its typed script map")
    module_pin = _exact(
        modules[context["host_id"]].get(SOURCE5_BUDGET_VALIDATOR_PATH),
        {"path", "sha256"},
        "execution-manifest budget-validator module pin",
    )
    _require(module_pin == {"path": SOURCE5_BUDGET_VALIDATOR_PATH,
                            "sha256": module_sha},
             "selected budget validator differs from the execution-manifest module pin")

    module_filename = globals().get("__file__")
    _require(type(module_filename) is str and bool(module_filename),
             "executing transfer-packet module has no Source-root file identity")
    source_root = Path(os.path.abspath(module_filename)).parent.parent
    root_fd = _open_abs_dir(str(source_root),
                            "Root-local selected Source5 tree",
                            private_final=False)
    scripts_fd = -1
    try:
        scripts_fd = os.open("scripts", os.O_RDONLY | _O_DIRECTORY |
                             _O_CLOEXEC | _O_NOFOLLOW, dir_fd=root_fd)
        name = "application-source5-evidence-budget.py"
        before_path = os.stat(name, dir_fd=scripts_fd,
                              follow_symlinks=False)
        mode = f"{stat.S_IFMT(before_path.st_mode) | stat.S_IMODE(before_path.st_mode):06o}"
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_size == module_size and mode == module_row["mode"],
                 "Root-local budget-validator mode/size differs from typed SourceV5")
        descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                             _O_NONBLOCK, dir_fd=scripts_fd)
        try:
            before = os.fstat(descriptor)
            _require(_info_key(before) == _info_key(before_path),
                     "Root-local budget-validator changed before its typed read")
            pieces: list[bytes] = []
            hasher = hashlib.sha256()
            total = 0
            while total < module_size:
                block = os.read(descriptor,
                                min(BLOCK_BYTES, module_size - total))
                _require(bool(block),
                         "Root-local budget-validator ended before its typed size")
                total += len(block)
                hasher.update(block)
                pieces.append(block)
            after = os.fstat(descriptor)
            after_path = os.stat(name, dir_fd=scripts_fd,
                                 follow_symlinks=False)
            _require(os.read(descriptor, 1) == b"" and total == module_size and
                     _info_key(before) == _info_key(after) ==
                         _info_key(after_path) and hasher.hexdigest() == module_sha,
                     "Root-local budget-validator bytes differ from typed SourceV5")
            module_raw = b"".join(pieces)
        finally:
            os.close(descriptor)
    finally:
        if scripts_fd >= 0:
            os.close(scripts_fd)
        os.close(root_fd)
    namespace: dict[str, Any] = {
        "__name__": "_allocatbelt_source5_pinned_budget_validator",
        "__file__": str(source_root / SOURCE5_BUDGET_VALIDATOR_PATH),
        "__package__": None,
    }
    try:
        exec(compile(module_raw, namespace["__file__"], "exec"),
             namespace, namespace)
    except Exception as error:
        raise TransferPacketError(
            f"selected Source5 budget validator cannot be loaded: {error}",
        ) from error
    _require(callable(namespace.get("validate_host_evidence_budget_v3")) and
             namespace.get("HOST_BUDGET_SCHEMA_V3") == HOST_BUDGET_SCHEMA_V3,
             "selected Source5 module lacks the exact host-budget v3 validator")
    return namespace


def _prepared_execution_replay_profile_fields_v1(
    execution: dict[str, Any],
) -> set[str]:
    """Recognize immutable owned-profile references without granting replay."""
    if "prepared_replay_inputs" not in execution:
        return set()
    hosts = execution.get("hosts")
    _require(execution.get("schema") == PREPARED_EXPLORATION_EXECUTION_SCHEMA and
             type(hosts) is list and len(hosts) == 2 and
             all(type(host) is str and bool(host) for host in hosts) and
             len(set(hosts)) == 2,
             "owned prepared replay references require the exact two-host V5 cohort")
    refs = _exact(execution["prepared_replay_inputs"], set(hosts),
                   "owned prepared replay profile map")
    pins = [_pin(refs[host], f"owned prepared replay profile {host}")
            for host in hosts]
    _require(len({pin["path"] for pin in pins}) == len(hosts),
             "owned prepared replay profiles alias another host's profile path")
    return {"prepared_replay_inputs"}


def _validate_prepared_execution_signer_binding_v1(
    execution: dict[str, Any], execution_pin: dict[str, str],
    signer_pin: dict[str, str], context: dict[str, Any],
) -> None:
    """Validate only V5 manifest/signer data, never a live SourceA scope."""
    fields = {
        "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
        "modules", "observed_hosts", "artifact_root", "output_root", "phase_order",
        "protocol_sha256", "qualification_eligible", "manifest_sha256", "scope",
        "prepared_input_generation", "prepared_capacity_registration",
        "archive_signer_contexts", "journal_width_contracts",
    } | _prepared_execution_replay_profile_fields_v1(execution)
    _exact(execution, fields, "prepared V5 execution manifest signer binding")
    hosts = execution["hosts"]
    _require(execution["schema"] == PREPARED_EXPLORATION_EXECUTION_SCHEMA and
             execution["scope"] == PREPARED_EXPLORATION_SCOPE and
             execution["campaign_id"] == context["campaign_id"] and
             type(hosts) is list and len(hosts) == 2 and
             all(type(host) is str and bool(host) for host in hosts) and
             len(set(hosts)) == 2 and context["host_id"] in hosts and
             execution["qualification_eligible"] is False and
             execution["phase_order"] == [
                 "exploration", "aa", "confirmation", "fixed_analysis",
                 "pressure", "pressure_analysis", "soak", "final_analysis",
             ] and
             execution["manifest_sha256"] == execution_pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in execution.items()
                                  if key != "manifest_sha256"},
                                 maximum_bytes=MAX_PLAN_BYTES)),
             "prepared V5 execution signer identity, cohort, scope or digest differs")
    widths = _exact(execution["journal_width_contracts"], set(hosts),
                     "prepared V5 execution journal-width map")
    for host in hosts:
        width = _exact(widths[host], {"artifact", "semantic_sha256"},
                        f"prepared V5 execution journal-width wrapper {host}")
        _pin({**_pin_raw(width["artifact"],
                         f"prepared V5 execution journal-width artifact {host}"),
              "semantic_sha256": width["semantic_sha256"]},
             f"prepared V5 execution journal width {host}")
    contexts = _exact(execution["archive_signer_contexts"], set(hosts),
                       "prepared V5 archive signer-context map")
    wrapper = _exact(contexts[context["host_id"]], {
        "artifact", "semantic_sha256",
    }, "prepared V5 signer-context wrapper")
    artifact = _pin_raw(wrapper["artifact"], "prepared V5 signer-context artifact")
    _require(artifact == {"path": signer_pin["path"],
                          "raw_sha256": signer_pin["raw_sha256"]} and
             wrapper["semantic_sha256"] == signer_pin["semantic_sha256"],
             "prepared V5 signer-context pin differs from its exact manifest entry")


def _read_source_archive_preparatory_validator(
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    context: dict[str, Any], *, prepared_exploration: bool = False,
) -> dict[str, Any]:
    """Load the archive validator only from its exact selected Source profile."""
    source_pin = _pin(context["source_manifest_pin"],
                      "preparatory Source manifest pin")
    execution_pin = _pin(context["execution_manifest_pin"],
                         "preparatory execution-manifest pin")
    _require(type(source_manifest_raw) is bytes and
             _sha(source_manifest_raw) == source_pin["raw_sha256"] and
             type(execution_manifest_raw) is bytes and
             _sha(execution_manifest_raw) == execution_pin["raw_sha256"],
             "preparatory packet Source/manifest bytes differ from their raw pins")
    source = _parse_canonical(
        source_manifest_raw, "preparatory selected SourceV5 manifest",
        maximum_bytes=MAX_SOURCE_MANIFEST_BYTES,
    )
    source_body = {key: item for key, item in source.items()
                   if key != "manifest_sha256"}
    inventory = source.get("source")
    _require(source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5 and
             source.get("manifest_sha256") == source_pin["semantic_sha256"] ==
                 _sha(_canonical(source_body,
                                 maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)) and
             type(inventory) is dict and type(inventory.get("files")) is list and
             inventory.get("source_tree_sha256") == _sha(_canonical({
                 "schema": SOURCE_INVENTORY_SCHEMA_V1,
                 "entries": inventory["files"],
             }, maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)),
             "preparatory selected SourceV5 schema/tree/semantic pin differs")
    module_rows = [row for row in inventory["files"]
                   if type(row) is dict and row.get("path") ==
                       PREPARATORY_ARCHIVE_VALIDATOR_PATH]
    _require(len(module_rows) == 1,
             "selected prep Source has no unique archive-validator row")
    module_row = _exact(module_rows[0], {
        "path", "kind", "mode", "sha256", "size",
    }, "selected prep archive-validator typed row")
    module_sha = _digest(module_row["sha256"],
                         "selected prep archive-validator digest")
    module_size = _uint(module_row["size"],
                        "selected prep archive-validator size", positive=True)
    _require(module_row["kind"] == "file" and
             module_row["mode"] in {"100644", "100755"} and
             module_size <= MAX_SOURCE_BUDGET_MODULE_BYTES,
             "selected prep archive validator is not a bounded typed script")
    execution = _parse_canonical(
        execution_manifest_raw, "preparatory selected execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    body = {key: item for key, item in execution.items()
            if key != "manifest_sha256"}
    if prepared_exploration:
        _exact(execution, {
            "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
            "modules", "observed_hosts", "artifact_root", "output_root",
            "phase_order", "protocol_sha256", "qualification_eligible",
            "manifest_sha256", "scope", "prepared_input_generation",
            "prepared_capacity_registration", "archive_signer_contexts",
            "journal_width_contracts",
        } | _prepared_execution_replay_profile_fields_v1(execution),
               "selected prepared-exploration execution manifest")
        _require(execution.get("schema") == PREPARED_EXPLORATION_EXECUTION_SCHEMA and
                 execution.get("scope") == PREPARED_EXPLORATION_SCOPE and
                 type(execution.get("hosts")) is list and
                 context["host_id"] in execution["hosts"] and
                 execution.get("campaign_id") == context["campaign_id"] and
                 execution.get("manifest_sha256") == execution_pin["semantic_sha256"] ==
                     _sha(_canonical(body, maximum_bytes=MAX_PLAN_BYTES)),
                 "selected prepared-exploration execution manifest differs from its exact pin")
        modules = execution.get("modules")
        _require(type(modules) is dict and context["host_id"] in modules and
                 type(modules[context["host_id"]]) is dict,
                 "selected prepared execution manifest omits its Source module map")
        original = _exact(execution.get("original_inputs"), {
            "spec", "plan", "source_manifests", "campaign_artifacts_root",
        }, "selected prepared execution original inputs")
        source_wrappers = original.get("source_manifests")
        _require(type(source_wrappers) is dict and context["host_id"] in source_wrappers,
                 "selected prepared execution omits its Source manifest wrapper")
        wrapper = _exact(source_wrappers[context["host_id"]], {
            "artifact", "semantic_sha256",
        }, "selected prepared Source manifest wrapper")
        artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                          "selected prepared Source manifest artifact")
        _require(artifact == {"path": source_pin["path"],
                              "raw_sha256": source_pin["raw_sha256"]} and
                 wrapper["semantic_sha256"] == source_pin["semantic_sha256"],
                 "selected prepared Source manifest differs from its execution wrapper")
        module_pin = _exact(
            modules[context["host_id"]].get(PREPARATORY_ARCHIVE_VALIDATOR_PATH),
            {"path", "sha256"}, "selected prepared archive-validator module pin",
        )
    else:
        _require(execution.get("schema") == PREPARATORY_EXECUTION_SCHEMA_V1 and
                 execution.get("campaign_id") == context["campaign_id"] and
                 execution.get("host_id") == context["host_id"] and
                 execution.get("manifest_sha256") == execution_pin["semantic_sha256"] ==
                     _sha(_canonical(body, maximum_bytes=MAX_PLAN_BYTES)),
                 "selected prep execution manifest differs from its exact pin")
        modules = execution.get("modules")
        _require(type(modules) is dict and context["host_id"] in modules and
                 type(modules[context["host_id"]]) is dict,
                 "selected prep execution manifest omits its Source module map")
        module_pin = _exact(
            modules[context["host_id"]].get(PREPARATORY_ARCHIVE_VALIDATOR_PATH),
            {"path", "sha256"}, "selected prep archive-validator module pin",
        )
    _require(module_pin == {"path": PREPARATORY_ARCHIVE_VALIDATOR_PATH,
                            "sha256": module_sha},
             "selected prep archive validator differs from its execution pin")
    if not prepared_exploration:
        original = execution.get("original_inputs")
        _require(type(original) is dict and
                 type(original.get("source_manifests")) is dict and
                 context["host_id"] in original["source_manifests"],
                 "selected prep execution manifest omits its Source input wrapper")
        wrapper = _exact(original["source_manifests"][context["host_id"]], {
            "artifact", "semantic_sha256",
        }, "selected prep Source input wrapper")
        artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                           "selected prep Source input artifact")
        _require(artifact == {"path": source_pin["path"],
                              "raw_sha256": source_pin["raw_sha256"]} and
                 wrapper["semantic_sha256"] == source_pin["semantic_sha256"],
                 "selected prep Source manifest differs from its execution wrapper")
    module_filename = globals().get("__file__")
    _require(type(module_filename) is str and bool(module_filename),
             "transfer-packet module has no selected Source root identity")
    source_root = Path(os.path.abspath(module_filename)).parent.parent
    module_path = source_root / PREPARATORY_ARCHIVE_VALIDATOR_PATH
    root_fd = _open_abs_dir(str(source_root),
                            "Root-local preparatory Source tree",
                            private_final=False)
    scripts_fd = -1
    module_fd = -1
    try:
        scripts_fd = os.open("scripts", os.O_RDONLY | _O_DIRECTORY |
                             _O_CLOEXEC | _O_NOFOLLOW, dir_fd=root_fd)
        name = "application-source5-evidence-archive.py"
        before_path = os.stat(name, dir_fd=scripts_fd,
                              follow_symlinks=False)
        actual_mode = f"{stat.S_IFMT(before_path.st_mode) | stat.S_IMODE(before_path.st_mode):06o}"
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_size == module_size and
                 actual_mode == module_row["mode"],
                 "Root-local prep archive validator mode/size differs from its typed Source pin")
        module_fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                            _O_NONBLOCK, dir_fd=scripts_fd)
        before = os.fstat(module_fd)
        _require(_info_key(before) == _info_key(before_path),
                 "Root-local prep archive validator changed before its typed read")
        pieces: list[bytes] = []
        total = 0
        hasher = hashlib.sha256()
        while total < module_size:
            block = os.read(module_fd, min(BLOCK_BYTES, module_size - total))
            _require(bool(block),
                     "Root-local prep archive validator ended before its typed size")
            total += len(block)
            hasher.update(block)
            pieces.append(block)
        after = os.fstat(module_fd)
        after_path = os.stat(name, dir_fd=scripts_fd,
                             follow_symlinks=False)
        _require(os.read(module_fd, 1) == b"" and total == module_size and
                 _info_key(before) == _info_key(after) == _info_key(after_path) and
                 hasher.hexdigest() == module_sha,
                 "Root-local prep archive validator bytes differ from typed Source pin")
        module_raw = b"".join(pieces)
    finally:
        if module_fd >= 0:
            os.close(module_fd)
        if scripts_fd >= 0:
            os.close(scripts_fd)
        os.close(root_fd)
    namespace: dict[str, Any] = {
        "__name__": "_allocatbelt_source5_preparatory_archive_validator",
        "__file__": str(module_path), "__package__": None,
    }
    try:
        exec(compile(module_raw, str(module_path), "exec"),
             namespace, namespace)
    except Exception as error:
        raise TransferPacketError(
            f"selected Source preparatory archive validator cannot load: {error}",
        ) from error
    if prepared_exploration:
        _require(callable(namespace.get(
                    "validate_prepared_exploration_budget_profile_v1")) and
                 namespace.get("PREPARED_EXPLORATION_EXECUTION_SCHEMA") ==
                    PREPARED_EXPLORATION_EXECUTION_SCHEMA and
                 namespace.get("HOST_BUDGET_SCHEMA_V4") == HOST_BUDGET_SCHEMA_V4,
                 "selected Archive source lacks its exact prepared-exploration profile")
    else:
        _require(callable(namespace.get("validate_preparatory_budget_profile_v1")) and
                 namespace.get("PREPARATORY_EXECUTION_SCHEMA_V1") ==
                     PREPARATORY_EXECUTION_SCHEMA_V1 and
                 namespace.get("PREPARATORY_BUDGET_SCHEMA_V1") ==
                     PREPARATORY_BUDGET_SCHEMA_V1,
                 "selected prep archive source lacks its exact profile validator")
    return namespace


def _host_preparatory_dependency_bytes(
    budget: dict[str, Any], context: dict[str, Any], *,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    plan_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    spec_raw: bytes | None,
    root_local: bool,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Use captured Root dependencies or stable host-pinned originals only."""
    if root_local:
        _require(source_manifest_raw is not None and
                 execution_manifest_raw is not None and
                 plan_raw is not None and
                 journal_width_contract_raw is not None and
                 spec_raw is not None,
                 "Root prep validation requires its six captured Source/Plan/budget/exec/width/Spec dependency bytes")
        return (source_manifest_raw, execution_manifest_raw, plan_raw,
                journal_width_contract_raw, spec_raw)
    source_pin = _pin(context["source_manifest_pin"],
                      "host prep Source pin")
    execution_pin = _pin(context["execution_manifest_pin"],
                         "host prep execution-manifest pin")
    if source_manifest_raw is None:
        source_manifest_raw, source_sha, _ = _read_regular_absolute(
            source_pin["path"], MAX_SOURCE_MANIFEST_BYTES,
            "host-pinned preparatory SourceV5 manifest",
        )
        _require(source_sha == source_pin["raw_sha256"],
                 "host prep Source bytes differ from their raw pin")
    if execution_manifest_raw is None:
        execution_manifest_raw, execution_sha, _ = _read_regular_absolute(
            execution_pin["path"], MAX_PLAN_BYTES,
            "host-pinned preparatory execution manifest",
        )
        _require(execution_sha == execution_pin["raw_sha256"],
                 "host prep execution bytes differ from their raw pin")
    plan_pin = _pin(context["plan_pin"], "preparatory host Plan pin")
    if plan_raw is None:
        plan_raw, plan_sha, _ = _read_regular_absolute(
            plan_pin["path"], MAX_PLAN_BYTES,
            "host-pinned preparatory PlanV3",
        )
        _require(plan_sha == plan_pin["raw_sha256"],
                 "host prep Plan bytes differ from their raw pin")
    execution = _parse_canonical(
        execution_manifest_raw, "host preparatory execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    width_wrapper = _exact(
        _exact(execution.get("preparatory_journal_width_contracts"),
               {context["host_id"]}, "host prep width map")[context["host_id"]],
        {"artifact", "semantic_sha256"}, "host prep width wrapper",
    )
    width_pin = _pin({
        **_pin_raw(width_wrapper["artifact"], "host prep width artifact"),
        "semantic_sha256": width_wrapper["semantic_sha256"],
    }, "host prep width pin")
    if journal_width_contract_raw is None:
        journal_width_contract_raw, width_sha, _ = _read_regular_absolute(
            width_pin["path"], PREPARATORY_MAX_WIDTH_BYTES,
            "host-pinned preparatory journal-width contract",
        )
        _require(width_sha == width_pin["raw_sha256"],
                 "host prep width bytes differ from their raw pin")
    spec_pin = _pin(budget["original_pins"]["initial_spec"],
                    "host preparatory original Spec pin")
    if spec_raw is None:
        spec_raw, spec_sha, _spec_info = _read_regular_absolute(
            spec_pin["path"], PREPARATORY_MAX_SPEC_BYTES,
            "host-pinned preparatory original SpecV3",
        )
        _require(spec_sha == spec_pin["raw_sha256"],
                 "host prep SpecV3 bytes differ from their exact raw pin")
    _require(type(spec_raw) is bytes and
             len(spec_raw) <= PREPARATORY_MAX_SPEC_BYTES and
             _sha(spec_raw) == spec_pin["raw_sha256"],
             "host preparatory SpecV3 differs from its exact raw pin")
    return (source_manifest_raw, execution_manifest_raw, plan_raw,
            journal_width_contract_raw, spec_raw)


def _validate_preparatory_budget_profile_v1(
    budget_raw: bytes, budget_pin: object,
    context: dict[str, Any] | None, campaign_id: str, host_id: str, *,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    plan_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    spec_raw: bytes | None,
    catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None,
    root_local: bool,
) -> tuple[dict[str, Any], dict[str, Any],
           tuple[int, int, int, int, list[str], str, int, int]]:
    pin = _pin(budget_pin, "preparatory host budget pin")
    _require(type(budget_raw) is bytes and
             _sha(budget_raw) == pin["raw_sha256"],
             "preparatory budget bytes differ from their exact raw pin")
    budget = _exact(_parse_canonical(
        budget_raw, "preparatory host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    ), PREPARATORY_BUDGET_FIELDS_V1,
                    "preparatory host evidence budget")
    _require(budget["schema"] == PREPARATORY_BUDGET_SCHEMA_V1 and
             budget["profile"] == PREPARATORY_PROFILE_V1 and
             budget["campaign_id"] == campaign_id and
             budget["host_id"] == host_id and
             budget["budget_sha256"] ==
                 _budget_body_semantic_sha256(budget) ==
                 pin["semantic_sha256"],
             "preparatory budget schema/profile/semantic pin differs")
    _require(context is not None and
             context["campaign_id"] == campaign_id and
             context["host_id"] == host_id and
             context["phase"] == "exploration" and
             _uint(context["job_index"], "preparatory host job index") < 360 and
             _pin(context["resource_budget_pin"],
                  "preparatory request budget pin") == pin,
             "preparatory packet validation lacks its original job context")
    source_manifest_raw, execution_manifest_raw, plan_raw, journal_width_contract_raw, spec_raw = \
        _host_preparatory_dependency_bytes(
            budget, context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            root_local=root_local,
        )
    namespace = _read_source_archive_preparatory_validator(
        source_manifest_raw, execution_manifest_raw, context,
    )
    try:
        profile = namespace["validate_preparatory_budget_profile_v1"](
            budget_raw, context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
    except Exception as error:
        raise TransferPacketError(
            f"selected Source preparatory budget/profile validator rejected the packet budget: {error}",
        ) from error
    _require(type(profile) is dict and profile.get("budget") == budget and
             type(profile.get("catalogue")) is dict and
             type(profile.get("transport_row")) is dict,
             "selected Source prep archive validator returned a malformed profile")
    _profile_required_request_schema(profile)
    row = profile["transport_row"]
    catalogue = profile["catalogue"]
    source_retention = budget["retention_policy"].get("source_policy")
    _require(type(source_retention) is dict,
             "preparatory retention lacks its exact source policy")
    index = context["job_index"]
    max_packet = _uint(row.get("transfer_packet_bytes"),
                       "preparatory per-job packet cap", positive=True)
    max_packet_inodes = 1
    max_window_bytes = _uint(
        source_retention.get("maximum_window_total_bytes"),
        "preparatory active-window byte cap", positive=True,
    )
    max_window_inodes = _uint(
        source_retention.get("maximum_window_total_inodes"),
        "preparatory active-window inode cap", positive=True,
    )
    max_ack = _uint(row.get("ack_bundle_bytes"),
                    "preparatory per-job ACK-bundle cap", positive=True)
    max_signature = _uint(
        budget["archive_transport"].get("maximum_signature_bytes"),
        "preparatory detached-signature cap", positive=True,
    )
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict and
             retention.get("maximum_signature_bytes") == max_signature == 4096 and
             max_signature <= MAX_GPG_OUTPUT_BYTES,
             "preparatory signature quota differs from its exact pinned allowance")
    roots = catalogue.get("root_byte_bounds")
    reservation = budget.get("storage_reservation")
    reservation_roots = reservation.get("roots") if type(reservation) is dict else None
    _require(type(roots) is dict and roots and
             type(reservation_roots) is list,
             "preparatory packet budget lacks exact roots/reservation")
    scratch_roots = [row["path"] for row in reservation_roots
                     if type(row) is dict and row.get("role") == "scratch"]
    _require(len(scratch_roots) == 1,
             "preparatory packet budget lacks one exact scratch root")
    limits = (max_packet, max_packet_inodes, max_window_bytes,
              max_window_inodes, list(roots), scratch_roots[0],
              max_ack, max_signature)
    return budget, profile, limits


def _validate_prepared_exploration_budget_profile_v1(
    budget_raw: bytes, budget_pin: object, context: dict[str, Any],
    campaign_id: str, host_id: str, *,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    plan_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    spec_raw: bytes | None,
    dependency_map_raw: bytes | None,
    dependency_cache_root: str | os.PathLike[str] | None,
    lineage_capture_manifest_raw: bytes | None,
    lineage_capture_stage_root: str | None,
    catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None,
    root_local: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    pin = _pin(budget_pin, "prepared V4 host budget pin")
    budget = _exact(_parse_canonical(
        budget_raw, "prepared V4 host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    ), HOST_BUDGET_FIELDS_V3, "prepared V4 host evidence budget")
    _require(type(context) is dict and
             context.get("campaign_id") == campaign_id and
             context.get("host_id") == host_id and
             _pin(context.get("resource_budget_pin"),
                  "prepared request budget context pin") == pin and
             budget.get("schema") == HOST_BUDGET_SCHEMA_V4 and
             budget.get("admission_profile") == PREPARED_EXPLORATION_ADMISSION_PROFILE and
             budget.get("execution_manifest_schema") ==
                 PREPARED_EXPLORATION_EXECUTION_SCHEMA and
             budget.get("campaign_id") == campaign_id and
             budget.get("host_id") == host_id and
             _sha(budget_raw) == pin["raw_sha256"] and
             budget.get("budget_sha256") == pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in budget.items()
                                  if key != "budget_sha256"},
                                 maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES)),
             "prepared V4 budget/context raw or semantic identity differs")
    derived_context, expected = _prepared_exploration_primary_context(budget, pin)
    _require(all(context.get(name) == derived_context[name] for name in (
        "campaign_id", "host_id", "source_manifest_pin", "plan_pin",
        "resource_budget_pin", "execution_manifest_pin",
    )), "prepared request context differs from the exact final budget pins")
    _require(type(lineage_capture_manifest_raw) is bytes and
             type(lineage_capture_stage_root) is str,
             "prepared V4 profile requires its captured lineage manifest and private stage")
    if root_local:
        _require(type(dependency_map_raw) is bytes and
                 dependency_cache_root is not None,
                 "Root prepared V4 profile requires its exact six-copy dependency map")
        primary_context, captured_source, captured_plan, captured_execution, \
            captured_width, captured_spec = _read_root_prepared_exploration_dependencies(
                budget, budget_raw, pin, derived_context,
                dependency_map_raw, dependency_cache_root,
            )
        _require(primary_context == derived_context,
                 "Root prepared V4 six-copy reader returned a changed context")
        source_manifest_raw = captured_source
        plan_raw = captured_plan
        execution_manifest_raw = captured_execution
        journal_width_contract_raw = captured_width
        spec_raw = captured_spec
    else:
        _require(dependency_map_raw is None and dependency_cache_root is None and
                 catalogue_chunk_paths is None and catalogue_cache_root is None,
                 "host prepared V4 validation cannot substitute Root-local maps")
        limits = (
            MAX_SOURCE_MANIFEST_BYTES, MAX_PLAN_BYTES,
            PREPARATORY_MAX_BUDGET_BYTES, MAX_PLAN_BYTES,
            MAX_JOURNAL_WIDTH_CONTRACT_BYTES, PREPARATORY_MAX_SPEC_BYTES,
        )
        captured = []
        for index, (origin_pin, maximum) in enumerate(zip(expected, limits, strict=True)):
            local, digest, _info = _read_regular_absolute(
                Path(origin_pin["path"]), maximum,
                f"prepared host primary dependency[{index}]",
            )
            _require(digest == origin_pin["raw_sha256"],
                     f"prepared host primary dependency[{index}] differs from its raw pin")
            captured.append(local)
        _require(captured[2] == budget_raw,
                 "prepared host primary budget copy differs from supplied bytes")
        source_manifest_raw, plan_raw, _budget_copy, execution_manifest_raw, \
            journal_width_contract_raw, spec_raw = captured
    _require(all(type(raw) is bytes for raw in (
        source_manifest_raw, plan_raw, execution_manifest_raw,
        journal_width_contract_raw, spec_raw,
    )), "prepared V4 six-copy dependency reader did not return exact bytes")
    archive_namespace = _read_source_archive_preparatory_validator(
        source_manifest_raw, execution_manifest_raw, derived_context,
        prepared_exploration=True,
    )
    try:
        profile = archive_namespace[
            "validate_prepared_exploration_budget_profile_v1"
        ](
            budget_raw, context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            lineage_capture_manifest_raw=lineage_capture_manifest_raw,
            lineage_capture_stage_root=lineage_capture_stage_root,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
    except Exception as error:
        raise TransferPacketError(
            f"selected Source V4 budget/profile validator rejected its metadata: {error}",
        ) from error
    _require(type(profile) is dict and profile.get("budget") == budget and
             type(profile.get("catalogue")) is dict and
             type(profile.get("execution_manifest")) is dict and
             (profile.get("required_request_schema") is None or
              profile.get("required_request_schema") == REQUEST_SCHEMA_V3),
             "selected Source prepared profile returned malformed metadata")
    _profile_required_request_schema(profile)
    return budget, profile


def _source_budget_catalogue_reader(
    budget: dict[str, Any], catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None, *, root_local: bool,
):
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             type(catalogue.get("chunks")) is list and
             0 < len(catalogue["chunks"]) <= MAX_ROWS,
             "v3 budget lacks its exact path-catalogue chunk list")
    descriptors: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(catalogue["chunks"]):
        row = _exact(value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"v3 catalogue descriptor[{index}]")
        origin = _path(row["path"], "v3 catalogue chunk origin")
        _digest(row["raw_sha256"], "v3 catalogue chunk raw digest")
        chunk_bytes = _uint(row["byte_count"],
                            "v3 catalogue chunk byte count", positive=True)
        chunk_rows = _uint(row["row_count"],
                            "v3 catalogue row count", positive=True)
        _require(origin not in descriptors and
                 chunk_bytes <= MAX_CATALOGUE_CHUNK_BYTES and
                 chunk_rows <= MAX_ROWS and
                 row["semantic_sha256"] == row["raw_sha256"],
                 "v3 catalogue descriptor repeats or changes its raw pin")
        descriptors[origin] = row
    if root_local:
        _require(type(catalogue_chunk_paths) is dict and
                 catalogue_cache_root is not None and
                 set(catalogue_chunk_paths) == set(descriptors),
                 "Root v3 validator requires the complete captured catalogue map")
        cache_root = Path(_path(catalogue_cache_root,
                                "Root v3 catalogue cache root"))
        cache_fd = _open_abs_dir(str(cache_root),
                                 "Root v3 catalogue cache root",
                                 private_final=True)
        os.close(cache_fd)
    else:
        _require(catalogue_chunk_paths is None and catalogue_cache_root is None,
                 "host v3 validator cannot mix Root-local catalogue mappings")
        cache_root = None

    def read_row(origin_value: str, byte_count_value: int) -> bytes:
        origin = _path(origin_value, "v3 catalogue row origin")
        row = descriptors.get(origin)
        _require(row is not None and
                 _uint(byte_count_value, "v3 catalogue chunk byte count",
                       positive=True) == row["byte_count"],
                 "v3 validator requested a chunk outside its exact descriptor set")
        if root_local:
            local = Path(_path(catalogue_chunk_paths[origin],
                               "Root-local v3 catalogue chunk"))
            _require(local != Path(origin) and local != cache_root and
                     cache_root in local.parents and
                     local.resolve(strict=True) == local,
                     "Root-local v3 catalogue chunk escapes its captured cache")
        else:
            local = Path(origin)
        raw, digest, info = _read_regular_absolute(
            local, row["byte_count"], "Source-pinned v3 catalogue chunk",
        )
        _require(len(raw) == row["byte_count"] and
                 digest == row["raw_sha256"] == row["semantic_sha256"] and
                 info.st_size == row["byte_count"],
                 "Source-pinned v3 catalogue bytes differ from their descriptor")
        return raw

    return read_row


def _validate_ready_host_budget_v3(
    budget_raw: bytes, budget: dict[str, Any], context: dict[str, Any], *,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None,
    root_local: bool,
) -> None:
    pin = _pin(context["resource_budget_pin"], "v3 validator host-budget pin")
    _require(_sha(budget_raw) == pin["raw_sha256"] and
             _sha(_canonical({key: item for key, item in budget.items()
                              if key != "budget_sha256"})) ==
                 pin["semantic_sha256"] and
             source_manifest_raw is not None and
             execution_manifest_raw is not None and
             journal_width_contract_raw is not None,
             "ready v3 validation lacks exact source/exec/width dependencies")
    namespace = _read_source_budget_module(
        source_manifest_raw, context, execution_manifest_raw,
    )
    reader = _source_budget_catalogue_reader(
        budget, catalogue_chunk_paths, catalogue_cache_root,
        root_local=root_local,
    )
    try:
        validated = namespace["validate_host_evidence_budget_v3"](
            budget, journal_width_contract_raw=journal_width_contract_raw,
            catalogue_row_reader=reader,
        )
    except Exception as error:
        raise TransferPacketError(
            f"selected Source5 budget v3 validator rejected its document: {error}",
        ) from error
    _require(validated == budget,
             "selected Source5 v3 validator returned a different budget object")


def _has_h15_archive_readback_roles(catalogue: object) -> bool:
    if type(catalogue) is not dict:
        return False
    role_bounds = catalogue.get("role_byte_bounds")
    if role_bounds is None:
        return False
    _require(type(role_bounds) is dict,
             "host path catalogue role-byte bounds are malformed")
    declared = {role for role in role_bounds
                if type(role) is str and
                role.startswith("source5_archive_read_")}
    has_analyzer_spool = SOURCE5_ANALYZER_SPOOL_ROLE in role_bounds
    _require(not declared or declared == SOURCE5_ARCHIVE_READ_ROLES,
             "H15 archive-read catalogue roles are partial or unknown")
    _require(not has_analyzer_spool or declared == SOURCE5_ARCHIVE_READ_ROLES,
             "v4 analyzer scratch role lacks the exact H15 readback slot closure")
    return bool(declared)


def _validate_execution_manifest_budget_binding(
    raw: bytes, context: dict[str, Any], budget: dict[str, Any],
    journal_width_contract_raw: bytes | None,
) -> dict[str, Any]:
    pin = _pin(context["execution_manifest_pin"],
                "budget execution-manifest context pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "execution-manifest bytes differ from their original context pin")
    value = _parse_canonical(
        raw, "pinned Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    base = {
        "schema", "campaign_id", "hosts", "original_inputs",
        "execution_sources", "modules", "observed_hosts",
        "capacity_completions", "artifact_root", "output_root",
        "phase_order", "protocol_sha256", "qualification_eligible",
        "manifest_sha256",
    }
    schema = budget["execution_manifest_schema"]
    if schema in {EXECUTION_SCHEMA_V2, EXECUTION_SCHEMA_V3}:
        manifest = _exact(value, (base - {"capacity_completions"}) | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration",
        }, "pinned Source5 execution manifest v2/v3")
        expected_scope = ("final_prepared" if schema == EXECUTION_SCHEMA_V2
                          else "final_prepared_bounded")
        _require(manifest["scope"] == expected_scope and
                 budget["journal_width_contract_pin"] is None,
                 "legacy R6 budget pin/scope differs from its execution schema")
    elif schema == EXECUTION_SCHEMA_V4:
        manifest = _exact(value, (base - {"capacity_completions"}) | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration", "archive_signer_contexts",
            "journal_width_contracts",
        }, "pinned Source5 execution manifest v4")
        hosts = manifest["hosts"]
        _require(manifest["scope"] == "final_prepared_bounded" and
                 type(hosts) is list and bool(hosts) and
                 all(type(host) is str and bool(host) for host in hosts) and
                 len(hosts) == len(set(hosts)) and
                 context["host_id"] in hosts,
                 "Source5 v4 execution-manifest scope/host map differs")
        signers = _exact(manifest["archive_signer_contexts"], set(hosts),
                         "Source5 v4 archive signer-context map")
        for host in hosts:
            wrapper = _exact(signers[host], {"artifact", "semantic_sha256"},
                             f"Source5 v4 {host} signer-context wrapper")
            artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                              f"Source5 v4 {host} signer-context artifact")
            _pin({**artifact, "semantic_sha256": wrapper["semantic_sha256"]},
                 f"Source5 v4 {host} signer-context pin")
        width_map = _exact(manifest["journal_width_contracts"], set(hosts),
                           "Source5 v4 journal-width contract map")
        wrapper = _exact(width_map[context["host_id"]], {
            "artifact", "semantic_sha256",
        }, "Source5 v4 selected-host journal-width wrapper")
        artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                           "Source5 v4 selected-host journal-width artifact")
        manifest_width_pin = _pin(
            {**artifact, "semantic_sha256": wrapper["semantic_sha256"]},
            "Source5 v4 selected-host journal-width pin",
        )
        budget_width_pin = _pin(
            budget["journal_width_contract_pin"],
            "Source5 v4 budget journal-width pin",
        )
        _require(manifest_width_pin == budget_width_pin,
                 "v4 budget width pin differs from its execution-manifest host entry")
        _require(journal_width_contract_raw is not None,
                 "v4 host budget requires raw width-contract bytes")
        _validate_v4_width_contract_bytes(
            journal_width_contract_raw, budget_width_pin, context,
        )
    else:
        raise TransferPacketError(
            "R6 host budget names an unsupported execution-manifest schema",
        )
    body = {key: item for key, item in manifest.items()
            if key != "manifest_sha256"}
    _require(manifest["schema"] == schema and
             manifest["campaign_id"] == context["campaign_id"] and
             manifest["qualification_eligible"] is False and
             manifest["manifest_sha256"] == _sha(_canonical(
                 body, maximum_bytes=MAX_PLAN_BYTES,
             )) ==
                 pin["semantic_sha256"],
             "Source5 execution manifest differs from its raw/semantic budget context pin")
    if budget.get("schema") == HOST_BUDGET_SCHEMA_V3:
        root = _path(manifest["artifact_root"],
                     "Source5 v3 artifact root")
        expected_budget_path = _path(
            str(Path(root) / context["campaign_id"] / "source5" /
                context["host_id"] / "evidence-budget" /
                "host-evidence-budget-v3.json"),
            "Source5 v3 deterministic host-budget path",
        )
        budget_pin = _pin(context["resource_budget_pin"],
                          "Source5 v3 host-budget context pin")
        _require(budget_pin["path"] == expected_budget_path and
                 PurePosixPath(budget_pin["path"]).name ==
                    "host-evidence-budget-v3.json",
                 "Source5 v3 budget pin differs from its exact reserved path")
    return manifest


def _validate_host_budget_revision(
    budget: dict[str, Any], campaign_id: str, host_id: str, *,
    context: dict[str, Any] | None = None,
    budget_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    require_manifest_binding: bool = False,
) -> bool:
    legacy = set(budget) == HOST_BUDGET_FIELDS_LEGACY
    ready_v3 = set(budget) == HOST_BUDGET_FIELDS_V3
    r6 = set(budget) == HOST_BUDGET_FIELDS_R6
    _require(legacy or r6 or ready_v3,
             "host evidence budget has an unsupported exact field set")
    schema_matches_fields = (
        ((legacy or r6) and budget.get("schema") == HOST_BUDGET_SCHEMA) or
        (ready_v3 and budget.get("schema") == HOST_BUDGET_SCHEMA_V3 and
         budget.get("admission_profile") == HOST_BUDGET_V3_ADMISSION_PROFILE)
    )
    _require(schema_matches_fields and
             budget.get("campaign_id") == campaign_id and
             budget.get("host_id") == host_id,
             "host evidence budget identity differs from request")
    if legacy:
        # Keep the historical 13-field budget, including signer-only v4
        # fixtures, on its old non-width-bound behavior.
        _require(not require_manifest_binding,
                 "R6 v4 budget verification requires the additive field set")
        _require(not _has_h15_archive_readback_roles(
                    budget.get("path_catalogue")),
                 "H15 archive-read retention requires the width-bound v4 budget variant")
        return False
    schema = budget["execution_manifest_schema"]
    _require(schema == EXECUTION_SCHEMA_V4,
             "width-bound host-budget fields are reserved for execution manifest v4")
    if ready_v3:
        _require(budget.get("schema") == HOST_BUDGET_SCHEMA_V3 and
                 budget.get("admission_profile") ==
                    HOST_BUDGET_V3_ADMISSION_PROFILE,
                 "host budget v3 admission profile differs")
        expected_blockers: list[str] = []
        expected_readiness = {
            "budget_complete": True, "execution_ready": True,
            "component_gate_ready": False, "qualification_eligible": False,
        }
    else:
        _require(budget.get("schema") == HOST_BUDGET_SCHEMA,
                 "R6 width extension must retain its v2 schema")
        expected_blockers = [
            "verified_between_pair_archive_ack_reclaim_not_integrated",
        ]
        expected_readiness = {
            "budget_complete": False, "execution_ready": False,
            "component_gate_ready": False, "qualification_eligible": False,
        }
    readiness = _exact(budget["readiness"], {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "width-bound host evidence budget readiness")
    _require(budget["execution_blockers"] == expected_blockers and
             readiness == expected_readiness,
             "width-bound host budget blockers/readiness differ from its schema")
    width_pin = _pin(budget["journal_width_contract_pin"],
                     "v4 journal-width contract pin")
    catalogue = budget.get("path_catalogue")
    retention = catalogue.get("retention_policy") if type(catalogue) is dict else None
    has_archive_readback = _has_h15_archive_readback_roles(catalogue)
    expected_local_roles = (
        ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY | {"journal_width_contract"} |
        ({SOURCE5_ARCHIVE_READ_CONTROL_ROLE} if has_archive_readback else set())
    )
    _require(type(retention) is dict and
             retention.get("always_local_roles") == sorted(expected_local_roles),
             "v4 retention always-local roles omit or broaden exact local roles")
    if context is not None:
        original = _exact(budget.get("original_pins"), {
            "spec", "plan", "execution_manifest", "source_manifests",
            "source_tree_sha256",
        }, "host budget original input pins")
        sources = original["source_manifests"]
        _require(type(sources) is dict and host_id in sources and
                 _pin(original["plan"], "budget PlanV3 pin") ==
                     context["plan_pin"] and
                 _pin(original["execution_manifest"],
                      "budget execution-manifest pin") ==
                     context["execution_manifest_pin"] and
                 _pin(sources[host_id], "budget SourceV5 pin") ==
                     context["source_manifest_pin"],
                 "checkpoint source/Plan/execution pins differ from host budget")
    if execution_manifest_raw is not None:
        _require(context is not None,
                 "execution-manifest validation lacks an exact checkpoint context")
        _validate_execution_manifest_budget_binding(
            execution_manifest_raw, context, budget,
            journal_width_contract_raw,
        )
    elif require_manifest_binding or ready_v3:
        raise TransferPacketError(
            "width-bound host budget requires its raw-pinned execution manifest",
        )
    if journal_width_contract_raw is not None:
        _require(schema == EXECUTION_SCHEMA_V4 and
                 execution_manifest_raw is not None,
                 "width-contract bytes require their exact v4 execution-manifest context")
    if ready_v3:
        _require(context is not None and
                 execution_manifest_raw is not None and
                 journal_width_contract_raw is not None,
                 "ready host budget v3 requires its exact captured execution and width dependencies")
        _require(budget_raw is not None,
                 "ready host budget v3 requires its exact raw budget bytes")
        _validate_ready_host_budget_v3(
            budget_raw, budget, context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
    return True


def _validate_h15_archive_readback_profile(
    budget: dict[str, Any], host_id: str,
    readback_rows: list[dict[str, Any]], role_byte_sums: dict[str, int],
    analyzer_rows: list[dict[str, Any]] | None = None,
) -> bool:
    """Check H15 reusable read slots against exact row and retained-root caps."""
    catalogue_value = budget.get("path_catalogue")
    has_readback = _has_h15_archive_readback_roles(catalogue_value)
    analyzer_rows = [] if analyzer_rows is None else analyzer_rows
    if not has_readback:
        _require(not readback_rows and not analyzer_rows,
                 "catalogue rows contain undeclared H15 archive-read roles")
        return False
    _require((set(budget) == HOST_BUDGET_FIELDS_R6 or
              set(budget) == HOST_BUDGET_FIELDS_V3) and
             budget.get("execution_manifest_schema") == EXECUTION_SCHEMA_V4,
             "H15 archive-read catalogue is not bound to a width-v4 budget")
    catalogue = _exact(catalogue_value, SOURCE5_PATH_CATALOGUE_FIELDS,
                       "H15 Source5 path catalogue manifest")
    body = {key: item for key, item in catalogue.items()
            if key != "semantic_sha256"}
    _require(catalogue["schema"] ==
             "allocatbelt.application-source5-host-path-catalogue.v2" and
             catalogue["semantic_sha256"] == _sha(_canonical(body)) and
             type(catalogue["role_byte_bounds"]) is dict and
             role_byte_sums == catalogue["role_byte_bounds"],
             "H15 path catalogue role/root source projection differs")
    retention = catalogue["retention_policy"]
    retention_fields = set(retention) if type(retention) is dict else set()
    _require(retention_fields == (
                 SOURCE5_RETENTION_POLICY_FIELDS |
                 SOURCE5_CLEANUP_RETENTION_FIELDS),
             "H15 width-bound readback requires the exact cleanup retention fields")
    retention = _exact(retention, retention_fields,
                       "H15 path catalogue retention policy")
    analyzer_required = (
        budget.get("execution_manifest_schema") == EXECUTION_SCHEMA_V4 and
        budget.get("journal_width_contract_pin") is not None
    )
    _require(len(analyzer_rows) == int(analyzer_required),
             "v4 width-bound readback requires exactly one analyzer scratch tree")
    expected_local = sorted(
        ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY |
        {"journal_width_contract", SOURCE5_ARCHIVE_READ_CONTROL_ROLE},
    )
    _require(retention["always_local_roles"] == expected_local and
             retention["schema"] ==
                 "allocatbelt.application-source5-between-pair-retention.v2" and
             retention["mode"] == "verified_between_pair_offload_v1" and
             retention["max_live_job_windows"] == 1 and
             retention["max_retained_failure_windows"] == 1,
             "H15 readback retention role/mode/window contract differs")

    profile: dict[str, dict[str, Any]] = {}
    for index, row_value in enumerate(readback_rows):
        row = _exact(row_value, {
            "path", "kind", "role", "host_id", "max_bytes",
            "max_file_bytes", "max_inodes", "storage_root", "owner",
            "phase", "run_id", "member_index", "aggregate_id",
            "aggregate_max_bytes", "origin_pin",
        }, f"H15 archive-read catalogue row[{index}]")
        role = row["role"]
        _require(role in SOURCE5_ARCHIVE_READ_ROLES and role not in profile and
                 row["host_id"] == host_id and
                 row["owner"] == "source5_controller" and
                 row["phase"] is None and row["run_id"] is None and
                 row["member_index"] is None and row["aggregate_id"] is None and
                 row["aggregate_max_bytes"] is None and row["origin_pin"] is None and
                 type(row["storage_root"]) is str,
                 f"H15 archive-read role {role} repeats or has job identity/owner drift")
        _path(row["path"], f"H15 archive-read {role} path")
        _path(row["storage_root"], f"H15 archive-read {role} storage root")
        for field in ("max_bytes", "max_file_bytes", "max_inodes"):
            _uint(row[field], f"H15 archive-read {role} {field}")
        _require(row["max_bytes"] > 0 and
                 row["max_file_bytes"] <= row["max_bytes"],
                 f"H15 archive-read {role} has an empty or inverted cap")
        tree = role == "source5_archive_read_stage"
        _require(row["kind"] == ("tree" if tree else "file") and
                 (tree and row["max_inodes"] > 1 and
                  row["max_file_bytes"] > 0 or
                  not tree and row["max_inodes"] == 1 and
                  row["max_file_bytes"] == row["max_bytes"]),
                 f"H15 archive-read {role} type/byte/inode bounds differ")
        if role in {"source5_archive_read_request_slot",
                    "source5_archive_read_response_slot",
                    "source5_archive_read_response_incoming"}:
            _require(row["max_bytes"] <= MAX_ARCHIVE_READ_METADATA_BYTES and
                     row["max_file_bytes"] == row["max_bytes"],
                     f"H15 archive-read metadata slot {role} exceeds its parser ceiling")
        elif role in SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES:
            _require(MIN_ARCHIVE_READ_BUNDLE_BYTES <= row["max_bytes"] <=
                     MAX_TOTAL_BYTES and
                     row["max_file_bytes"] == row["max_bytes"],
                     f"H15 archive-read bundle slot {role} exceeds its transport ceiling")
        elif role == "source5_archive_read_stage":
            _require(row["max_bytes"] <= MAX_TOTAL_BYTES and
                     row["max_file_bytes"] <= MAX_ARCHIVE_OBJECT_BYTES and
                     row["max_inodes"] <= MAX_ARCHIVE_READ_OBJECTS + 1,
                     "H15 archive-read stage exceeds its exact payload/object/inode limits")
        elif role == SOURCE5_ARCHIVE_READ_CONTROL_ROLE:
            _require(row["max_bytes"] <= MAX_TOTAL_BYTES and
                     row["max_file_bytes"] == row["max_bytes"],
                     "H15 read-control ledger exceeds its bounded regular-file limit")
        profile[role] = row
    _require(set(profile) == SOURCE5_ARCHIVE_READ_ROLES,
             "H15 archive-read catalogue omits one exact reusable slot")
    for role in SOURCE5_ARCHIVE_READ_ROLES:
        _require(role_byte_sums.get(role) == profile[role]["max_bytes"],
                 f"H15 archive-read role {role} byte sum differs from its row")
    response = [profile[role] for role in
                SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES]
    bundle = [profile[role] for role in
              SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES]
    for label, pair in (("response", response), ("bundle", bundle)):
        _require(len(pair) == 2 and
                 len({(row["max_bytes"], row["max_file_bytes"],
                       row["max_inodes"], row["storage_root"],
                       row["owner"]) for row in pair}) == 1,
                 f"H15 readback {label} alternatives are not same-cap/same-root")
    transient = [profile[role] for role in SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES]
    roots = {row["storage_root"] for row in transient}
    _require(len(roots) == 1,
             "H15 archive-read slots do not share one caller-reserved scratch root")
    read_root = next(iter(roots))
    analyzer_row = None
    if analyzer_required:
        analyzer_row = _exact(analyzer_rows[0], {
            "path", "kind", "role", "host_id", "max_bytes",
            "max_file_bytes", "max_inodes", "storage_root", "owner",
            "phase", "run_id", "member_index", "aggregate_id",
            "aggregate_max_bytes", "origin_pin",
        }, "v4 analyzer scratch catalogue row")
        _require(analyzer_row["role"] == SOURCE5_ANALYZER_SPOOL_ROLE and
                 analyzer_row["kind"] == "tree" and
                 analyzer_row["host_id"] == host_id and
                 analyzer_row["owner"] == "source5_controller" and
                 analyzer_row["phase"] is None and
                 analyzer_row["run_id"] is None and
                 analyzer_row["member_index"] is None and
                 analyzer_row["aggregate_id"] is None and
                 analyzer_row["aggregate_max_bytes"] is None and
                 analyzer_row["origin_pin"] is None and
                 analyzer_row["storage_root"] == read_root and
                 analyzer_row["max_bytes"] > 0 and
                 analyzer_row["max_bytes"] <= MAX_TOTAL_BYTES and
                 analyzer_row["max_file_bytes"] > 0 and
                 analyzer_row["max_file_bytes"] <= analyzer_row["max_bytes"] and
                 1 < analyzer_row["max_inodes"] <= MAX_ARCHIVE_READ_OBJECTS + 1,
                 "v4 analyzer scratch tree has an invalid exact root or finite cap")
        expected_analyzer_root = (
            Path(read_root) / budget["campaign_id"] / host_id / "analyzer-spool"
        )
        _require(Path(analyzer_row["path"]) == expected_analyzer_root and
                 role_byte_sums.get(SOURCE5_ANALYZER_SPOOL_ROLE) ==
                     analyzer_row["max_bytes"],
                 "v4 analyzer scratch path or role-byte projection differs")
    control = profile[SOURCE5_ARCHIVE_READ_CONTROL_ROLE]
    control_root = control["storage_root"]
    _require(read_root != control_root,
             "H15 readback scratch and persistent output roots are aliased")
    request = profile["source5_archive_read_request_slot"]
    stage = profile["source5_archive_read_stage"]
    expected_readback_root = (
        Path(read_root) / budget["campaign_id"] / host_id / "archive-readback"
    )
    expected_read_paths = {
        "source5_archive_read_request_slot": expected_readback_root / "request.json",
        "source5_archive_read_response_slot": expected_readback_root / "response.json",
        "source5_archive_read_response_incoming":
            expected_readback_root / "response.json.incoming",
        "source5_archive_read_bundle": expected_readback_root / "response.tar",
        "source5_archive_read_bundle_incoming":
            expected_readback_root / "response.tar.incoming",
        "source5_archive_read_stage": expected_readback_root / "stage",
    }
    _require(all(Path(profile[role]["path"]) == expected
                 for role, expected in expected_read_paths.items()) and
             Path(control["path"]) ==
                 Path(control_root) / budget["campaign_id"] / "source5" /
                 host_id / "archive-read-control.jsonl",
             "H15 reusable readback paths differ from their exact campaign layout")
    window_bytes = (request["max_bytes"] + response[0]["max_bytes"] +
                    bundle[0]["max_bytes"] + stage["max_bytes"])
    window_inodes = (request["max_inodes"] + response[0]["max_inodes"] +
                     bundle[0]["max_inodes"] + stage["max_inodes"])
    if analyzer_row is not None:
        window_bytes += analyzer_row["max_bytes"]
        window_inodes += analyzer_row["max_inodes"]
    _uint(window_bytes, "H15 archive-read window bytes")
    _uint(window_inodes, "H15 archive-read window inodes")
    persistent_bytes = retention["persistent_root_byte_bounds"]
    persistent_inodes = retention["persistent_root_inode_bounds"]
    window_byte_bounds = retention["maximum_window_root_byte_bounds"]
    window_inode_bounds = retention["maximum_window_root_inode_bounds"]
    live_bytes = retention["maximum_live_root_byte_bounds"]
    live_inodes = retention["maximum_live_root_inode_bounds"]
    catalogue_roots = set(catalogue["root_byte_bounds"])
    _require(all(type(value) is dict for value in (
                 persistent_bytes, persistent_inodes, window_byte_bounds,
                 window_inode_bounds, live_bytes, live_inodes)) and
             all(set(value) == catalogue_roots for value in (
                 persistent_bytes, persistent_inodes, window_byte_bounds,
                 window_inode_bounds, live_bytes, live_inodes)) and
             read_root in persistent_bytes and read_root in persistent_inodes and
             read_root in window_byte_bounds and read_root in window_inode_bounds and
             read_root in live_bytes and read_root in live_inodes and
             control_root in persistent_bytes and control_root in persistent_inodes and
             control_root in live_bytes and control_root in live_inodes and
             window_byte_bounds[read_root] >= window_bytes and
             window_inode_bounds[read_root] >= window_inodes and
             persistent_bytes[control_root] >= control["max_bytes"] and
             persistent_inodes[control_root] >= control["max_inodes"] and
             live_bytes[read_root] >=
                 persistent_bytes[read_root] + window_byte_bounds[read_root] and
             live_inodes[read_root] >=
                 persistent_inodes[read_root] + window_inode_bounds[read_root] and
             live_bytes[control_root] >= persistent_bytes[control_root] and
             live_inodes[control_root] >= persistent_inodes[control_root],
             "H15 readback slot byte/inode ceilings escape retained root bounds")
    _require(_uint(retention["maximum_window_total_bytes"],
                   "H15 total live-window bytes") >= window_bytes and
             _uint(retention["maximum_window_total_inodes"],
                   "H15 total live-window inodes") >= window_inodes,
             "H15 total live-window ceilings are below the readback slot window")

    for root in catalogue_roots:
        _require(_uint(live_bytes[root], f"H15 live bytes for {root}") ==
                    _uint(persistent_bytes[root],
                          f"H15 persistent bytes for {root}") +
                    _uint(window_byte_bounds[root],
                          f"H15 window bytes for {root}") and
                 _uint(live_inodes[root], f"H15 live inodes for {root}") ==
                    _uint(persistent_inodes[root],
                          f"H15 persistent inodes for {root}") +
                    _uint(window_inode_bounds[root],
                          f"H15 window inodes for {root}"),
                 f"H15 live root bounds for {root} are not persistent plus one window")

    reservation = _exact(budget.get("storage_reservation"), {
        "pin", "roots", "required_bytes_by_root", "required_inodes_by_root",
    }, "H15 host storage reservation")
    _require(type(reservation["roots"]) is dict and
             type(reservation["required_bytes_by_root"]) is dict and
             type(reservation["required_inodes_by_root"]) is dict and
             set(reservation["required_bytes_by_root"]) == set(reservation["roots"]) and
             set(reservation["required_inodes_by_root"]) == set(reservation["roots"]),
             "H15 storage reservation maps are malformed")
    reserved_roots = {}
    for root_path, value in reservation["roots"].items():
        root = _exact(value, {
            "path", "role", "reserved_bytes", "reserved_inodes", "filesystem_id",
        }, f"H15 storage root {root_path}")
        _path(root_path, "H15 storage reservation root path")
        _require(root["path"] == root_path and
                 root["role"] in {"artifact", "output", "scratch",
                                   "evidence_store"} and
                 type(root["filesystem_id"]) is str and
                 re.fullmatch(r"[0-9]+", root["filesystem_id"]) is not None,
                 f"H15 storage root {root_path} has an invalid identity")
        _uint(root["reserved_bytes"], f"H15 reserved bytes for {root_path}")
        _uint(root["reserved_inodes"], f"H15 reserved inodes for {root_path}")
        _uint(reservation["required_bytes_by_root"][root_path],
              f"H15 required bytes for {root_path}")
        _uint(reservation["required_inodes_by_root"][root_path],
              f"H15 required inodes for {root_path}")
        _require(root["reserved_bytes"] >=
                    reservation["required_bytes_by_root"][root_path] and
                 root["reserved_inodes"] >=
                    reservation["required_inodes_by_root"][root_path],
                 f"H15 reserved root {root_path} is below required bounds")
        _require(root_path in catalogue_roots or
                 root["role"] == "evidence_store",
                 f"H15 storage root {root_path} is not catalogue-bound")
        reserved_roots[root_path] = root
    _require(set(reserved_roots) >= catalogue_roots and
             set(row["role"] for row in reserved_roots.values()) ==
                 {"artifact", "output", "scratch", "evidence_store"} and
             reserved_roots[read_root]["role"] == "scratch" and
             reserved_roots[control_root]["role"] == "output",
             "H15 readback roots do not resolve to their exact reserved domains")
    for root in catalogue_roots:
        _require(reservation["required_bytes_by_root"][root] >=
                    live_bytes[root] and
                 reservation["required_inodes_by_root"][root] >=
                    live_inodes[root],
                 f"H15 storage reservation omits the live bound for {root}")
    for root, minimum_bytes, minimum_inodes in (
        (read_root, persistent_bytes[read_root] + window_bytes,
         persistent_inodes[read_root] + window_inodes),
        (control_root, persistent_bytes[control_root],
         persistent_inodes[control_root]),
    ):
        declared = reserved_roots.get(root)
        required_bytes = reservation["required_bytes_by_root"].get(root)
        required_inodes = reservation["required_inodes_by_root"].get(root)
        _require(declared is not None and
                 (root != read_root or declared["role"] == "scratch") and
                 (root != control_root or declared["role"] == "output") and
                 type(required_bytes) is int and required_bytes >= minimum_bytes and
                 type(required_inodes) is int and required_inodes >= minimum_inodes and
                 declared["reserved_bytes"] >= required_bytes and
                 declared["reserved_inodes"] >= required_inodes,
                 "H15 readback storage root reservation is below its byte/inode bounds")
    return True


def _validate_archive_signer_context(
    raw: bytes, signer_context_pin: object, context: dict[str, Any],
    maximum_signature_bytes: int, execution_manifest_pin: object,
    execution_manifest_raw: bytes,
    *, require_width_contract: bool = False,
) -> dict[str, Any]:
    pin = _pin(signer_context_pin, "host archive signer-context pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "host archive signer-context bytes differ from their raw pin")
    value = _exact(_parse_canonical(raw, "host archive signer context"), {
        "schema", "campaign_id", "host_id", "authorized_primary_fingerprint",
        "maximum_signature_bytes", "keyring_pin", "gpgv_pin",
        "signature_format", "signer_context_sha256",
    }, "host archive signer context")
    body = {key: item for key, item in value.items()
            if key != "signer_context_sha256"}
    fingerprint = value["authorized_primary_fingerprint"]
    _require(type(fingerprint) is str and
             re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", fingerprint) is not None,
             "host signer-context fingerprint is malformed")
    keyring_pin = _pin_raw(value["keyring_pin"],
                           "host signer-context keyring pin")
    gpgv_pin = _pin_raw(value["gpgv_pin"],
                        "host signer-context GPGV pin")
    _require(value["schema"] == ARCHIVE_SIGNER_CONTEXT_SCHEMA and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             fingerprint == context["authorized_signer_fingerprint"] and
             value["signer_context_sha256"] == _sha(_canonical(body)) ==
                 pin["semantic_sha256"] and
             _uint(value["maximum_signature_bytes"],
                   "host signer-context signature quota", positive=True) ==
                 maximum_signature_bytes and
             value["signature_format"] ==
                 "binary_detached_primary_sha256_v1",
             "host signer context differs from its raw pin, identity, quota or format")
    checked_execution_pin = _pin(
        execution_manifest_pin, "host execution-manifest pin",
    )
    _require(checked_execution_pin == context["execution_manifest_pin"] and
             type(execution_manifest_raw) is bytes and
             _sha(execution_manifest_raw) == checked_execution_pin["raw_sha256"],
             "host execution-manifest bytes differ from the checkpoint pin")
    execution_probe = _parse_canonical(
        execution_manifest_raw, "host Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    if execution_probe.get("schema") == PREPARATORY_EXECUTION_SCHEMA_V1:
        execution = _exact(execution_probe, PREPARATORY_EXECUTION_FIELDS_V1,
                           "preparatory host execution manifest")
        execution_body = {key: item for key, item in execution.items()
                          if key != "manifest_sha256"}
        hosts = execution["hosts"]
        _require(execution["campaign_id"] == context["campaign_id"] and
                 execution["host_id"] == context["host_id"] and
                 type(hosts) is list and len(hosts) in (2, 3) and
                 all(type(host) is str and host for host in hosts) and
                 len(set(hosts)) == len(hosts) and context["host_id"] in hosts and
                 execution["scope"] == "preparatory_exploration" and
                 execution["phase_order"] == ["exploration"] and
                 execution["qualification_eligible"] is False and
                 execution["manifest_sha256"] == _sha(_canonical(
                     execution_body, maximum_bytes=MAX_PLAN_BYTES,
                 )) == checked_execution_pin["semantic_sha256"],
                 "preparatory execution manifest schema/scope/self digest differs")
        contexts = _exact(execution["archive_signer_contexts"],
                          {context["host_id"]},
                          "preparatory host signer-context map")
        wrapper = _exact(contexts[context["host_id"]], {
            "artifact", "semantic_sha256",
        }, "preparatory signer-context wrapper")
        artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                           "preparatory signer-context artifact")
        _require(artifact == {"path": pin["path"],
                              "raw_sha256": pin["raw_sha256"]} and
                 wrapper["semantic_sha256"] == pin["semantic_sha256"],
                 "prep signer-context pin differs from its exact manifest entry")
        return {
            "signer_context_pin": pin,
            "authorized_primary_fingerprint": fingerprint,
            "maximum_signature_bytes": maximum_signature_bytes,
            "keyring_pin": keyring_pin, "gpgv_pin": gpgv_pin,
            "execution_manifest_pin": checked_execution_pin,
        }
    if execution_probe.get("schema") == PREPARED_EXPLORATION_EXECUTION_SCHEMA:
        _validate_prepared_execution_signer_binding_v1(
            execution_probe, checked_execution_pin, pin, context,
        )
        return {
            "schema": value["schema"], "campaign_id": context["campaign_id"],
            "host_id": context["host_id"],
            "authorized_primary_fingerprint": fingerprint,
            "maximum_signature_bytes": maximum_signature_bytes,
            "keyring_pin": keyring_pin, "gpgv_pin": gpgv_pin,
            "signature_format": value["signature_format"],
            "signer_context_sha256": value["signer_context_sha256"],
            "execution_manifest_pin": checked_execution_pin,
        }
    execution_fields = {
        "schema", "campaign_id", "hosts", "original_inputs",
        "execution_sources", "modules", "observed_hosts", "artifact_root",
        "output_root", "phase_order", "protocol_sha256",
        "qualification_eligible", "scope", "prepared_input_generation",
        "prepared_capacity_registration", "archive_signer_contexts",
        "manifest_sha256",
    }
    if require_width_contract:
        execution_fields.add("journal_width_contracts")
    execution = _exact(_parse_canonical(
        execution_manifest_raw, "host Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    ), execution_fields, "bounded Source5 execution manifest v4")
    execution_body = {key: item for key, item in execution.items()
                      if key != "manifest_sha256"}
    hosts = execution["hosts"]
    _require(execution["schema"] ==
             "allocatbelt.application-source5-campaign-execution.v4" and
             execution["campaign_id"] == context["campaign_id"] and
             type(hosts) is list and len(hosts) in (2, 3) and
             all(type(host) is str and bool(host) for host in hosts) and
             len(hosts) == len(set(hosts)) and context["host_id"] in hosts and
             execution["scope"] == "final_prepared_bounded" and
             execution["qualification_eligible"] is False and
             execution["manifest_sha256"] == _sha(_canonical(
                 execution_body, maximum_bytes=MAX_PLAN_BYTES,
             )) ==
                 checked_execution_pin["semantic_sha256"],
             "host execution manifest schema, identity, scope or digest differs")
    contexts = _exact(
        execution["archive_signer_contexts"], set(hosts),
        "host execution-manifest signer-context map",
    )
    wrapper = _exact(contexts[context["host_id"]], {
        "artifact", "semantic_sha256",
    }, "host execution-manifest signer-context wrapper")
    artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                       "host execution-manifest signer-context artifact")
    _require(artifact == {"path": pin["path"], "raw_sha256": pin["raw_sha256"]} and
             wrapper["semantic_sha256"] == pin["semantic_sha256"],
             "host signer-context pin differs from its execution-manifest entry")
    return {
        "schema": value["schema"], "campaign_id": context["campaign_id"],
        "host_id": context["host_id"],
        "authorized_primary_fingerprint": fingerprint,
        "maximum_signature_bytes": maximum_signature_bytes,
        "keyring_pin": keyring_pin, "gpgv_pin": gpgv_pin,
        "signature_format": value["signature_format"],
        "signer_context_sha256": value["signer_context_sha256"],
        "execution_manifest_pin": checked_execution_pin,
    }


def _validate_budget_context(
    budget: dict[str, Any], context: dict[str, Any], *,
    budget_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    require_manifest_binding: bool = False,
) -> None:
    if type(budget) is dict and budget.get("schema") == \
            PREPARATORY_BUDGET_SCHEMA_V1:
        _require(type(budget_raw) is bytes,
                 "preparatory budget context validation requires exact raw bytes")
        _validate_preparatory_budget_profile_v1(
            budget_raw, context["resource_budget_pin"], context,
            context["campaign_id"], context["host_id"],
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
        return
    budget, _is_r6 = _exact_host_budget(budget, "host evidence budget")
    _validate_host_budget_revision(
        budget, context["campaign_id"], context["host_id"],
        context=context, budget_raw=budget_raw,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local,
        require_manifest_binding=require_manifest_binding,
    )
    _validate_budget_origin_pins(budget, context)


def _validate_budget_origin_pins(
    budget_value: dict[str, Any], context: dict[str, Any],
) -> None:
    """Check exact Source/Plan/manifest identity after budget math was sealed."""
    if type(budget_value) is dict and budget_value.get("schema") == \
            PREPARATORY_BUDGET_SCHEMA_V1:
        budget = _exact(budget_value, PREPARATORY_BUDGET_FIELDS_V1,
                        "preparatory host evidence budget")
        pins = _exact(budget.get("original_pins"), {
            "preparation", "capacity_generation", "initial_spec",
            "initial_plan", "source_manifests", "observed_hosts",
            "typed_modules", "archive_signer_context",
            "capacity_registration", "execution_basis_sha256",
        }, "preparatory budget original pins")
        _require(
                 budget.get("campaign_id") == context["campaign_id"] and
                 budget.get("host_id") == context["host_id"] and
                 _pin({key: pins["initial_plan"][key] for key in (
                     "path", "raw_sha256", "semantic_sha256",
                 )}, "preparatory budget initial Plan pin") ==
                     _pin(context["plan_pin"], "preparatory request Plan pin") and
                 type(pins.get("source_manifests")) is dict and
                 context["host_id"] in pins["source_manifests"] and
                 _pin({key: pins["source_manifests"][context["host_id"]][key]
                       for key in ("path", "raw_sha256", "semantic_sha256")},
                      "preparatory budget Source pin") ==
                     _pin(context["source_manifest_pin"],
                          "preparatory request Source pin"),
                 "preparatory request Source/Plan pins differ from the budget basis")
        return
    budget, _ = _exact_host_budget(budget_value, "host evidence budget")
    original = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    _digest(original["source_tree_sha256"], "budget source tree SHA-256")
    sources = original["source_manifests"]
    _require(type(sources) is dict and context["host_id"] in sources and
             _pin(original["plan"], "budget PlanV3 pin") == context["plan_pin"] and
             _pin(original["execution_manifest"],
                  "budget execution-manifest pin") ==
                 context["execution_manifest_pin"] and
             _pin(sources[context["host_id"]], "budget SourceV5 pin") ==
                 context["source_manifest_pin"],
             "checkpoint source/Plan/execution pins differ from host budget")


def _parse_catalogue_local_map(
    raw: bytes, campaign_id: str, host_id: str, budget_pin: object,
) -> dict[str, str]:
    value = _exact(_parse_canonical(raw, "Root-local catalogue path map"), {
        "schema", "campaign_id", "host_id", "resource_budget_pin",
        "chunks", "map_sha256",
    }, "Root-local catalogue path map")
    body = {key: item for key, item in value.items() if key != "map_sha256"}
    _require(value["schema"] == CATALOGUE_LOCAL_MAP_SCHEMA and
             value["campaign_id"] == campaign_id and
             value["host_id"] == host_id and
             _pin(value["resource_budget_pin"], "catalogue map budget pin") ==
                 _pin(budget_pin, "host evidence budget pin") and
             value["map_sha256"] == _sha(_canonical(body)) and
             type(value["chunks"]) is list,
             "Root-local catalogue path map identity/digest differs")
    paths = {}
    local_paths = set()
    previous = ""
    for index, item_value in enumerate(value["chunks"]):
        item = _exact(item_value, {"origin_path", "local_path"},
                      f"Root-local catalogue chunk map[{index}]")
        origin = _path(item["origin_path"], "catalogue chunk origin")
        local = _path(item["local_path"], "Root-local catalogue chunk")
        _require(origin > previous and local != origin and local not in local_paths,
                 "Root-local catalogue map is unsorted or aliases an origin path")
        previous = origin
        local_paths.add(local)
        paths[origin] = local
    return paths


def _prepared_exploration_primary_context(
    budget: dict[str, Any], budget_pin: object,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Project the V5 six-copy closure; this does not admit a host budget."""
    _exact(budget, HOST_BUDGET_FIELDS_V3, "prepared-exploration host budget")
    checked_budget_pin = _pin(budget_pin, "prepared-exploration budget pin")
    _require(budget["schema"] == HOST_BUDGET_SCHEMA_V4 and
             budget["admission_profile"] == PREPARED_EXPLORATION_ADMISSION_PROFILE and
             budget["execution_manifest_schema"] == PREPARED_EXPLORATION_EXECUTION_SCHEMA,
             "prepared-exploration budget schema/profile/execution version differs")
    campaign_id = _token(budget["campaign_id"], "prepared-exploration campaign ID")
    host_id = _token(budget["host_id"], "prepared-exploration host ID")
    original = _exact(budget["original_pins"], {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256", "prepared_exploration",
    }, "prepared-exploration final original pins")
    sources = original["source_manifests"]
    _require(type(sources) is dict and len(sources) in (2, 3) and host_id in sources,
             "prepared-exploration source cohort is incomplete")
    source_pins = {}
    for source_host, value in sources.items():
        _token(source_host, "prepared-exploration source host")
        source_pins[source_host] = _pin(value, "prepared-exploration Source manifest pin")
    lineage = _exact(original["prepared_exploration"], set(sources),
                      "prepared-exploration ancestor host map")
    lineage_paths = set()
    for source_host, value in lineage.items():
        pair = _exact(value, {"bridge_header", "record_index"},
                       f"prepared-exploration {source_host} ancestor pins")
        for kind in ("bridge_header", "record_index"):
            pin = _pin_raw(pair[kind], f"prepared-exploration {source_host} {kind}")
            _require(pin["path"] not in lineage_paths,
                     "prepared-exploration ancestor metadata repeats an origin path")
            lineage_paths.add(pin["path"])
    tree = original["source_tree_sha256"]
    _require(type(tree) is str and re.fullmatch(r"[0-9a-f]{64}", tree) is not None,
             "prepared-exploration source-tree pin is malformed")
    plan_pin = _pin(original["plan"], "prepared-exploration FINAL Plan pin")
    execution_pin = _pin(original["execution_manifest"], "prepared-exploration FINAL execution pin")
    width_pin = _pin(budget["journal_width_contract_pin"], "prepared-exploration FINAL width pin")
    spec_pin = _pin(original["spec"], "prepared-exploration FINAL Spec pin")
    pins = [source_pins[host_id], plan_pin, checked_budget_pin,
            execution_pin, width_pin, spec_pin]
    _require(len({pin["path"] for pin in pins}) == 6 and
             not ({pin["path"] for pin in pins} & lineage_paths),
             "prepared-exploration final primary pins alias another dependency or ancestor")
    return ({
        "campaign_id": campaign_id, "host_id": host_id,
        "source_manifest_pin": source_pins[host_id], "plan_pin": plan_pin,
        "resource_budget_pin": checked_budget_pin,
        "execution_manifest_pin": execution_pin,
    }, pins)


def _budget_origin_context(
    budget: dict[str, Any], budget_pin: object,
) -> dict[str, Any]:
    """Project only the original pins needed for the closed dependency map."""
    checked_pin = _pin(budget_pin, "host evidence budget pin")
    original = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    sources = original["source_manifests"]
    host_id = _token(budget.get("host_id"), "host budget host ID")
    _require(type(sources) is dict and host_id in sources,
             "host budget omits its selected SourceV5 pin")
    return {
        "campaign_id": _token(budget.get("campaign_id"),
                               "host budget campaign ID"),
        "host_id": host_id,
        "source_manifest_pin": _pin(sources[host_id],
                                     "host budget SourceV5 pin"),
        "plan_pin": _pin(original["plan"], "host budget PlanV3 pin"),
        "resource_budget_pin": checked_pin,
        "execution_manifest_pin": _pin(
            original["execution_manifest"],
            "host budget execution-manifest pin",
        ),
    }


def _read_root_budget_dependencies(
    budget: dict[str, Any], budget_raw: bytes, budget_pin: object,
    dependency_map_raw: bytes, dependency_cache_root: str | os.PathLike[str],
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    """Read the exact five dependency copies without opening host-origin paths."""
    context = _budget_origin_context(budget, budget_pin)
    dependency_map = _exact(
        _parse_canonical(dependency_map_raw,
                         "Root-local dependency map"),
        {"schema", "campaign_id", "host_id", "entries", "map_sha256"},
        "Root-local dependency map",
    )
    body = {key: item for key, item in dependency_map.items()
            if key != "map_sha256"}
    _require(dependency_map["schema"] == DEPENDENCY_LOCAL_MAP_SCHEMA and
             dependency_map["campaign_id"] == context["campaign_id"] and
             dependency_map["host_id"] == context["host_id"] and
             dependency_map["map_sha256"] == _sha(_canonical(body)) and
             type(dependency_map["entries"]) is list,
             "Root-local dependency map identity or digest differs")
    entries = dependency_map["entries"]
    _require(len(entries) == 5,
             "width-bound budget requires the exact five-row dependency map")
    origin_pins = [
        context["source_manifest_pin"], context["plan_pin"],
        context["resource_budget_pin"], context["execution_manifest_pin"],
        _pin(budget["journal_width_contract_pin"],
             "host budget journal-width contract pin"),
    ]
    paths: dict[str, str] = {}
    local_paths: set[str] = set()
    for index, (entry_value, expected_pin) in enumerate(
            zip(entries, origin_pins, strict=True)):
        entry = _exact(entry_value, {"origin_pin", "local_path"},
                       f"Root-local dependency map row[{index}]")
        pin = _pin(entry["origin_pin"],
                   f"Root-local dependency origin pin[{index}]")
        local = _path(entry["local_path"],
                      f"Root-local dependency file[{index}]")
        _require(pin == expected_pin and local != pin["path"] and
                 local not in local_paths and pin["path"] not in paths,
                 "Root-local dependency map is not the exact ordered five-pin closure")
        local_paths.add(local)
        paths[pin["path"]] = local
    cache_root = Path(_path(
        os.fspath(dependency_cache_root),
        "Root-local dependency cache root",
    ))
    cache_fd = _open_abs_dir(str(cache_root),
                             "Root-local dependency cache root",
                             private_final=True)
    os.close(cache_fd)
    captured: dict[str, bytes] = {}
    limits = {
        context["source_manifest_pin"]["path"]: MAX_SOURCE_MANIFEST_BYTES,
        context["plan_pin"]["path"]: MAX_PLAN_BYTES,
        context["resource_budget_pin"]["path"]: MAX_JSON_BYTES,
        context["execution_manifest_pin"]["path"]: MAX_PLAN_BYTES,
        origin_pins[4]["path"]: MAX_JOURNAL_WIDTH_CONTRACT_BYTES,
    }
    for pin in origin_pins:
        origin = pin["path"]
        local = Path(paths[origin])
        _require(local != cache_root and cache_root in local.parents and
                 local.resolve(strict=True) == local,
                 "Root-local dependency copy is aliased or outside its private cache")
        raw, actual, _info = _read_regular_absolute(
            local, limits[origin], "Root-local captured dependency",
        )
        _require(actual == pin["raw_sha256"],
                 "Root-local dependency bytes differ from their origin raw pin")
        captured[origin] = raw
    _require(captured[context["resource_budget_pin"]["path"]] == budget_raw,
             "Root-local host budget differs from the supplied pinned bytes")
    return (
        context,
        captured[context["source_manifest_pin"]["path"]],
        captured[context["execution_manifest_pin"]["path"]],
        captured[origin_pins[4]["path"]],
    )


def _read_root_preparatory_dependencies(
    budget: dict[str, Any], budget_raw: bytes, budget_pin: object,
    context: dict[str, Any], dependency_map_raw: bytes,
    dependency_cache_root: str | os.PathLike[str],
) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes, bytes]:
    """Reopen the exact six Root-local prep dependencies without origin IO."""
    _exact(budget, PREPARATORY_BUDGET_FIELDS_V1,
           "Root preparatory host evidence budget")
    checked_budget_pin = _pin(budget_pin, "Root preparatory budget pin")
    _require(_sha(budget_raw) == checked_budget_pin["raw_sha256"] and
             _pin(context["resource_budget_pin"],
                  "Root preparatory request budget pin") == checked_budget_pin and
             budget.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1 and
             budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"],
             "Root prep budget does not match the exact request context")
    width_pin = _pin(budget["journal_width_contract_pin"],
                     "Root preparatory journal-width pin")
    spec_pin = _pin(budget["original_pins"]["initial_spec"],
                    "Root preparatory original Spec pin")
    expected = [
        context["source_manifest_pin"], context["plan_pin"],
        context["resource_budget_pin"], context["execution_manifest_pin"],
        width_pin, spec_pin,
    ]
    local_map = _exact(_parse_canonical(
        dependency_map_raw, "Root-local preparatory dependency map",
    ), {"schema", "campaign_id", "host_id", "entries", "map_sha256"},
                       "Root-local preparatory dependency map")
    map_body = {key: item for key, item in local_map.items()
                if key != "map_sha256"}
    _require(local_map["schema"] == DEPENDENCY_LOCAL_MAP_SCHEMA and
             local_map["campaign_id"] == context["campaign_id"] and
             local_map["host_id"] == context["host_id"] and
             local_map["map_sha256"] == _sha(_canonical(map_body)) and
             type(local_map["entries"]) is list and
             len(local_map["entries"]) == 6,
             "Root prep dependency map identity/size/self digest differs")
    dependency_paths: dict[str, str] = {}
    local_paths = set()
    for index, (entry_value, expected_pin) in enumerate(zip(
            local_map["entries"], expected, strict=True)):
        entry = _exact(entry_value, {"origin_pin", "local_path"},
                       f"Root prep dependency map row[{index}]")
        origin_pin = _pin(entry["origin_pin"],
                          f"Root prep dependency origin pin[{index}]")
        local_path = _path(entry["local_path"],
                           f"Root prep dependency local path[{index}]")
        _require(origin_pin == expected_pin and
                 origin_pin["path"] not in dependency_paths and
                 local_path != origin_pin["path"] and
                 local_path not in local_paths,
                 "Root prep dependency map is not the exact ordered six-pin closure")
        dependency_paths[origin_pin["path"]] = local_path
        local_paths.add(local_path)
    cache_root = Path(_path(os.fspath(dependency_cache_root),
                            "Root preparatory dependency cache root"))
    root_fd = _open_abs_dir(str(cache_root),
                            "Root preparatory dependency cache root",
                            private_final=True)
    os.close(root_fd)
    limits = [
        MAX_SOURCE_MANIFEST_BYTES, MAX_PLAN_BYTES,
        PREPARATORY_MAX_BUDGET_BYTES, MAX_PLAN_BYTES,
        PREPARATORY_MAX_WIDTH_BYTES, PREPARATORY_MAX_SPEC_BYTES,
    ]
    captured = []
    for pin, maximum in zip(expected, limits, strict=True):
        origin = pin["path"]
        local_text = dependency_paths[origin]
        local = Path(_path(local_text, "Root preparatory mapped dependency"))
        _require(origin == pin["path"] and local != cache_root and
                 cache_root in local.parents and local != Path(origin) and
                 local.resolve(strict=True) == local,
                 "Root prep dependency path aliases or escapes its exact private cache")
        raw, actual, _info = _read_regular_absolute(
            local, maximum, "Root-local captured preparatory dependency",
        )
        _require(actual == pin["raw_sha256"],
                 "Root prep dependency bytes differ from their original raw pin")
        captured.append(raw)
    _require(captured[2] == budget_raw,
             "Root-local preparatory budget copy differs from supplied bytes")
    execution = _parse_canonical(
        captured[3], "Root-local preparatory execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    spec_wrapper = _exact(
        _exact(execution.get("original_inputs"), {
            "spec", "plan", "source_manifests", "campaign_artifacts_root",
        }, "Root prep execution original inputs")["spec"],
        {"artifact", "semantic_sha256"},
        "Root prep execution initial Spec wrapper",
    )
    execution_spec_pin = _pin({
        **_pin_raw(spec_wrapper["artifact"],
                   "Root prep execution initial Spec artifact"),
        "semantic_sha256": spec_wrapper["semantic_sha256"],
    }, "Root prep execution initial Spec pin")
    _require(execution_spec_pin == spec_pin,
             "sixth Root prep dependency does not match both original Spec pin sets")
    return (context, captured[0], captured[1], captured[3], captured[4],
            captured[5])


def _read_root_prepared_exploration_dependencies(
    budget: dict[str, Any], budget_raw: bytes, budget_pin: object,
    context: dict[str, Any], dependency_map_raw: bytes,
    dependency_cache_root: str | os.PathLike[str],
) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes, bytes]:
    """Reopen the exact six FINAL V5 dependencies without opening old origins."""
    derived_context, expected = _prepared_exploration_primary_context(budget, budget_pin)
    _require(context == derived_context,
             "Root V5 request context differs from its exact final budget pins")
    checked_budget_pin = expected[2]
    _require(type(budget_raw) is bytes and _sha(budget_raw) == checked_budget_pin["raw_sha256"] and
             budget_raw == _canonical(budget, maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES) and
             budget["budget_sha256"] == checked_budget_pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in budget.items()
                                  if key != "budget_sha256"},
                                 maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES)),
             "Root V5 budget differs from its exact raw/semantic pin")
    spec_pin = expected[5]
    local_map = _exact(_parse_canonical(
        dependency_map_raw, "Root-local prepared-exploration dependency map",
    ), {"schema", "campaign_id", "host_id", "entries", "map_sha256"},
                       "Root-local prepared-exploration dependency map")
    map_body = {key: item for key, item in local_map.items()
                if key != "map_sha256"}
    _require(local_map["schema"] == DEPENDENCY_LOCAL_MAP_SCHEMA and
             local_map["campaign_id"] == context["campaign_id"] and
             local_map["host_id"] == context["host_id"] and
             local_map["map_sha256"] == _sha(_canonical(map_body)) and
             type(local_map["entries"]) is list and
             len(local_map["entries"]) == 6,
             "Root V5 dependency map identity/size/self digest differs")
    dependency_paths: dict[str, str] = {}
    local_paths = set()
    for index, (entry_value, expected_pin) in enumerate(zip(
            local_map["entries"], expected, strict=True)):
        entry = _exact(entry_value, {"origin_pin", "local_path"},
                       f"Root V5 dependency map row[{index}]")
        origin_pin = _pin(entry["origin_pin"],
                          f"Root V5 dependency origin pin[{index}]")
        local_path = _path(entry["local_path"],
                           f"Root V5 dependency local path[{index}]")
        _require(origin_pin == expected_pin and
                 origin_pin["path"] not in dependency_paths and
                 local_path != origin_pin["path"] and
                 local_path not in local_paths,
                 "Root V5 dependency map is not the exact ordered six-pin closure")
        dependency_paths[origin_pin["path"]] = local_path
        local_paths.add(local_path)
    cache_root = Path(_path(os.fspath(dependency_cache_root),
                            "Root V5 dependency cache root"))
    root_fd = _open_abs_dir(str(cache_root),
                            "Root V5 dependency cache root",
                            private_final=True)
    root_identity = os.fstat(root_fd)
    try:
        limits = [
            MAX_SOURCE_MANIFEST_BYTES, MAX_PLAN_BYTES,
            PREPARATORY_MAX_BUDGET_BYTES, MAX_PLAN_BYTES,
            PREPARATORY_MAX_WIDTH_BYTES, PREPARATORY_MAX_SPEC_BYTES,
        ]
        captured = []
        for pin, maximum in zip(expected, limits, strict=True):
            origin = pin["path"]
            local_text = dependency_paths[origin]
            local = Path(_path(local_text, "Root V5 mapped dependency"))
            _require(origin == pin["path"] and local != cache_root and
                     cache_root in local.parents and local != Path(origin) and
                     local.resolve(strict=True) == local,
                     "Root V5 dependency path aliases or escapes its exact private cache")
            raw, actual, _info = _read_regular_absolute(
                local, maximum, "Root-local captured prepared-exploration dependency",
            )
            _require(actual == pin["raw_sha256"],
                     "Root V5 dependency bytes differ from their original raw pin")
            captured.append(raw)
        _require(captured[2] == budget_raw,
                 "Root-local prepared-exploration budget copy differs from supplied bytes")
        execution = _parse_canonical(
            captured[3], "Root-local prepared-exploration execution manifest",
            maximum_bytes=MAX_PLAN_BYTES,
        )
        _exact(execution, {
            "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
            "modules", "observed_hosts", "artifact_root", "output_root", "phase_order",
            "protocol_sha256", "qualification_eligible", "manifest_sha256", "scope",
            "prepared_input_generation", "prepared_capacity_registration",
            "archive_signer_contexts", "journal_width_contracts",
        } | _prepared_execution_replay_profile_fields_v1(execution),
               "Root V5 execution manifest")
        _require(execution["schema"] == PREPARED_EXPLORATION_EXECUTION_SCHEMA and
                 execution["scope"] == PREPARED_EXPLORATION_SCOPE and
                 execution["campaign_id"] == context["campaign_id"] and
                 execution["qualification_eligible"] is False and
                 execution["manifest_sha256"] == expected[3]["semantic_sha256"] ==
                     _sha(_canonical({key: value for key, value in execution.items()
                                      if key != "manifest_sha256"}, maximum_bytes=MAX_PLAN_BYTES)),
                 "Root V5 execution identity, scope or semantic pin differs")
        spec_wrapper = _exact(
            _exact(execution.get("original_inputs"), {
                "spec", "plan", "source_manifests", "campaign_artifacts_root",
            }, "Root V5 execution original inputs")["spec"],
            {"artifact", "semantic_sha256"},
            "Root V5 execution final Spec wrapper",
        )
        execution_spec_pin = _pin({
            **_pin_raw(spec_wrapper["artifact"],
                       "Root V5 execution final Spec artifact"),
            "semantic_sha256": spec_wrapper["semantic_sha256"],
        }, "Root V5 execution final Spec pin")
        _require(execution_spec_pin == spec_pin,
                 "sixth Root V5 dependency does not match both original Spec pin sets")
        final_root = os.stat(cache_root, follow_symlinks=False)
        held_root = os.fstat(root_fd)
        _require((final_root.st_dev, final_root.st_ino) ==
                     (held_root.st_dev, held_root.st_ino) ==
                     (root_identity.st_dev, root_identity.st_ino) and
                 stat.S_ISDIR(final_root.st_mode) and
                 final_root.st_uid == held_root.st_uid == os.getuid() and
                 stat.S_IMODE(final_root.st_mode) == stat.S_IMODE(held_root.st_mode) == 0o700 and
                 cache_root.resolve(strict=True) == cache_root,
                 "Root V5 dependency cache custody changed during the six-copy read")
        return (context, captured[0], captured[1], captured[3], captured[4],
                captured[5])
    finally:
        os.close(root_fd)


def _read_host_budget_dependencies(
    budget_raw: bytes, budget_pin: object,
    context: dict[str, Any],
) -> tuple[bytes | None, bytes | None, bytes | None]:
    """Read the two v3 inputs from their exact host-local pinned paths."""
    preparatory = _parse_canonical(
        budget_raw, "host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if preparatory.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        budget = _exact(preparatory, PREPARATORY_BUDGET_FIELDS_V1,
                        "preparatory host evidence budget")
        pin = _pin(budget_pin, "preparatory host evidence budget pin")
        _require(_sha(budget_raw) == pin["raw_sha256"] and
                 _pin(context["resource_budget_pin"],
                      "preparatory request budget pin") == pin and
                 budget.get("campaign_id") == context["campaign_id"] and
                 budget.get("host_id") == context["host_id"],
                 "preparatory host budget dependencies differ from request identity")
        source_pin = _pin(context["source_manifest_pin"],
                          "preparatory host Source pin")
        execution_pin = _pin(context["execution_manifest_pin"],
                             "preparatory host execution pin")
        execution_raw, execution_sha, _ = _read_regular_absolute(
            execution_pin["path"], MAX_PLAN_BYTES,
            "host-pinned preparatory execution manifest",
        )
        _require(execution_sha == execution_pin["raw_sha256"],
                 "host preparatory execution bytes differ from their raw pin")
        execution = _parse_canonical(
            execution_raw, "host-pinned preparatory execution manifest",
            maximum_bytes=MAX_PLAN_BYTES,
        )
        wrapper = _exact(
            _exact(execution.get("preparatory_journal_width_contracts"),
                   {context["host_id"]}, "host preparatory width map")[context["host_id"]],
            {"artifact", "semantic_sha256"},
            "host preparatory width wrapper",
        )
        width_pin = _pin({
            **_pin_raw(wrapper["artifact"], "host preparatory width artifact"),
            "semantic_sha256": wrapper["semantic_sha256"],
        }, "host preparatory width pin")
        width_raw, width_sha, _ = _read_regular_absolute(
            width_pin["path"], PREPARATORY_MAX_WIDTH_BYTES,
            "host-pinned preparatory journal-width contract",
        )
        source_raw, source_sha, _ = _read_regular_absolute(
            source_pin["path"], MAX_SOURCE_MANIFEST_BYTES,
            "host-pinned preparatory SourceV5 manifest",
        )
        _require(width_sha == width_pin["raw_sha256"] and
                 source_sha == source_pin["raw_sha256"],
                 "host preparatory Source/width bytes differ from their raw pins")
        return source_raw, execution_raw, width_raw
    budget, _width_bound = _exact_host_budget(
        _parse_canonical(budget_raw, "host evidence budget"),
        "host evidence budget",
    )
    pin = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == pin["raw_sha256"] and
             _pin(context["resource_budget_pin"],
                  "host request budget pin") == pin,
             "host budget dependencies are not bound to the request pin")
    if budget.get("schema") != HOST_BUDGET_SCHEMA_V3:
        return None, None, None
    expected_context = _budget_origin_context(budget, pin)
    _require_same_budget_context(expected_context, context)
    source_pin = expected_context["source_manifest_pin"]
    execution_pin = expected_context["execution_manifest_pin"]
    width_pin = _pin(budget["journal_width_contract_pin"],
                     "host v3 width-contract pin")
    execution_raw, execution_sha, _ = _read_regular_absolute(
        execution_pin["path"], MAX_PLAN_BYTES,
        "host-pinned execution manifest",
    )
    width_raw, width_sha, _ = _read_regular_absolute(
        width_pin["path"], MAX_JOURNAL_WIDTH_CONTRACT_BYTES,
        "host-pinned journal-width contract",
    )
    _require(execution_sha == execution_pin["raw_sha256"] and
             width_sha == width_pin["raw_sha256"],
             "host v3 execution/width bytes differ from their exact pins")
    source_raw, source_sha, _ = _read_regular_absolute(
        source_pin["path"], MAX_SOURCE_MANIFEST_BYTES,
        "host-pinned SourceV5 manifest",
    )
    _require(source_sha == source_pin["raw_sha256"],
             "host v3 SourceV5 bytes differ from their exact pin")
    return source_raw, execution_raw, width_raw


def _require_same_budget_context(
    expected: dict[str, Any], actual: dict[str, Any],
) -> None:
    for field in (
        "campaign_id", "host_id", "source_manifest_pin", "plan_pin",
        "resource_budget_pin", "execution_manifest_pin",
    ):
        if field.endswith("_pin"):
            _require(_pin(expected[field], f"expected {field}") ==
                     _pin(actual[field], f"actual {field}"),
                     f"request changed its exact host-budget {field}")
        else:
            _require(expected[field] == actual[field],
                     f"request changed its host-budget {field}")


def _parse_canonical(
    raw: bytes, label: str, *, maximum_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= maximum_bytes and
             raw.endswith(b"\n") and b"\r" not in raw,
             f"{label} framing differs from canonical JSON")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise TransferPacketError(f"{label} is malformed JSON: {error}") from error
    _require(type(value) is dict and
             _canonical(value, maximum_bytes=maximum_bytes) == raw,
             f"{label} is not canonical JSON")
    return value


def _parse_checkpoint_metadata(raw: bytes, label: str) -> dict[str, Any]:
    value = _parse_canonical(
        raw, label, maximum_bytes=MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
    )
    _require(len(raw) <= _checkpoint_metadata_limit(value),
             f"{label} exceeds its exact versioned metadata ceiling")
    return value


def _info_key(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, info.st_uid)


def _rename_identity(info: os.stat_result) -> tuple[int, ...]:
    # A same-directory rename may update ctime while preserving the file bytes.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_nlink, info.st_uid)


def _open_abs_dir(path_value: object, label: str, *, private_final: bool) -> int:
    path = Path(_path(str(path_value), label))
    fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            _require(component not in ("", ".", ".."),
                     f"{label} has an unsafe component")
            child = os.open(component, os.O_RDONLY | _O_DIRECTORY |
                            _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode), f"{label} is not a directory")
        if private_final:
            _require(info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     f"{label} is not an owned mode-0700 directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_relative_dir(root_fd: int, relative: str, *, create: bool,
                       label: str) -> int:
    parts = PurePosixPath(relative).parts
    _require(parts and all(part not in ("", ".", "..", "/") for part in parts),
             f"{label} has an unsafe relative path")
    fd = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | _O_DIRECTORY |
                                _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            else:
                child = os.open(part, os.O_RDONLY | _O_DIRECTORY |
                                _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            _require(stat.S_ISDIR(info.st_mode) and
                     info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     f"{label} traverses a non-private directory")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _parent_at(root_fd: int, relative: str, *, create: bool,
               label: str) -> tuple[int, str]:
    pure = PurePosixPath(relative)
    _require(not pure.is_absolute() and pure.name not in ("", ".", "..") and
             all(part not in ("", ".", "..", "/") for part in pure.parts),
             f"{label} path is unsafe")
    parent = "." if len(pure.parts) == 1 else "/".join(pure.parts[:-1])
    fd = os.dup(root_fd) if parent == "." else _open_relative_dir(
        root_fd, parent, create=create, label=label,
    )
    return fd, pure.name


def _read_fd(fd: int, size: int, maximum: int, label: str,
             *, collect: bool) -> tuple[bytes | None, str, os.stat_result]:
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
             before.st_size == size and size <= maximum,
             f"{label} is not the exact bounded mode-0600 single-link file")
    hasher = hashlib.sha256()
    parts: list[bytes] | None = [] if collect else None
    count = 0
    while count < size:
        block = os.read(fd, min(BLOCK_BYTES, size - count))
        _require(bool(block), f"{label} ended before its pinned size")
        count += len(block)
        hasher.update(block)
        if parts is not None:
            parts.append(block)
    _require(os.read(fd, 1) == b"" and count == size and
             _info_key(before) == _info_key(os.fstat(fd)),
             f"{label} changed while being read")
    return (None if parts is None else b"".join(parts),
            hasher.hexdigest(), before)


def _read_regular_absolute(path_value: object, maximum: int,
                           label: str) -> tuple[bytes, str, os.stat_result]:
    path = Path(_path(str(path_value), f"{label} path"))
    _require(path.resolve(strict=True) == path,
             f"{label} traverses a symlink or alias")
    parent_fd = _open_abs_dir(str(path.parent), f"{label} parent",
                              private_final=True)
    try:
        before_path = os.stat(path.name, dir_fd=parent_fd,
                              follow_symlinks=False)
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and before_path.st_size <= maximum,
                 f"{label} is not an owned mode-0600 bounded regular file")
        fd = os.open(path.name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _require(_info_key(before) == _info_key(before_path),
                     f"{label} changed identity before read")
            raw, digest, _ = _read_fd(fd, before.st_size, maximum, label,
                                      collect=True)
            after_path = os.stat(path.name, dir_fd=parent_fd,
                                 follow_symlinks=False)
            _require(raw is not None and _info_key(before) == _info_key(after_path),
                     f"{label} changed at its path during read")
            return raw, digest, before
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _budget_limits_with_archive_profile(
    budget_raw: bytes, budget_pin: object, campaign_id: str, host_id: str,
    *, budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    prepared_dependency_map_raw: bytes | None = None,
    prepared_dependency_cache_root: str | os.PathLike[str] | None = None,
    lineage_capture_manifest_raw: bytes | None = None,
    lineage_capture_stage_root: str | None = None,
) -> tuple[tuple[int, int, int, int, list[str], str, int, int],
           dict[str, Any] | None]:
    pin = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == pin["raw_sha256"],
             "host evidence budget bytes differ from their raw pin")
    budget_probe = _parse_canonical(
        budget_raw, "host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        _require(budget_context is not None,
                 "preparatory budget validation requires its exact original job context")
        budget, profile, limits = _validate_preparatory_budget_profile_v1(
            budget_raw, pin, budget_context, campaign_id, host_id,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
        return limits, profile
    if budget_probe.get("schema") == HOST_BUDGET_SCHEMA_V4:
        _require(budget_context is not None,
                 "prepared V4 budget validation requires its exact archive context")
        budget, profile = _validate_prepared_exploration_budget_profile_v1(
            budget_raw, pin, budget_context, campaign_id, host_id,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            dependency_map_raw=prepared_dependency_map_raw,
            dependency_cache_root=prepared_dependency_cache_root,
            lineage_capture_manifest_raw=lineage_capture_manifest_raw,
            lineage_capture_stage_root=lineage_capture_stage_root,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
        catalogue = profile["catalogue"]
        retention = catalogue.get("retention_policy")
        _require(type(retention) is dict,
                 "prepared V4 catalogue lacks its exact retention projection")
        max_packet = _uint(retention.get("maximum_transfer_packet_bytes"),
                           "prepared V4 transfer-packet byte cap", positive=True)
        max_packet_inodes = _uint(
            retention.get("maximum_transfer_packet_inodes"),
            "prepared V4 transfer-packet inode cap", positive=True,
        )
        max_window_bytes = _uint(retention.get("maximum_window_total_bytes"),
                                 "prepared V4 live-window byte cap", positive=True)
        max_window_inodes = _uint(retention.get("maximum_window_total_inodes"),
                                  "prepared V4 live-window inode cap", positive=True)
        max_ack = _uint(retention.get("maximum_ack_bundle_bytes"),
                        "prepared V4 ACK-bundle byte cap", positive=True)
        max_signature = _uint(retention.get("maximum_signature_bytes"),
                              "prepared V4 signature cap", positive=True)
        transport = budget.get("transport")
        _require(max_signature <= MAX_GPG_OUTPUT_BYTES and
                 type(transport) is dict and
                 transport.get("maximum_job_packet_bytes") == max_packet and
                 transport.get("maximum_job_packet_inodes") == max_packet_inodes,
                 "prepared V4 transport limits differ from the selected catalogue")
        roots = catalogue.get("root_byte_bounds")
        reservation = budget.get("storage_reservation")
        reservation_roots = reservation.get("roots") if type(reservation) is dict else None
        _require(type(roots) is dict and bool(roots) and
                 type(reservation_roots) is dict,
                 "prepared V4 budget lacks exact roots/reservation")
        scratch_roots = [root for root, row in reservation_roots.items()
                         if type(row) is dict and row.get("role") == "scratch"]
        _require(len(scratch_roots) == 1,
                 "prepared V4 budget lacks one exact scratch root")
        return ((max_packet, max_packet_inodes, max_window_bytes,
                 max_window_inodes, list(roots), scratch_roots[0],
                 max_ack, max_signature), profile)
    _require(len(budget_raw) <= MAX_JSON_BYTES,
             "final host evidence budget exceeds its unchanged metadata ceiling")
    budget, is_width_bound = _exact_host_budget(
        _parse_canonical(budget_raw, "host evidence budget"),
        "host evidence budget",
    )
    if budget_context is not None:
        _require(_pin(budget_context["resource_budget_pin"],
                      "budget-context host budget pin") == pin and
                 budget_context["campaign_id"] == campaign_id and
                 budget_context["host_id"] == host_id,
                 "budget context identity differs from its exact pin")
    _require(not is_width_bound or budget_context is not None or
             budget.get("schema") == HOST_BUDGET_SCHEMA,
             "ready host budget v3 requires its original pinned context")
    _validate_host_budget_revision(
        budget, campaign_id, host_id, context=budget_context,
        budget_raw=budget_raw,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local,
        require_manifest_binding=(budget.get("schema") == HOST_BUDGET_SCHEMA_V3),
    )
    blockers = budget["execution_blockers"]
    readiness = _exact(budget["readiness"], {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "host evidence budget readiness")
    _require(type(blockers) is list and
             all(type(item) is str and bool(item) for item in blockers) and
             len(blockers) == len(set(blockers)) and
             all(type(readiness[field]) is bool for field in readiness) and
             readiness["qualification_eligible"] is False and
             (not readiness["execution_ready"] or
              (readiness["budget_complete"] and not blockers)),
             "host evidence budget blockers/readiness are inconsistent")
    body = {key: item for key, item in budget.items()
            if key != "budget_sha256"}
    budget_sha = _digest(budget.get("budget_sha256"),
                         "host evidence budget semantic digest")
    _require(budget_sha == _sha(_canonical(body)) and
             budget_sha == pin["semantic_sha256"],
             "host evidence budget semantic pin differs")
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict, "budget lacks its pinned path catalogue")
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict,
             "budget path catalogue lacks retention policy")
    max_packet = _uint(retention.get("maximum_transfer_packet_bytes"),
                       "budget transfer packet byte cap", positive=True)
    max_packet_inodes = _uint(
        retention.get("maximum_transfer_packet_inodes"),
        "budget transfer packet inode cap", positive=True,
    )
    max_window_bytes = _uint(retention.get("maximum_window_total_bytes"),
                             "budget live-window byte cap")
    max_window_inodes = _uint(retention.get("maximum_window_total_inodes"),
                              "budget live-window inode cap")
    max_ack_bundle = _uint(retention.get("maximum_ack_bundle_bytes"),
                           "budget ACK-bundle byte cap", positive=True)
    max_signature = _uint(retention.get("maximum_signature_bytes"),
                          "budget detached-signature byte cap", positive=True)
    _require(max_signature <= MAX_GPG_OUTPUT_BYTES,
             "budget signature cap exceeds the generic bounded parser ceiling")
    transport = budget.get("transport")
    _require(type(transport) is dict and
             transport.get("maximum_job_packet_bytes") == max_packet and
             transport.get("maximum_job_packet_inodes") == max_packet_inodes,
             "budget transport packet limits differ from its path catalogue")
    reservation = budget.get("storage_reservation")
    _require(type(reservation) is dict and
             type(reservation.get("roots")) is dict,
             "budget lacks its pinned storage roots")
    scratch_roots = [
        root for root, row in reservation["roots"].items()
        if type(row) is dict and row.get("role") == "scratch"
    ]
    _require(len(scratch_roots) == 1,
             "budget does not declare one packet scratch root")
    source_roots = catalogue.get("root_byte_bounds")
    _require(type(source_roots) is dict and source_roots,
             "budget path catalogue has no source roots")
    return ((max_packet, max_packet_inodes, max_window_bytes,
             max_window_inodes, list(source_roots), scratch_roots[0],
             max_ack_bundle, max_signature), None)


def _budget_limits(
    budget_raw: bytes, budget_pin: object, campaign_id: str, host_id: str,
    *, budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    prepared_dependency_map_raw: bytes | None = None,
    prepared_dependency_cache_root: str | os.PathLike[str] | None = None,
    lineage_capture_manifest_raw: bytes | None = None,
    lineage_capture_stage_root: str | None = None,
) -> tuple[int, int, int, int, list[str], str, int, int]:
    """Keep the legacy eight-value ABI for non-request-aware consumers."""
    limits, _profile = _budget_limits_with_archive_profile(
        budget_raw, budget_pin, campaign_id, host_id,
        budget_context=budget_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local,
        prepared_dependency_map_raw=prepared_dependency_map_raw,
        prepared_dependency_cache_root=prepared_dependency_cache_root,
        lineage_capture_manifest_raw=lineage_capture_manifest_raw,
        lineage_capture_stage_root=lineage_capture_stage_root,
    )
    return limits


def _validate_fixed_v3_tmp_proofs(request: dict[str, Any]) -> None:
    """Check the closed Fixed wire profile; owner bytes are verified by Archive."""
    _require(request["context"]["phase"] in {
                 "exploration", "aa", "confirmation",
             } and set(request["owner_receipt_pins"]) == {
                 "component_receipt", "fixed_pair_host_receipt",
             }, "v3 request requires the strict Fixed owner profile")
    proofs = request["empty_tmp_proofs"]
    _require(len(proofs) == 4,
             "v3 request requires all four Fixed TMP proofs")
    expected_order = [("component_receipt", ordinal, domain)
                      for ordinal in (0, 1)
                      for domain in ("", "probe_tmpdir")]
    order = []
    for index, proof_value in enumerate(proofs):
        _require(type(proof_value) is dict,
                 f"v3 TMP proof[{index}] is not an object")
        fields = {
            "role", "path", "owner_receipt_pin", "member_ordinal",
            "device", "inode", "mode", "mount", "bytes_used",
            "file_count", "directory_count", "bytes_limit", "inode_limit",
        }
        if proof_value.get("domain") == "probe_tmpdir":
            fields.add("domain")
        proof = _exact(proof_value, fields, f"v3 TMP proof[{index}]")
        _require(proof["role"] == "component_receipt" and
                 _pin(proof["owner_receipt_pin"], "v3 TMP owner pin") ==
                    request["owner_receipt_pins"]["component_receipt"],
                 "v3 TMP proof differs from the exact Fixed owner pin")
        _path(proof["path"], "v3 TMP path")
        for field in ("member_ordinal", "device", "inode", "mode",
                      "bytes_used", "file_count", "directory_count",
                      "bytes_limit", "inode_limit"):
            _uint(proof[field], f"v3 TMP proof {field}")
        _require(proof["inode"] > 0 and proof["mode"] == 0o700 and
                 proof["bytes_used"] == proof["file_count"] ==
                    proof["directory_count"] == 0 and
                 proof["bytes_limit"] > 0 and proof["inode_limit"] > 0,
                 "v3 TMP proof counters or private identity differ")
        mount = _exact(proof["mount"], {
            "mount_id", "major_minor", "mount_root", "mount_point",
            "filesystem_type", "mount_source", "device",
        }, "v3 TMP mount")
        _require(mount["device"] == proof["device"],
                 "v3 TMP mount device differs")
        order.append((proof["role"], proof["member_ordinal"],
                      proof.get("domain", "")))
    _require(order == expected_order,
             "v3 TMP proofs must be the canonical four member/probe facts")


def _validate_request(value: object) -> dict[str, Any]:
    base_fields = {
        "schema", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "entries", "request_sha256",
    }
    _require(type(value) is dict, "checkpoint request is not an object")
    if value.get("schema") in {REQUEST_SCHEMA, REQUEST_SCHEMA_V3}:
        request = _exact(value, base_fields, "checkpoint request v1/v3")
        tree_inventories = None
    elif value.get("schema") == REQUEST_SCHEMA_V2:
        request = _exact(value, base_fields | {"tree_inventories"},
                          "checkpoint request v2")
        tree_inventories = request["tree_inventories"]
        _require(type(tree_inventories) is list and bool(tree_inventories),
                 "v2 checkpoint request requires at least one exact tree declaration")
    else:
        raise TransferPacketError("checkpoint request schema differs")
    context = _exact(request["context"], {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "source_manifest_pin", "execution_manifest_pin", "plan_pin",
        "resource_budget_pin", "predecessor_ack_pin",
        "authorized_signer_fingerprint",
    }, "checkpoint request context")
    _require(context["schema"] ==
             "allocatbelt.application-source5-evidence-archive-context.v1",
             "checkpoint request context schema differs")
    campaign = _token(context["campaign_id"], "request campaign ID")
    host = _token(context["host_id"], "request host ID")
    _token(context["phase"], "request phase")
    _require(type(context["authorized_signer_fingerprint"]) is str and
             re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}",
                          context["authorized_signer_fingerprint"]) is not None,
             "request authorized signer fingerprint is malformed")
    _uint(context["job_index"], "request original job index")
    for name in ("source_manifest_pin", "execution_manifest_pin",
                 "plan_pin", "resource_budget_pin"):
        _pin(context[name], f"request {name}")
    predecessor = context["predecessor_ack_pin"]
    _require(predecessor is None or type(predecessor) is dict,
             "request predecessor pin is malformed")
    if predecessor is not None:
        _pin(predecessor, "request predecessor pin")
    job_pin = _pin_raw(request["job_record_pin"], "request job record pin")
    _require(request["predecessor_ack_pin"] == predecessor and
             type(request["owner_receipt_pins"]) is dict and
             list(request["owner_receipt_pins"]) ==
                 sorted(request["owner_receipt_pins"]) and
             type(request["empty_tmp_proofs"]) is list,
             "checkpoint request receipt/predecessor map is malformed")
    rows = request["entries"]
    _require(type(rows) is list and 0 < len(rows) <= MAX_ROWS,
             "checkpoint request entry count is outside its finite bound")
    previous = ""
    total = 0
    expected_receipt_origins = set()
    for index, value in enumerate(rows):
        row = _exact(value, {
            "origin_path", "role", "byte_count", "raw_sha256",
            "semantic_sha256",
        }, f"request entry[{index}]")
        origin = _path(row["origin_path"], f"request entry[{index}] origin")
        role = _token(row["role"], f"request entry[{index}] role")
        _require(role not in NON_EXPORTABLE_JOB_ROLES,
                 "non-exportable Source5 controller/job role is not exportable")
        size = _uint(row["byte_count"], f"request entry[{index}] byte count")
        _require(size <= MAX_OBJECT_BYTES and origin > previous,
                 "request entries are unsorted, duplicated, or too large")
        previous = origin
        total += size
        _digest(row["raw_sha256"], f"request entry[{index}] raw digest")
        semantic = row["semantic_sha256"]
        _require(semantic is None or
                 (type(semantic) is str and
                  re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                 "request entry semantic digest is malformed")
        if _is_owner_receipt_role(row["role"]):
            expected_receipt_origins.add(origin)
    _require(total <= MAX_OBJECT_BYTES * MAX_ROWS,
             "request aggregate payload exceeds finite arithmetic bounds")
    _require(all(row["origin_path"] != job_pin["path"] for row in rows),
             "always-local job record cannot appear in reclaimable packet entries")
    for role, pin_value in request["owner_receipt_pins"].items():
        _token(role, "request owner receipt role")
        pin = _pin(pin_value, f"request owner receipt {role}")
        row = next((item for item in rows if item["origin_path"] == pin["path"]), None)
        _require(row is not None and row["role"] == role and
                 row["raw_sha256"] == pin["raw_sha256"] and
                 row["semantic_sha256"] == pin["semantic_sha256"],
                 "request owner pin does not match one exact row")
    _require(set(request["owner_receipt_pins"]) ==
             {row["role"] for row in rows
              if _is_owner_receipt_role(row["role"])} and
             len(expected_receipt_origins) == len(request["owner_receipt_pins"]),
             "request owner receipt map does not close over receipt rows")
    if tree_inventories is not None:
        _validate_tree_inventories(
            tree_inventories, rows, request["owner_receipt_pins"],
        )
    if request["schema"] == REQUEST_SCHEMA_V3:
        _validate_fixed_v3_tmp_proofs(request)
    authorization = _exact(request["authorization"], {
        "authorization_id", "authorization_head", "terminal_head",
        "component_sha256", "process_metrics_sha256",
    }, "checkpoint request terminal authorization")
    _token(authorization["authorization_id"],
           "checkpoint request authorization ID")
    for field in ("authorization_head", "terminal_head", "component_sha256",
                  "process_metrics_sha256"):
        _digest(authorization[field],
                f"checkpoint request authorization {field}")
    body = {key: item for key, item in request.items()
            if key != "request_sha256"}
    _require(_digest(request["request_sha256"], "request self digest") ==
             _sha(_canonical(
                 body, maximum_bytes=_checkpoint_metadata_limit(request),
             )),
             "checkpoint request self digest differs")
    return request


def _object_identity(origin: str, raw_sha: str) -> str:
    name = _sha(origin.encode("utf-8"))
    return f"{name[:2]}/{name}-{raw_sha}.bin"


def _packet_member_name(origin: str, raw_sha: str) -> str:
    object_id = _object_identity(origin, raw_sha)
    transfer_id = _sha(object_id.encode("ascii"))
    return f"objects/{transfer_id}.bin"


def _tar_size(members: Iterable[tuple[str, int]]) -> int:
    content = 0
    for name, size in members:
        _require(type(name) is str and len(name.encode("ascii")) <= 100,
                 "packet member name exceeds its deterministic short encoding")
        _require(type(size) is int and 0 <= size <= MAX_OBJECT_BYTES,
                 "packet member size is outside bounded PAX")
        content += TAR_BLOCK_BYTES + (
            (size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
        ) * TAR_BLOCK_BYTES
        if size > USTAR_MAX_SIZE:
            record = _pax_size_record(size)
            _require(len(record) <= MAX_PAX_HEADER_BYTES,
                     "PAX size extension exceeds its finite header bound")
            content += TAR_BLOCK_BYTES + (
                (len(record) + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
            ) * TAR_BLOCK_BYTES
    with_end_markers = content + 1024
    return ((with_end_markers + TAR_RECORD_BYTES - 1) //
            TAR_RECORD_BYTES) * TAR_RECORD_BYTES


def _pax_size_record(size: int) -> bytes:
    body = f"size={size}\n".encode("ascii")
    record_length = len(body) + 2
    while True:
        candidate = len(body) + len(str(record_length)) + 1
        if candidate == record_length:
            break
        record_length = candidate
    return f"{record_length} ".encode("ascii") + body


def _open_source(
    origin: str, roots: list[str], *, expected_regular_mode: int | None = None,
) -> tuple[int, str, os.stat_result]:
    path = Path(_path(origin, "origin object path"))
    candidates = [Path(_path(root, "budget source root")) for root in roots
                  if path != Path(root) and Path(root) in path.parents]
    _require(bool(candidates),
             "origin path escapes every byte-bounded host budget root")
    root = max(candidates, key=lambda item: len(item.parts))
    relative = path.relative_to(root).as_posix()
    root_fd = _open_abs_dir(str(root), "budget source root",
                            private_final=True)
    parent_fd, name = _parent_at(root_fd, relative, create=False,
                                 label="origin source")
    os.close(root_fd)
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            expected_mode = (0o600 if expected_regular_mode is None
                             else _uint(expected_regular_mode,
                                       "typed tree file mode"))
            _require(info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == expected_mode and
                     info.st_nlink == 1,
                     "origin source is not the exact owned single-link regular file")
            fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                         _O_NONBLOCK, dir_fd=parent_fd)
            opened = os.fstat(fd)
            _require(_info_key(opened) == _info_key(info),
                     "origin source changed identity before open")
            return fd, "regular", opened
        _require(expected_regular_mode is None and
                 stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid() and
                 info.st_nlink == 1,
                 "origin source is not a regular file or literal owned symlink")
        return parent_fd, "symlink:" + name, info
    except BaseException:
        os.close(parent_fd)
        raise


def _read_symlink(
    parent_fd: int, name: str, expected: dict[str, Any],
) -> tuple[bytes, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    target = os.readlink(name, dir_fd=parent_fd)
    raw = os.fsencode(target)
    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require(_info_key(before) == _info_key(after) and
             len(raw) == expected["byte_count"] and
             _sha(raw) == expected["raw_sha256"],
             "literal symlink bytes differ from the exact request row")
    return raw, after


def _hash_source(origin: str, roots: list[str],
                 row: dict[str, Any], *,
                 expected_regular_mode: int | None = None) -> tuple[str, int, tuple[int, ...]]:
    fd, kind, info = _open_source(
        origin, roots, expected_regular_mode=expected_regular_mode,
    )
    try:
        if kind.startswith("symlink:"):
            parent_fd, name = fd, kind.split(":", 1)[1]
            raw, after = _read_symlink(parent_fd, name, row)
            return "symlink", len(raw), _info_key(after)
        _require(info.st_size == row["byte_count"] and
                 info.st_size <= MAX_OBJECT_BYTES,
                 "origin regular-file size differs from the request row")
        hasher = hashlib.sha256()
        total = 0
        while total < info.st_size:
            block = os.read(fd, min(BLOCK_BYTES, info.st_size - total))
            _require(bool(block), "origin regular file shortened while hashing")
            total += len(block)
            hasher.update(block)
        _require(os.read(fd, 1) == b"" and total == row["byte_count"] and
                 hasher.hexdigest() == row["raw_sha256"] and
                 _info_key(info) == _info_key(os.fstat(fd)),
                 "origin regular file changed or differs from its raw pin")
        return "regular", total, _info_key(os.fstat(fd))
    finally:
        if kind.startswith("symlink:"):
            os.close(fd)
        else:
            os.close(fd)


class _HashingReader:
    def __init__(self, fd: int, size: int) -> None:
        self.fd = fd
        self.size = size
        self.count = 0
        self.hasher = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        remaining = self.size - self.count
        if remaining <= 0:
            return b""
        amount = remaining if size is None or size < 0 else min(size, remaining)
        block = os.read(self.fd, min(BLOCK_BYTES, amount))
        _require(bool(block), "origin file shortened during tar streaming")
        self.count += len(block)
        self.hasher.update(block)
        return block


def _octal_field(value: int, width: int) -> bytes:
    _require(type(value) is int and 0 <= value <= MAX_OBJECT_BYTES,
             "tar header number is outside its finite bound")
    digits = f"{value:o}".encode("ascii")
    _require(len(digits) < width,
             "tar header number exceeds its octal field")
    return b"0" * (width - len(digits) - 1) + digits + b"\x00"


def _tar_header(name: str, size: int, *, typeflag: bytes = b"0") -> bytes:
    encoded = name.encode("ascii", "strict")
    _require(0 < len(encoded) <= 100 and typeflag in (b"0", b"x"),
             "tar member header name/type is outside the packet grammar")
    header = bytearray(TAR_BLOCK_BYTES)
    header[0:len(encoded)] = encoded
    header[100:108] = _octal_field(0o600, 8)
    header[108:116] = _octal_field(0, 8)
    header[116:124] = _octal_field(0, 8)
    header[124:136] = _octal_field(
        0 if size > USTAR_MAX_SIZE else size, 12,
    )
    header[136:148] = _octal_field(0, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    checksum = sum(header)
    checksum_field = f"{checksum:06o}".encode("ascii") + b"\x00 "
    _require(len(checksum_field) == 8,
             "tar header checksum exceeds its fixed field")
    header[148:156] = checksum_field
    return bytes(header)


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        _require(written > 0, "packet writer made no progress")
        view = view[written:]


def _write_at_fd(parent_fd: int, name: str, raw: bytes,
                 label: str) -> tuple[str, int]:
    _require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES,
             f"{label} exceeds its bounded metadata size")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, raw)
        os.fsync(fd)
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and
                 info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and
                 info.st_nlink == 1 and info.st_size == len(raw),
                 f"{label} writer did not produce its exact private file")
    finally:
        os.close(fd)
    os.fsync(parent_fd)
    return _sha(raw), len(raw)


def _read_fd_at(parent_fd: int, name: str, maximum: int, label: str,
                *, expected_bytes: int) -> tuple[bytes, str, os.stat_result]:
    path_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require(stat.S_ISREG(path_info.st_mode) and
             path_info.st_uid == os.getuid() and
             stat.S_IMODE(path_info.st_mode) == 0o600 and
             path_info.st_nlink == 1 and path_info.st_size == expected_bytes,
             f"{label} is not its exact private mode-0600 file")
    fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                 dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        _require(_info_key(before) == _info_key(path_info),
                 f"{label} changed identity before reopen")
        raw, digest, _ = _read_fd(fd, expected_bytes, maximum, label,
                                  collect=True)
        after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require(raw is not None and
                 _info_key(before) == _info_key(after_path),
                 f"{label} changed during reopen")
        return raw, digest, before
    finally:
        os.close(fd)


def _write_padding(fd: int, size: int) -> None:
    padding = (-size) % TAR_BLOCK_BYTES
    if padding:
        _write_all(fd, b"\x00" * padding)


def _budget_and_pin_for_request(
    request: dict[str, Any], budget_path: str | os.PathLike[str],
    *, source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> tuple[dict[str, Any], bytes,
           tuple[int, int, int, int, list[str], str, int, int]]:
    pin = request["context"]["resource_budget_pin"]
    raw, actual, _ = _read_regular_absolute(
        os.fspath(budget_path), PREPARATORY_MAX_BUDGET_BYTES,
        "pinned host budget",
    )
    _require(actual == pin["raw_sha256"],
             "host budget local bytes differ from checkpoint request raw pin")
    limits, profile = _budget_limits_with_archive_profile(
        raw, pin, request["context"]["campaign_id"],
        request["context"]["host_id"],
        budget_context=request["context"],
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
    )
    _require_profile_request_schema(profile, request["schema"])
    return _parse_canonical(raw, "pinned host budget"), raw, limits


def _request_job_group(request: dict[str, Any]) -> tuple[str, str, str, str]:
    context = request["context"]
    record_name = PurePosixPath(request["job_record_pin"]["path"]).name
    _require(record_name.endswith(".json") and len(record_name) > 5,
             "checkpoint request job-record path lacks its original run ID")
    run_id = _run_id(record_name[:-5], "original Source5 run ID")
    return (context["host_id"], context["phase"], run_id,
            context["campaign_id"])


def _job_record_catalogue_row(
    request: dict[str, Any], budget: dict[str, Any], *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, Any]:
    host_id, phase, run_id, _campaign_id = _request_job_group(request)
    path = request["job_record_pin"]["path"]
    row = _catalogue_rows_for_paths(
        budget, {path}, host_id, phase, run_id,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )[path]
    _require(row["role"] == "source5_job_record" and
             row["kind"] == "file" and row["max_file_bytes"] > 0,
             "raw-pinned job record lacks its exact always-local catalogue row")
    return row


def _job_record_source(
    request: dict[str, Any], budget: dict[str, Any], roots: list[str],
) -> tuple[dict[str, Any], tuple[str, int, tuple[int, ...]]]:
    catalogue_row = _job_record_catalogue_row(request, budget)
    pin = request["job_record_pin"]
    fd, kind, before = _open_source(pin["path"], roots)
    try:
        _require(kind == "regular" and stat.S_ISREG(before.st_mode) and
                 0 < before.st_size <= catalogue_row["max_file_bytes"] and
                 before.st_size <= MAX_JSON_BYTES,
                 "always-local job record is not a bounded regular file")
        row = {
            "origin_path": pin["path"], "byte_count": before.st_size,
            "raw_sha256": pin["raw_sha256"], "semantic_sha256": None,
        }
        identity = _hash_source(pin["path"], roots, row)
        return row, identity
    finally:
        os.close(fd)


def _offer_body(
    request_pin: dict[str, str], packet_path: str, packet_sha: str,
    packet_size: int, receiver_path: str, receiver_cap: int,
) -> dict[str, Any]:
    body = {
        "schema": "allocatbelt.application-source5-archive-transfer-offer.v1",
        "checkpoint_request_pin": request_pin,
        "transfer_packet_pin": {
            "path": packet_path, "raw_sha256": packet_sha,
            "byte_count": packet_size,
        },
        "acknowledgement_receiver": {
            "path": receiver_path, "maximum_bytes": receiver_cap,
        },
        "offer_sha256": "",
    }
    digest = _sha(_canonical({key: item for key, item in body.items()
                              if key != "offer_sha256"}))
    return {**body, "offer_sha256": digest}


def publish_transfer_offer(
    request_raw: bytes, request_pin: object, packet_pin: object,
    budget_raw: bytes, budget_pin: object, offer_path: str | os.PathLike[str],
    acknowledgement_receiver_path: str | os.PathLike[str],
    *, source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Publish the exact v1 offer only at its prospectively budgeted job paths."""
    request = _validate_request(_parse_checkpoint_metadata(
        request_raw, "host checkpoint request",
    ))
    checked_request_pin = _pin(request_pin, "checkpoint request pin")
    _require(_sha(request_raw) == checked_request_pin["raw_sha256"] and
             request["request_sha256"] ==
                 checked_request_pin["semantic_sha256"],
             "offer request differs from its exact pin")
    packet = _exact(packet_pin, {
        "path", "raw_sha256", "byte_count",
    }, "transfer packet pin")
    packet_path = _path(packet["path"], "transfer packet origin path")
    packet_sha = _digest(packet["raw_sha256"], "transfer packet raw digest")
    packet_size = _uint(packet["byte_count"], "transfer packet byte count",
                        positive=True)
    offer_path_text = _path(os.fspath(offer_path), "offer output path")
    receiver_path = _path(os.fspath(acknowledgement_receiver_path),
                          "ACK bundle receiver path")
    budget_pin_checked = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "offer budget bytes differ from raw pin")
    budget = _parse_canonical(
        budget_raw, "host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    context = request["context"]
    if budget.get("schema") != PREPARATORY_BUDGET_SCHEMA_V1:
        _validate_budget_origin_pins(budget, context)
    if request["schema"] in {REQUEST_SCHEMA_V2, REQUEST_SCHEMA_V3}:
        _entry_catalogue_rows(request, budget)
    limits, profile = _budget_limits_with_archive_profile(
        budget_raw, budget_pin_checked, context["campaign_id"],
        context["host_id"],
        budget_context=context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
    )
    _require_profile_request_schema(profile, request["schema"])
    (max_packet, packet_inodes, _window_bytes, _window_inodes, _roots,
     _scratch, max_ack, _max_signature) = limits
    _require(packet_inodes == 1 and packet_size <= max_packet,
             "offer packet pin exceeds the exact one-inode budget")
    (req_row, packet_row, offer_row, receiver_row,
     incoming_row) = _offer_catalogue_rows(
        request, budget, checked_request_pin["path"], packet_path,
        offer_path_text, receiver_path,
    )
    _require(len(request_raw) <= req_row["max_file_bytes"] and
             packet_size <= packet_row["max_file_bytes"] and
             receiver_row["max_file_bytes"] <= max_ack and
             receiver_row["max_file_bytes"] > 0 and
             incoming_row["max_file_bytes"] == receiver_row["max_file_bytes"],
             "offer request/packet/ACK caps differ from exact catalogue ceilings")
    request_disk_raw, request_disk_sha, _ = _read_regular_absolute(
        checked_request_pin["path"], req_row["max_file_bytes"],
        "host checkpoint request before offer",
    )
    _require(request_disk_raw == request_raw and
             request_disk_sha == checked_request_pin["raw_sha256"],
             "catalogued checkpoint request file differs from its exact pin")
    packet_disk_sha, packet_info = _hash_absolute_regular(
        Path(packet_path), packet_row["max_file_bytes"],
        "transfer packet before offer",
    )
    _require(packet_disk_sha == packet_sha and
             packet_info.st_size == packet_size,
             "catalogued transfer packet file differs from its exact pin")
    receiver = Path(receiver_path)
    receiver_parent_fd = _open_abs_dir(
        str(receiver.parent), "ACK receiver parent", private_final=True,
    )
    try:
        for receiver_name in (receiver.name, receiver.name + ".incoming"):
            try:
                os.stat(receiver_name, dir_fd=receiver_parent_fd,
                        follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise TransferPacketError(
                "exclusive ACK final/incoming path already exists",
            )
    finally:
        os.close(receiver_parent_fd)
    offer = _offer_body(
        checked_request_pin, packet_path, packet_sha, packet_size,
        receiver_path, receiver_row["max_file_bytes"],
    )
    raw = _canonical(offer)
    _require(len(raw) <= offer_row["max_file_bytes"],
             "transfer offer exceeds its exact catalogue path ceiling")
    path = Path(offer_path_text)
    parent_fd = _open_abs_dir(str(path.parent), "transfer offer parent",
                              private_final=True)
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TransferPacketError(
                "catalogued transfer offer path already exists",
            )
        raw_sha, size = _write_at_fd(parent_fd, path.name, raw,
                                     "Source5 transfer offer")
        reopened, reopened_sha, _ = _read_fd_at(
            parent_fd, path.name, MAX_JSON_BYTES,
            "Source5 transfer offer", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "transfer offer failed independent reopen")
        return offer, {
            "path": str(path), "raw_sha256": raw_sha,
            "semantic_sha256": offer["offer_sha256"],
        }
    finally:
        os.close(parent_fd)


def _validate_transfer_offer_with_profile(
    offer_raw: bytes, offer_pin: object, budget_raw: bytes,
    budget_pin: object, *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> tuple[dict[str, Any], dict[str, str],
           tuple[int, int, int, int, list[str], str, int, int],
           dict[str, Any] | None]:
    offer = _exact(_parse_canonical(offer_raw, "archive transfer offer"), {
        "schema", "checkpoint_request_pin", "transfer_packet_pin",
        "acknowledgement_receiver", "offer_sha256",
    }, "archive transfer offer")
    checked_offer_pin = _pin(offer_pin, "archive transfer offer pin")
    body = {key: item for key, item in offer.items()
            if key != "offer_sha256"}
    _require(offer["schema"] ==
             "allocatbelt.application-source5-archive-transfer-offer.v1" and
             offer["offer_sha256"] == _sha(_canonical(body)) and
             checked_offer_pin["raw_sha256"] == _sha(offer_raw) and
             checked_offer_pin["semantic_sha256"] == offer["offer_sha256"],
             "transfer offer bytes or semantic pin differs")
    request_pin = _pin(offer["checkpoint_request_pin"],
                       "offer checkpoint request pin")
    packet_pin = _exact(offer["transfer_packet_pin"], {
        "path", "raw_sha256", "byte_count",
    }, "offer transfer packet pin")
    packet_pin = {
        "path": _path(packet_pin["path"], "offer packet path"),
        "raw_sha256": _digest(packet_pin["raw_sha256"],
                              "offer packet raw digest"),
        "byte_count": _uint(packet_pin["byte_count"],
                            "offer packet size", positive=True),
    }
    receiver = _exact(offer["acknowledgement_receiver"], {
        "path", "maximum_bytes",
    }, "offer ACK bundle receiver")
    receiver_path = _path(receiver["path"], "offer ACK receiver path")
    receiver_cap = _uint(receiver["maximum_bytes"],
                         "offer ACK bundle byte cap", positive=True)
    budget = _parse_canonical(
        budget_raw, "host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    budget_pin_checked = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "offer budget bytes differ from their raw pin")
    _require(budget.get("budget_sha256") ==
             _budget_body_semantic_sha256(budget) ==
             budget_pin_checked["semantic_sha256"],
             "offer budget semantic pin differs")
    limits, profile = _budget_limits_with_archive_profile(
        budget_raw, budget_pin_checked, budget["campaign_id"],
        budget["host_id"],
        budget_context=budget_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=(catalogue_chunk_paths is not None),
    )
    (max_packet, packet_inodes, _window_bytes, _window_inodes, _roots,
     _scratch, max_ack, _max_signature) = limits
    offer_path = checked_offer_pin["path"]
    request_path = request_pin["path"]
    packet_path = packet_pin["path"]
    incoming_path = _path(receiver_path + ".incoming",
                          "offer ACK incoming path")
    rows = _catalogue_rows_for_paths(
        budget, {offer_path, request_path, packet_path, receiver_path,
                 incoming_path},
        budget["host_id"], None, None,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    phase = rows[request_path]["phase"]
    run_id = rows[request_path]["run_id"]
    _require(type(phase) is str and type(run_id) is str and
             all(row["phase"] == phase and row["run_id"] == run_id
                 for row in rows.values()),
             "offer paths do not share one original phase/run group")
    expected_roles = {
        offer_path: "source5_transfer_offer",
        request_path: "source5_checkpoint_request",
        packet_path: "source5_transfer_packet",
        receiver_path: "source5_ack_bundle",
        incoming_path: "source5_ack_bundle_incoming",
    }
    for path, role in expected_roles.items():
        _require(rows[path]["role"] == role,
                 f"offer path {path} is not catalogued as {role}")
    _require(rows[incoming_path]["max_file_bytes"] ==
             rows[receiver_path]["max_file_bytes"] and
             rows[incoming_path]["max_bytes"] ==
                 rows[receiver_path]["max_bytes"] and
             rows[incoming_path]["storage_root"] ==
                 rows[receiver_path]["storage_root"] and
             rows[incoming_path]["owner"] == rows[receiver_path]["owner"] and
             rows[incoming_path]["max_inodes"] == 1 and
             rows[receiver_path]["max_inodes"] == 1,
             "incoming/final ACK alternatives differ from their exact cap")
    _require(packet_inodes == 1 and packet_pin["byte_count"] <= max_packet and
             packet_pin["byte_count"] <= rows[packet_path]["max_file_bytes"] and
             receiver_cap == rows[receiver_path]["max_file_bytes"] and
             receiver_cap <= max_ack,
             "offer paths or caps differ from the pinned catalogue")
    return offer, checked_offer_pin, limits, profile


def validate_transfer_offer(
    offer_raw: bytes, offer_pin: object, budget_raw: bytes,
    budget_pin: object, *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> tuple[dict[str, Any], dict[str, str],
           tuple[int, int, int, int, list[str], str, int, int]]:
    """Validate a request-less offer without claiming its request version."""
    offer, pin, limits, _profile = _validate_transfer_offer_with_profile(
        offer_raw, offer_pin, budget_raw, budget_pin,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        budget_context=budget_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
    )
    return offer, pin, limits


def _catalogue_rows_for_paths(
    budget: dict[str, Any], paths: set[str], host_id: str,
    phase: str | None, run_id: str | None,
    *, catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    tree_paths: set[str] | None = None,
    require_tree_closure: bool = False,
) -> dict[str, dict[str, Any]]:
    tree_paths = set() if tree_paths is None else tree_paths
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             catalogue.get("schema") ==
                 "allocatbelt.application-source5-host-path-catalogue.v2" and
             type(catalogue.get("chunks")) is list and
             type(catalogue.get("entry_count")) is int,
             "pinned host budget lacks its exact path catalogue")
    chunk_bytes = _uint(catalogue.get("chunk_bytes"),
                        "catalogue chunk byte ceiling", positive=True)
    entry_count = _uint(catalogue.get("entry_count"),
                        "catalogue entry count", positive=True)
    _require(chunk_bytes <= MAX_CATALOGUE_CHUNK_BYTES,
             "catalogue chunk byte ceiling exceeds the producer metadata bound")
    catalogue_body = {key: item for key, item in catalogue.items()
                      if key != "semantic_sha256"}
    _require(catalogue.get("semantic_sha256") ==
             _sha(_canonical(catalogue_body)),
             "host path catalogue semantic digest differs")
    _require((catalogue_chunk_paths is None) ==
             (catalogue_cache_root is None),
             "Root-local catalogue mapping and cache root must be supplied together")
    local_cache = None
    if catalogue_chunk_paths is not None:
        _require(type(catalogue_chunk_paths) is dict,
                 "Root-local catalogue map is not a path dictionary")
        local_cache = Path(_path(catalogue_cache_root,
                                 "Root-local catalogue cache root"))
        cache_fd = _open_abs_dir(str(local_cache),
                                 "Root-local catalogue cache root",
                                 private_final=True)
        os.close(cache_fd)
    expected_chunk_rows = 0
    found: dict[str, dict[str, Any]] = {}
    role_byte_sums: dict[str, int] = {}
    readback_rows: list[dict[str, Any]] = []
    analyzer_rows: list[dict[str, Any]] = []
    declared_job_trees: set[str] = set()
    previous_chunk = ""
    previous_path = ""
    seen_chunk_paths = set()
    for index, descriptor_value in enumerate(catalogue["chunks"]):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"host path catalogue chunk[{index}]")
        chunk_path = _path(descriptor["path"], "host path catalogue chunk path")
        raw_sha = _digest(descriptor["raw_sha256"], "catalogue chunk raw digest")
        semantic_sha = _digest(descriptor["semantic_sha256"],
                               "catalogue chunk semantic digest")
        byte_count = _uint(descriptor["byte_count"], "catalogue chunk byte count",
                           positive=True)
        row_count = _uint(descriptor["row_count"], "catalogue chunk row count",
                          positive=True)
        _require(chunk_path > previous_chunk and
                 semantic_sha == raw_sha and
                 byte_count <= chunk_bytes and
                 row_count <= entry_count and row_count <= byte_count and
                 expected_chunk_rows + row_count <= entry_count,
                 "host path catalogue chunk pin/order differs")
        previous_chunk = chunk_path
        seen_chunk_paths.add(chunk_path)
        if catalogue_chunk_paths is None:
            read_path = chunk_path
        else:
            _require(chunk_path in catalogue_chunk_paths,
                     "Root-local map omits a pinned host catalogue origin")
            read_path = _path(catalogue_chunk_paths[chunk_path],
                              "Root-local catalogue chunk path")
            local = Path(read_path)
            _require(read_path != chunk_path and local != local_cache and
                     local_cache in local.parents,
                     "Root-local catalogue chunk aliases or escapes its cache")
        raw, digest, _ = _read_regular_absolute(
            read_path, byte_count, "host path catalogue chunk",
        )
        _require(len(raw) == byte_count and digest == raw_sha,
                 "host path catalogue chunk differs from its raw pin")
        lines = raw.splitlines(keepends=True)
        _require(len(lines) == row_count and bool(lines),
                 "host path catalogue chunk row count differs")
        chunk_first = None
        chunk_last = None
        for line_index, line in enumerate(lines):
            _require(line.endswith(b"\n") and b"\r" not in line and
                     len(line) <= 64 * 1024,
                     "path catalogue line framing/size differs")
            try:
                row_value = json.loads(line.decode("ascii", "strict"))
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise TransferPacketError(
                    f"path catalogue row is malformed: {error}",
                ) from error
            row = _exact(row_value, {
                "path", "kind", "role", "host_id", "max_bytes",
                "max_file_bytes", "max_inodes", "storage_root", "owner",
                "phase", "run_id", "member_index", "aggregate_id",
                "aggregate_max_bytes", "origin_pin",
            }, "path catalogue row")
            _require(line == _canonical(row),
                     "path catalogue row is not canonical")
            row_path = _path(row["path"], "catalogue row path")
            role = _token(row["role"], "catalogue row role")
            _require(row_path > previous_path and row["kind"] in {"file", "tree"} and
                     (row["host_id"] is None or
                      type(row["host_id"]) is str) and
                     (row["phase"] is None or type(row["phase"]) is str) and
                     (row["run_id"] is None or type(row["run_id"]) is str),
                     "path catalogue order/identity is malformed")
            previous_path = row_path
            chunk_first = row_path if chunk_first is None else chunk_first
            chunk_last = row_path
            for field in ("max_bytes", "max_file_bytes", "max_inodes"):
                _uint(row[field], f"catalogue row {field}")
            _require(row["max_file_bytes"] <= row["max_bytes"] and
                     ((row["kind"] == "file" and row["max_inodes"] == 1) or
                      (row["kind"] == "tree" and row["max_inodes"] > 0)),
                     "catalogue row per-file/inode bounds are malformed")
            role_byte_sums[role] = (
                role_byte_sums.get(role, 0) + row["max_bytes"]
            )
            if role in SOURCE5_ARCHIVE_READ_ROLES:
                readback_rows.append(row)
            if role == SOURCE5_ANALYZER_SPOOL_ROLE:
                analyzer_rows.append(row)
            if (require_tree_closure and row["kind"] == "tree" and
                    role == "opaque_trace"):
                _require(type(row["host_id"]) is str and
                         type(row["phase"]) is str and
                         type(row["run_id"]) is str,
                         "opaque-trace tree declaration lacks its exact job identity")
                tree_host = _token(row["host_id"],
                                   "opaque-trace catalogue host ID")
                tree_phase = _token(row["phase"],
                                    "opaque-trace catalogue phase")
                tree_run = _run_id(row["run_id"],
                                   "opaque-trace catalogue run ID")
                if (tree_host, tree_phase, tree_run) == (host_id, phase, run_id):
                    declared_job_trees.add(row_path)
            if row_path in paths:
                expected_kind = "tree" if row_path in tree_paths else "file"
                _require(row_path not in found and row["kind"] == expected_kind and
                         row["host_id"] == host_id and
                         (phase is None or row["phase"] == phase) and
                         (run_id is None or row["run_id"] == run_id),
                         "catalogued path is missing, duplicated, or outside its exact job/tree role")
                found[row_path] = row
        _require(chunk_first == descriptor["first_path"] and
                 chunk_last == descriptor["last_path"],
                 "path catalogue chunk path range differs from its actual rows")
        expected_chunk_rows += row_count
    _require(expected_chunk_rows == catalogue["entry_count"] and
             set(found) == paths,
             "exact offer paths do not close over the pinned catalogue")
    if require_tree_closure:
        _require(declared_job_trees == tree_paths,
                 "v2 tree inventories omit or add an opaque-trace catalogue declaration")
    if catalogue_chunk_paths is not None:
        _require(set(catalogue_chunk_paths) == seen_chunk_paths,
                 "Root-local catalogue map is not the complete exact chunk set")
    _validate_h15_archive_readback_profile(
        budget, host_id, readback_rows, role_byte_sums, analyzer_rows,
    )
    return found


def _offer_catalogue_rows(
    request: dict[str, Any], budget: dict[str, Any],
    request_path: str, packet_path: str, offer_path: str,
    receiver_path: str, *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    host_id, phase, run_id, _campaign_id = _request_job_group(request)
    incoming_path = _path(receiver_path + ".incoming",
                          "ACK bundle incoming path")
    paths = {request_path, packet_path, offer_path, receiver_path,
             incoming_path}
    rows = _catalogue_rows_for_paths(
        budget, paths, host_id, phase, run_id,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    expected_roles = {
        request_path: "source5_checkpoint_request",
        packet_path: "source5_transfer_packet",
        offer_path: "source5_transfer_offer",
        receiver_path: "source5_ack_bundle",
        incoming_path: "source5_ack_bundle_incoming",
    }
    for path, role in expected_roles.items():
        _require(rows[path]["role"] == role and rows[path]["kind"] == "file",
                 f"catalogued path {path} has role other than {role}")
    _require(rows[incoming_path]["max_file_bytes"] ==
             rows[receiver_path]["max_file_bytes"] and
             rows[incoming_path]["max_bytes"] ==
                 rows[receiver_path]["max_bytes"] and
             rows[incoming_path]["storage_root"] ==
                 rows[receiver_path]["storage_root"] and
             rows[incoming_path]["owner"] == rows[receiver_path]["owner"] and
             rows[incoming_path]["max_inodes"] == 1 and
             rows[receiver_path]["max_inodes"] == 1,
             "incoming and final ACK alternatives have different exact caps")
    return (rows[request_path], rows[packet_path], rows[offer_path],
            rows[receiver_path], rows[incoming_path])


def _entry_catalogue_rows(
    request: dict[str, Any], budget: dict[str, Any], *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, dict[str, Any]]:
    host_id, phase, run_id, _campaign_id = _request_job_group(request)
    entries = request["entries"]
    tree_inventories_value = request.get("tree_inventories")
    tree_file_paths: set[str] = set()
    tree_file_modes: dict[str, int] = {}
    trees = []
    if tree_inventories_value is not None:
        trees, tree_file_paths = _validate_tree_inventories(
            tree_inventories_value, entries, request["owner_receipt_pins"],
        )
    tree_paths = {row["root_path"] for row in trees}
    paths = ({row["origin_path"] for row in entries} - tree_file_paths) | tree_paths
    rows = _catalogue_rows_for_paths(
        budget, paths, host_id, phase, run_id,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        tree_paths=tree_paths,
        require_tree_closure=tree_inventories_value is not None,
    )
    tree_entries: dict[str, dict[str, Any]] = {}
    for tree in trees:
        catalogue_row = rows[tree["root_path"]]
        max_file_bytes = max(
            (entry["size"] for entry in tree["entries"]
             if entry["kind"] == "file"),
            default=0,
        )
        _require(catalogue_row["role"] == tree["role"] == "opaque_trace" and
                 catalogue_row["kind"] == "tree" and
                 catalogue_row["max_inodes"] >= tree["entry_count"] + 1 and
                 tree["byte_count"] <= catalogue_row["max_bytes"] and
                 max_file_bytes <= catalogue_row["max_file_bytes"],
                 "tree inventory exceeds its exact typed catalogue root cap")
        for item in tree["entries"]:
            if item["kind"] == "file":
                tree_entries[item["path"]] = item
    for entry in entries:
        tree_entry = tree_entries.get(entry["origin_path"])
        if tree_entry is not None:
            _require(entry["role"] == "opaque_trace" and
                     entry["byte_count"] == tree_entry["size"] and
                     entry["raw_sha256"] == tree_entry["raw_sha256"] and
                     entry["semantic_sha256"] is None,
                     "tree payload differs from its exact typed inventory row")
            continue
        catalogue_row = rows[entry["origin_path"]]
        _require(catalogue_row["role"] == entry["role"] and
                 catalogue_row["kind"] == "file" and
                 catalogue_row["max_inodes"] == 1 and
                 catalogue_row["max_file_bytes"] ==
                     catalogue_row["max_bytes"] and
                 entry["byte_count"] <= catalogue_row["max_file_bytes"],
                 "request object row exceeds its exact source-pinned catalogue role/cap")
        if catalogue_row["origin_pin"] is not None:
            origin_pin = _exact(catalogue_row["origin_pin"], {
                "raw_sha256", "semantic_sha256",
            }, "catalogued source origin pin")
            origin_raw = _digest(origin_pin["raw_sha256"],
                                 "catalogued source origin raw digest")
            origin_semantic = origin_pin["semantic_sha256"]
            _require(origin_semantic is None or
                     type(origin_semantic) is str,
                     "catalogued source origin semantic digest is malformed")
            if origin_semantic is not None:
                origin_semantic = _digest(
                    origin_semantic,
                    "catalogued source origin semantic digest",
                )
            _require(origin_raw == entry["raw_sha256"] and
                     origin_semantic == entry["semantic_sha256"],
                     "request object differs from its source-pinned catalogue origin")
    _require(set(rows) == paths and
             all(path not in rows for path in tree_file_paths),
             "tree descendants were treated as wildcard catalogue declarations")
    return rows


def _request_inode_count(request: dict[str, Any]) -> int:
    rows = request["entries"]
    trees = request.get("tree_inventories")
    if trees is None:
        return len(rows)
    tree_file_paths = {
        item["path"] for tree in trees for item in tree["entries"]
        if item["kind"] == "file"
    }
    return (len(rows) - len(tree_file_paths) +
            sum(1 + tree["entry_count"] for tree in trees))


def _packet_parent(
    packet_path: str, scratch_root: str,
) -> tuple[int, str]:
    path = Path(_path(packet_path, "packet output path"))
    root = Path(_path(scratch_root, "budget packet scratch root"))
    _require(path != root and root in path.parents,
             "packet output escapes the budget-reserved scratch root")
    root_fd = _open_abs_dir(str(root), "budget packet scratch root",
                            private_final=True)
    parent_fd, name = _parent_at(root_fd, path.relative_to(root).as_posix(),
                                 create=False, label="packet output")
    os.close(root_fd)
    return parent_fd, name


def export_transfer_packet(
    request_raw: bytes, request_pin: object,
    budget_path: str | os.PathLike[str],
    packet_path: str | os.PathLike[str],
    offer_path: str | os.PathLike[str],
    acknowledgement_receiver_path: str | os.PathLike[str],
    *, source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> dict[str, Any]:
    """Stream one canonical request and its exact source bytes into one tar file."""
    request = _validate_request(_parse_checkpoint_metadata(
        request_raw, "host checkpoint request",
    ))
    pin = _pin(request_pin, "host checkpoint request pin")
    _require(_sha(request_raw) == pin["raw_sha256"] and
             request["request_sha256"] == pin["semantic_sha256"],
             "host checkpoint request differs from its transfer pin")
    _budget, budget_raw, limits = _budget_and_pin_for_request(
        request, budget_path,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
    )
    if _budget.get("schema") != PREPARATORY_BUDGET_SCHEMA_V1:
        _validate_budget_origin_pins(_budget, request["context"])
    (max_packet, max_packet_inodes, max_window_bytes, max_window_inodes,
     roots, scratch_root, max_ack_bundle_bytes, max_signature_bytes) = limits
    rows = request["entries"]
    _entry_catalogue_rows(request, _budget)
    payload = sum(row["byte_count"] for row in rows)
    _require(payload <= max_window_bytes and
             _request_inode_count(request) <= max_window_inodes,
             "job payload exceeds the pinned live-window bytes/inodes")
    job_row, job_identity = _job_record_source(
        request, _budget, roots,
    )
    members = [("checkpoint-request.json", len(request_raw)),
               ("validation/job-record.json", job_row["byte_count"])]
    identities = {}
    tree_file_paths: set[str] = set()
    tree_file_modes: dict[str, int] = {}
    tree_metadata_paths: set[str] = set()
    if request.get("tree_inventories") is not None:
        trees, tree_file_paths = _validate_tree_inventories(
            request["tree_inventories"], request["entries"],
            request["owner_receipt_pins"],
        )
        tree_metadata_paths = {
            tree["inventory_pin"]["path"] for tree in trees
        } | {tree["owner_receipt_pin"]["path"] for tree in trees}
        tree_file_modes = {
            entry["path"]: entry["mode"] for tree in trees
            for entry in tree["entries"] if entry["kind"] == "file"
        }
    for row in rows:
        name = _packet_member_name(row["origin_path"], row["raw_sha256"])
        members.append((name, row["byte_count"]))
        identity = _hash_source(
            row["origin_path"], roots, row,
            expected_regular_mode=tree_file_modes.get(row["origin_path"]),
        )
        _require(row["origin_path"] not in tree_file_paths or
                 identity[0] == "regular",
                 "ProbeV2 inventory file origin is not a no-follow regular file")
        _require(row["origin_path"] not in tree_metadata_paths or
                 identity[0] == "regular",
                 "ProbeV2 receipt/inventory origin is not a no-follow regular file")
        _require(not _is_owner_receipt_role(row["role"]) or
                 identity[0] == "regular",
                 "owner receipt origin is not a no-follow regular file")
        identities[row["origin_path"]] = identity
    packet_size = _tar_size(members)
    _require(max_packet_inodes == 1 and packet_size <= max_packet,
             "complete tar packet cannot fit the pinned byte/inode reservation")
    destination = _path(os.fspath(packet_path), "packet output path")
    offer_path_text = _path(os.fspath(offer_path), "offer output path")
    receiver_path_text = _path(
        os.fspath(acknowledgement_receiver_path), "ACK receiver output path",
    )
    (req_row, packet_row, offer_row, receiver_row,
     incoming_row) = _offer_catalogue_rows(
        request, _budget, pin["path"], destination, offer_path_text,
        receiver_path_text,
    )
    _require(len(request_raw) <= req_row["max_file_bytes"] and
             packet_size <= packet_row["max_file_bytes"] and
             receiver_row["max_file_bytes"] <= max_ack_bundle_bytes and
             receiver_row["max_file_bytes"] > 0 and
             incoming_row["max_file_bytes"] == receiver_row["max_file_bytes"],
             "request/packet/ACK paths exceed their exact prewrite caps")
    request_disk_raw, request_disk_sha, _request_info = _read_regular_absolute(
        pin["path"], req_row["max_file_bytes"],
        "catalogued checkpoint request before packet write",
    )
    _require(request_disk_raw == request_raw and
             request_disk_sha == pin["raw_sha256"],
             "request path differs from its exact transfer pin")
    provisional_offer = _offer_body(
        pin, destination, "f" * 64, packet_size,
        receiver_path_text, receiver_row["max_file_bytes"],
    )
    _require(len(_canonical(provisional_offer)) <= offer_row["max_file_bytes"],
             "provisional offer exceeds its exact catalogue file ceiling")
    receiver_parent_fd = _open_abs_dir(
        str(Path(receiver_path_text).parent), "ACK receiver parent",
        private_final=True,
    )
    try:
        receiver_name = Path(receiver_path_text).name
        for candidate_name in (receiver_name, receiver_name + ".incoming"):
            try:
                os.stat(candidate_name, dir_fd=receiver_parent_fd,
                        follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise TransferPacketError(
                "exclusive ACK final/incoming path already exists before export",
            )
    finally:
        os.close(receiver_parent_fd)
    parent_fd, name = _packet_parent(destination, scratch_root)
    try:
        out_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(out_fd, 0o600)
            position = 0

            def emit(raw: bytes) -> None:
                nonlocal position
                _write_all(out_fd, raw)
                position += len(raw)

            def emit_member_header(member: str, size: int) -> None:
                nonlocal position
                if size > USTAR_MAX_SIZE:
                    pax_record = _pax_size_record(size)
                    emit(_tar_header("PaxHeaders/size", len(pax_record),
                                     typeflag=b"x"))
                    emit(pax_record)
                    pax_padding = (-len(pax_record)) % TAR_BLOCK_BYTES
                    if pax_padding:
                        emit(b"\x00" * pax_padding)
                emit(_tar_header(member, size, typeflag=b"0"))

            emit_member_header("checkpoint-request.json", len(request_raw))
            emit(request_raw)
            request_padding = (-len(request_raw)) % TAR_BLOCK_BYTES
            if request_padding:
                emit(b"\x00" * request_padding)
            job_fd, job_kind, job_before = _open_source(
                request["job_record_pin"]["path"], roots,
            )
            try:
                _require(job_kind == "regular" and
                         _info_key(job_before) == job_identity[2] and
                         job_before.st_size == job_row["byte_count"],
                         "always-local job record identity changed before transfer")
                emit_member_header("validation/job-record.json",
                                   job_row["byte_count"])
                job_stream = _HashingReader(job_fd, job_row["byte_count"])
                while job_stream.count < job_row["byte_count"]:
                    emit(job_stream.read(BLOCK_BYTES))
                _require(job_stream.count == job_row["byte_count"] and
                         job_stream.hasher.hexdigest() == job_row["raw_sha256"] and
                         _info_key(job_before) == _info_key(os.fstat(job_fd)),
                         "always-local job record changed during transfer")
                job_padding = (-job_row["byte_count"]) % TAR_BLOCK_BYTES
                if job_padding:
                    emit(b"\x00" * job_padding)
            finally:
                os.close(job_fd)
            for row in rows:
                member = _packet_member_name(
                    row["origin_path"], row["raw_sha256"],
                )
                fd, kind, before = _open_source(
                    row["origin_path"], roots,
                    expected_regular_mode=tree_file_modes.get(
                        row["origin_path"],
                    ),
                )
                try:
                    emit_member_header(member, row["byte_count"])
                    if kind.startswith("symlink:"):
                        parent_source, leaf = fd, kind.split(":", 1)[1]
                        raw_link, after = _read_symlink(
                            parent_source, leaf, row,
                        )
                        _require(_info_key(after) ==
                                 identities[row["origin_path"]][2],
                                 "source link identity changed before export")
                        emit(raw_link)
                        link_padding = (-len(raw_link)) % TAR_BLOCK_BYTES
                        if link_padding:
                            emit(b"\x00" * link_padding)
                    else:
                        _require(identities[row["origin_path"]][0] ==
                                 "regular" and
                                 _info_key(before) ==
                                 identities[row["origin_path"]][2] and
                                 before.st_size == row["byte_count"],
                                 "source file identity changed before export")
                        stream = _HashingReader(fd, row["byte_count"])
                        while stream.count < row["byte_count"]:
                            block = stream.read(BLOCK_BYTES)
                            emit(block)
                        after = os.fstat(fd)
                        _require(stream.count == row["byte_count"] and
                                 stream.hasher.hexdigest() ==
                                     row["raw_sha256"] and
                                 _info_key(before) == _info_key(after),
                                 "source file changed during packet streaming")
                        file_padding = (-row["byte_count"]) % TAR_BLOCK_BYTES
                        if file_padding:
                            emit(b"\x00" * file_padding)
                finally:
                    os.close(fd)
            emit(b"\x00" * 1024)
            trailer_padding = packet_size - position
            _require(0 <= trailer_padding < TAR_RECORD_BYTES,
                     "packet record padding differs from its preflight size")
            if trailer_padding:
                emit(b"\x00" * trailer_padding)
            _require(position == packet_size,
                     "packet writer size differs from its preflight bound")
            os.fsync(out_fd)
        finally:
            os.close(out_fd)
        os.fsync(parent_fd)
        # Independent reopen and full packet hash; packet creation remains
        # outside the APP/pressure timed lanes and uses the reserved one inode.
        packet_sha, packet_info = _hash_absolute_regular(
            Path(destination), max_packet, "completed transfer packet",
        )
        _require(packet_info.st_size == packet_size,
                 "completed transfer packet differs from its sealed size/hash")
        return {
            "schema": PACKET_PIN_SCHEMA,
            "path": destination, "raw_sha256": packet_sha,
            "byte_count": packet_info.st_size,
            "request_pin": pin,
            "maximum_packet_bytes": max_packet,
        }
    finally:
        os.close(parent_fd)


def _hash_absolute_regular(path: Path, maximum: int,
                           label: str) -> tuple[str, os.stat_result]:
    path_text = _path(str(path), f"{label} path")
    checked = Path(path_text)
    _require(checked.resolve(strict=True) == checked,
             f"{label} traverses a symlink or alias")
    parent_fd = _open_abs_dir(str(checked.parent), f"{label} parent",
                              private_final=True)
    try:
        path_info = os.stat(checked.name, dir_fd=parent_fd,
                            follow_symlinks=False)
        _require(stat.S_ISREG(path_info.st_mode) and
                 path_info.st_uid == os.getuid() and
                 stat.S_IMODE(path_info.st_mode) == 0o600 and
                 path_info.st_nlink == 1 and path_info.st_size <= maximum,
                 f"{label} is not an owned private bounded regular file")
        fd = os.open(checked.name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _require(_info_key(before) == _info_key(path_info),
                     f"{label} changed identity before hashing")
            hasher = hashlib.sha256()
            total = 0
            while total < before.st_size:
                block = os.read(fd, min(BLOCK_BYTES, before.st_size - total))
                _require(bool(block), f"{label} shortened while hashing")
                total += len(block)
                hasher.update(block)
            _require(os.read(fd, 1) == b"" and total == before.st_size and
                     _info_key(before) == _info_key(os.fstat(fd)) and
                     _info_key(before) == _info_key(os.stat(
                         checked.name, dir_fd=parent_fd,
                         follow_symlinks=False,
                     )), f"{label} changed during stable hash")
            return hasher.hexdigest(), before
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _packet_file(
    path_value: str | os.PathLike[str], maximum: int,
) -> tuple[int, os.stat_result]:
    path = Path(_path(os.fspath(path_value), "transfer packet path"))
    _require(path.resolve(strict=True) == path,
             "transfer packet path traverses a symlink or alias")
    parent_fd = _open_abs_dir(str(path.parent), "packet parent",
                              private_final=True)
    try:
        before_path = os.stat(path.name, dir_fd=parent_fd,
                              follow_symlinks=False)
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and before_path.st_size <= maximum,
                 "transfer packet is not an owned bounded mode-0600 single-link file")
        fd = os.open(path.name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        opened = os.fstat(fd)
        _require(_info_key(opened) == _info_key(before_path),
                 "transfer packet changed identity before open")
        os.close(parent_fd)
        return fd, opened
    except BaseException:
        os.close(parent_fd)
        raise


def _hash_packet_fd(fd: int, expected: os.stat_result) -> str:
    hasher = hashlib.sha256()
    offset = 0
    while offset < expected.st_size:
        block = os.pread(fd, min(BLOCK_BYTES, expected.st_size - offset), offset)
        _require(bool(block), "packet shortened during independent raw hash")
        hasher.update(block)
        offset += len(block)
    _require(offset == expected.st_size and
             _info_key(expected) == _info_key(os.fstat(fd)),
             "packet changed during independent raw hash")
    return hasher.hexdigest()


def _parse_octal(value: bytes, label: str) -> int:
    _require(value and not (value[0] & 0x80),
             f"{label} uses unsupported base-256 encoding")
    trimmed = value.strip(b"\x00 ")
    _require(bool(trimmed) and all(48 <= byte <= 55 for byte in trimmed),
             f"{label} is not bounded octal")
    return int(trimmed, 8)


def _read_tar_header(fd: int, offset: int, file_size: int) -> dict[str, Any] | None:
    _require(0 <= offset <= file_size - TAR_BLOCK_BYTES,
             "tar packet ended before a complete header")
    header = os.pread(fd, TAR_BLOCK_BYTES, offset)
    _require(len(header) == TAR_BLOCK_BYTES,
             "tar packet ended during a header")
    if header == b"\x00" * TAR_BLOCK_BYTES:
        return None
    _require(header[257:263] == b"ustar\x00" and header[263:265] == b"00",
             "packet member is not the accepted USTAR header version")
    _require(header[265:345] == b"\x00" * 80 and
             header[345:500] == b"\x00" * 155 and
             header[500:512] == b"\x00" * 12,
             "packet header uses unsupported owner, prefix, or device fields")
    expected_checksum = _parse_octal(header[148:156], "tar header checksum")
    check = bytearray(header)
    check[148:156] = b" " * 8
    _require(sum(check) == expected_checksum,
             "tar header checksum differs")
    name_raw = header[0:100].split(b"\x00", 1)[0]
    prefix_raw = header[345:500].split(b"\x00", 1)[0]
    try:
        name = name_raw.decode("ascii", "strict")
        prefix = prefix_raw.decode("ascii", "strict")
    except UnicodeError as error:
        raise TransferPacketError("tar member name is not ASCII") from error
    full_name = name if not prefix else prefix + "/" + name
    _require(full_name and not full_name.startswith("/") and
             all(part not in ("", ".", "..") for part in
                 PurePosixPath(full_name).parts),
             "tar member name is absolute or traverses a path")
    return {
        "name": full_name,
        "mode": _parse_octal(header[100:108], "tar mode"),
        "uid": _parse_octal(header[108:116], "tar uid"),
        "gid": _parse_octal(header[116:124], "tar gid"),
        "size": _parse_octal(header[124:136], "tar size"),
        "mtime": _parse_octal(header[136:148], "tar mtime"),
        "typeflag": header[156:157],
        "linkname": header[157:257].split(b"\x00", 1)[0],
        "offset": offset,
    }


def _read_tar_bytes(fd: int, offset: int, size: int, maximum: int,
                    label: str) -> bytes:
    _require(0 <= size <= maximum,
             f"{label} exceeds its pre-parse byte ceiling")
    chunks = []
    total = 0
    while total < size:
        block = os.pread(fd, min(BLOCK_BYTES, size - total), offset + total)
        _require(bool(block), f"{label} shortened while reading")
        total += len(block)
        chunks.append(block)
    _require(total == size, f"{label} size differs")
    return b"".join(chunks)


def _require_zero_padding(fd: int, offset: int, size: int, label: str) -> int:
    padding = (-size) % TAR_BLOCK_BYTES
    if padding:
        raw = _read_tar_bytes(fd, offset + size, padding,
                              TAR_BLOCK_BYTES, f"{label} padding")
        _require(raw == b"\x00" * padding,
                 f"{label} has nonzero tar padding")
    return offset + size + padding


def _parse_pax_size(fd: int, header: dict[str, Any], file_size: int) -> tuple[int, int]:
    _require(header["name"] == "PaxHeaders/size" and
             header["typeflag"] == b"x" and header["mode"] == 0o600 and
             header["uid"] == 0 and header["gid"] == 0 and
             header["mtime"] == 0 and header["linkname"] == b"" and
             0 < header["size"] <= MAX_PAX_HEADER_BYTES,
             "extended tar header is not one bounded size-only PAX header")
    end = header["offset"] + TAR_BLOCK_BYTES + header["size"]
    _require(end <= file_size,
             "PAX header exceeds the packet file size")
    raw = _read_tar_bytes(
        fd, header["offset"] + TAR_BLOCK_BYTES, header["size"],
        MAX_PAX_HEADER_BYTES, "PAX size header",
    )
    space = raw.find(b" ")
    _require(space > 0 and raw.endswith(b"\n") and
             raw[:space].isdigit() and int(raw[:space]) == len(raw),
             "PAX record length/framing differs")
    body = raw[space + 1:-1]
    _require(body.startswith(b"size=") and body.count(b"=") == 1 and
             body[5:].isdigit(),
             "PAX header contains anything except one numeric size")
    size = int(body[5:])
    _require(0 <= size <= MAX_OBJECT_BYTES and _pax_size_record(size) == raw,
             "PAX size record is noncanonical or outside its finite bound")
    return size, _require_zero_padding(
        fd, header["offset"] + TAR_BLOCK_BYTES, header["size"], "PAX header",
    )


def _hash_packet_member(
    fd: int, offset: int, size: int, expected_sha: str,
) -> None:
    hasher = hashlib.sha256()
    total = 0
    while total < size:
        block = os.pread(fd, min(BLOCK_BYTES, size - total), offset + total)
        _require(bool(block), "tar object shortened during closure hashing")
        total += len(block)
        hasher.update(block)
    _require(total == size and hasher.hexdigest() == expected_sha,
             "tar object bytes differ from their exact row pin")


def _scan_packet(
    fd: int, packet_info: os.stat_result,
    expected_request_pin: dict[str, str],
    budget: dict[str, Any],
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
) -> tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]]:
    file_size = packet_info.st_size
    offset = 0
    first = _read_tar_header(fd, offset, file_size)
    _require(first is not None and first["name"] == "checkpoint-request.json" and
             first["typeflag"] == b"0" and first["mode"] == 0o600 and
             first["uid"] == 0 and first["gid"] == 0 and first["mtime"] == 0 and
             first["linkname"] == b"" and
             first["size"] <= MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
             "packet does not begin with one bounded canonical request file")
    request_size = first["size"]
    request_raw = _read_tar_bytes(
        fd, offset + TAR_BLOCK_BYTES, request_size,
        MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
        "packet checkpoint request",
    )
    request = _validate_request(_parse_checkpoint_metadata(
        request_raw, "packet checkpoint request",
    ))
    _require(_sha(request_raw) == expected_request_pin["raw_sha256"] and
             request["request_sha256"] ==
                 expected_request_pin["semantic_sha256"],
             "packet checkpoint request differs from its external pin")
    _entry_catalogue_rows(
        request, budget, catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    maximum_job_record_bytes = _job_record_catalogue_row(
        request, budget, catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )["max_file_bytes"]
    offset = _require_zero_padding(
        fd, offset + TAR_BLOCK_BYTES, request_size,
        "packet checkpoint request",
    )
    job_header = _read_tar_header(fd, offset, file_size)
    _require(job_header is not None and
             job_header["name"] == "validation/job-record.json" and
             job_header["typeflag"] == b"0" and
             job_header["mode"] == 0o600 and job_header["uid"] == 0 and
             job_header["gid"] == 0 and job_header["mtime"] == 0 and
             job_header["linkname"] == b"" and
             0 < job_header["size"] <= maximum_job_record_bytes and
             job_header["size"] <= MAX_JSON_BYTES,
             "packet lacks its exact bounded always-local job-record member")
    job_record_size = job_header["size"]
    job_record_offset = offset + TAR_BLOCK_BYTES
    job_record_raw = _read_tar_bytes(
        fd, job_record_offset, job_record_size, maximum_job_record_bytes,
        "packet always-local job record",
    )
    _require(_sha(job_record_raw) == request["job_record_pin"]["raw_sha256"],
             "packet job-record bytes differ from the original raw pin")
    job_record = _parse_canonical(job_record_raw,
                                  "packet always-local job record")
    _require(job_record.get("schema") ==
             "allocatbelt.application-source5-job-record.v1" and
             job_record.get("record_sha256") == _sha(_canonical({
                 key: item for key, item in job_record.items()
                 if key != "record_sha256"
             })),
             "packet job-record self digest or schema differs")
    if request.get("tree_inventories") is not None:
        job = job_record.get("job")
        record_name = PurePosixPath(
            request["job_record_pin"]["path"],
        ).name[:-5]
        _require(type(job) is dict and
                 job.get("host_id") == request["context"]["host_id"] and
                 job.get("phase") == request["context"]["phase"] and
                 job.get("run_id") == record_name and
                 type(job.get("ordinal")) is int and job["ordinal"] > 0 and
                 all(tree["owner_job_sha256"] == _sha(_canonical(job))
                     for tree in request["tree_inventories"]),
                 "packet tree inventory owner job differs from its raw-pinned job record")
    job_location = {
        "offset": job_record_offset, "byte_count": job_record_size,
        "raw_sha256": request["job_record_pin"]["raw_sha256"],
    }
    offset = _require_zero_padding(fd, job_record_offset, job_record_size,
                                   "packet always-local job record")
    locations = []
    for row in request["entries"]:
        header = _read_tar_header(fd, offset, file_size)
        _require(header is not None,
                 "packet ended before every raw object member")
        expected_size = row["byte_count"]
        if expected_size > USTAR_MAX_SIZE:
            pax_size, offset = _parse_pax_size(fd, header, file_size)
            _require(pax_size == expected_size,
                     "PAX object size differs from the exact request row")
            header = _read_tar_header(fd, offset, file_size)
            _require(header is not None,
                     "packet ended after its PAX size header")
            _require(header["size"] == 0,
                     "large member USTAR header has an unexpected fallback size")
            offset += TAR_BLOCK_BYTES
        else:
            _require(header["size"] == expected_size,
                     "tar object size differs from its exact request row")
            offset += TAR_BLOCK_BYTES
        member_name = _packet_member_name(
            row["origin_path"], row["raw_sha256"],
        )
        _require(header["name"] == member_name and
                 header["typeflag"] == b"0" and header["mode"] == 0o600 and
                 header["uid"] == 0 and header["gid"] == 0 and
                 header["mtime"] == 0 and header["linkname"] == b"",
                 "packet object member is not its exact regular content-addressed file")
        data_offset = offset
        _hash_packet_member(fd, data_offset, expected_size, row["raw_sha256"])
        offset = _require_zero_padding(fd, data_offset, expected_size,
                                       "packet object")
        locations.append({
            "origin_path": row["origin_path"],
            "object_id": _object_identity(row["origin_path"],
                                           row["raw_sha256"]),
            "offset": data_offset, "byte_count": expected_size,
            "raw_sha256": row["raw_sha256"],
        })
    _validate_packet_tree_inventory_payloads(fd, request, locations)
    end = _read_tar_header(fd, offset, file_size)
    _require(end is None, "packet has an extra or unrecognized tar member")
    offset += TAR_BLOCK_BYTES
    second_end = os.pread(fd, TAR_BLOCK_BYTES, offset)
    _require(second_end == b"\x00" * TAR_BLOCK_BYTES,
             "packet lacks the complete tar end marker")
    offset += TAR_BLOCK_BYTES
    expected_packet_size = _tar_size(
        [("checkpoint-request.json", request_size),
         ("validation/job-record.json", job_record_size)] +
        [(_packet_member_name(row["origin_path"], row["raw_sha256"]),
          row["byte_count"]) for row in request["entries"]],
    )
    _require(expected_packet_size == file_size and offset <= file_size and
             file_size - offset < TAR_RECORD_BYTES,
             "packet size differs from exact header/padding closure")
    trailer = _read_tar_bytes(fd, offset, file_size - offset,
                              TAR_RECORD_BYTES, "tar record padding")
    _require(trailer == b"\x00" * len(trailer),
             "packet has nonzero trailing tar padding")
    return request, request_raw, job_location, locations


def _document_self_digest(
    raw: bytes, field: str, label: str, *,
    maximum_bytes: int = MAX_JSON_BYTES,
) -> tuple[dict[str, Any], str]:
    value = _parse_canonical(raw, label, maximum_bytes=maximum_bytes)
    document_limit = (_checkpoint_metadata_limit(value)
                      if field == "checkpoint_sha256" else maximum_bytes)
    _require(len(raw) <= document_limit,
             f"{label} exceeds its exact versioned metadata ceiling")
    claimed = _digest(value.get(field), f"{label} self digest")
    body = {key: item for key, item in value.items() if key != field}
    _require(claimed == _sha(_canonical(body,
                                       maximum_bytes=document_limit)),
             f"{label} self digest differs")
    return value, claimed


def _validate_ack_bundle_documents(
    checkpoint_raw: bytes, manifest_raw: bytes, ack_raw: bytes,
    signature_raw: bytes, maximum_signature_bytes: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    checkpoint, checkpoint_sha = _document_self_digest(
        checkpoint_raw, "checkpoint_sha256", "final checkpoint",
        maximum_bytes=MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
    )
    checkpoint_base_fields = {
        "schema", "request_pin", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "object_manifest_pin", "entries", "checkpoint_sha256",
    }
    if checkpoint.get("schema") == \
            "allocatbelt.application-source5-evidence-job-checkpoint.v1":
        _exact(checkpoint, checkpoint_base_fields, "final checkpoint v1")
        request_schema = REQUEST_SCHEMA
        tree_inventories = None
    elif checkpoint.get("schema") == \
            "allocatbelt.application-source5-evidence-job-checkpoint.v2":
        _exact(checkpoint, checkpoint_base_fields | {"tree_inventories"},
               "final checkpoint v2")
        request_schema = REQUEST_SCHEMA_V2
        tree_inventories = checkpoint["tree_inventories"]
    elif checkpoint.get("schema") == \
            "allocatbelt.application-source5-evidence-job-checkpoint.v3":
        _exact(checkpoint, checkpoint_base_fields, "final checkpoint v3")
        request_schema = REQUEST_SCHEMA_V3
        tree_inventories = None
    else:
        raise TransferPacketError("final checkpoint schema differs")
    request_pin = _pin(checkpoint["request_pin"], "checkpoint request pin")
    context = checkpoint["context"]
    request_projection = _validate_request({
        "schema": request_schema, "context": context,
        "job_record_pin": checkpoint["job_record_pin"],
        "authorization": checkpoint["authorization"],
        "predecessor_ack_pin": checkpoint["predecessor_ack_pin"],
        "owner_receipt_pins": checkpoint["owner_receipt_pins"],
        "empty_tmp_proofs": checkpoint["empty_tmp_proofs"],
        "entries": checkpoint["entries"],
        "request_sha256": request_pin["semantic_sha256"],
        **({"tree_inventories": tree_inventories}
           if tree_inventories is not None else {}),
    })
    _require(checkpoint["predecessor_ack_pin"] ==
             request_projection["context"]["predecessor_ack_pin"],
             "final checkpoint predecessor differs from its original request")
    manifest_pin = _pin(checkpoint["object_manifest_pin"],
                         "checkpoint object-manifest pin")
    manifest, manifest_sha = _document_self_digest(
        manifest_raw, "manifest_sha256", "object manifest",
    )
    manifest = _exact(manifest, {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
        "predecessor_ack_pin", "objects", "object_count", "payload_bytes",
        "manifest_sha256",
    }, "object manifest")
    _require(manifest["schema"] ==
             "allocatbelt.application-source5-evidence-object-manifest.v1" and
             manifest["campaign_id"] == context["campaign_id"] and
             manifest["host_id"] == context["host_id"] and
             manifest["phase"] == context["phase"] and
             manifest["job_index"] == context["job_index"] and
             manifest["job_record_raw_sha256"] ==
                 checkpoint["job_record_pin"]["raw_sha256"] and
             manifest["predecessor_ack_pin"] ==
                 checkpoint["predecessor_ack_pin"] and
             type(manifest["job_ordinal"]) is int and
             manifest["job_ordinal"] > 0 and
             type(manifest["job_sha256"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", manifest["job_sha256"]) and
             type(manifest["run_id"]) is str and
             type(manifest["objects"]) is list and
             len(manifest["objects"]) == len(checkpoint["entries"]) ==
                 manifest["object_count"],
             "object manifest identity or row count differs from checkpoint")
    if tree_inventories is not None:
        _require(all(tree["owner_job_sha256"] == manifest["job_sha256"]
                     for tree in tree_inventories),
                 "ACK object manifest job digest differs from the typed tree owner")
    total_object_bytes = 0
    for entry_value, object_value in zip(
        checkpoint["entries"], manifest["objects"], strict=True,
    ):
        entry = _exact(entry_value, {
            "origin_path", "role", "byte_count", "raw_sha256",
            "semantic_sha256",
        }, "checkpoint object entry")
        entry_role = _token(entry["role"], "checkpoint object role")
        _require(entry_role not in NON_EXPORTABLE_JOB_ROLES,
                 "non-exportable Source5 controller/job role is not in an ACK closure")
        obj = _exact(object_value, {
            "origin_path", "role", "object_id", "byte_count", "raw_sha256",
            "semantic_sha256", "object_pin",
        }, "object manifest entry")
        origin = _path(entry["origin_path"], "checkpoint object origin")
        raw_sha = _digest(entry["raw_sha256"], "checkpoint object raw digest")
        object_name = _sha(origin.encode("utf-8"))
        object_id = f"{object_name[:2]}/{object_name}-{raw_sha}.bin"
        expected_object_pin = _exact(obj["object_pin"], {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
        }, "manifest content-addressed object pin")
        _require(obj["origin_path"] == origin and obj["role"] == entry["role"] and
                 obj["object_id"] == object_id and
                 obj["byte_count"] == entry["byte_count"] and
                 obj["raw_sha256"] == raw_sha and
                 obj["semantic_sha256"] == entry["semantic_sha256"] and
                 _path(expected_object_pin["path"],
                       "manifest private object path").endswith("/objects/" + object_id) and
                 expected_object_pin["raw_sha256"] == raw_sha and
                 expected_object_pin["semantic_sha256"] == raw_sha and
                 expected_object_pin["byte_count"] == entry["byte_count"],
                 "object manifest row differs from exact checkpoint object closure")
        total_object_bytes += entry["byte_count"]
        _require(total_object_bytes <= MAX_OBJECT_BYTES * MAX_ROWS,
                 "object manifest aggregate byte count exceeds finite bounds")
    _require(manifest["payload_bytes"] == total_object_bytes,
             "object manifest total differs from its exact checkpoint rows")
    ack, ack_sha = _document_self_digest(ack_raw, "ack_sha256", "durable ACK")
    _exact(ack, {
        "schema", "checkpoint_pin", "object_manifest_pin",
        "predecessor_ack_pin", "signer_fingerprint", "durable_commit",
        "ack_sha256",
    }, "durable ACK")
    _require(ack["schema"] ==
             "allocatbelt.application-source5-evidence-durable-ack.v1" and
             ack["checkpoint_pin"]["raw_sha256"] == _sha(checkpoint_raw) and
             ack["checkpoint_pin"]["semantic_sha256"] == checkpoint_sha and
             ack["object_manifest_pin"] == manifest_pin and
             ack["object_manifest_pin"]["raw_sha256"] == _sha(manifest_raw) and
             ack["object_manifest_pin"]["semantic_sha256"] == manifest_sha and
             checkpoint["object_manifest_pin"] == manifest_pin and
             ack["predecessor_ack_pin"] ==
                 checkpoint["predecessor_ack_pin"] and
             ack["signer_fingerprint"] ==
                 checkpoint["context"]["authorized_signer_fingerprint"] and
             type(signature_raw) is bytes and
             0 < len(signature_raw) <= maximum_signature_bytes <=
                 MAX_GPG_OUTPUT_BYTES,
             "ACK bundle documents do not form one exact signed closure")
    durable = _exact(ack["durable_commit"], {
        "commit_id", "archive_source5_directory", "checkpoint_pin",
        "object_manifest_pin", "object_reopen_sha256", "object_count",
        "payload_bytes", "job_record_validation",
    }, "ACK bundle durable commit")
    job_validation = _exact(durable["job_record_validation"], {
        "path", "origin_path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "ACK bundle always-local job-record validation")
    _require(_path(job_validation["path"], "job-record validation path") and
             _path(job_validation["origin_path"], "job-record origin path") ==
                 checkpoint["job_record_pin"]["path"] and
             _digest(job_validation["raw_sha256"],
                     "job-record validation raw digest") ==
                 checkpoint["job_record_pin"]["raw_sha256"] and
             _digest(job_validation["semantic_sha256"],
                     "job-record validation semantic digest") and
             _uint(job_validation["byte_count"],
                   "job-record validation byte count", positive=True),
             "ACK bundle job-record validation facts differ from its checkpoint")
    _require(durable["checkpoint_pin"] == ack["checkpoint_pin"] and
             durable["object_manifest_pin"] == ack["object_manifest_pin"] and
             durable["object_count"] == manifest.get("object_count") and
             durable["payload_bytes"] == manifest.get("payload_bytes"),
             "ACK bundle durable counts differ from its object manifest")
    return checkpoint, manifest, ack


def _read_ack_bundle_documents_fd(
    fd: int, file_size: int, maximum_signature_bytes: int,
) -> list[bytes]:
    """Read one exact four-member ACK bundle from an already bounded fd."""
    names = ["checkpoint.json", "object-manifest.json", "ack.json", "ack.sig"]
    docs: list[bytes] = []
    offset = 0
    for name in names:
        header = _read_tar_header(fd, offset, file_size)
        maximum = (
            maximum_signature_bytes if name == "ack.sig" else
            MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES
            if name == "checkpoint.json" else MAX_JSON_BYTES
        )
        _require(header is not None and header["name"] == name and
                 header["typeflag"] == b"0" and header["mode"] == 0o600 and
                 header["uid"] == 0 and header["gid"] == 0 and
                 header["mtime"] == 0 and header["linkname"] == b"" and
                 header["size"] <= maximum,
                 "ACK bundle member names/types/sizes are not the exact four-file set")
        data_offset = offset + TAR_BLOCK_BYTES
        raw = _read_tar_bytes(fd, data_offset, header["size"], maximum,
                              f"ACK bundle {name}")
        docs.append(raw)
        offset = _require_zero_padding(fd, data_offset, header["size"],
                                       f"ACK bundle {name}")
    _require(_read_tar_header(fd, offset, file_size) is None,
             "ACK bundle contains an extra member")
    offset += TAR_BLOCK_BYTES
    _require(os.pread(fd, TAR_BLOCK_BYTES, offset) ==
             b"\x00" * TAR_BLOCK_BYTES,
             "ACK bundle lacks its full tar end marker")
    offset += TAR_BLOCK_BYTES
    _require(offset <= file_size and
             file_size - offset < TAR_RECORD_BYTES and
             _read_tar_bytes(fd, offset, file_size - offset,
                             TAR_RECORD_BYTES, "ACK bundle trailer") ==
                 b"\x00" * (file_size - offset) and
             _tar_size(zip(names, [len(raw) for raw in docs], strict=True)) ==
                 file_size,
             "ACK bundle size/trailer differs from its exact four-file closure")
    return docs


def build_ack_bundle(
    checkpoint_raw: bytes, manifest_raw: bytes, ack_raw: bytes,
    signature_raw: bytes, budget_raw: bytes, budget_pin: object,
    output_path: str | os.PathLike[str],
    *, source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, Any]:
    """Write one bounded four-file USTAR ACK response bundle."""
    checkpoint_document = _parse_checkpoint_metadata(
        checkpoint_raw, "final checkpoint",
    )
    limits, profile = _budget_limits_with_archive_profile(
        budget_raw, budget_pin,
        checkpoint_document["context"]["campaign_id"],
        checkpoint_document["context"]["host_id"],
        budget_context=checkpoint_document["context"],
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=(catalogue_chunk_paths is not None),
    )
    maximum_signature_bytes = limits[-1]
    checkpoint, _manifest, _ack = _validate_ack_bundle_documents(
        checkpoint_raw, manifest_raw, ack_raw, signature_raw,
        maximum_signature_bytes,
    )
    _require_profile_request_schema(
        profile, _request_schema_for_checkpoint_schema(checkpoint["schema"]),
    )
    _require(checkpoint["context"]["resource_budget_pin"] ==
             _pin(budget_pin, "host evidence budget pin"),
             "checkpoint signer quota is not bound to the exact host budget")
    max_ack_bundle = limits[-2]
    members = [
        ("checkpoint.json", checkpoint_raw),
        ("object-manifest.json", manifest_raw),
        ("ack.json", ack_raw), ("ack.sig", signature_raw),
    ]
    _require(all(len(name) <= 100 for name, _raw in members) and
             len(checkpoint_raw) <= _checkpoint_metadata_limit(checkpoint) and
             len(manifest_raw) <= MAX_JSON_BYTES and len(ack_raw) <= MAX_JSON_BYTES and
             len(signature_raw) <= maximum_signature_bytes,
             "ACK bundle member exceeds its fixed metadata/signature ceiling")
    bundle_size = _tar_size([(name, len(raw)) for name, raw in members])
    _require(bundle_size <= max_ack_bundle,
             "complete ACK bundle exceeds the pinned catalogue byte ceiling")
    output = Path(_path(os.fspath(output_path), "ACK bundle output path"))
    parent_fd = _open_abs_dir(str(output.parent), "ACK bundle output parent",
                              private_final=True)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            position = 0
            for name, raw in members:
                header = _tar_header(name, len(raw), typeflag=b"0")
                _write_all(fd, header)
                _write_all(fd, raw)
                padding = (-len(raw)) % TAR_BLOCK_BYTES
                if padding:
                    _write_all(fd, b"\x00" * padding)
                position += TAR_BLOCK_BYTES + len(raw) + padding
            _write_all(fd, b"\x00" * 1024)
            position += 1024
            trailer_padding = bundle_size - position
            _require(0 <= trailer_padding < TAR_RECORD_BYTES,
                     "ACK bundle trailer differs from its bounded record size")
            if trailer_padding:
                _write_all(fd, b"\x00" * trailer_padding)
                position += trailer_padding
            _require(position == bundle_size,
                     "ACK bundle writer size differs from its preflight bound")
            os.fsync(fd)
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                     info.st_size == bundle_size,
                     "ACK bundle writer did not produce its exact private file")
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        raw_sha, reopened_info = _hash_absolute_regular(
            output, max_ack_bundle, "completed ACK bundle",
        )
        _require(reopened_info.st_size == bundle_size,
                 "ACK bundle failed independent reopen size check")
        return {
            "path": str(output), "raw_sha256": raw_sha,
            "byte_count": bundle_size,
        }
    finally:
        os.close(parent_fd)


def read_ack_bundle(
    bundle_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
    bundle_pin: object, signer_context_raw: bytes,
    signer_context_pin: object, execution_manifest_raw: bytes,
    execution_manifest_pin: object,
    journal_width_contract_raw: bytes | None = None,
    *, budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, Any]:
    """Read the exact four regular ACK members without extracting tar paths."""
    offer_probe = _exact(_parse_canonical(offer_raw,
                                          "preparatory or final ACK offer"), {
        "schema", "checkpoint_request_pin", "transfer_packet_pin",
        "acknowledgement_receiver", "offer_sha256",
    }, "ACK bundle offer")
    budget_probe = _parse_canonical(
        budget_raw, "host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    offered_request = None
    if (budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1 and
            budget_context is None):
        request_pin = _pin(offer_probe["checkpoint_request_pin"],
                           "prep ACK offer request pin")
        request_raw, request_sha, _request_info = _read_regular_absolute(
            request_pin["path"], MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
            "offered preparatory checkpoint request",
        )
        _require(request_sha == request_pin["raw_sha256"],
                 "host preparatory request bytes differ from the offered raw pin")
        request = _validate_request(_parse_checkpoint_metadata(
            request_raw, "offered preparatory checkpoint request",
        ))
        _require(request["request_sha256"] == request_pin["semantic_sha256"],
                 "host preparatory request semantic pin differs from its offer")
        offered_request = request
        budget_context = request["context"]
    offer, _offer_pin, limits, budget_profile = \
        _validate_transfer_offer_with_profile(
        offer_raw, offer_pin, budget_raw, budget_pin,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        budget_context=budget_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
    )
    if (_profile_required_request_schema(budget_profile) is not None and
            offered_request is None):
        request_pin = _pin(offer["checkpoint_request_pin"],
                           "required-profile ACK request pin")
        request_raw, request_sha, _request_info = _read_regular_absolute(
            request_pin["path"], MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
            "required-profile offered checkpoint request",
        )
        _require(request_sha == request_pin["raw_sha256"],
                 "required-profile request bytes differ from their offer pin")
        offered_request = _validate_request(_parse_checkpoint_metadata(
            request_raw, "required-profile offered checkpoint request",
        ))
        _require(offered_request["request_sha256"] ==
                 request_pin["semantic_sha256"],
                 "required-profile request semantic pin differs from its offer")
    if offered_request is not None:
        _require_profile_request_schema(
            budget_profile, offered_request["schema"],
        )
        if budget_context is not None:
            _require_same_budget_context(
                budget_context, offered_request["context"],
            )
    maximum_signature_bytes = limits[-1]
    if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        budget = _exact(budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                        "preparatory host evidence budget")
    else:
        budget, _is_r6 = _exact_host_budget(
            _parse_canonical(budget_raw, "host evidence budget"),
            "host evidence budget v2",
        )
    receiver = offer["acknowledgement_receiver"]
    path = Path(_path(os.fspath(bundle_path), "ACK bundle receiver path"))
    _require(str(path) == receiver["path"],
             "ACK bundle is not at its exact offered receiver path")
    expected_bundle = _exact(bundle_pin, {
        "path", "raw_sha256", "byte_count",
    }, "ACK bundle pin")
    _require(expected_bundle["path"] == receiver["path"],
             "ACK bundle pin path differs from offer")
    raw_sha = _digest(expected_bundle["raw_sha256"], "ACK bundle raw digest")
    bundle_size = _uint(expected_bundle["byte_count"],
                        "ACK bundle byte count", positive=True)
    _require(bundle_size <= receiver["maximum_bytes"] and
             bundle_size <= limits[-2],
             "ACK bundle exceeds the exact offered/catalogued byte cap")
    fd, info = _packet_file(path, receiver["maximum_bytes"])
    try:
        actual_sha = _hash_packet_fd(fd, info)
        _require(actual_sha == raw_sha and info.st_size == bundle_size,
                 "ACK bundle raw bytes differ from their transfer pin")
        docs = _read_ack_bundle_documents_fd(
            fd, info.st_size, maximum_signature_bytes,
        )
        checkpoint, manifest, ack = _validate_ack_bundle_documents(
            docs[0], docs[1], docs[2], docs[3], maximum_signature_bytes,
        )
        _require_profile_request_schema(
            budget_profile,
            _request_schema_for_checkpoint_schema(checkpoint["schema"]),
        )
        context = checkpoint["context"]
        if budget_context is not None:
            _require_same_budget_context(budget_context, context)
        width_bound = (budget.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1 or (
            (set(budget) == HOST_BUDGET_FIELDS_R6 or
             set(budget) == HOST_BUDGET_FIELDS_V3) and
            budget.get("execution_manifest_schema") == EXECUTION_SCHEMA_V4
        ))
        if budget.get("schema") != PREPARATORY_BUDGET_SCHEMA_V1:
            _validate_budget_origin_pins(budget, context)
        signer_context = _validate_archive_signer_context(
            signer_context_raw, signer_context_pin, context,
            maximum_signature_bytes, execution_manifest_pin,
            execution_manifest_raw,
            require_width_contract=width_bound,
        )
        _require(ack["signer_fingerprint"] ==
                 signer_context["authorized_primary_fingerprint"] and
                 len(docs[3]) <= signer_context["maximum_signature_bytes"],
                 "ACK signer differs from the host-pinned signer context")
        _require(checkpoint["request_pin"] ==
                 offer["checkpoint_request_pin"],
                 "returned final checkpoint differs from the offered request pin")
        _require(checkpoint["context"]["resource_budget_pin"] ==
                 _pin(budget_pin, "host evidence budget pin"),
                 "returned checkpoint differs from the pinned host budget")
        _require(_info_key(info) == _info_key(os.fstat(fd)) and
                 _hash_packet_fd(fd, info) == actual_sha,
                 "ACK bundle changed while its exact members were read")
        source5_root = Path(_path(
            ack["durable_commit"]["archive_source5_directory"]["path"],
            "signed private Source5 root",
        ))
        context = checkpoint["context"]
        _require(source5_root.name == "source5" and
                 source5_root.parent.name == context["host_id"] and
                 source5_root.parent.parent.name == context["campaign_id"],
                 "signed ACK archive root is outside its original campaign/host")
        phase = _token(manifest["phase"], "ACK bundle original phase")
        leaf = (f"{manifest['job_ordinal']:06d}-"
                f"{manifest['job_sha256']}.json")
        ack_path = source5_root / "acks" / phase / leaf
        signature_path = source5_root / "acks" / "signatures" / phase / f"{leaf[:-5]}.sig"
        checkpoint_pin = ack["checkpoint_pin"]
        manifest_pin = ack["object_manifest_pin"]
        ack_pin = {
            "path": str(ack_path), "raw_sha256": _sha(docs[2]),
            "semantic_sha256": ack["ack_sha256"],
        }
        signature_pin = {
            "path": str(signature_path), "raw_sha256": _sha(docs[3]),
            "signer_fingerprint": ack["signer_fingerprint"],
        }
        return {
            "checkpoint": checkpoint, "checkpoint_raw": docs[0],
            "checkpoint_pin": checkpoint_pin,
            "manifest": manifest, "manifest_raw": docs[1],
            "manifest_pin": manifest_pin,
            "ack": ack, "ack_raw": docs[2], "signature_raw": docs[3],
            "ack_pin": ack_pin, "signature_pin": signature_pin,
            "signer_context": signer_context,
            "signer_context_pin": _pin(
                signer_context_pin, "host signer-context pin",
            ),
            "bundle_pin": expected_bundle,
        }
    finally:
        os.close(fd)


def _rename_noreplace(parent_fd: int, source_name: str,
                      destination_name: str) -> None:
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    _require(function is not None,
             "atomic no-replace ACK publication is unavailable on this host")
    function.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    result = function(
        parent_fd, os.fsencode(source_name), parent_fd,
        os.fsencode(destination_name), RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise TransferPacketError(
            f"atomic ACK no-replace publication failed: {os.strerror(code)}",
        )


def publish_ack_bundle(
    incoming_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
    bundle_pin: object,
    *, budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
) -> dict[str, Any]:
    """Publish completed SFTP bytes from the offered .incoming name atomically.

    This operation takes no phase lock: its waiting controller already owns
    that lock and observes only the immutable final receiver path.
    """
    offer, checked_offer_pin, limits, budget_profile = \
        _validate_transfer_offer_with_profile(
        offer_raw, offer_pin, budget_raw, budget_pin,
        budget_context=budget_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        journal_width_contract_raw=journal_width_contract_raw,
    )
    receiver = offer["acknowledgement_receiver"]
    final_path = _path(receiver["path"], "offered final ACK receiver")
    incoming = _path(os.fspath(incoming_path), "uploaded incoming ACK path")
    _require(incoming == final_path + ".incoming",
             "SFTP upload is not at the exact offered same-directory .incoming path")
    expected = _exact(bundle_pin, {
        "path", "raw_sha256", "byte_count",
    }, "uploaded ACK bundle pin")
    _require(_path(expected["path"], "ACK bundle final pin path") == final_path,
             "uploaded ACK bundle pin does not name the offered final path")
    raw_sha = _digest(expected["raw_sha256"], "uploaded ACK bundle raw digest")
    byte_count = _uint(expected["byte_count"],
                       "uploaded ACK bundle byte count", positive=True)
    maximum = min(receiver["maximum_bytes"], limits[-2])
    _require(byte_count <= maximum,
             "uploaded ACK bundle exceeds the pinned campaign byte cap")
    final = Path(final_path)
    source = Path(incoming)
    _require(source.parent == final.parent,
             "ACK .incoming file and final receiver are not same-directory")
    parent_fd = _open_abs_dir(str(final.parent), "ACK receiver parent",
                              private_final=True)
    try:
        source_info = os.stat(source.name, dir_fd=parent_fd,
                              follow_symlinks=False)
        _require(stat.S_ISREG(source_info.st_mode) and
                 source_info.st_uid == os.getuid() and
                 stat.S_IMODE(source_info.st_mode) == 0o600 and
                 source_info.st_nlink == 1 and
                 source_info.st_size == byte_count,
                 "uploaded ACK .incoming path is not its exact private regular file")
        source_fd = os.open(
            source.name, os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=parent_fd,
        )
        try:
            before = os.fstat(source_fd)
            _require(_info_key(before) == _info_key(source_info),
                     "uploaded ACK .incoming changed identity before hashing")
            actual_sha = _hash_packet_fd(source_fd, before)
            _require(actual_sha == raw_sha and before.st_size == byte_count,
                     "uploaded ACK .incoming bytes differ from the coordinator pin")
            if _profile_required_request_schema(budget_profile) is not None:
                documents = _read_ack_bundle_documents_fd(
                    source_fd, before.st_size, limits[-1],
                )
                checkpoint, _manifest, _ack = _validate_ack_bundle_documents(
                    documents[0], documents[1], documents[2], documents[3],
                    limits[-1],
                )
                _require_profile_request_schema(
                    budget_profile,
                    _request_schema_for_checkpoint_schema(checkpoint["schema"]),
                )
                _require(checkpoint["request_pin"] ==
                         offer["checkpoint_request_pin"] and
                         checkpoint["context"]["resource_budget_pin"] ==
                             _pin(budget_pin, "host evidence budget pin"),
                         "uploaded ACK documents differ from the offered request/budget")
                if budget_context is not None:
                    _require_same_budget_context(
                        budget_context, checkpoint["context"],
                    )
                _require(_hash_packet_fd(source_fd, before) == raw_sha,
                         "uploaded ACK .incoming changed while its documents were validated")
            os.fsync(source_fd)
            _require(_info_key(before) == _info_key(os.fstat(source_fd)) and
                     _info_key(before) == _info_key(os.stat(
                         source.name, dir_fd=parent_fd,
                         follow_symlinks=False,
                     )),
                     "uploaded ACK .incoming changed during its durable hash")
            try:
                os.stat(final.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise TransferPacketError(
                    "offered final ACK receiver already exists; refusing replacement",
                )
            _rename_noreplace(parent_fd, source.name, final.name)
            os.fsync(parent_fd)
            published = os.stat(final.name, dir_fd=parent_fd,
                                follow_symlinks=False)
            _require(_rename_identity(published) == _rename_identity(before),
                     "published ACK changed identity during atomic rename")
        finally:
            os.close(source_fd)
        final_fd, final_info = _packet_file(final, maximum)
        try:
            _require(_info_key(final_info) == _info_key(published) and
                     _hash_packet_fd(final_fd, final_info) == raw_sha and
                     final_info.st_size == byte_count,
                     "published final ACK failed independent reopen verification")
        finally:
            os.close(final_fd)
        return {
            "path": final_path, "raw_sha256": raw_sha,
            "byte_count": byte_count,
        }
    finally:
        os.close(parent_fd)


def _write_stage_file(
    root_fd: int, relative: str, packet_fd: int, source_offset: int,
    expected_size: int, expected_sha: str,
) -> str:
    parent_fd, name = _parent_at(root_fd, relative, create=True,
                                 label="packet stage object")
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            hasher = hashlib.sha256()
            total = 0
            while total < expected_size:
                block = os.pread(
                    packet_fd, min(BLOCK_BYTES, expected_size - total),
                    source_offset + total,
                )
                _require(bool(block), "packet object shortened during extraction")
                total += len(block)
                hasher.update(block)
                _write_all(fd, block)
            _require(total == expected_size and
                     hasher.hexdigest() == expected_sha,
                     "extracted object changed after the full packet pass")
            os.fsync(fd)
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and
                     info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and
                     info.st_nlink == 1 and info.st_size == expected_size,
                     "extracted object is not an owned private regular file")
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        check_fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                           _O_NONBLOCK, dir_fd=parent_fd)
        try:
            _raw, digest, _info = _read_fd(
                check_fd, expected_size, expected_size,
                "reopened extracted object", collect=False,
            )
            _require(_raw is None and digest == expected_sha,
                     "extracted object failed independent reopen hashing")
        finally:
            os.close(check_fd)
        return relative
    finally:
        os.close(parent_fd)


def peek_preparatory_packet_context(
    packet_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
) -> dict[str, Any]:
    """Read only the first bounded request member to select its six-map pins.

    This Root-side bootstrap performs no extraction or publication. The full
    packet and all objects are rechecked by ``import_transfer_packet`` after
    Source-selected prep validation.
    """
    offer = _exact(_parse_canonical(offer_raw, "prep packet offer"), {
        "schema", "checkpoint_request_pin", "transfer_packet_pin",
        "acknowledgement_receiver", "offer_sha256",
    }, "prep packet offer")
    checked_offer_pin = _pin(offer_pin, "prep packet offer pin")
    offer_body = {key: item for key, item in offer.items()
                  if key != "offer_sha256"}
    _require(offer["schema"] ==
             "allocatbelt.application-source5-archive-transfer-offer.v1" and
             offer["offer_sha256"] == _sha(_canonical(offer_body)) and
             checked_offer_pin["raw_sha256"] == _sha(offer_raw) and
             checked_offer_pin["semantic_sha256"] == offer["offer_sha256"],
             "prep packet offer raw/semantic pin differs")
    budget_pin_checked = _pin(budget_pin, "prep packet host budget pin")
    _require(type(budget_raw) is bytes and
             _sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "prep packet budget bytes differ from their raw pin")
    budget = _exact(_parse_canonical(
        budget_raw, "prep packet host budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    ), PREPARATORY_BUDGET_FIELDS_V1, "prep packet host budget")
    _require(budget["schema"] == PREPARATORY_BUDGET_SCHEMA_V1 and
             budget["profile"] == PREPARATORY_PROFILE_V1 and
             budget["budget_sha256"] ==
                 _budget_body_semantic_sha256(budget) ==
                 budget_pin_checked["semantic_sha256"],
             "prep packet budget schema/profile/self pin differs")
    packet_pin = _exact(offer["transfer_packet_pin"], {
        "path", "raw_sha256", "byte_count",
    }, "prep packet transfer pin")
    packet_path_text = _path(os.fspath(packet_path), "prep packet local path")
    _require(packet_path_text == packet_pin["path"],
             "prep packet local path differs from its offered origin")
    expected_packet_sha = _digest(packet_pin["raw_sha256"],
                                  "prep packet raw digest")
    expected_packet_size = _uint(packet_pin["byte_count"],
                                 "prep packet byte count", positive=True)
    _require(expected_packet_size <= MAX_TOTAL_BYTES,
             "prep packet exceeds the generic finite preflight ceiling")
    fd, info = _packet_file(packet_path_text, MAX_TOTAL_BYTES)
    try:
        _require(info.st_size == expected_packet_size,
                 "prep packet size differs from its offered metadata pin")
        header = _read_tar_header(fd, 0, info.st_size)
        _require(header is not None and
                 header["name"] == "checkpoint-request.json" and
                 header["typeflag"] == b"0" and header["mode"] == 0o600 and
                 header["uid"] == 0 and header["gid"] == 0 and
                 header["mtime"] == 0 and header["linkname"] == b"" and
                 header["size"] <= MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
                 "prep packet does not begin with its bounded exact request member")
        request_raw = _read_tar_bytes(
            fd, TAR_BLOCK_BYTES, header["size"],
            MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
            "prep packet request context",
        )
        request = _validate_request(_parse_checkpoint_metadata(
            request_raw, "prep packet request context",
        ))
        request_pin = _pin(offer["checkpoint_request_pin"],
                           "prep offer request pin")
        _require(_sha(request_raw) == request_pin["raw_sha256"] and
                 request["request_sha256"] == request_pin["semantic_sha256"],
                 "prep packet request differs from its exact offer pin")
        return request["context"]
    finally:
        os.close(fd)


def import_transfer_packet(
    packet_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
    staging_root: str | os.PathLike[str],
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
    *, budget_context: dict[str, Any] | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> dict[str, Any]:
    """Verify the complete no-link packet before writing its first stage file."""
    offer, checked_offer_pin, offer_limits, budget_profile = \
        _validate_transfer_offer_with_profile(
        offer_raw, offer_pin, budget_raw, budget_pin,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        budget_context=budget_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
    )
    expected = _pin(offer["checkpoint_request_pin"],
                    "offered request pin")
    packet_pin = offer["transfer_packet_pin"]
    expected_context = budget_context
    budget_document = _parse_canonical(
        budget_raw, "host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    budget_pin_checked = _pin(budget_pin, "host budget pin")
    _require(_sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "host budget differs from its raw pin")
    if budget_document.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        parsed_budget = _exact(budget_document, PREPARATORY_BUDGET_FIELDS_V1,
                               "preparatory host evidence budget")
    else:
        parsed_budget, _is_r6 = _exact_host_budget(
            budget_document, "host evidence budget",
        )
    _require(parsed_budget["schema"] in {
                 HOST_BUDGET_SCHEMA, HOST_BUDGET_SCHEMA_V3,
                 PREPARATORY_BUDGET_SCHEMA_V1,
             }, "host budget schema differs")
    limits = offer_limits
    (max_packet, max_inodes, max_window_bytes, max_window_inodes,
     _roots, _scratch, max_ack_bundle_bytes, max_signature_bytes) = limits
    packet_probe = Path(_path(os.fspath(packet_path), "packet path"))
    packet_fd, packet_info = _packet_file(packet_probe, max_packet)
    try:
        packet_sha = _hash_packet_fd(packet_fd, packet_info)
        _require(packet_sha == packet_pin["raw_sha256"] and
                 packet_info.st_size == packet_pin["byte_count"],
                 "transferred packet differs from its exact offer pin")
        request, request_raw, job_record_location, locations = _scan_packet(
            packet_fd, packet_info, expected, parsed_budget,
            catalogue_chunk_paths, catalogue_cache_root,
        )
        _require_profile_request_schema(budget_profile, request["schema"])
        context = request["context"]
        if expected_context is not None:
            _require_same_budget_context(expected_context, context)
        if parsed_budget.get("schema") != PREPARATORY_BUDGET_SCHEMA_V1:
            _validate_budget_origin_pins(parsed_budget, context)
        _require(context["campaign_id"] == parsed_budget["campaign_id"] and
                 context["host_id"] == parsed_budget["host_id"] and
                 _pin(context["resource_budget_pin"], "request host budget") ==
                     budget_pin_checked,
                 "packet request is not bound to the exact host budget")
        (request_row, packet_row, _offer_row, receiver_row,
         incoming_row) = _offer_catalogue_rows(
            request, parsed_budget, expected["path"], packet_pin["path"],
            checked_offer_pin["path"],
            offer["acknowledgement_receiver"]["path"],
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
        )
        job_record_row = _job_record_catalogue_row(
            request, parsed_budget,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
        )
        _require(len(request_raw) <= request_row["max_file_bytes"] and
                 job_record_location["byte_count"] <=
                     job_record_row["max_file_bytes"] and
                 packet_info.st_size <= packet_row["max_file_bytes"] and
                 offer["acknowledgement_receiver"]["maximum_bytes"] ==
                     receiver_row["max_file_bytes"] and
                 incoming_row["max_file_bytes"] == receiver_row["max_file_bytes"],
                 "packet request/response differs from exact catalogue file ceilings")
        rows = request["entries"]
        payload = sum(row["byte_count"] for row in rows)
        _require(payload <= max_window_bytes and
                 _request_inode_count(request) <= max_window_inodes and
                 max_inodes == 1 and
                 packet_info.st_size <= max_packet,
                 "transfer packet exceeds its pinned byte/inode budget")
        _require(_info_key(packet_info) == _info_key(os.fstat(packet_fd)) and
                 _hash_packet_fd(packet_fd, packet_info) == packet_sha,
                 "transfer packet changed while its complete closure was verified")

        stage = Path(_path(os.fspath(staging_root), "private staging root"))
        stage_fd = _open_abs_dir(str(stage), "private packet stage root",
                                 private_final=True)
        try:
            _require(not os.listdir(stage_fd),
                     "packet stage root must start empty")
            request_fd = os.open(
                "checkpoint-request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=stage_fd,
            )
            try:
                _write_all(request_fd, request_raw)
                os.fsync(request_fd)
            finally:
                os.close(request_fd)
            os.fsync(stage_fd)
            reopened_fd = os.open(
                "checkpoint-request.json", os.O_RDONLY | _O_CLOEXEC |
                _O_NOFOLLOW | _O_NONBLOCK, dir_fd=stage_fd,
            )
            try:
                reopened, digest, _ = _read_fd(
                    reopened_fd, len(request_raw),
                    MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
                    "staged checkpoint request", collect=True,
                )
                _require(reopened == request_raw and digest == _sha(request_raw),
                         "staged checkpoint request failed independent reopen")
            finally:
                os.close(reopened_fd)
            _write_stage_file(
                stage_fd, "validation/job-record.json", packet_fd,
                job_record_location["offset"],
                job_record_location["byte_count"],
                job_record_location["raw_sha256"],
            )
            staged_files = {}
            for location in locations:
                relative = f"objects/{location['object_id']}"
                _write_stage_file(
                    stage_fd, relative, packet_fd, location["offset"],
                    location["byte_count"], location["raw_sha256"],
                )
                staged_files[location["origin_path"]] = str(stage / relative)
            _require(_info_key(packet_info) == _info_key(os.fstat(packet_fd)) and
                     _hash_packet_fd(packet_fd, packet_info) == packet_sha,
                     "packet changed during stage extraction")
            return {
                "request": request, "request_raw": request_raw,
                "request_pin": expected,
                "offer": offer, "offer_pin": checked_offer_pin,
                "acknowledgement_receiver":
                    offer["acknowledgement_receiver"],
                "request_path": str(stage / "checkpoint-request.json"),
                "job_record_path": str(stage / "validation" / "job-record.json"),
                "job_record_raw_sha256": job_record_location["raw_sha256"],
                "job_record_byte_count": job_record_location["byte_count"],
                "staging_root": str(stage), "staged_files": staged_files,
                "packet_byte_count": packet_info.st_size,
                "packet_raw_sha256": packet_sha,
                "object_count": len(rows), "payload_bytes": payload,
            }
        finally:
            os.close(stage_fd)
    finally:
        os.close(packet_fd)

def _cli_pin_document(
    file_path: str | None, inline_json: str | None, label: str,
) -> dict[str, Any]:
    if inline_json is not None:
        _require(type(inline_json) is str and
                 len(inline_json) <= MAX_INLINE_PIN_BYTES and
                 not any(ord(char) < 32 or ord(char) == 127
                         for char in inline_json),
                 f"{label} inline argument exceeds its single-line pin bound")
        raw = inline_json.encode("ascii", "strict") + b"\n"
        _require(len(raw) <= MAX_INLINE_PIN_BYTES,
                 f"{label} inline bytes exceed their pin bound")
    else:
        _require(type(file_path) is str, f"{label} pin input is missing")
        raw, _raw_sha, _info = _read_regular_absolute(
            file_path, MAX_JSON_BYTES, label,
        )
    return _parse_canonical(raw, label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export/import one bounded Source5 checkpoint-request packet.",
    )
    sub = parser.add_subparsers(dest="operation", required=True)
    export_parser = sub.add_parser("export-transfer")
    export_parser.add_argument("--request", required=True)
    export_parser.add_argument("--budget", required=True)
    export_parser.add_argument("--request-origin", required=True)
    export_parser.add_argument("--packet", required=True)
    export_parser.add_argument("--offer", required=True)
    export_parser.add_argument("--acknowledgement-receiver", required=True)
    import_parser = sub.add_parser("import-transfer")
    import_parser.add_argument("--packet", required=True)
    import_parser.add_argument("--budget", required=True)
    import_parser.add_argument("--budget-pin", required=True)
    import_parser.add_argument("--offer", required=True)
    import_parser.add_argument("--offer-pin", required=True)
    import_parser.add_argument("--staging-root", required=True)
    import_parser.add_argument("--catalogue-chunk-map", required=True)
    import_parser.add_argument("--catalogue-cache-root", required=True)
    import_parser.add_argument("--dependency-local-map")
    import_parser.add_argument("--dependency-cache-root")
    ack_parser = sub.add_parser("build-ack-bundle")
    ack_parser.add_argument("--checkpoint", required=True)
    ack_parser.add_argument("--object-manifest", required=True)
    ack_parser.add_argument("--ack", required=True)
    ack_parser.add_argument("--signature", required=True)
    ack_parser.add_argument("--budget", required=True)
    ack_parser.add_argument("--output", required=True)
    ack_parser.add_argument("--dependency-local-map")
    ack_parser.add_argument("--dependency-cache-root")
    ack_parser.add_argument("--catalogue-chunk-map")
    ack_parser.add_argument("--catalogue-cache-root")
    publish_parser = sub.add_parser("publish-ack")
    publish_parser.add_argument("--incoming", required=True)
    publish_parser.add_argument("--budget", required=True)
    publish_parser.add_argument("--offer", required=True)
    for pin_name in ("budget", "offer", "bundle"):
        pin_group = publish_parser.add_mutually_exclusive_group(required=True)
        pin_group.add_argument(f"--{pin_name}-pin")
        pin_group.add_argument(
            f"--{pin_name}-pin-json",
            help="bounded canonical pin JSON without its final newline",
        )
    args = parser.parse_args(argv)
    try:
        if args.operation == "build-ack-bundle":
            checkpoint_raw, _checkpoint_sha, _ = _read_regular_absolute(
                args.checkpoint, MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
                "final checkpoint",
            )
            checkpoint = _parse_checkpoint_metadata(
                checkpoint_raw, "final checkpoint",
            )
            manifest_raw, _manifest_sha, _ = _read_regular_absolute(
                args.object_manifest, MAX_JSON_BYTES, "object manifest",
            )
            ack_raw, _ack_sha, _ = _read_regular_absolute(
                args.ack, MAX_JSON_BYTES, "durable ACK",
            )
            signature_raw, _signature_sha, _ = _read_regular_absolute(
                args.signature, MAX_GPG_OUTPUT_BYTES, "ACK signature",
            )
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, PREPARATORY_MAX_BUDGET_BYTES,
                "host evidence budget",
            )
            budget_pin = checkpoint["context"]["resource_budget_pin"]
            budget_probe = _parse_canonical(
                budget_raw, "host evidence budget",
                maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
            )
            if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
                budget_value = _exact(
                    budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                    "preparatory host evidence budget",
                )
            else:
                _require(len(budget_raw) <= MAX_JSON_BYTES,
                         "final host evidence budget exceeds its historic metadata ceiling")
                budget_value, _ = _exact_host_budget(
                    budget_probe, "host evidence budget",
                )
            execution_manifest_raw = None
            journal_width_contract_raw = None
            spec_raw = None
            source_manifest_raw = None
            plan_raw = None
            catalogue_chunk_paths = None
            catalogue_cache_root = None
            if budget_value["schema"] == PREPARATORY_BUDGET_SCHEMA_V1:
                _require(args.dependency_local_map is not None and
                         args.dependency_cache_root is not None and
                         args.catalogue_chunk_map is not None and
                         args.catalogue_cache_root is not None,
                         "preparatory ACK packaging requires exact six-map dependencies and catalogue")
                dependency_map_raw, _map_sha, _ = _read_regular_absolute(
                    args.dependency_local_map, MAX_JSON_BYTES,
                    "Root-local preparatory dependency map",
                )
                (budget_context, source_manifest_raw, plan_raw,
                 execution_manifest_raw, journal_width_contract_raw,
                 spec_raw) = \
                    _read_root_preparatory_dependencies(
                        budget_value, budget_raw, budget_pin,
                        checkpoint["context"], dependency_map_raw,
                        args.dependency_cache_root,
                    )
                catalogue_map_raw, _catalogue_map_sha, _ = \
                    _read_regular_absolute(
                        args.catalogue_chunk_map, MAX_JSON_BYTES,
                        "Root-local preparatory catalogue map",
                    )
                catalogue_chunk_paths = _parse_catalogue_local_map(
                    catalogue_map_raw, budget_value["campaign_id"],
                    budget_value["host_id"], budget_pin,
                )
                catalogue_cache_root = _path(
                    args.catalogue_cache_root,
                    "Root-local preparatory catalogue cache root",
                )
            elif budget_value["schema"] == HOST_BUDGET_SCHEMA_V3:
                _require(args.dependency_local_map is not None and
                         args.dependency_cache_root is not None and
                         args.catalogue_chunk_map is not None and
                         args.catalogue_cache_root is not None,
                         "v3 ACK packaging requires exact dependency and catalogue maps")
                dependency_map_raw, _map_sha, _ = _read_regular_absolute(
                    args.dependency_local_map, MAX_JSON_BYTES,
                    "Root-local dependency map",
                )
                expected_context, source_manifest_raw, execution_manifest_raw, \
                    journal_width_contract_raw = \
                    _read_root_budget_dependencies(
                    budget_value, budget_raw, budget_pin,
                    dependency_map_raw, args.dependency_cache_root,
                )
                _require_same_budget_context(
                    expected_context, checkpoint["context"],
                )
                catalogue_map_raw, _catalogue_map_sha, _ = \
                    _read_regular_absolute(
                    args.catalogue_chunk_map, MAX_JSON_BYTES,
                    "Root-local catalogue chunk map",
                )
                catalogue_chunk_paths = _parse_catalogue_local_map(
                    catalogue_map_raw, budget_value["campaign_id"],
                    budget_value["host_id"], budget_pin,
                )
                catalogue_cache_root = _path(
                    args.catalogue_cache_root,
                    "Root-local catalogue cache root",
                )
            bundle_pin = build_ack_bundle(
                checkpoint_raw, manifest_raw, ack_raw, signature_raw,
                budget_raw, budget_pin, args.output,
                source_manifest_raw=source_manifest_raw,
                execution_manifest_raw=execution_manifest_raw,
                plan_raw=plan_raw,
                journal_width_contract_raw=journal_width_contract_raw,
                spec_raw=spec_raw,
                catalogue_chunk_paths=catalogue_chunk_paths,
                catalogue_cache_root=catalogue_cache_root,
            )
            sys.stdout.buffer.write(_canonical({
                "schema": "allocatbelt.application-source5-archive-ack-bundle-pin.v1",
                **bundle_pin,
            }))
            return 0
        if args.operation == "export-transfer":
            request_raw, request_sha, _ = _read_regular_absolute(
                args.request, MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
                "host checkpoint request",
            )
            request = _validate_request(_parse_checkpoint_metadata(
                request_raw, "host checkpoint request",
            ))
            request_pin = {
                "path": _path(args.request_origin, "request origin path"),
                "raw_sha256": request_sha,
                "semantic_sha256": request["request_sha256"],
            }
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, PREPARATORY_MAX_BUDGET_BYTES,
                "host evidence budget",
            )
            source_manifest_raw, execution_manifest_raw, journal_width_contract_raw = \
                _read_host_budget_dependencies(
                budget_raw, request["context"]["resource_budget_pin"],
                request["context"],
            )
            result = export_transfer_packet(
                request_raw, request_pin, args.budget, args.packet,
                args.offer, args.acknowledgement_receiver,
                source_manifest_raw=source_manifest_raw,
                execution_manifest_raw=execution_manifest_raw,
                journal_width_contract_raw=journal_width_contract_raw,
            )
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, PREPARATORY_MAX_BUDGET_BYTES,
                "host evidence budget",
            )
            offer, offer_pin = publish_transfer_offer(
                request_raw, request_pin, result, budget_raw,
                request["context"]["resource_budget_pin"], args.offer,
                args.acknowledgement_receiver,
                source_manifest_raw=source_manifest_raw,
                execution_manifest_raw=execution_manifest_raw,
                journal_width_contract_raw=journal_width_contract_raw,
            )
            sys.stdout.buffer.write(_canonical({
                **result, "offer": offer, "offer_pin": offer_pin,
            }))
            return 0
        if args.operation == "publish-ack":
            offer_raw, _offer_sha, _ = _read_regular_absolute(
                args.offer, MAX_JSON_BYTES, "archive transfer offer",
            )
            offer_pin = _pin(
                _cli_pin_document(args.offer_pin, args.offer_pin_json,
                                  "archive transfer offer pin"),
                "external archive transfer offer pin",
            )
            offer_value = _exact(
                _parse_canonical(offer_raw, "archive transfer offer"), {
                    "schema", "checkpoint_request_pin", "transfer_packet_pin",
                    "acknowledgement_receiver", "offer_sha256",
                }, "archive transfer offer",
            )
            offer_body = {key: item for key, item in offer_value.items()
                          if key != "offer_sha256"}
            _require(offer_value["schema"] ==
                     "allocatbelt.application-source5-archive-transfer-offer.v1" and
                     offer_value["offer_sha256"] == _sha(_canonical(offer_body)) and
                     offer_pin["raw_sha256"] == _sha(offer_raw) and
                     offer_pin["semantic_sha256"] == offer_value["offer_sha256"],
                     "archive transfer offer differs from its exact raw/semantic pin")
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, PREPARATORY_MAX_BUDGET_BYTES,
                "host evidence budget",
            )
            budget_pin = _pin(
                _cli_pin_document(args.budget_pin, args.budget_pin_json,
                                  "host evidence budget pin"),
                "external host evidence budget pin",
            )
            checkpoint_request_pin = _pin(
                offer_value.get("checkpoint_request_pin"),
                "offered checkpoint request pin",
            )
            request_raw, request_sha, _ = _read_regular_absolute(
                checkpoint_request_pin["path"],
                MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
                "offered host checkpoint request",
            )
            request = _validate_request(_parse_checkpoint_metadata(
                request_raw, "offered host checkpoint request",
            ))
            _require(request_sha == checkpoint_request_pin["raw_sha256"] and
                     request["request_sha256"] ==
                        checkpoint_request_pin["semantic_sha256"],
                     "offered host checkpoint request differs from its raw pin")
            source_manifest_raw, execution_manifest_raw, journal_width_contract_raw = \
                _read_host_budget_dependencies(
                budget_raw, budget_pin, request["context"],
            )
            bundle_pin_value = _cli_pin_document(
                args.bundle_pin, args.bundle_pin_json,
                "coordinator ACK bundle pin",
            )
            bundle_pin = _exact(bundle_pin_value, {
                "path", "raw_sha256", "byte_count",
            }, "coordinator ACK bundle pin")
            result = publish_ack_bundle(
                args.incoming, budget_raw, budget_pin,
                offer_raw, offer_pin, bundle_pin,
                budget_context=request["context"],
                source_manifest_raw=source_manifest_raw,
                execution_manifest_raw=execution_manifest_raw,
                journal_width_contract_raw=journal_width_contract_raw,
            )
            sys.stdout.buffer.write(_canonical({
                "schema": "allocatbelt.application-source5-archive-ack-bundle-pin.v1",
                **result,
            }))
            return 0
        offer_raw, _offer_sha, _ = _read_regular_absolute(
            args.offer, MAX_JSON_BYTES, "archive transfer offer",
        )
        offer_pin_raw, _offer_pin_sha, _ = _read_regular_absolute(
            args.offer_pin, MAX_JSON_BYTES, "archive transfer offer pin file",
        )
        offer_pin = _parse_canonical(
            offer_pin_raw, "archive transfer offer pin file",
        )
        _pin(offer_pin, "external archive transfer offer pin")
        budget_raw, _budget_sha, _ = _read_regular_absolute(
            args.budget, PREPARATORY_MAX_BUDGET_BYTES,
            "host evidence budget",
        )
        budget_pin_raw, _pin_raw_sha, _ = _read_regular_absolute(
            args.budget_pin, MAX_JSON_BYTES, "host evidence budget pin file",
        )
        budget_pin = _parse_canonical(
            budget_pin_raw, "host evidence budget pin file",
        )
        _pin(budget_pin, "external host evidence budget pin")
        budget_probe = _parse_canonical(
            budget_raw, "host evidence budget",
            maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
        )
        if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
            budget_doc = _exact(
                budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                "preparatory host evidence budget",
            )
        else:
            _require(len(budget_raw) <= MAX_JSON_BYTES,
                     "final host evidence budget exceeds its historic metadata ceiling")
            budget_doc, _is_r6 = _exact_host_budget(
                budget_probe, "host evidence budget v2",
            )
        budget_context = None
        source_manifest_raw = None
        execution_manifest_raw = None
        plan_raw = None
        journal_width_contract_raw = None
        spec_raw = None
        catalogue_map_raw, _catalogue_map_sha, _ = _read_regular_absolute(
            args.catalogue_chunk_map, MAX_JSON_BYTES,
            "Root-local catalogue chunk map",
        )
        if budget_doc["schema"] == PREPARATORY_BUDGET_SCHEMA_V1:
            _require(args.dependency_local_map is not None and
                     args.dependency_cache_root is not None,
                     "preparatory packet import requires the exact Root six-map dependencies")
            catalogue_chunk_paths = _parse_catalogue_local_map(
                catalogue_map_raw, budget_doc["campaign_id"],
                budget_doc["host_id"], budget_pin,
            )
            budget_context = peek_preparatory_packet_context(
                args.packet, budget_raw, budget_pin, offer_raw, offer_pin,
            )
            dependency_map_raw, _dependency_map_sha, _ = \
                _read_regular_absolute(
                    args.dependency_local_map, MAX_JSON_BYTES,
                    "Root-local preparatory dependency map",
                )
            (budget_context, source_manifest_raw, plan_raw,
             execution_manifest_raw, journal_width_contract_raw,
             spec_raw) = \
                _read_root_preparatory_dependencies(
                    budget_doc, budget_raw, budget_pin, budget_context,
                    dependency_map_raw, args.dependency_cache_root,
                )
        elif budget_doc["schema"] == HOST_BUDGET_SCHEMA_V3:
            _require(args.dependency_local_map is not None and
                     args.dependency_cache_root is not None,
                     "v3 packet import requires the exact Root-local five-row dependency map")
            dependency_map_raw, _dependency_map_sha, _ = \
                _read_regular_absolute(
                args.dependency_local_map, MAX_JSON_BYTES,
                "Root-local dependency map",
            )
            budget_context, source_manifest_raw, execution_manifest_raw, \
                journal_width_contract_raw = \
                _read_root_budget_dependencies(
                budget_doc, budget_raw, budget_pin, dependency_map_raw,
                args.dependency_cache_root,
            )
        catalogue_map_raw, _catalogue_map_sha, _ = _read_regular_absolute(
            args.catalogue_chunk_map, MAX_JSON_BYTES,
            "Root-local catalogue chunk map",
        )
        catalogue_chunk_paths = _parse_catalogue_local_map(
            catalogue_map_raw, budget_doc["campaign_id"],
            budget_doc["host_id"], budget_pin,
        )
        result = import_transfer_packet(
            args.packet, budget_raw, budget_pin, offer_raw, offer_pin,
            args.staging_root, catalogue_chunk_paths,
            _path(args.catalogue_cache_root, "Root-local catalogue cache root"),
            budget_context=budget_context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
        )
        summary = {
            "schema": PACKET_PIN_SCHEMA,
            "offer_pin": result["offer_pin"],
            "acknowledgement_receiver":
                result["acknowledgement_receiver"],
            "packet_path": _path(args.packet, "transfer packet path"),
            "packet_raw_sha256": result["packet_raw_sha256"],
            "request_pin": result["request_pin"],
            "staging_root": result["staging_root"],
            "request_path": result["request_path"],
            "job_record_path": result["job_record_path"],
            "job_record_raw_sha256": result["job_record_raw_sha256"],
            "job_record_byte_count": result["job_record_byte_count"],
            "staged_files": result["staged_files"],
            "packet_byte_count": result["packet_byte_count"],
            "object_count": result["object_count"],
            "payload_bytes": result["payload_bytes"],
        }
        sys.stdout.buffer.write(_canonical(summary))
        return 0
    except (TransferPacketError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Source5 transfer packet failed: {type(error).__name__}: {error}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
