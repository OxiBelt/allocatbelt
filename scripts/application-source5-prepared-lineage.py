#!/usr/bin/env python3
"""Pure projection and non-authorizing proof for prepared exploration lineage.

The projection reserves the two initial-only bridge files before any original
APP runs.  The verifier accepts only pinned bytes from a caller-owned closed
reader and source-owned algorithms whose module pins the caller already
validated.  It does not perform GPG verification, owner replay, filesystem
inspection, scheduling, or qualification gating.
"""
from __future__ import annotations

import hashlib
import json
import re
import types
from pathlib import Path, PurePosixPath
from typing import Any, Callable


SOURCE_PATH = "scripts/application-source5-prepared-lineage.py"

SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2 = \
    "allocatbelt.application-source5-prepared-inputs-provenance.v2"
SOURCE5_PREPARED_INPUTS_PROVENANCE_V2_FIELDS = frozenset({
    "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    "exploration_lineage",
})
SOURCE5_PREPARED_EXPLORATION_LINEAGE_PIN_FIELDS = frozenset({
    "bridge_header", "record_index",
})

HEADER_SCHEMA = "allocatbelt.application-source5-prepared-exploration-bridge-header.v1"
INDEX_ROW_SCHEMA = "allocatbelt.application-source5-prepared-exploration-index-row.v1"
LINEAGE_PROOF_SCHEMA_V1 = \
    "allocatbelt.application-source5-prepared-exploration-lineage-proof.v1"
LINEAGE_PROOF_SCHEMA_V2 = \
    "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2"
PILOT_SCHEMA = "allocatbelt.application-capacity-pilot.v1"
LINEAGE_DIRECTORY = "preparatory-exploration-lineage-v1"
HEADER_NAME = "bridge-header.json"
INDEX_NAME = "record-index.jsonl"
LINEAGE_ROLE = "preparation"
LINEAGE_OWNER = "source5_controller"
HOST_JOB_COUNT = 360
HOST_CALLBACK_COUNT = 2160
HOST_JOURNAL_RECORD_COUNT = 2161
MAX_PATH_BYTES = 4096
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_CHECKPOINT_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_SOURCE_HOST_FIELDS = {
    "host_id", "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
}
_PILOT_FIELDS = {
    "path", "kind", "role", "host_id", "max_bytes", "max_file_bytes",
    "max_inodes", "storage_root", "owner", "phase", "run_id",
    "member_index", "aggregate_id", "aggregate_max_bytes", "origin_pin",
}


class PreparedExplorationLineageError(ValueError):
    """A pinned preparatory lineage projection or structural proof is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparedExplorationLineageError(message)


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == fields,
            f"{label} has an unexpected field set")
    return value


def canonical_bytes(value: object) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise PreparedExplorationLineageError(
            f"value is not canonical JSON: {error}",
        ) from error
    return (text + "\n").encode("ascii")


def _json_snapshot(value: object, label: str) -> Any:
    """Return a detached Source-owned value containing only canonical JSON data."""
    try:
        return json.loads(canonical_bytes(value))
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError,
            RecursionError) as error:
        raise PreparedExplorationLineageError(
            f"{label} cannot be retained as canonical JSON: {error}",
        ) from error


def sha256_bytes(raw: bytes) -> str:
    require(type(raw) is bytes, "lineage hash input must be bytes")
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    require(type(value) is str and _DIGEST.fullmatch(value) is not None,
            f"{label} is not a lowercase SHA-256 digest")
    return value


def _bounded_uint(value: object, label: str, maximum: int) -> int:
    require(type(value) is int and 0 <= value <= maximum,
            f"{label} is outside its finite unsigned range")
    return value


def _token(value: object, label: str) -> str:
    require(type(value) is str and _TOKEN.fullmatch(value) is not None,
            f"{label} is not a canonical token")
    return value


def _absolute_path(value: object, label: str) -> str:
    require(type(value) is str and value.startswith("/") and
            len(value.encode("utf-8")) <= MAX_PATH_BYTES and
            "\\" not in value and "\x00" not in value and
            not any(ord(char) < 32 or ord(char) == 127 for char in value),
            f"{label} is not a bounded absolute path")
    path = PurePosixPath(value)
    require(path.as_posix() == value and ".." not in path.parts and
            "." not in path.parts and value != "/" and
            not value.endswith("/"),
            f"{label} is not a normalized absolute path")
    return value


def _pin(value: object, label: str, *, semantic: bool = False) -> dict[str, str]:
    fields = {"path", "raw_sha256"} | ({"semantic_sha256"} if semantic else set())
    pin = exact(value, fields, label)
    _absolute_path(pin["path"], f"{label} path")
    _digest(pin["raw_sha256"], f"{label} raw digest")
    if semantic:
        _digest(pin["semantic_sha256"], f"{label} semantic digest")
    return pin

def validate_prepared_input_provenance_v2(
    value: object, *, expected_hosts: list[str],
) -> dict[str, Any]:
    """Validate the exact V2 provenance wrapper without granting authority.

    The selected V5 profile has two hosts. Each lineage entry preserves its
    original raw header/index pins; no imported flag, copied records, metrics,
    or gate assertion is accepted as a substitute.
    """
    require(type(expected_hosts) is list and len(expected_hosts) == 2,
            "prepared-input provenance v2 requires the exact two-host profile")
    hosts = [_token(host, f"prepared-input provenance host[{index}]")
             for index, host in enumerate(expected_hosts)]
    require(len(set(hosts)) == 2,
            "prepared-input provenance v2 repeats a selected host")
    provenance = exact(
        value, set(SOURCE5_PREPARED_INPUTS_PROVENANCE_V2_FIELDS),
        "prepared-input provenance v2",
    )
    require(provenance.get("schema") ==
                SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2,
            "prepared-input provenance schema is not v2")
    preparation_pin = _pin(provenance["preparation_pin"],
                           "prepared-input v2 preparation pin")
    final_spec_pin = _pin(provenance["final_spec_pin"],
                          "prepared-input v2 final Spec pin")
    final_plan_pin = _pin(provenance["final_plan_pin"],
                          "prepared-input v2 final Plan pin")
    lineage = exact(provenance["exploration_lineage"], set(hosts),
                    "prepared-input v2 exploration-lineage cohort")
    normalized_lineage: dict[str, dict[str, dict[str, str]]] = {}
    for host in hosts:
        row = exact(
            lineage[host], set(SOURCE5_PREPARED_EXPLORATION_LINEAGE_PIN_FIELDS),
            f"prepared-input v2 {host} lineage pins",
        )
        normalized_lineage[host] = {
            name: dict(_pin(row[name], f"prepared-input v2 {host} {name} pin"))
            for name in ("bridge_header", "record_index")
        }
    return {
        "schema": SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2,
        "preparation_pin": dict(preparation_pin),
        "final_spec_pin": dict(final_spec_pin),
        "final_plan_pin": dict(final_plan_pin),
        "exploration_lineage": normalized_lineage,
    }



def _pin_template(path: str) -> dict[str, str]:
    return {"path": path, "raw_sha256": "0" * 64,
            "semantic_sha256": "0" * 64}


def _max_path() -> str:
    """Return a valid path whose JSON spelling reaches the UTF-8 path bound.

    Source path validation permits U+0080 and quotes. ``ensure_ascii=True``
    spells U+0080 as six ASCII bytes for two UTF-8 bytes, which is the largest
    accepted-path expansion. The trailing quote also exercises JSON escaping.
    """
    value = "/" + "\u0080" * 2047 + '"'
    require(len(value.encode("utf-8")) == MAX_PATH_BYTES and
            len(json.dumps(value, ensure_ascii=True).encode("ascii")) == 12_287,
            "maximum escaped path witness changed its UTF-8 byte width")
    return value


def _path_join(root: str, *parts: str, label: str) -> str:
    _absolute_path(root, f"{label} root")
    path = PurePosixPath(root).joinpath(*parts).as_posix()
    return _absolute_path(path, label)


def _header_template(campaign_id: str, host_id: str, output_root: str) -> dict[str, Any]:
    campaign_id = _token(campaign_id, "lineage campaign ID")
    host_id = _token(host_id, "lineage host ID")
    output_root = _absolute_path(output_root, "lineage output root")
    base = PurePosixPath(output_root) / campaign_id / "source5" / host_id
    bridge = base / LINEAGE_DIRECTORY
    journal = (PurePosixPath(output_root) / campaign_id / "chronology" /
               host_id / "dispatch-journal.jsonl")
    phase_ledger = base / "exploration" / "controller-ledger.jsonl"
    pilot = base / "exploration" / "capacity-pilot.json"
    return {
        "schema": HEADER_SCHEMA,
        "campaign_id": campaign_id,
        "host_id": host_id,
        "scope": "initial_only",
        "initial_output_root": output_root,
        "initial": {
            "execution_manifest_pin": _pin_template(_max_path()),
            "spec_pin": _pin_template(_max_path()),
            "plan_pin": _pin_template(_max_path()),
            "source_manifest_pins": [
                {"host_id": "h" * 96, "path": _max_path(),
                 "raw_sha256": "0" * 64, "semantic_sha256": "0" * 64,
                 "source_tree_sha256": "0" * 64}
                for index in range(3)
            ],
            "observed_host_pin": {
                "path": _max_path(), "raw_sha256": "0" * 64,
                "boot_id_sha256": "0" * 64, "controls_sha256": "0" * 64,
            },
            "capacity_generation_sha256": "0" * 64,
            "capacity_registration_head": "0" * 64,
            "host_budget_pin": _pin_template(_max_path()),
            "journal_width_pin": _pin_template(_max_path()),
            "fixed_spec_host_pin": _pin_template(_max_path()),
            "prepared_host_binding_sha256": "0" * 64,
            "signer_context_pin": _pin_template(_max_path()),
            "signer_fingerprint": "F" * 64,
            "maximum_signature_bytes": MAX_SIGNATURE_BYTES,
        },
        "journal": {
            "pin": {"path": journal.as_posix(), "raw_sha256": "0" * 64},
            "byte_count": (1 << 64) - 1,
            "record_count": HOST_JOURNAL_RECORD_COUNT,
            "head": "0" * 64,
        },
        "phase_ledger": {
            "pin": {"path": phase_ledger.as_posix(), "raw_sha256": "0" * 64},
            "row_count": HOST_JOB_COUNT,
        },
        "pilot": {
            "pin": {"path": pilot.as_posix(), "raw_sha256": "0" * 64,
                    "semantic_sha256": "0" * 64},
            "pair_count": HOST_JOB_COUNT,
        },
        "record_index": {
            "pin": {"path": (bridge / INDEX_NAME).as_posix(), "raw_sha256": "0" * 64},
            "row_count": HOST_JOB_COUNT,
        },
        "qualification_eligible": False,
    }


def _index_row_template(
    index: int, job: dict[str, Any], campaign_id: str, host_id: str,
    output_root: str,
) -> dict[str, Any]:
    ordinal = job["ordinal"]
    job_sha = sha256_bytes(canonical_bytes(job))
    leaf = f"{ordinal:06d}-{job_sha}"
    metadata = _path_join(
        output_root, campaign_id, "chronology", host_id,
        "evidence-checkpoints", "exploration", label="lineage checkpoint directory",
    )
    record = _path_join(
        output_root, campaign_id, "source5", host_id, "exploration", "job-records",
        f"{job['run_id']}.json", label="lineage job record path",
    )
    checkpoint_paths = {
        "request": _path_join(metadata, f"{leaf}.request.json", label="lineage request path"),
        "checkpoint": _path_join(metadata, f"{leaf}.checkpoint.json", label="lineage checkpoint path"),
        "object_manifest": _path_join(metadata, f"{leaf}.object-manifest.json",
                                       label="lineage object manifest path"),
    }
    remote_max = _max_path()
    callback = {
        "authorization_id": "source5-" + "f" * 64,
        "authorization_head": "0" * 64,
        "app_started_heads": ["0" * 64, "0" * 64],
        "app_start_proof_sha256": ["0" * 64, "0" * 64],
        "app_terminal_heads": ["0" * 64, "0" * 64],
        "app_terminal_event_sha256": ["0" * 64, "0" * 64],
        "job_terminal_head": "0" * 64,
        "component_sha256": "0" * 64,
        "process_metrics_sha256": "0" * 64,
        "callback_count": 6,
    }
    return {
        "schema": INDEX_ROW_SCHEMA,
        "row_index": index,
        "job": job,
        "job_sha256": job_sha,
        "job_record_pin": {"path": record, "raw_sha256": "0" * 64},
        "archive_pins": {
            "request_pin": _pin_template(checkpoint_paths["request"]),
            "checkpoint_pin": _pin_template(checkpoint_paths["checkpoint"]),
            "object_manifest_pin": _pin_template(checkpoint_paths["object_manifest"]),
            "ack_pin": _pin_template(remote_max),
            "signature_pin": {"path": remote_max, "raw_sha256": "0" * 64,
                              "signer_fingerprint": "F" * 64},
        },
        "pilot_pair_raw_sha256": "0" * 64,
        "callback_witness": callback,
    }


def project_prepared_exploration_lineage_outputs(
    campaign_id: str, host_id: str, output_root: str,
    jobs: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return the exact two global Source catalogue rows and finite byte caps.

    The index cap sums one canonical LF-terminated maximum-schema row for each
    actual original job. Job values and deterministic local paths are exact;
    every permitted absolute path uses the Source 4096-byte UTF-8 bound and
    its maximum ``ensure_ascii`` spelling. No parser-byte ceiling is
    multiplied by the job count.
    """
    campaign_id = _token(campaign_id, "lineage campaign ID")
    host_id = _token(host_id, "lineage host ID")
    output_root = _absolute_path(output_root, "lineage output root")
    require(type(jobs) is list and len(jobs) == HOST_JOB_COUNT,
            "lineage projection requires all 360 selected-host Plan jobs")
    require(all(type(job) is dict and job.get("phase") == "exploration" and
                job.get("host_id") == host_id and
                type(job.get("ordinal")) is int and job["ordinal"] > 0 and
                type(job.get("run_id")) is str and job["run_id"]
                for job in jobs),
            "lineage projection job identity differs from its original campaign/host")
    for index, job in enumerate(jobs):
        _token(job["run_id"], f"lineage original job[{index}] run ID")
    require(len({job["run_id"] for job in jobs}) == HOST_JOB_COUNT and
            len({sha256_bytes(canonical_bytes(job)) for job in jobs}) == HOST_JOB_COUNT,
            "lineage projection repeats an original job identity")
    header_path = _path_join(
        output_root, campaign_id, "source5", host_id, LINEAGE_DIRECTORY,
        HEADER_NAME, label="lineage header path",
    )
    index_path = _path_join(
        output_root, campaign_id, "source5", host_id, LINEAGE_DIRECTORY,
        INDEX_NAME, label="lineage index path",
    )
    header_maximum = len(canonical_bytes(_header_template(campaign_id, host_id, output_root)))
    lines = [canonical_bytes(_index_row_template(index, job, campaign_id, host_id,
                                                 output_root))
             for index, job in enumerate(jobs)]
    index_maximum = sum(len(line) for line in lines)
    require(header_maximum > 0 and index_maximum > 0,
            "lineage projection produced an empty output reservation")
    common = {
        "kind": "file", "role": LINEAGE_ROLE, "host_id": host_id,
        "max_inodes": 1, "storage_root": output_root,
        "owner": LINEAGE_OWNER, "phase": None, "run_id": None,
        "member_index": None, "aggregate_id": None,
        "aggregate_max_bytes": None, "origin_pin": None,
    }
    header_row = {
        "path": header_path, **common, "max_bytes": header_maximum,
        "max_file_bytes": header_maximum,
    }
    index_row = {
        "path": index_path, **common, "max_bytes": index_maximum,
        "max_file_bytes": index_maximum,
    }
    exact(header_row, _PILOT_FIELDS, "lineage header output row")
    exact(index_row, _PILOT_FIELDS, "lineage index output row")
    return {"header": header_row, "index": index_row}


def _parse_canonical_object(raw: bytes, label: str, maximum_bytes: int) -> dict[str, Any]:
    require(type(raw) is bytes and 0 < len(raw) <= maximum_bytes,
            f"{label} is empty or exceeds its finite bound")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label} repeats a JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda item: (_ for _ in ()).throw(
                               PreparedExplorationLineageError(
                                   f"{label} contains non-finite JSON number {item}",
                               )))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreparedExplorationLineageError(f"{label} is not bounded ASCII JSON") from error
    require(type(value) is dict and canonical_bytes(value) == raw,
            f"{label} is not one canonical JSON object")
    return value


def _validate_header(value: object, campaign_id: str, host_id: str,
                     output_root: str) -> dict[str, Any]:
    header = exact(value, {
        "schema", "campaign_id", "host_id", "scope", "initial_output_root",
        "initial", "journal", "phase_ledger", "pilot", "record_index",
        "qualification_eligible",
    }, "prepared exploration bridge header")
    require(header["schema"] == HEADER_SCHEMA and
            header["campaign_id"] == campaign_id and header["host_id"] == host_id and
            header["scope"] == "initial_only" and
            header["initial_output_root"] == output_root and
            header["qualification_eligible"] is False,
            "prepared exploration header changed initial-only identity or eligibility")
    initial = exact(header["initial"], {
        "execution_manifest_pin", "spec_pin", "plan_pin", "source_manifest_pins",
        "observed_host_pin", "capacity_generation_sha256",
        "capacity_registration_head", "host_budget_pin", "journal_width_pin",
        "fixed_spec_host_pin", "prepared_host_binding_sha256",
        "signer_context_pin", "signer_fingerprint", "maximum_signature_bytes",
    }, "prepared exploration initial context")
    for name in ("execution_manifest_pin", "spec_pin", "plan_pin", "host_budget_pin",
                 "journal_width_pin", "fixed_spec_host_pin", "signer_context_pin"):
        _pin(initial[name], f"initial {name}", semantic=True)
    source_pins = initial["source_manifest_pins"]
    require(type(source_pins) is list and len(source_pins) in {2, 3},
            "prepared exploration header must retain the actual two- or three-host Source cohort")
    source_hosts = []
    for index, source_value in enumerate(source_pins):
        source = exact(source_value, _SOURCE_HOST_FIELDS,
                       f"initial Source manifest pin[{index}]")
        source_hosts.append(_token(source["host_id"], "initial Source host ID"))
        _absolute_path(source["path"], "initial Source manifest path")
        for field in ("raw_sha256", "semantic_sha256", "source_tree_sha256"):
            _digest(source[field], f"initial Source manifest {field}")
    require(len(set(source_hosts)) == len(source_pins) and host_id in source_hosts,
            "prepared exploration header repeats or omits a Source host")
    observed = exact(initial["observed_host_pin"], {
        "path", "raw_sha256", "boot_id_sha256", "controls_sha256",
    }, "initial observed host pin")
    _absolute_path(observed["path"], "initial observed host path")
    for name in ("raw_sha256", "boot_id_sha256", "controls_sha256"):
        _digest(observed[name], f"initial observed host {name}")
    for name in ("capacity_generation_sha256", "capacity_registration_head",
                 "prepared_host_binding_sha256"):
        _digest(initial[name], f"initial {name}")
    fingerprint = initial["signer_fingerprint"]
    require(type(fingerprint) is str and
            re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", fingerprint) is not None and
            initial["maximum_signature_bytes"] == MAX_SIGNATURE_BYTES and
            type(initial["maximum_signature_bytes"]) is int,
            "prepared exploration header changed its pinned signer fingerprint/quota")
    journal = exact(header["journal"], {"pin", "byte_count", "record_count", "head"},
                    "initial chronology journal pin")
    journal_pin = exact(journal["pin"], {"path", "raw_sha256"},
                        "initial chronology journal raw pin")
    _absolute_path(journal_pin["path"], "initial chronology journal path")
    _digest(journal_pin["raw_sha256"], "initial chronology journal raw digest")
    _digest(journal["head"], "initial chronology journal chain head")
    require(type(journal["byte_count"]) is int and
            0 < journal["byte_count"] <= (1 << 64) - 1 and
            journal["record_count"] == HOST_JOURNAL_RECORD_COUNT and
            type(journal["record_count"]) is int,
            "initial journal byte/count bounds differ from its setup and 2160 callbacks")
    ledger = exact(header["phase_ledger"], {"pin", "row_count"},
                   "initial exploration phase-ledger pin")
    ledger_pin = exact(ledger["pin"], {"path", "raw_sha256"},
                       "initial exploration phase-ledger raw pin")
    _absolute_path(ledger_pin["path"], "initial exploration phase-ledger path")
    _digest(ledger_pin["raw_sha256"], "initial exploration phase-ledger digest")
    require(ledger["row_count"] == HOST_JOB_COUNT and type(ledger["row_count"]) is int,
            "initial exploration ledger does not contain all original jobs")
    pilot = exact(header["pilot"], {"pin", "pair_count"}, "original capacity pilot pin")
    _pin(pilot["pin"], "original capacity pilot", semantic=True)
    require(pilot["pair_count"] == HOST_JOB_COUNT and type(pilot["pair_count"]) is int,
            "original capacity pilot does not bind 360 pairs")
    index = exact(header["record_index"], {"pin", "row_count"},
                  "prepared exploration record-index pin")
    index_pin = exact(index["pin"], {"path", "raw_sha256"},
                      "prepared exploration record-index raw pin")
    _absolute_path(index_pin["path"], "prepared exploration record-index path")
    _digest(index_pin["raw_sha256"], "prepared exploration record-index digest")
    require(index["row_count"] == HOST_JOB_COUNT and type(index["row_count"]) is int,
            "prepared exploration record index does not contain 360 jobs")
    expected_paths = project_prepared_exploration_lineage_outputs(
        campaign_id, host_id, output_root,
        [{"campaign_id": campaign_id, "host_id": host_id, "phase": "exploration",
          "ordinal": ordinal, "run_id": f"projection-{ordinal}"}
         for ordinal in range(1, HOST_JOB_COUNT + 1)],
    )
    require(index_pin["path"] == expected_paths["index"]["path"] and
            journal_pin["path"] == _path_join(
                output_root, campaign_id, "chronology", host_id,
                "dispatch-journal.jsonl", label="expected initial journal path",
            ) and
            ledger_pin["path"] == _path_join(
                output_root, campaign_id, "source5", host_id, "exploration",
                "controller-ledger.jsonl", label="expected initial phase-ledger path",
            ) and
            pilot["pin"]["path"] == _path_join(
                output_root, campaign_id, "source5", host_id, "exploration",
                "capacity-pilot.json", label="expected initial pilot path",
            ), "prepared exploration header changed a deterministic initial output path")
    return header


def _validate_archive_pins(
    value: object, row: dict[str, Any], campaign_id: str, host_id: str,
    output_root: str,
) -> dict[str, Any]:
    archive = exact(value, {
        "request_pin", "checkpoint_pin", "object_manifest_pin", "ack_pin",
        "signature_pin",
    }, "prepared exploration signed archive pins")
    request = _pin(archive["request_pin"], "archived request", semantic=True)
    checkpoint = _pin(archive["checkpoint_pin"], "archived checkpoint", semantic=True)
    object_manifest = _pin(archive["object_manifest_pin"],
                           "archived object manifest", semantic=True)
    ack = _pin(archive["ack_pin"], "archived ACK", semantic=True)
    signature = exact(archive["signature_pin"], {
        "path", "raw_sha256", "signer_fingerprint",
    }, "archived signature pin")
    _absolute_path(signature["path"], "archived signature path")
    _digest(signature["raw_sha256"], "archived signature raw digest")
    fingerprint = signature["signer_fingerprint"]
    require(type(fingerprint) is str and fingerprint == fingerprint.upper() and
            re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", fingerprint) is not None,
            "archived signature fingerprint is malformed")
    job = row["job"]
    leaf = f"{job['ordinal']:06d}-{row['job_sha256']}"
    metadata = _path_join(
        output_root, campaign_id, "chronology", host_id,
        "evidence-checkpoints", "exploration", label="expected archive metadata directory",
    )
    require(request["path"] == _path_join(metadata, f"{leaf}.request.json",
                                           label="expected archive request") and
            checkpoint["path"] == _path_join(metadata, f"{leaf}.checkpoint.json",
                                              label="expected archive checkpoint") and
            object_manifest["path"] == _path_join(
                metadata, f"{leaf}.object-manifest.json",
                label="expected archive object manifest",
            ), "prepared exploration archive metadata changed its exact local paths")
    ack_path = PurePosixPath(ack["path"])
    signature_path = PurePosixPath(signature["path"])
    require(len(ack["path"].encode("utf-8")) <= MAX_PATH_BYTES and
            len(signature["path"].encode("utf-8")) <= MAX_PATH_BYTES and
            ack_path.parent.name == "exploration" and
            ack_path.parent.parent.name == "acks" and
            ack_path.name == f"{leaf}.json" and
            signature_path.parent.name == "exploration" and
            signature_path.parent.parent.name == "signatures" and
            signature_path.parent.parent.parent == ack_path.parent.parent and
            signature_path.name == f"{leaf}.sig",
            "prepared exploration ACK/signature paths do not share the exact durable Root")
    return archive


def _validate_callback_witness(value: object, row: dict[str, Any]) -> dict[str, Any]:
    witness = exact(value, {
        "authorization_id", "authorization_head", "app_started_heads",
        "app_start_proof_sha256", "app_terminal_heads",
        "app_terminal_event_sha256", "job_terminal_head", "component_sha256",
        "process_metrics_sha256", "callback_count",
    }, "prepared exploration callback witness")
    require(witness["callback_count"] == 6 and type(witness["callback_count"]) is int and
            type(witness["authorization_id"]) is str and
            witness["authorization_id"].startswith("source5-") and
            len(witness["authorization_id"]) <= 96,
            "prepared exploration callback witness changed its exact six-event lifecycle")
    for name in ("authorization_head", "job_terminal_head", "component_sha256",
                 "process_metrics_sha256"):
        _digest(witness[name], f"callback witness {name}")
    for name in ("app_started_heads", "app_start_proof_sha256",
                 "app_terminal_heads", "app_terminal_event_sha256"):
        values = witness[name]
        require(type(values) is list and len(values) == 2,
                f"callback witness {name} must have two original members")
        for index, digest in enumerate(values):
            _digest(digest, f"callback witness {name}[{index}]")
    return witness


def _validate_index_row(
    value: object, index: int, job: dict[str, Any], campaign_id: str,
    host_id: str, output_root: str,
) -> dict[str, Any]:
    row = exact(value, {
        "schema", "row_index", "job", "job_sha256", "job_record_pin",
        "archive_pins", "pilot_pair_raw_sha256", "callback_witness",
    }, f"prepared exploration index row[{index}]")
    require(row["schema"] == INDEX_ROW_SCHEMA and row["row_index"] == index and
            type(row["row_index"]) is int and row["job"] == job and
            row["job_sha256"] == sha256_bytes(canonical_bytes(job)),
            f"prepared exploration index row[{index}] changed its original Plan job/order")
    record_pin = _pin(row["job_record_pin"], f"job record pin[{index}]")
    expected_record = _path_join(
        output_root, campaign_id, "source5", host_id,
        "exploration", "job-records", f"{job['run_id']}.json",
        label=f"expected job-record path[{index}]",
    )
    require(record_pin["path"] == expected_record,
            f"prepared exploration index row[{index}] changed its original record path")
    _validate_archive_pins(row["archive_pins"], row, campaign_id, host_id,
                           output_root)
    _digest(row["pilot_pair_raw_sha256"], f"pilot pair digest[{index}]")
    _validate_callback_witness(row["callback_witness"], row)
    return row


def validate_prepared_exploration_lineage_documents(
    header_raw: bytes, index_raw: bytes, expected_jobs: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Check canonical header/index bytes against the exact initial Plan order."""
    require(type(expected_jobs) is list and len(expected_jobs) == HOST_JOB_COUNT and
            all(type(job) is dict for job in expected_jobs),
            "lineage structural validation requires all 360 actual Plan jobs")
    first = expected_jobs[0]
    host_id = _token(first.get("host_id"), "lineage host ID")
    header = _parse_canonical_object(header_raw, "prepared exploration header", 256 * 1024)
    # Plan jobs carry the campaign in their run IDs, not a campaign_id field.
    # SourceA and the final verifier bind this header to their own campaign.
    campaign_id = _token(header.get("campaign_id"), "lineage campaign ID")
    output_root = _absolute_path(header.get("initial_output_root"),
                                 "lineage initial output root")
    _validate_header(header, campaign_id, host_id, output_root)
    projected = project_prepared_exploration_lineage_outputs(
        campaign_id, host_id, output_root, expected_jobs,
    )
    require(type(index_raw) is bytes and 0 < len(index_raw) <= projected["index"]["max_bytes"] and
            sha256_bytes(index_raw) == header["record_index"]["pin"]["raw_sha256"],
            "prepared exploration index differs from its header pin or schema/path projection")
    lines = index_raw.splitlines(keepends=True)
    require(len(lines) == HOST_JOB_COUNT and all(
        line.endswith(b"\n") and b"\r" not in line and line != b"\n"
        for line in lines
    ), "prepared exploration index does not contain exactly 360 LF-terminated rows")
    rows = []
    callback_count = 0
    for index, (line, job) in enumerate(zip(lines, expected_jobs, strict=True)):
        row_value = _parse_canonical_object(
            line, f"prepared exploration index line[{index}]",
            projected["index"]["max_bytes"],
        )
        row = _validate_index_row(row_value, index, job, campaign_id, host_id,
                                  output_root)
        callback_count += row["callback_witness"]["callback_count"]
        rows.append(row)
    require(callback_count == HOST_CALLBACK_COUNT,
            "prepared exploration index does not bind the original 2160 callbacks")
    require(sum(len(line) for line in lines) == len(index_raw),
            "prepared exploration index contains trailing bytes")
    return header, rows


def build_prepared_exploration_bridge_header(
    campaign_id: str, host_id: str, output_root: str,
    initial: dict[str, Any], journal: dict[str, Any],
    phase_ledger: dict[str, Any], pilot_pin: dict[str, Any],
    record_index_pin: dict[str, Any],
) -> dict[str, Any]:
    """Build and schema-check the exact initial-only bridge header body."""
    header = {
        "schema": HEADER_SCHEMA, "campaign_id": campaign_id,
        "host_id": host_id, "scope": "initial_only",
        "initial_output_root": output_root, "initial": initial,
        "journal": journal, "phase_ledger": phase_ledger,
        "pilot": {"pin": pilot_pin, "pair_count": HOST_JOB_COUNT},
        "record_index": {"pin": record_index_pin,
                         "row_count": HOST_JOB_COUNT},
        "qualification_eligible": False,
    }
    _validate_header(header, campaign_id, host_id, output_root)
    require(type(record_index_pin) is dict and
            record_index_pin["path"] == project_prepared_exploration_lineage_outputs(
                campaign_id, host_id, output_root,
                [{"phase": "exploration", "host_id": host_id,
                  "ordinal": ordinal, "run_id": f"projection-{ordinal}"}
                 for ordinal in range(1, HOST_JOB_COUNT + 1)],
            )["index"]["path"],
            "prepared exploration header builder changed its fixed index path")
    return header


def build_prepared_exploration_lineage_index_row(
    index: int, job: dict[str, Any], campaign_id: str, host_id: str,
    output_root: str, job_record_pin: dict[str, Any],
    archive_pins: dict[str, Any], pilot_pair_raw_sha256: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Build one compact index row from the actual retained canonical record."""
    _digest(pilot_pair_raw_sha256, "prepared exploration pilot-pair digest")
    record_pin = _pin(job_record_pin, "prepared exploration record pin")
    require(record_pin["raw_sha256"] == sha256_bytes(canonical_bytes(record)),
            "prepared exploration index record pin differs from raw record bytes")
    row = {
        "schema": INDEX_ROW_SCHEMA, "row_index": index, "job": job,
        "job_sha256": sha256_bytes(canonical_bytes(job)),
        "job_record_pin": record_pin,
        "archive_pins": archive_pins,
        "pilot_pair_raw_sha256": pilot_pair_raw_sha256,
        "callback_witness": _record_callback_witness(record),
    }
    _validate_index_row(row, index, job, campaign_id, host_id, output_root)
    _validate_record_against_row(canonical_bytes(record), row, campaign_id, host_id)
    return row


def _reader_bytes(
    artifact_reader: Callable[[dict[str, str], int], bytes], pin: dict[str, str],
    maximum: int, label: str,
) -> bytes:
    require(callable(artifact_reader), "lineage artifact reader is not callable")
    # Semantic pins belong to the document verifier. The captured-byte reader
    # accepts only the exact origin path and raw digest, even when its caller
    # also carries a separately checked semantic digest.
    raw = artifact_reader({
        "path": pin["path"], "raw_sha256": pin["raw_sha256"],
    }, maximum)
    require(type(raw) is bytes and 0 < len(raw) <= maximum and
            sha256_bytes(raw) == pin["raw_sha256"],
            f"{label} reader bytes differ from their exact bounded raw pin")
    return raw


def _record_callback_witness(record: dict[str, Any]) -> dict[str, Any]:
    chronology = exact(record.get("chronology"), {
        "authorization_id", "authorization_head", "app_started_heads",
        "app_terminal_heads", "job_terminal_head", "component_sha256",
        "process_metrics_sha256", "app_start_events", "app_terminal_events",
        "member_processes",
    }, "original retained job chronology")
    starts = chronology["app_start_events"]
    terminals = chronology["app_terminal_events"]
    require(type(starts) is list and len(starts) == 2 and
            type(terminals) is list and len(terminals) == 2,
            "original retained job does not have two start and terminal callbacks")
    start_heads, terminal_heads = chronology["app_started_heads"], chronology["app_terminal_heads"]
    require(type(start_heads) is list and len(start_heads) == 2 and
            type(terminal_heads) is list and len(terminal_heads) == 2,
            "original retained job callback head lists changed cardinality")
    return {
        "authorization_id": chronology["authorization_id"],
        "authorization_head": chronology["authorization_head"],
        "app_started_heads": list(start_heads),
        "app_start_proof_sha256": [sha256_bytes(canonical_bytes(item)) for item in starts],
        "app_terminal_heads": list(terminal_heads),
        "app_terminal_event_sha256": [
            sha256_bytes(canonical_bytes(item)) for item in terminals
        ],
        "job_terminal_head": chronology["job_terminal_head"],
        "component_sha256": chronology["component_sha256"],
        "process_metrics_sha256": chronology["process_metrics_sha256"],
        "callback_count": 6,
    }


def _validate_record_against_row(
    record_raw: bytes, row: dict[str, Any], campaign_id: str, host_id: str,
) -> dict[str, Any]:
    record = _parse_canonical_object(record_raw, "original retained job record", MAX_RECORD_BYTES)
    require(set(record) == {
        "schema", "state", "job", "pair_directory", "process_metrics", "evidence",
        "chronology", "qualification_eligible", "record_sha256",
    } and record.get("schema") == "allocatbelt.application-source5-job-record.v1" and
        record.get("job") == row["job"] and record.get("state") == "valid_pair" and
        record.get("qualification_eligible") is False,
        "original retained job record changed its fixed-pair Source identity/state")
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    require(record["record_sha256"] == sha256_bytes(canonical_bytes(unsigned)),
            "original retained job record changed its self digest")
    evidence = record["evidence"]
    require(type(evidence) is dict and evidence.get("kind") == "source5_fixed_pair" and
            evidence.get("host_receipt") is not None,
            "original retained job record lost its strict fixed-pair receipt")
    witness = _record_callback_witness(record)
    require(witness == row["callback_witness"] and
            sha256_bytes(canonical_bytes(record.get("process_metrics"))) ==
                witness["process_metrics_sha256"],
            "prepared exploration callback/metric witness differs from its raw record")
    require(row["job"]["host_id"] == host_id and
            row["job"]["phase"] == "exploration",
            "prepared exploration record belongs to a different campaign/host")
    return record


def _pilot_pair_map(pilot: dict[str, Any], campaign_module: object) -> dict[tuple[str, str, str, int], str]:
    require(pilot.get("schema") == PILOT_SCHEMA and type(pilot.get("cells")) is list,
            "original capacity pilot has an unsupported schema")
    result: dict[tuple[str, str, str, int], str] = {}
    for cell_index, cell_value in enumerate(pilot["cells"]):
        cell = exact(cell_value, {"family", "profile", "allocator", "pairs"},
                     f"capacity pilot cell[{cell_index}]")
        require(type(cell["pairs"]) is list and len(cell["pairs"]) == 6,
                f"capacity pilot cell[{cell_index}] omits its six original pairs")
        for pair_index, pair_value in enumerate(cell["pairs"]):
            require(type(pair_value) is dict and type(pair_value.get("ordinal")) is int,
                    f"capacity pilot cell[{cell_index}] pair[{pair_index}] is malformed")
            key = (cell["family"], cell["profile"], cell["allocator"], pair_value["ordinal"])
            require(key not in result,
                    "original capacity pilot repeats a context/allocator/ordinal pair")
            result[key] = _digest(pair_value.get("raw_pair_sha256"),
                                  "original capacity pilot raw pair digest")
    require(len(result) == HOST_JOB_COUNT,
            "original capacity pilot does not contain the original 360 unique pairs")
    return result


def _validate_initial_to_final_fill(
    initial_spec: dict[str, Any], final_spec: dict[str, Any],
    initial_plan: dict[str, Any], final_plan: dict[str, Any],
    campaign_module: object, campaign_inputs_module: object,
    host_id: str,
) -> None:
    core = getattr(campaign_inputs_module, "preparation_core_from_spec", None)
    build_jobs = getattr(campaign_module, "build_jobs", None)
    digest_object = getattr(campaign_module, "digest_object", None)
    require(callable(core) and callable(build_jobs) and callable(digest_object),
            "caller did not supply source-pinned pure campaign/InputPrep algorithms")
    require(initial_spec.get("rates") == [] and initial_spec.get("oracles") == [] and
            type(final_spec.get("rates")) is list and
            type(final_spec.get("oracles")) is list,
            "initial/final Spec rates or oracle slots changed their permitted fill shape")
    require(core(initial_spec) == core(final_spec),
            "final Spec changed a preparation-declared immutable field")

    def without_allowed_fill(spec: dict[str, Any]) -> dict[str, Any]:
        result = json.loads(json.dumps(spec))
        result["rates"] = []
        result["oracles"] = []
        inputs = result.get("qualification_inputs")
        require(type(inputs) is dict,
                "initial/final Spec omits the original qualification input slots")
        for name in ("capacity_templates", "pressure_conditions"):
            rows = inputs.get(name)
            require(type(rows) is list,
                    f"initial/final Spec omits its {name} slot list")
            for index, row in enumerate(rows):
                require(type(row) is dict,
                        f"initial/final {name}[{index}] is malformed")
                row.pop("evidence", None)
        return result

    require(canonical_bytes(without_allowed_fill(initial_spec)) ==
            canonical_bytes(without_allowed_fill(final_spec)),
            "final Spec changed data outside the rate/oracle and capacity/pressure evidence slots")
    for label, plan, spec in (("initial", initial_plan, initial_spec),
                              ("final", final_plan, final_spec)):
        require(type(plan.get("jobs")) is dict and
                plan.get("spec_sha256") == digest_object(spec),
                f"{label} Plan is not bound to its actual Spec")
        for phase in ("exploration", "aa", "confirmation"):
            built = build_jobs(spec, phase)
            require(canonical_bytes(plan["jobs"].get(phase)) == canonical_bytes(built),
                    f"{label} Plan {phase} jobs differ from the Source campaign builder")
    require(canonical_bytes(initial_plan["jobs"]["exploration"]) ==
            canonical_bytes(final_plan["jobs"]["exploration"]),
            "final fill changed the original exploration jobs or order")
    selected = [job for job in initial_plan["jobs"]["exploration"]
                if type(job) is dict and job.get("host_id") == host_id]
    require(len(selected) == HOST_JOB_COUNT,
            "initial/final plans do not retain the original 360 selected-host jobs")


def _source5_prepared_lineage_initial_context(
    header: dict[str, Any], initial_spec: dict[str, Any],
    initial_plan: dict[str, Any], final_prepared: dict[str, Any],
    expected_jobs: list[dict[str, Any]], *,
    artifact_reader: Callable[[dict[str, str], int], bytes],
    chronology_module: object, source5_campaign_module: object,
    preparatory_budget_module: object,
) -> dict[str, Any]:
    """Read and cross-bind the old execution, width, and budget documents."""
    initial = header["initial"]
    host_id, campaign_id = header["host_id"], header["campaign_id"]
    replay_journal = getattr(chronology_module, "replay_journal_bytes", None)
    project_width = getattr(
        chronology_module, "_source5_preparatory_journal_projection", None,
    )
    cleanup_limits_from_budget = getattr(
        chronology_module, "_source5_cleanup_limits_from_budget", None,
    )
    build_execution_basis = getattr(
        preparatory_budget_module, "build_execution_basis", None,
    )
    validate_width = getattr(
        preparatory_budget_module, "validate_journal_width_contract", None,
    )
    build_original_pins = getattr(
        source5_campaign_module, "_source5_preparatory_original_pins", None,
    )
    require(callable(replay_journal) and callable(project_width) and
            callable(cleanup_limits_from_budget) and
            callable(build_execution_basis) and callable(validate_width) and
            callable(build_original_pins),
            "caller did not supply the independently pinned SourceA, SourceH, and prep-budget algorithms")
    execution_maximum = getattr(chronology_module, "MAX_PLAN_BYTES", None)
    width_maximum = getattr(
        chronology_module, "MAX_SOURCE5_JOURNAL_WIDTH_CONTRACT_BYTES", None,
    )
    budget_maximum = getattr(
        chronology_module, "MAX_SOURCE5_PREPARATORY_BUDGET_BYTES", None,
    )
    manifest_fields = getattr(
        chronology_module, "SOURCE5_PREPARATORY_EXECUTION_FIELDS", None,
    )
    expected_schema = getattr(
        chronology_module, "SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1", None,
    )
    require(type(execution_maximum) is int and execution_maximum > 0 and
            type(width_maximum) is int and width_maximum > 0 and
            type(budget_maximum) is int and budget_maximum > 0 and
            type(manifest_fields) in (set, frozenset) and
            type(expected_schema) is str,
            "SourceA preparatory replay module has no finite pinned profile constants")
    execution_pin = _pin(initial["execution_manifest_pin"],
                         "initial execution-manifest pin", semantic=True)
    execution_raw = _reader_bytes(
        artifact_reader, {"path": execution_pin["path"],
                          "raw_sha256": execution_pin["raw_sha256"]},
        execution_maximum, "initial preparatory execution manifest",
    )
    execution = _parse_canonical_object(
        execution_raw, "initial preparatory execution manifest", execution_maximum,
    )
    exact(execution, set(manifest_fields), "initial preparatory execution manifest")
    semantic = sha256_bytes(canonical_bytes({
        key: value for key, value in execution.items()
        if key != "manifest_sha256"
    }))
    require(execution.get("schema") == expected_schema and
            execution.get("manifest_sha256") == execution_pin["semantic_sha256"] == semantic and
            execution.get("campaign_id") == campaign_id and
            execution.get("host_id") == host_id and
            execution.get("hosts") == [item["host_id"]
                                        for item in initial["source_manifest_pins"]] and
            execution.get("scope") == "preparatory_exploration" and
            execution.get("phase_order") == ["exploration"] and
            execution.get("qualification_eligible") is False and
            execution.get("output_root") == header["initial_output_root"] and
            execution.get("protocol_sha256") == sha256_bytes(
                canonical_bytes(initial_spec["protocol"]),
            ),
            "initial execution manifest differs from its header pin, host cohort, or scope")
    basis = execution.get("preparatory_execution_basis_sha256")
    try:
        require(build_execution_basis(execution) == basis,
                "Source-pinned prep budget algorithm changed the execution basis")
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"Source-pinned prep budget algorithm rejected the execution basis: {error}",
        ) from error
    original = exact(execution.get("original_inputs"), {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "initial execution-manifest original inputs")
    for name, pin in (("spec", initial["spec_pin"]),
                      ("plan", initial["plan_pin"])):
        wrapper = exact(original[name], {"artifact", "semantic_sha256"},
                        f"initial execution-manifest {name} wrapper")
        artifact = exact(wrapper["artifact"], {"path", "raw_sha256"},
                         f"initial execution-manifest {name} artifact")
        require(artifact == {"path": pin["path"], "raw_sha256": pin["raw_sha256"]} and
                wrapper["semantic_sha256"] == pin["semantic_sha256"],
                f"initial execution manifest changed its original {name} pin")
    source_pins = initial["source_manifest_pins"]
    source_refs = initial_spec.get("source_manifests")
    require(type(source_refs) is list and len(source_refs) == len(source_pins) and
            len({item.get("host_id") for item in source_refs if type(item) is dict}) ==
                len(source_refs),
            "initial Spec Source references do not uniquely cover the pinned cohort")
    source_map = exact(original["source_manifests"],
                       {item["host_id"] for item in source_pins},
                       "initial execution-manifest source pins")
    source_ref_map = {item["host_id"]: item for item in source_refs}
    require(set(source_ref_map) == set(source_map),
            "initial Spec Source references differ from the execution-manifest cohort")
    source_documents: dict[str, dict[str, Any]] = {}
    max_manifest_bytes = getattr(chronology_module, "MAX_MANIFEST_BYTES", None)
    source_schema = getattr(chronology_module, "SOURCE_SCHEMA", None)
    require(type(max_manifest_bytes) is int and max_manifest_bytes > 0 and
            type(source_schema) is str,
            "SourceA has no finite Source-manifest verifier constants")
    for source_pin in source_pins:
        selected_host = source_pin["host_id"]
        wrapper = exact(source_map[selected_host], {"artifact", "semantic_sha256"},
                        f"initial execution-manifest {selected_host} Source wrapper")
        artifact = exact(wrapper["artifact"], {"path", "raw_sha256"},
                         f"initial execution-manifest {selected_host} Source artifact")
        source_ref = exact(source_ref_map[selected_host],
                           {"host_id", "relative_path", "sha256"},
                           f"initial Spec {selected_host} Source reference")
        source_path = Path(initial["spec_pin"]["path"]).parent / source_ref["relative_path"]
        require(artifact == {"path": source_pin["path"],
                             "raw_sha256": source_pin["raw_sha256"]} and
                wrapper["semantic_sha256"] == source_pin["semantic_sha256"] ==
                    source_ref["sha256"] and
                str(source_path) == source_pin["path"],
                f"initial execution manifest/Spec changed {selected_host} Source pins")
        source_raw = _reader_bytes(
            artifact_reader, artifact, max_manifest_bytes,
            f"initial {selected_host} Source manifest",
        )
        source_document = _parse_canonical_object(
            source_raw, f"initial {selected_host} Source manifest", max_manifest_bytes,
        )
        source_semantic = sha256_bytes(canonical_bytes({
            key: value for key, value in source_document.items()
            if key != "manifest_sha256"
        }))
        require(source_document.get("schema") == source_schema and
                source_document.get("manifest_sha256") ==
                    source_pin["semantic_sha256"] == source_semantic and
                source_document.get("source", {}).get("source_tree_sha256") ==
                    source_pin["source_tree_sha256"],
                f"initial {selected_host} Source manifest bytes differ from their raw/semantic/tree pins")
        source_documents[selected_host] = source_document
    execution_sources = exact(execution.get("execution_sources"), set(source_map),
                              "initial execution-manifest Source snapshots")
    module_map = exact(execution.get("modules"), set(source_map),
                       "initial execution-manifest module map")
    for selected_host, source_document in source_documents.items():
        source_value = source_document.get("source")
        source_files = source_value.get("files") if type(source_value) is dict else None
        require(type(source_files) is list,
                f"initial {selected_host} Source manifest has no typed file inventory")
        typed_files = {item.get("path"): item for item in source_files
                       if type(item) is dict and type(item.get("path")) is str}
        expected_modules = {
            path: {"path": path, "sha256": item["sha256"]}
            for path, item in typed_files.items()
            if item.get("kind") == "file" and path.startswith("scripts/") and
            PurePosixPath(path).suffix in {".py", ".sh"}
        }
        source_snapshot = exact(execution_sources[selected_host], {
            "source_root", "git_commit", "source_tree_sha256", "build_sha256",
        }, f"initial {selected_host} execution Source snapshot")
        source_pin = next(pin for pin in source_pins
                          if pin["host_id"] == selected_host)
        require(module_map[selected_host] == expected_modules and
                source_snapshot["source_tree_sha256"] ==
                    source_pin["source_tree_sha256"] ==
                        source_document["source"]["source_tree_sha256"] and
                source_snapshot["git_commit"] == source_document["source"]["git_commit"] and
                source_snapshot["build_sha256"] == sha256_bytes(canonical_bytes(
                    source_document["build"],
                )),
                f"initial {selected_host} execution module/source-tree pins differ from its manifest")
    selected_source = source_documents[host_id]
    selected_files = {item["path"]: item for item in selected_source["source"]["files"]}
    source_h_path = getattr(
        chronology_module, "SOURCE5_PREPARATORY_CONTROLLER_SOURCE_PATH", None,
    )
    prep_budget_path = getattr(
        source5_campaign_module, "PREPARATORY_BUDGET_SOURCE_PATH", None,
    )
    expected_prep_budget_path = getattr(
        chronology_module, "SOURCE5_PREPARATORY_BUDGET_SOURCE_PATH", None,
    )
    require(type(source_h_path) is str and type(prep_budget_path) is str and
            prep_budget_path == expected_prep_budget_path and
            all(type(selected_files.get(path)) is dict and
                selected_files[path].get("kind") == "file" and
                module_map[host_id].get(path) == {
                    "path": path, "sha256": selected_files[path].get("sha256"),
                }
                for path in (source_h_path, prep_budget_path)),
            "SourceH/prep-budget algorithms are absent from the selected typed Source inventory")
    original_pins = json.loads(json.dumps(final_prepared["original_pins"]))
    original_pins["spec"] = dict(initial["spec_pin"])
    original_pins["plan"] = dict(initial["plan_pin"])
    original_pins["source_manifests"] = json.loads(
        json.dumps(initial["source_manifest_pins"]),
    )
    for field, relative in (
        ("capacity_stage", chronology_module.CAPACITY_STAGE_SOURCE_PATH),
        ("chronology_module", chronology_module.CHRONOLOGY_SOURCE_PATH),
        ("pair_runner", chronology_module.PAIR_RUNNER_SOURCE_PATH),
    ):
        typed = selected_files.get(relative)
        require(type(typed) is dict and typed.get("kind") == "file" and
                original_pins.get(field) == {"path": relative, "sha256": typed.get("sha256")},
                f"initial {field} source pin differs from its selected typed Source inventory")
    captured_paths = {
        "campaign_controller": chronology_module.CONTROLLER_SOURCE_PATH,
        "campaign_inputs": "scripts/application-campaign-inputs.py",
        "feedback_reader": "scripts/application-feedback-readback.py",
        "capacity_producer": "scripts/application-byte-capacity.py",
    }
    expected_captured = [
        {"role": role, "path": path,
         "sha256": selected_files[path]["sha256"]}
        for role, path in captured_paths.items()
    ]
    require(original_pins.get("captured_modules") == expected_captured,
            "initial captured-module pins differ from the selected typed Source inventory")
    require(original_pins.get("campaign_id") == campaign_id and
            original_pins.get("host_id") == host_id and
            original_pins.get("source_manifests") == initial["source_manifest_pins"],
            "initial original-pin projection changed its campaign/host/Source cohort")
    observed_original = exact(original_pins["observed_host"], {
        "path", "raw_sha256", "boot_id_sha256", "controls_sha256", "controls",
        "cpu_affinity", "network_namespace_inode",
    }, "initial original observed-host projection")
    require(observed_original["path"] == initial["observed_host_pin"]["path"] and
            observed_original["raw_sha256"] == initial["observed_host_pin"]["raw_sha256"] and
            observed_original["boot_id_sha256"] == initial["observed_host_pin"]["boot_id_sha256"] and
            observed_original["controls_sha256"] == initial["observed_host_pin"]["controls_sha256"] and
            type(observed_original["controls"]) is dict and
            sha256_bytes(canonical_bytes(observed_original["controls"])) ==
                observed_original["controls_sha256"] and
            type(observed_original["cpu_affinity"]) is list and
            observed_original["cpu_affinity"] == sorted(set(observed_original["cpu_affinity"])) and
            all(type(cpu) is int and 0 <= cpu <= 65535
                for cpu in observed_original["cpu_affinity"]) and
            type(observed_original["network_namespace_inode"]) is int and
            observed_original["network_namespace_inode"] > 0,
            "initial original pins changed the selected observed-host facts")
    observed_map = exact(execution.get("observed_hosts"), set(source_map),
                         "initial execution-manifest observed-host map")
    observed = exact(observed_map[host_id], {
        "artifact", "host_fingerprint_sha256", "controls_sha256",
    }, "initial execution-manifest selected observed host")
    observed_artifact = exact(observed["artifact"], {"path", "raw_sha256"},
                              "initial execution-manifest observed-host artifact")
    observed_pin = initial["observed_host_pin"]
    require(observed_artifact == {
                "path": observed_pin["path"], "raw_sha256": observed_pin["raw_sha256"],
            } and observed["controls_sha256"] ==
                observed["host_fingerprint_sha256"] ==
                    observed_pin["controls_sha256"],
            "initial execution manifest changed the original observed-host pin")
    observed_raw = _reader_bytes(
        artifact_reader,
        {"path": observed_pin["path"], "raw_sha256": observed_pin["raw_sha256"]},
        max_manifest_bytes, "initial observed-host document",
    )
    observed_document = _parse_canonical_object(
        observed_raw, "initial observed-host document", max_manifest_bytes,
    )
    generation = exact(execution.get("preparatory_capacity_generation"), {
        "completion", "provenance",
    }, "initial preparatory capacity generation")
    generation_pin = exact(generation["completion"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "initial preparatory capacity-generation pin")
    require(generation_pin["semantic_sha256"] == initial["capacity_generation_sha256"],
            "initial execution manifest changed the capacity-generation semantic pin")
    registration = exact(execution.get("preparatory_capacity_registration"), {
        "completion", "host_completion", "host_verification", "ledger",
        "capacity_schedule_sha256", "registration_head",
    }, "initial preparatory capacity registration")
    require(registration["registration_head"] == initial["capacity_registration_head"] and
            registration["completion"] == generation_pin,
            "initial execution manifest changed the actual prepared-capacity registration")
    signer_map = exact(execution.get("archive_signer_contexts"), {host_id},
                       "initial execution-manifest signer map")
    signer_wrapper = exact(signer_map[host_id], {"artifact", "semantic_sha256"},
                           "initial execution-manifest signer wrapper")
    signer_pin = _pin({**signer_wrapper["artifact"],
                       "semantic_sha256": signer_wrapper["semantic_sha256"]},
                      "initial signer-context pin", semantic=True)
    require(signer_pin == initial["signer_context_pin"],
            "initial execution manifest changed the signed-ACK verifier context pin")
    signer_raw = _reader_bytes(
        artifact_reader, {"path": signer_pin["path"],
                          "raw_sha256": signer_pin["raw_sha256"]},
        64 * 1024, "initial archive signer context",
    )
    signer = _parse_canonical_object(signer_raw, "initial archive signer context", 64 * 1024)
    signer_body = {key: value for key, value in signer.items()
                   if key != "signer_context_sha256"}
    require(signer.get("schema") == "allocatbelt.application-source5-archive-signer-context.v1" and
            signer.get("campaign_id") == campaign_id and signer.get("host_id") == host_id and
            signer.get("authorized_primary_fingerprint") == initial["signer_fingerprint"] and
            signer.get("maximum_signature_bytes") == initial["maximum_signature_bytes"] and
            signer.get("signer_context_sha256") == signer_pin["semantic_sha256"] ==
                sha256_bytes(canonical_bytes(signer_body)),
            "initial signer context changed its pinned identity or signature quota")
    width_map = exact(execution.get("preparatory_journal_width_contracts"), {host_id},
                      "initial preparatory journal-width map")
    width_wrapper = exact(width_map[host_id], {"artifact", "semantic_sha256"},
                          "initial preparatory journal-width wrapper")
    width_pin = _pin({**width_wrapper["artifact"],
                      "semantic_sha256": width_wrapper["semantic_sha256"]},
                     "initial journal-width pin", semantic=True)
    require(width_pin == initial["journal_width_pin"],
            "initial execution manifest changed its exact journal-width pin")
    budget_map = exact(execution.get("preparatory_host_budgets"), {host_id},
                       "initial preparatory host-budget map")
    budget_wrapper = exact(budget_map[host_id], {"artifact", "semantic_sha256"},
                           "initial preparatory host-budget wrapper")
    budget_pin = _pin({**budget_wrapper["artifact"],
                       "semantic_sha256": budget_wrapper["semantic_sha256"]},
                      "initial host-budget pin", semantic=True)
    require(budget_pin == initial["host_budget_pin"],
            "initial execution manifest changed its exact host-budget pin")
    artifact_root = _absolute_path(execution.get("artifact_root"),
                                   "initial execution artifact root")
    width_expected = _path_join(
        artifact_root, campaign_id, "source5", host_id, "evidence-budget",
        "preparatory-journal-width-v1.json", label="initial journal-width artifact path",
    )
    budget_expected = _path_join(
        artifact_root, campaign_id, "source5", host_id, "evidence-budget",
        "host-evidence-budget-preparatory-v1.json", label="initial host-budget artifact path",
    )
    require(width_pin["path"] == width_expected and budget_pin["path"] == budget_expected,
            "initial width/budget artifacts escaped their fixed Source-owned paths")
    width_raw = _reader_bytes(
        artifact_reader, {"path": width_pin["path"], "raw_sha256": width_pin["raw_sha256"]},
        width_maximum, "initial journal-width contract",
    )
    budget_raw = _reader_bytes(
        artifact_reader, {"path": budget_pin["path"], "raw_sha256": budget_pin["raw_sha256"]},
        budget_maximum, "initial host evidence budget",
    )
    width_contract = _parse_canonical_object(
        width_raw, "initial journal-width contract", width_maximum,
    )
    budget = _parse_canonical_object(
        budget_raw, "initial host evidence budget", budget_maximum,
    )
    width_semantic = sha256_bytes(canonical_bytes({
        key: value for key, value in width_contract.items() if key != "contract_sha256"
    }))
    budget_semantic = sha256_bytes(canonical_bytes({
        key: value for key, value in budget.items() if key != "budget_sha256"
    }))
    require(width_contract.get("schema") ==
                "allocatbelt.application-source5-preparatory-journal-width-contract.v1" and
            width_contract.get("contract_sha256") == width_pin["semantic_sha256"] == width_semantic and
            budget.get("schema") ==
                "allocatbelt.application-source5-preparatory-exploration-budget.v1" and
            budget.get("budget_sha256") == budget_pin["semantic_sha256"] == budget_semantic and
            width_contract.get("campaign_id") == budget.get("campaign_id") == campaign_id and
            width_contract.get("host_id") == budget.get("host_id") == host_id and
            width_contract.get("execution_basis_sha256") ==
                budget.get("execution_basis_sha256") == basis and
            budget.get("journal_width_contract_pin") == width_pin and
            budget.get("readiness") == {
                "preparatory_budget_complete": True, "preparatory_execution_ready": True,
                "full_horizon_execution_ready": False, "component_gate_ready": False,
                "qualification_eligible": False,
            }, "initial width/budget documents differ from their pinned execution context")
    budget_fields = getattr(preparatory_budget_module, "BUDGET_FIELDS", None)
    validate_read_schedule = getattr(
        preparatory_budget_module, "_validate_read_schedule", None,
    )
    validate_readiness = getattr(
        preparatory_budget_module, "_validate_readiness", None,
    )
    require(type(budget_fields) in (set, frozenset) and
            callable(validate_read_schedule) and callable(validate_readiness),
            "Source-pinned prep budget module lacks its exact budget/readiness/read-schedule validators")
    try:
        exact(budget, set(budget_fields), "initial preparatory host evidence budget")
        require(budget.get("profile") ==
                    getattr(preparatory_budget_module, "PREPARATORY_PROFILE", None) and
                type(budget.get("original_pins")) is dict,
                "initial prep budget changed its exact Source profile/original pins")
        validate_readiness(budget["readiness"])
        validate_read_schedule(budget["read_schedule"], width_contract)
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"Source-pinned prep budget schema/read projection rejected initial inputs: {error}",
        ) from error
    owner_paths = getattr(chronology_module, "SOURCE5_WIDTH_OWNER_PATHS", None)
    require(type(owner_paths) is dict and bool(owner_paths),
            "SourceA width verifier has no exact owner-source inventory")
    owner_pins = exact(width_contract.get("owner_pins"), set(owner_paths),
                       "initial journal-width owner-source pins")
    for role, relative in owner_paths.items():
        typed = selected_files.get(relative)
        pin = exact(owner_pins[role], {"path", "raw_sha256", "byte_count"},
                    f"initial journal-width {role} owner pin")
        require(type(typed) is dict and typed.get("kind") == "file" and
                pin == {"path": relative, "raw_sha256": typed.get("sha256"),
                        "byte_count": typed.get("size")},
                f"initial journal-width {role} differs from the selected Source inventory")
    require(final_prepared.get("source5_preparatory_capacity_generation") is None or
            final_prepared.get("source5_preparatory_capacity_generation") == generation,
            "final Source context changed its initial prepared-capacity generation")
    source_manifest_map = {pin["host_id"]: pin for pin in source_pins}
    selected_source_pin = source_manifest_map[host_id]
    require(width_contract.get("initial_spec_pin") == initial["spec_pin"] and
            width_contract.get("initial_plan_pin") == initial["plan_pin"] and
            width_contract.get("capacity_generation_pin") == generation_pin and
            width_contract.get("source_manifest_pin") == {
                key: selected_source_pin[key]
                for key in ("path", "raw_sha256", "semantic_sha256")
            }, "initial journal-width contract changed its exact prep input pins")
    source_manifest_pins_by_host = {
        pin["host_id"]: pin for pin in source_pins
    }
    prep_context = types.SimpleNamespace(
        manifest=execution,
        preparatory_capacity_generation=generation,
        preparatory_capacity_registration=registration,
        preparatory_execution_basis_sha256=basis,
        source_manifest_pins=source_manifest_pins_by_host,
        sources=source_documents,
        host_id=host_id,
        spec_pin=initial["spec_pin"],
        spec_semantic_sha256=initial["spec_pin"]["semantic_sha256"],
        plan_pin=initial["plan_pin"],
        plan_semantic_sha256=initial["plan_pin"]["semantic_sha256"],
        archive_signer_context_pin=signer_pin,
    )
    try:
        preparatory_original_pins = build_original_pins(prep_context)
        require(type(preparatory_original_pins) is dict and
                width_contract.get("original_pins_sha256") ==
                    sha256_bytes(canonical_bytes(preparatory_original_pins)) and
                budget.get("original_pins") == preparatory_original_pins,
                "initial width/budget artifacts changed SourceH preparatory original pins")
        validate_width(
            width_contract,
            expected_campaign_id=campaign_id,
            expected_host_id=host_id,
            expected_execution_basis_sha256=basis,
            expected_original_pins=preparatory_original_pins,
        )
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"SourceH/prep budget original-pin or width validation failed: {error}",
        ) from error
    schedule_validator = getattr(preparatory_budget_module, "_validate_schedule", None)
    require(callable(schedule_validator),
            "Source-pinned prep budget module has no bounded schedule validator")
    try:
        schedule = schedule_validator(budget.get("schedule"), width_contract)
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"Source-pinned prep budget schedule rejected the phase-ledger cap: {error}",
        ) from error
    try:
        width_projection, event_projection = project_width(
            width_contract, expected_jobs, host_id,
        )
        cleanup_limits = cleanup_limits_from_budget(budget)
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"SourceA width/budget projection rejected initial lineage context: {error}",
        ) from error
    require(type(width_projection) is dict and type(event_projection) is dict and
            event_projection.get("maximum_callback_events") == HOST_JOURNAL_RECORD_COUNT and
            event_projection.get("maximum_journal_bytes") == width_projection.get("maximum_journal_bytes") and
            type(cleanup_limits) is dict,
            "initial SourceA width/budget projection changed its finite replay horizon")
    phase_ledger_maximum = schedule.get("maximum_phase_ledger_bytes")
    phase_ledger_record_maximum = getattr(
        chronology_module, "MAX_EVENT_BYTES", None,
    )
    require(type(phase_ledger_maximum) is int and
            type(phase_ledger_record_maximum) is int and
            phase_ledger_record_maximum == MAX_RECORD_BYTES and
            0 < phase_ledger_maximum <= HOST_JOB_COUNT * phase_ledger_record_maximum,
            "initial Source-owned phase-ledger reservation is outside the exact 360-row record cap")
    return {
        "execution_manifest": execution, "budget": budget,
        "width_contract": width_contract, "width_projection": width_projection,
        "event_projection": event_projection, "cleanup_limits": cleanup_limits,
        "original_pins": original_pins,
        "preparatory_original_pins": preparatory_original_pins,
        "phase_ledger_maximum_bytes": phase_ledger_maximum,
        "phase_ledger_record_maximum_bytes": phase_ledger_record_maximum,
        "observed_host_document": observed_document,
    }


def _replay_initial_preparatory_journal_and_ledger(
    header: dict[str, Any], expected_jobs: list[dict[str, Any]],
    rows: list[dict[str, Any]], original_context: dict[str, Any],
    *, artifact_reader: Callable[[dict[str, str], int], bytes],
    chronology_module: object, campaign_module: object,
    journal_raw: bytes, phase_ledger_raw: bytes,
) -> dict[str, Any]:
    """Replay the old raw chain and phase rows with SourceA's pure algorithms."""
    campaign_id, host_id = header["campaign_id"], header["host_id"]
    initial = header["initial"]
    original_pins = original_context["original_pins"]
    width_projection = original_context["width_projection"]
    event_projection = original_context["event_projection"]
    cleanup_limits = original_context["cleanup_limits"]
    journal = header["journal"]
    journal_pin = journal["pin"]
    require(type(journal_raw) is bytes and
            len(journal_raw) == journal["byte_count"] and
            sha256_bytes(journal_raw) == journal_pin["raw_sha256"],
            "initial raw journal differs from its exact header byte-count/digest pin")
    replay_fn = getattr(chronology_module, "replay_journal_bytes", None)
    require(callable(replay_fn),
            "caller did not supply SourceA's pure bounded journal replay API")
    sidecar_resolver = None
    sidecar_maximum = cleanup_limits.get("sidecar_admission_bytes")
    if type(sidecar_maximum) is int and sidecar_maximum > 0:
        def sidecar_resolver(pin: dict[str, Any], role: str, selected_host: str) -> bytes:
            require(role == "source5_cleanup_sidecar" and selected_host == host_id,
                    "SourceA requested a cleanup sidecar outside the selected old host")
            sidecar_pin = exact(pin, {"path", "raw_sha256", "byte_count"},
                                "initial cleanup-sidecar pin")
            require(_bounded_uint(
                sidecar_pin["byte_count"],
                "initial cleanup-sidecar byte count", sidecar_maximum,
            ) > 0, "initial cleanup-sidecar byte count must be positive")
            return _reader_bytes(
                artifact_reader,
                {"path": sidecar_pin["path"], "raw_sha256": sidecar_pin["raw_sha256"]},
                sidecar_maximum, "initial Source5 cleanup sidecar",
            )
    try:
        structural = replay_fn(
            journal_raw, original_pins, campaign_id, host_id,
            initial["observed_host_pin"]["boot_id_sha256"],
            maximum_events=event_projection["maximum_callback_events"],
            maximum_bytes=event_projection["maximum_journal_bytes"],
            source5_width_projection=width_projection,
            source5_bounded_v3=True,
            cleanup_sidecar_resolver=sidecar_resolver,
            cleanup_sidecar_limits=cleanup_limits,
            output_root=Path(header["initial_output_root"]),
        )
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"SourceA rejected the pinned original preparatory journal: {error}",
        ) from error
    require(structural.get("journal_chain_replayed") is True and
            structural.get("journal_raw_sha256") == journal_pin["raw_sha256"] and
            structural.get("journal_byte_count") == journal["byte_count"] and
            structural.get("record_count") == HOST_JOURNAL_RECORD_COUNT and
            structural.get("terminal_head") == journal["head"] and
            structural.get("pending_source5_authorization") is None and
            structural.get("pending_dispatch_authorization") is None and
            structural.get("cleanup_blocked") is False and
            structural.get("source5_cleanup_blocked") is False and
            structural.get("source5_failed_owner_window") is False and
            structural.get("source5_analyses") == {} and
            structural.get("analysis_results_replayed") is False and
            structural.get("component_results_replayed") is False,
            "SourceA journal replay differs from its exact initial-only header or claims owner replay")
    event_counts: dict[str, int] = {}
    for item in structural["events"]:
        event_counts[item["event"]] = event_counts.get(item["event"], 0) + 1
    require(event_counts == {
        "source5_prepared_capacity_registered": 1,
        "source5_authorized": HOST_JOB_COUNT,
        "source5_app_started": 2 * HOST_JOB_COUNT,
        "source5_app_terminal": 2 * HOST_JOB_COUNT,
        "source5_job_terminal": HOST_JOB_COUNT,
    }, "initial journal does not contain one setup and exactly 360 original six-event jobs")
    registrations = structural["registrations"]
    require(len(registrations) == 1 and
            registrations[0]["event"] == "source5_prepared_capacity_registered" and
            registrations[0]["sequence"] == 1 and
            registrations[0]["record_sha256"] == initial["capacity_registration_head"],
            "initial journal registration head differs from its actual one-event setup row")
    registration_details = registrations[0]["details"]
    execution = original_context["execution_manifest"]
    generation = execution["preparatory_capacity_generation"]
    manifest_registration = execution["preparatory_capacity_registration"]
    require(registration_details["campaign_id"] == campaign_id and
            registration_details["host_id"] == host_id and
            registration_details["completion"] == generation["completion"] and
            registration_details["provenance"] == generation["provenance"] and
            registration_details["host_completion"] ==
                manifest_registration["host_completion"] and
            registration_details["host_verification"] ==
                manifest_registration["host_verification"] and
            registration_details["capacity_ledger"] == manifest_registration["ledger"] and
            registration_details["capacity_schedule_sha256"] ==
                manifest_registration["capacity_schedule_sha256"] and
            manifest_registration["registration_head"] == initial["capacity_registration_head"] and
            registration_details["completion"]["semantic_sha256"] ==
                initial["capacity_generation_sha256"] and
            registration_details["provenance"]["initial_spec_pin"] == {
                "path": initial["spec_pin"]["path"],
                "raw_sha256": initial["spec_pin"]["raw_sha256"],
            } and
            registration_details["provenance"]["initial_plan_pin"] == {
                "path": initial["plan_pin"]["path"],
                "raw_sha256": initial["plan_pin"]["raw_sha256"],
            }, "initial setup row changed its original generation/Spec/Plan context")
    authorizations = structural["source5_authorizations"]
    finished = {(item["phase"], item["job_run_id"]): item
                for item in structural["source5_finished"]}
    require(len(authorizations) == len(finished) == len(expected_jobs) == len(rows) == HOST_JOB_COUNT and
            len(structural["events"]) == HOST_JOURNAL_RECORD_COUNT and
            set(finished) == {("exploration", job["run_id"]) for job in expected_jobs},
            "initial journal authorization/terminal set differs from the original 360-job Plan")
    phase_ledger = header["phase_ledger"]
    ledger_pin = phase_ledger["pin"]
    ledger_maximum = original_context.get("phase_ledger_maximum_bytes")
    record_maximum = original_context.get("phase_ledger_record_maximum_bytes")
    require(type(ledger_maximum) is int and ledger_maximum > 0 and
            type(record_maximum) is int and record_maximum == MAX_RECORD_BYTES and
            type(phase_ledger_raw) is bytes and
            len(phase_ledger_raw) <= min(ledger_maximum, HOST_JOB_COUNT * record_maximum) and
            sha256_bytes(phase_ledger_raw) == ledger_pin["raw_sha256"],
            "initial phase-ledger bytes exceed their finite SourceA bound or differ from the header pin")
    ledger_lines = phase_ledger_raw.splitlines(keepends=True)
    require(len(ledger_lines) == HOST_JOB_COUNT and all(
        line.endswith(b"\n") and b"\r" not in line and line != b"\n"
        for line in ledger_lines
    ), "initial phase ledger does not contain exactly 360 canonical ordered rows")
    records: list[dict[str, Any]] = []
    verify_callback = getattr(
        chronology_module, "_source5_validate_v4_terminal_callback_events", None,
    )
    require(callable(verify_callback),
            "SourceA lacks its pure original terminal-callback structural verifier")
    for index, (line, job, row, authorization) in enumerate(zip(
            ledger_lines, expected_jobs, rows, authorizations, strict=True)):
        record = _parse_canonical_object(
            line, f"initial phase-ledger row[{index}]", MAX_RECORD_BYTES,
        )
        require(canonical_bytes(record) == line and record.get("job") == job and
                authorization["phase"] == "exploration" and
                authorization["job_index"] == index and
                authorization["job"] == job and
                authorization["job_run_id"] == job["run_id"],
                f"initial phase-ledger row[{index}] changed its exact original Plan order")
        record_pin = row["job_record_pin"]
        record_raw = _reader_bytes(
            artifact_reader, record_pin, MAX_RECORD_BYTES,
            f"initial retained job record[{index}]",
        )
        require(record_raw == line and
                _validate_record_against_row(record_raw, row, campaign_id, host_id) == record,
                f"initial phase-ledger row[{index}] differs from its separately pinned job record")
        witness = row["callback_witness"]
        starts, terminals = authorization["starts"], authorization["terminals"]
        terminal = authorization["job_terminal"]
        done = finished[("exploration", job["run_id"])]
        capacity_ledger = registration_details["capacity_ledger"]
        require(authorization["execution_manifest"] == {
                    "path": initial["execution_manifest_pin"]["path"],
                    "raw_sha256": initial["execution_manifest_pin"]["raw_sha256"],
                } and authorization["output_root"] == record["pair_directory"] and
                authorization["capacity_registration_head"] ==
                    initial["capacity_registration_head"] and
                authorization["capacity_completion"] == {
                    "path": registration_details["host_completion"]["path"],
                    "raw_sha256": registration_details["host_completion"]["raw_sha256"],
                } and authorization["capacity_ledger_raw_sha256"] ==
                    capacity_ledger["raw_sha256"] and
                authorization["capacity_terminal_head"] == capacity_ledger["terminal_head"] and
                authorization["capacity_schedule_sha256"] ==
                    registration_details["capacity_schedule_sha256"] and
                record["evidence"]["execution_manifest"] ==
                    authorization["execution_manifest"],
                f"initial authorization[{index}] changed its old execution/capacity context")
        require(len(starts) == len(terminals) == 2 and
                terminal["state_claim"] == done["job_terminal"]["state_claim"] == "valid_pair" and
                witness["authorization_id"] == authorization["authorization_id"] and
                witness["authorization_head"] == authorization["authorization_head"] and
                witness["app_started_heads"] == [item["event_head"] for item in starts] and
                witness["app_start_proof_sha256"] == [item["proof_sha256"] for item in starts] and
                witness["app_terminal_heads"] == [item["event_head"] for item in terminals] and
                witness["job_terminal_head"] == terminal["event_head"] ==
                    done["job_terminal"]["event_head"] and
                witness["component_sha256"] == terminal["details"]["component_sha256"] and
                witness["process_metrics_sha256"] ==
                    terminal["details"]["process_metrics_sha256"] ==
                    sha256_bytes(canonical_bytes(record["process_metrics"])) and
                witness["app_terminal_event_sha256"] == [
                    sha256_bytes(canonical_bytes(item))
                    for item in record["chronology"]["app_terminal_events"]
                ], f"initial callback witness[{index}] differs from SourceA journal ancestry")
        overlay = record["evidence"]["overlay"]
        verify_callback(
            record["chronology"]["app_terminal_events"], authorization,
            campaign_id, host_id, record["evidence"], {},
            archived_overlay_sha256=overlay["raw_sha256"],
        )
        records.append(record)
    validate_ledger = getattr(campaign_module, "validate_phase_ledger", None)
    require(callable(validate_ledger),
            "caller did not supply the independently pinned Source campaign phase-ledger validator")
    try:
        validate_ledger(records, expected_jobs, "exploration", host_id)
    except Exception as error:
        raise PreparedExplorationLineageError(
            f"Source campaign module rejected the original phase ledger: {error}",
        ) from error
    return {
        "initial_journal_pin": {"path": journal_pin["path"],
                                "raw_sha256": journal_pin["raw_sha256"]},
        "initial_journal_byte_count": structural["journal_byte_count"],
        "initial_journal_record_count": structural["record_count"],
        "initial_journal_head": structural["terminal_head"],
        "initial_phase_ledger_pin": {"path": ledger_pin["path"],
                                     "raw_sha256": ledger_pin["raw_sha256"]},
        "initial_phase_ledger_byte_count": len(phase_ledger_raw),
        "initial_phase_ledger_row_count": len(records),
        "job_count": HOST_JOB_COUNT, "callback_count": HOST_CALLBACK_COUNT,
        "structural_only": True, "component_replay_required": True,
        "fresh_sourcea_gpg_replay_required": True,
        "qualification_eligible": False,
        "records": records,
        "journal_authorizations": list(authorizations),
        "journal_finished": [
            finished[("exploration", job["run_id"])]
            for job in expected_jobs
        ],
    }


def _verify_source5_prepared_exploration_lineage_impl(
    final_prepared: dict[str, Any], lineage_pins: dict[str, Any], *,
    artifact_reader: Callable[[dict[str, str], int], bytes],
    campaign_module: object, input_preparation_module: object,
    campaign_inputs_module: object, chronology_module: object,
    source5_campaign_module: object, preparatory_budget_module: object,
) -> dict[str, Any]:
    """Perform the complete structural validation shared by both result APIs.

    ``artifact_reader`` accepts one exact raw pin and byte bound and returns
    bytes from a caller-closed captured store. Campaign, preparation, input,
    chronology, SourceH campaign, and preparatory-budget algorithms must be
    Source-owned modules whose inventory pins the caller has already
    validated. Journal and ledger replay stays structural; this function does
    not call GPG, an APP, or a gate.
    """
    require(type(final_prepared) is dict,
            "final prepared Source context is not an object")
    campaign_id = _token(final_prepared.get("campaign_id"), "final campaign ID")
    host_id = _token(final_prepared.get("host_id"), "final selected host ID")
    final_output_root = _absolute_path(final_prepared.get("output_root"),
                                       "final output root")
    pins = exact(lineage_pins, {"bridge_header", "record_index"},
                 "prepared exploration lineage pins")
    header_pin = _pin(pins["bridge_header"], "prepared exploration header raw pin")
    index_pin = _pin(pins["record_index"], "prepared exploration index raw pin")
    require(callable(artifact_reader),
            "prepared exploration lineage has no closed byte reader")
    header_raw = _reader_bytes(artifact_reader, header_pin, 256 * 1024,
                               "prepared exploration header")
    header_value = _parse_canonical_object(header_raw, "prepared exploration header", 256 * 1024)
    initial_output_root = _absolute_path(header_value.get("initial_output_root"),
                                         "initial output root")
    require(initial_output_root != final_output_root,
            "initial and final Source generations must use distinct output roots")
    header = _validate_header(header_value, campaign_id, host_id, initial_output_root)
    header_path = _path_join(
        initial_output_root, campaign_id, "source5", host_id, LINEAGE_DIRECTORY,
        HEADER_NAME, label="expected bridge header path",
    )
    index_path = _path_join(
        initial_output_root, campaign_id, "source5", host_id, LINEAGE_DIRECTORY,
        INDEX_NAME, label="expected record index path",
    )
    require(header_pin["path"] == header_path and
            header["record_index"]["pin"]["path"] == index_pin["path"] == index_path and
            header["record_index"]["pin"]["raw_sha256"] == index_pin["raw_sha256"],
            "prepared exploration lineage pins differ from the initial header/index")
    initial = header["initial"]
    initial_spec_pin = _pin(initial["spec_pin"], "initial Spec pin", semantic=True)
    initial_plan_pin = _pin(initial["plan_pin"], "initial Plan pin", semantic=True)
    initial_spec_raw = _reader_bytes(artifact_reader, initial_spec_pin, MAX_SPEC_BYTES,
                                     "initial Spec")
    initial_plan_raw = _reader_bytes(artifact_reader, initial_plan_pin, MAX_PLAN_BYTES,
                                     "initial Plan")
    initial_spec = _parse_canonical_object(initial_spec_raw, "initial Spec", MAX_SPEC_BYTES)
    initial_plan = _parse_canonical_object(initial_plan_raw, "initial Plan", MAX_PLAN_BYTES)
    digest_object = getattr(campaign_module, "digest_object", None)
    initial_plan_semantic = sha256_bytes(canonical_bytes({
        key: value for key, value in initial_plan.items() if key != "plan_sha256"
    }))
    require(callable(digest_object) and
            digest_object(initial_spec) == initial_spec_pin["semantic_sha256"] and
            initial_plan.get("plan_sha256") == initial_plan_pin["semantic_sha256"] ==
                initial_plan_semantic,
            "initial Spec/Plan bytes differ from their Source semantic pins")
    final_original = final_prepared.get("original_pins")
    require(type(final_original) is dict,
            "final Source context omits its independently checked original pins")
    final_spec_pin = _pin(final_original.get("spec"), "final Spec pin", semantic=True)
    final_plan_pin = _pin(final_original.get("plan"), "final Plan pin", semantic=True)
    final_spec_raw = _reader_bytes(artifact_reader, final_spec_pin, MAX_SPEC_BYTES,
                                   "final Spec")
    final_plan_raw = _reader_bytes(artifact_reader, final_plan_pin, MAX_PLAN_BYTES,
                                   "final Plan")
    final_spec = _parse_canonical_object(final_spec_raw, "final Spec", MAX_SPEC_BYTES)
    final_plan = _parse_canonical_object(final_plan_raw, "final Plan", MAX_PLAN_BYTES)
    final_plan_semantic = sha256_bytes(canonical_bytes({
        key: value for key, value in final_plan.items() if key != "plan_sha256"
    }))
    require(digest_object(final_spec) == final_spec_pin["semantic_sha256"] and
            final_plan.get("plan_sha256") == final_plan_pin["semantic_sha256"] ==
                final_plan_semantic,
            "final Spec/Plan bytes differ from their Source semantic pins")
    _validate_initial_to_final_fill(
        initial_spec, final_spec, initial_plan, final_plan,
        campaign_module, campaign_inputs_module, host_id,
    )
    require(final_original.get("source_manifests") == initial["source_manifest_pins"],
            "final Source context changed one of the original Source manifest pins")
    observed = final_original.get("observed_host")
    require(type(observed) is dict and
            observed.get("path") == initial["observed_host_pin"]["path"] and
            observed.get("raw_sha256") == initial["observed_host_pin"]["raw_sha256"] and
            observed.get("boot_id_sha256") == initial["observed_host_pin"]["boot_id_sha256"] and
            observed.get("controls_sha256") == initial["observed_host_pin"]["controls_sha256"],
            "final Source context changed the original observed host facts")
    expected_jobs = [job for job in initial_plan["jobs"]["exploration"]
                     if type(job) is dict and job.get("host_id") == host_id]
    projected = project_prepared_exploration_lineage_outputs(
        campaign_id, host_id, initial_output_root, expected_jobs,
    )
    index_raw = _reader_bytes(
        artifact_reader, index_pin, projected["index"]["max_bytes"],
        "prepared exploration record index",
    )
    checked_header, rows = validate_prepared_exploration_lineage_documents(
        header_raw, index_raw, expected_jobs,
    )
    require(checked_header == header,
            "prepared exploration header changed between structural reads")
    initial_context = _source5_prepared_lineage_initial_context(
        header, initial_spec, initial_plan, final_prepared, expected_jobs,
        artifact_reader=artifact_reader, chronology_module=chronology_module,
        source5_campaign_module=source5_campaign_module,
        preparatory_budget_module=preparatory_budget_module,
    )
    journal = header["journal"]
    journal_raw = _reader_bytes(
        artifact_reader, journal["pin"],
        initial_context["event_projection"]["maximum_journal_bytes"],
        "initial chronology journal",
    )
    phase_ledger_pin = header["phase_ledger"]["pin"]
    phase_ledger_maximum = initial_context["phase_ledger_maximum_bytes"]
    phase_ledger_raw = _reader_bytes(
        artifact_reader, phase_ledger_pin, phase_ledger_maximum,
        "initial exploration phase ledger",
    )
    initial_replay = _replay_initial_preparatory_journal_and_ledger(
        header, expected_jobs, rows, initial_context, artifact_reader=artifact_reader,
        chronology_module=chronology_module, campaign_module=campaign_module,
        journal_raw=journal_raw, phase_ledger_raw=phase_ledger_raw,
    )
    pilot_pin = _pin(header["pilot"]["pin"], "original pilot pin", semantic=True)
    pilot_maximum = getattr(input_preparation_module, "capacity_pilot_maximum_bytes", None)
    require(callable(pilot_maximum),
            "caller did not supply the Source-owned pilot size algorithm")
    allocators = getattr(campaign_module, "ALLOCATORS", None)
    preregistration = getattr(campaign_module, "preregistration_digest", None)
    digest_object = getattr(campaign_module, "digest_object", None)
    require(type(allocators) in (list, tuple) and callable(preregistration) and
            callable(digest_object),
            "caller did not supply Source-owned campaign pilot primitives")
    pilot_max_bytes = pilot_maximum(
        initial_spec, host_id, allocators, preregistration(initial_spec),
    )
    require(type(pilot_max_bytes) is int and 0 < pilot_max_bytes <= MAX_PLAN_BYTES,
            "original capacity-pilot size is outside its Source-derived bound")
    pilot_raw = _reader_bytes(artifact_reader, pilot_pin, pilot_max_bytes,
                              "original capacity pilot")
    pilot = _parse_canonical_object(pilot_raw, "original capacity pilot", pilot_max_bytes)
    require(digest_object(pilot) == pilot_pin["semantic_sha256"] and
            pilot.get("host_id") == host_id and
            pilot.get("spec_sha256") == preregistration(initial_spec),
            "original capacity pilot differs from its initial Spec/host semantic pin")
    pair_map = _pilot_pair_map(pilot, campaign_module)
    require(sha256_bytes(index_raw) == index_pin["raw_sha256"] and
            sha256_bytes(header_raw) == header_pin["raw_sha256"],
            "prepared exploration lineage bytes changed their exact pins")
    initial_records = initial_replay["records"]
    require(type(initial_records) is list and len(initial_records) == len(rows),
            "SourceA journal/ledger replay did not close over every indexed old record")
    for index, row in enumerate(rows):
        job = row["job"]
        key = (job["family"], job["profile"], job["allocator"], job["ordinal"])
        require(pair_map.get(key) == row["pilot_pair_raw_sha256"],
                f"prepared exploration row[{index}] changed its original pilot pair")
        record = initial_records[index]
        record_pin = row["job_record_pin"]
        _validate_record_against_row(canonical_bytes(record), row, campaign_id, host_id)
        _validate_indexed_archive_bytes(artifact_reader, row, pilot_max_bytes, index)
    ancestor = {
        "bridge_header_pin": {"path": header_pin["path"],
                              "raw_sha256": header_pin["raw_sha256"]},
        "record_index_pin": {"path": index_pin["path"],
                             "raw_sha256": index_pin["raw_sha256"]},
        "header_byte_count": len(header_raw),
        "index_byte_count": len(index_raw),
        "job_list_sha256": sha256_bytes(canonical_bytes(expected_jobs)),
        "journal": {
            "pin": initial_replay["initial_journal_pin"],
            "byte_count": initial_replay["initial_journal_byte_count"],
            "record_count": initial_replay["initial_journal_record_count"],
            "head": initial_replay["initial_journal_head"],
        },
        "phase_ledger": {
            "pin": initial_replay["initial_phase_ledger_pin"],
            "byte_count": initial_replay["initial_phase_ledger_byte_count"],
            "row_count": initial_replay["initial_phase_ledger_row_count"],
        },
    }
    return {
        "schema": LINEAGE_PROOF_SCHEMA_V2,
        "campaign_id": campaign_id, "host_id": host_id,
        "initial_output_root": initial_output_root,
        "final_output_root": final_output_root,
        "bridge_header": header,
        "index_rows": rows,
        "capture_context": {
            "execution_manifest": initial_context["execution_manifest"],
            "width_contract": initial_context["width_contract"],
            "budget": initial_context["budget"],
            "preparatory_original_pins": initial_context[
                "preparatory_original_pins"],
        },
        "records": initial_records,
        "journal_authorizations": initial_replay["journal_authorizations"],
        "journal_finished": initial_replay["journal_finished"],
        "bridge_header_pin": {"path": header_pin["path"],
                               "raw_sha256": header_pin["raw_sha256"]},
        "record_index_pin": {"path": index_pin["path"],
                             "raw_sha256": index_pin["raw_sha256"]},
        "job_count": HOST_JOB_COUNT, "callback_count": HOST_CALLBACK_COUNT,
        "allowed_slot_fill_proved": True,
        "initial_journal_pin": initial_replay["initial_journal_pin"],
        "initial_journal_structurally_replayed": True,
        "initial_phase_ledger_structurally_replayed": True,
        "initial_journal_head": initial_replay["initial_journal_head"],
        "initial_journal_record_count": initial_replay["initial_journal_record_count"],
        "initial_phase_ledger_pin": initial_replay["initial_phase_ledger_pin"],
        "initial_phase_ledger_byte_count":
            initial_replay["initial_phase_ledger_byte_count"],
        "initial_phase_ledger_row_count": initial_replay["initial_phase_ledger_row_count"],
        "ancestor": ancestor,
        "component_replay_required": True,
        "fresh_sourcea_gpg_replay_required": True,
        "qualification_eligible": False,
    }


def verify_source5_prepared_exploration_lineage(
    final_prepared: dict[str, Any], lineage_pins: dict[str, Any], *,
    artifact_reader: Callable[[dict[str, str], int], bytes],
    campaign_module: object, input_preparation_module: object,
    campaign_inputs_module: object, chronology_module: object,
    source5_campaign_module: object, preparatory_budget_module: object,
) -> dict[str, Any]:
    """Return the legacy lean v1 structural proof without authority claims."""
    checked = _verify_source5_prepared_exploration_lineage_impl(
        final_prepared, lineage_pins, artifact_reader=artifact_reader,
        campaign_module=campaign_module,
        input_preparation_module=input_preparation_module,
        campaign_inputs_module=campaign_inputs_module,
        chronology_module=chronology_module,
        source5_campaign_module=source5_campaign_module,
        preparatory_budget_module=preparatory_budget_module,
    )
    lean_fields = (
        "campaign_id", "host_id", "initial_output_root", "final_output_root",
        "bridge_header_pin", "record_index_pin", "job_count", "callback_count",
        "allowed_slot_fill_proved", "initial_journal_pin",
        "initial_journal_structurally_replayed",
        "initial_phase_ledger_structurally_replayed", "initial_journal_head",
        "initial_journal_record_count", "initial_phase_ledger_pin",
        "initial_phase_ledger_byte_count", "initial_phase_ledger_row_count",
        "component_replay_required", "fresh_sourcea_gpg_replay_required",
        "qualification_eligible",
    )
    return {"schema": LINEAGE_PROOF_SCHEMA_V1,
            **{name: checked[name] for name in lean_fields}}


def verify_source5_prepared_exploration_lineage_v2(
    final_prepared: dict[str, Any], lineage_pins: dict[str, Any], *,
    artifact_reader: Callable[[dict[str, str], int], bytes],
    campaign_module: object, input_preparation_module: object,
    campaign_inputs_module: object, chronology_module: object,
    source5_campaign_module: object, preparatory_budget_module: object,
) -> dict[str, Any]:
    """Return SourceA's enriched structural proof; never authority or readiness."""
    checked = _verify_source5_prepared_exploration_lineage_impl(
        final_prepared, lineage_pins, artifact_reader=artifact_reader,
        campaign_module=campaign_module,
        input_preparation_module=input_preparation_module,
        campaign_inputs_module=campaign_inputs_module,
        chronology_module=chronology_module,
        source5_campaign_module=source5_campaign_module,
        preparatory_budget_module=preparatory_budget_module,
    )
    return _json_snapshot(checked, "SourceA rich prepared-exploration proof")


def _validate_indexed_archive_bytes(
    artifact_reader: Callable[[dict[str, str], int], bytes], row: dict[str, Any],
    _pilot_maximum: int, index: int,
) -> None:
    """Check raw archive object pins and relationships without claiming GPG."""
    archive = row["archive_pins"]
    limits = {
        "request_pin": MAX_CHECKPOINT_BYTES,
        "checkpoint_pin": MAX_CHECKPOINT_BYTES,
        "object_manifest_pin": MAX_METADATA_BYTES,
        "ack_pin": MAX_METADATA_BYTES,
    }
    values = {}
    for name, maximum in limits.items():
        pin = _pin(archive[name], f"indexed {name}[{index}]", semantic=True)
        raw = _reader_bytes(artifact_reader, pin, maximum, f"indexed {name}[{index}]")
        values[name] = _parse_canonical_object(
            raw, f"indexed {name}[{index}]", maximum,
        )
    signature = archive["signature_pin"]
    signature_raw = _reader_bytes(
        artifact_reader, {"path": signature["path"],
                          "raw_sha256": signature["raw_sha256"]},
        MAX_SIGNATURE_BYTES, f"indexed signature[{index}]",
    )
    require(bool(signature_raw), f"indexed signature[{index}] is empty")
    request = values["request_pin"]
    checkpoint = values["checkpoint_pin"]
    object_manifest = values["object_manifest_pin"]
    ack = values["ack_pin"]
    ack_unsigned = {key: value for key, value in ack.items() if key != "ack_sha256"}
    require(ack.get("ack_sha256") == archive["ack_pin"]["semantic_sha256"] and
            sha256_bytes(canonical_bytes(ack_unsigned)) == ack.get("ack_sha256") and
            ack.get("checkpoint_pin") == {
                key: archive["checkpoint_pin"][key]
                for key in ("path", "raw_sha256", "semantic_sha256")
            } and
            ack.get("object_manifest_pin") == {
                key: archive["object_manifest_pin"][key]
                for key in ("path", "raw_sha256", "semantic_sha256")
            } and
            checkpoint.get("request_pin") == {
                key: archive["request_pin"][key]
                for key in ("path", "raw_sha256", "semantic_sha256")
            } and
            ack.get("signer_fingerprint") == signature["signer_fingerprint"] and
            type(object_manifest.get("objects")) is list,
            f"indexed original signed archive metadata[{index}] has inconsistent pins")


__all__ = [
    "HEADER_NAME", "HEADER_SCHEMA", "HOST_CALLBACK_COUNT", "HOST_JOB_COUNT",
    "HOST_JOURNAL_RECORD_COUNT", "INDEX_NAME", "INDEX_ROW_SCHEMA",
    "LINEAGE_DIRECTORY", "LINEAGE_OWNER", "LINEAGE_ROLE", "SOURCE_PATH",
    "PreparedExplorationLineageError", "build_prepared_exploration_bridge_header",
    "build_prepared_exploration_lineage_index_row", "canonical_bytes",
    "project_prepared_exploration_lineage_outputs",
    "validate_prepared_exploration_lineage_documents",
    "verify_source5_prepared_exploration_lineage",
    "verify_source5_prepared_exploration_lineage_v2",
    "SOURCE5_PREPARED_EXPLORATION_LINEAGE_PIN_FIELDS",
    "SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2",
    "SOURCE5_PREPARED_INPUTS_PROVENANCE_V2_FIELDS",
    "validate_prepared_input_provenance_v2",
]
