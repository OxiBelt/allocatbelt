#!/usr/bin/env python3
"""Inspect source-pinned Source5 owner schemas without importing them.

The result is a finite owner-contract profile for planning only. It derives
file slots and role ceilings from the exact SourceV5-pinned source bytes; it
does not bless a host budget or claim that dynamic Soak/TMP trees are closed.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import Any


SCHEMA = "allocatbelt.application-source5-owner-evidence-catalogue.v1"
SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v5"
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
OWNER_PATHS = {
    "fixed_pair": "scripts/application-fixed-pair.py",
    "pressure_pair": "scripts/application-pressure-pair.py",
    "source5_controller": "scripts/application-source5-campaign.py",
    "source5_soak": "scripts/application-source5-soak.py",
    "soak_reader": "scripts/application-soak-readback.py",
    "offline_dispatcher": "scripts/application-source5-offline-dispatch.py",
    "chronology": "scripts/application-campaign-chronology.py",
    "evidence_transport": "scripts/application-source5-evidence-transport-v3.py",
}


class CatalogueError(ValueError):
    """A source-pinned owner schema is missing or malformed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogueError(message)


def _canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise CatalogueError(f"{type(value).__name__} is not canonical JSON: {error}") from error


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= (1 << 64) - 1,
             f"{label} is not a u64")
    _require(not positive or value > 0, f"{label} must be positive")
    return value


def _source_rows(source: object) -> dict[str, dict[str, Any]]:
    _require(type(source) is dict and source.get("schema") == SOURCE_SCHEMA,
             "owner catalogue requires the exact SourceV5 manifest")
    manifest_body = {key: value for key, value in source.items()
                     if key != "manifest_sha256"}
    _require(type(source.get("manifest_sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", source["manifest_sha256"]) and
             _sha(_canonical(manifest_body)) == source["manifest_sha256"],
             "SourceV5 owner catalogue manifest semantic digest differs")
    rows = source.get("source", {}).get("files") if type(source.get("source")) is dict else None
    _require(type(rows) is list and rows,
             "SourceV5 owner catalogue has no typed source rows")
    result: dict[str, dict[str, Any]] = {}
    previous = ""
    for index, row in enumerate(rows):
        _require(type(row) is dict and type(row.get("path")) is str and
                 row["path"] > previous and row["path"] not in result,
                 f"SourceV5 owner row[{index}] is malformed or unordered")
        previous = row["path"]
        result[row["path"]] = row
    return result


def _integer_expression(
    node: ast.AST, label: str, definitions: dict[str, ast.expr],
    resolved: dict[str, int], active: set[str],
) -> int:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name):
        if node.id in resolved:
            return resolved[node.id]
        _require(node.id in definitions and node.id not in active,
                 f"{label} references an unpinned or recursive integer constant {node.id}")
        active.add(node.id)
        value = _integer_expression(
            definitions[node.id], f"{label}.{node.id}", definitions, resolved, active,
        )
        active.remove(node.id)
        resolved[node.id] = value
        return value
    if isinstance(node, ast.BinOp) and type(node.op) in {
        ast.Add, ast.Sub, ast.Mult, ast.FloorDiv,
    }:
        left = _integer_expression(node.left, label, definitions, resolved, active)
        right = _integer_expression(node.right, label, definitions, resolved, active)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        _require(right != 0 and left % right == 0,
                 f"{label} uses a nonintegral source expression")
        return left // right
    raise CatalogueError(f"{label} is not a closed integer source expression")


def _top_level_constant_pool(tree: ast.Module, label: str) -> dict[str, int]:
    definitions: dict[str, ast.expr] = {}
    for node in tree.body:
        targets: list[ast.expr] = []
        expression: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = node.targets
            expression = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            expression = node.value
        for target in targets:
            if (isinstance(target, ast.Name) and
                    target.id.startswith(("MAX_", "PROBE_"))):
                _require(expression is not None and target.id not in definitions,
                         f"{label} repeats or omits source constant {target.id}")
                definitions[target.id] = expression
    resolved: dict[str, int] = {}
    for name in definitions:
        try:
            resolved[name] = _integer_expression(
                definitions[name], f"{label}.{name}", definitions,
                resolved, {name},
            )
        except CatalogueError:
            continue
    return resolved


def _top_level_constants(tree: ast.Module, names: set[str], label: str) -> dict[str, int]:
    values = _top_level_constant_pool(tree, label)
    _require(names <= set(values),
             f"{label} source constants omit a requested limit")
    return {name: values[name] for name in sorted(names)}


def _top_level_role_limits(
    tree: ast.Module, variable: str, constants: dict[str, int], label: str,
) -> dict[str, int]:
    matches: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == variable
                for target in node.targets):
            matches.append(node.value)
    _require(len(matches) == 1 and isinstance(matches[0], ast.Dict) and
             not any(key is None for key in matches[0].keys),
             f"{label} has no unique literal {variable} role table")
    result: dict[str, int] = {}
    for key, value in zip(matches[0].keys, matches[0].values, strict=True):
        _require(isinstance(key, ast.Constant) and type(key.value) is str and
                 key.value not in result,
                 f"{label}.{variable} has a duplicate or nonliteral role")
        if isinstance(value, ast.Name):
            _require(value.id in constants,
                     f"{label}.{variable}.{key.value} uses an unbounded role ceiling")
            maximum = constants[value.id]
        else:
            maximum = _integer_expression(value, f"{label}.{variable}.{key.value}",
                                          {}, {}, set())
        result[key.value] = _uint(maximum,
                                  f"{label}.{variable}.{key.value}", positive=True)
    _require(result, f"{label}.{variable} is empty")
    return result


def _function(tree: ast.Module, name: str, label: str) -> ast.FunctionDef:
    matches = [node for node in tree.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
               node.name == name]
    _require(len(matches) == 1 and isinstance(matches[0], ast.FunctionDef),
             f"{label} has no unique synchronous {name} owner function")
    return matches[0]


def _top_level_numeric_constants(
    tree: ast.Module, names: set[str], label: str,
) -> dict[str, int | float]:
    result: dict[str, int | float] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        selected = [target.id for target in targets
                    if isinstance(target, ast.Name) and target.id in names]
        if not selected:
            continue
        _require(len(selected) == 1 and selected[0] not in result and
                 isinstance(value, ast.Constant) and
                 type(value.value) in {int, float},
                 f"{label} has a missing, duplicate, or nonliteral numeric source constant")
        result[selected[0]] = value.value
    _require(set(result) == names,
             f"{label} source constants omit an exact requested name")
    return result


def _function_call_numeric_argument(
    tree: ast.Module, function_name: str, module_name: str,
    function_attr: str, argument_index: int, label: str,
) -> int | float:
    function = _function(tree, function_name, label)
    matches = []
    for node in ast.walk(function):
        if (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Attribute) and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == module_name and
                node.func.attr == function_attr and
                len(node.args) > argument_index):
            matches.append(node.args[argument_index])
    _require(bool(matches) and all(
        isinstance(argument, ast.Constant) and
        type(argument.value) in {int, float}
        for argument in matches
    ), f"{label}.{function_name} has no closed literal {module_name}.{function_attr} interval")
    values = {argument.value for argument in matches}
    _require(len(values) == 1,
             f"{label}.{function_name} uses inconsistent {module_name}.{function_attr} intervals")
    return values.pop()


def _literal_dict_keys(node: ast.AST, label: str) -> list[str]:
    _require(isinstance(node, ast.Dict) and not any(key is None for key in node.keys),
             f"{label} is not a closed literal dictionary")
    keys: list[str] = []
    for key in node.keys:
        _require(isinstance(key, ast.Constant) and type(key.value) is str,
                 f"{label} has a nonliteral key")
        keys.append(key.value)
    _require(len(keys) == len(set(keys)), f"{label} repeats an owner slot")
    return sorted(keys)


def _literal_string_set(
    node: ast.AST, label: str, *,
    sequence_definitions: dict[str, ast.AST] | None = None,
) -> list[str]:
    def resolve(value: ast.AST, active: set[str]) -> list[str]:
        if isinstance(value, (ast.Set, ast.Tuple, ast.List)):
            result: list[str] = []
            for item in value.elts:
                _require(isinstance(item, ast.Constant) and
                         type(item.value) is str,
                         f"{label} has a nonliteral slot name")
                result.append(item.value)
            _require(len(result) == len(set(result)),
                     f"{label} repeats an owner slot")
            return result
        if isinstance(value, ast.Name):
            definitions = sequence_definitions or {}
            _require(value.id in definitions and value.id not in active,
                     f"{label} references an unpinned or recursive string sequence")
            return resolve(definitions[value.id], active | {value.id})
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and
                value.func.id == "set" and len(value.args) == 1 and
                not value.keywords and isinstance(value.args[0], ast.Name)):
            return sorted(set(resolve(value.args[0], active)))
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
            left = resolve(value.left, active)
            right = resolve(value.right, active)
            return sorted(set(left) | set(right))
        raise CatalogueError(f"{label} is not a closed literal string-set expression")

    values = resolve(node, set())
    _require(bool(values), f"{label} is empty")
    return values


def _top_level_string_sequences(
    tree: ast.Module, label: str,
) -> dict[str, ast.AST]:
    definitions: dict[str, ast.AST] = {}
    ambiguous: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if not isinstance(value, (ast.Set, ast.Tuple, ast.List)):
            continue
        if not all(isinstance(item, ast.Constant) and type(item.value) is str
                   for item in value.elts):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                if target.id in definitions:
                    ambiguous.add(target.id)
                    definitions.pop(target.id, None)
                    continue
                if target.id in ambiguous:
                    continue
                definitions[target.id] = value
    # Ambiguous names are omitted; a set expression may use only one closed
    # top-level literal sequence and will reject a reference to the omission.
    return definitions


def _assigned_literal(tree: ast.Module, function_name: str, target: str,
                      label: str, *, dictionary: bool) -> list[str]:
    function = _function(tree, function_name, label)
    matches: list[ast.AST] = []
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(item, ast.Name) and item.id == target for item in targets):
                matches.append(node.value)
    _require(len(matches) == 1,
             f"{label}.{function_name} has no unique {target} declaration")
    return (_literal_dict_keys(matches[0], f"{label}.{function_name}.{target}")
            if dictionary else
            _literal_string_set(
                matches[0], f"{label}.{function_name}.{target}",
                sequence_definitions=_top_level_string_sequences(tree, label),
            ))


def _exact_call_set(tree: ast.Module, function_name: str, label: str) -> list[str]:
    function = _function(tree, function_name, label)
    matches: list[ast.AST] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exact" and len(node.args) >= 2:
            if isinstance(node.args[0], ast.Subscript):
                value = node.args[0].value
                key = node.args[0].slice
                if (isinstance(value, ast.Name) and value.id == "member" and
                        isinstance(key, ast.Constant) and key.value == "outputs"):
                    matches.append(node.args[1])
    _require(len(matches) == 1,
             f"{label}.{function_name} does not expose one exact member outputs schema")
    return _literal_string_set(matches[0], f"{label}.{function_name}.member.outputs")


def _fixed_pair_root_slots(tree: ast.Module) -> list[str]:
    function = _function(tree, "_allowed_output_paths", "fixed-pair owner")
    matches: list[ast.AST] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "allowed"
                for target in node.targets):
            matches.append(node.value)
    _require(len(matches) == 1 and isinstance(matches[0], ast.Set),
             "fixed-pair owner has no unique literal output allowlist")
    slots: list[str] = []
    dynamic_runtime_names = 0
    expected_dynamic = ast.parse(
        'Path(overlay["runtime_bindings"]["pin"]["path"]).name',
        mode="eval",
    ).body
    for item in matches[0].elts:
        if isinstance(item, ast.Constant) and type(item.value) is str:
            slots.append(item.value)
            continue
        if (isinstance(item, ast.Attribute) and item.attr == "name" and
                isinstance(item.value, ast.Call) and
                isinstance(item.value.func, ast.Name) and
                item.value.func.id == "Path" and
                ast.dump(item, include_attributes=False) ==
                    ast.dump(expected_dynamic, include_attributes=False)):
            dynamic_runtime_names += 1
            slots.append("$runtime_bindings.pin.basename")
            continue
        raise CatalogueError("fixed-pair owner allowlist has an unknown dynamic output slot")
    _require(len(slots) == 6 and dynamic_runtime_names == 1 and
             len(slots) == len(set(slots)),
             "fixed-pair owner root-output allowlist differs from its six-slot schema")
    return sorted(slots)


def _source_code_inputs(source: object, source_bytes_value: object) -> dict[str, bytes]:
    rows = _source_rows(source)
    _require(type(source_bytes_value) is dict and
             set(source_bytes_value) == set(OWNER_PATHS.values()),
             "owner source bytes do not cover the exact declared owner modules")
    result: dict[str, bytes] = {}
    for role, path in OWNER_PATHS.items():
        record = rows.get(path)
        raw = source_bytes_value[path]
        _require(type(record) is dict and record.get("kind") == "file" and
                 record.get("mode") in {"100644", "100755"} and
                 type(raw) is bytes and 0 < len(raw) <= MAX_SCRIPT_BYTES and
                 len(raw) == record.get("size") and _sha(raw) == record.get("sha256"),
                 f"{role} source bytes differ from their exact SourceV5 typed pin")
        result[role] = raw
    return result


def inspect_owner_evidence_contracts(
    source_value: object, owner_source_bytes_value: object,
) -> dict[str, Any]:
    """Build a source-pinned owner path/limit profile from syntax only.

    Dynamic Soak stream filenames and each actual job's produced descendants
    remain explicit blockers; this profile is a schema input, not a readiness
    assertion.
    """
    source = source_value
    raw_by_role = _source_code_inputs(source, owner_source_bytes_value)
    trees = {
        role: ast.parse(raw, filename=OWNER_PATHS[role], mode="exec")
        for role, raw in raw_by_role.items()
    }

    fixed_tree = trees["fixed_pair"]
    fixed_member_slots = _assigned_literal(
        fixed_tree, "_construct_members", "outputs",
        "fixed-pair owner", dictionary=True,
    )
    fixed_pair_slots = _fixed_pair_root_slots(fixed_tree)
    fixed_limits = _top_level_constants(fixed_tree, {
        "MAX_PAIR_OUTPUT_BYTES", "MAX_OUTPUT_FILES", "MAX_OUTPUT_DIRECTORIES",
        "MAX_PROC_ENTRIES",
        "MAX_TMPDIR_BYTES", "MAX_TMPDIR_INODES", "MAX_RECEIPT_BYTES",
        "MAX_STDOUT_BYTES", "MAX_STDERR_BYTES", "MAX_TIME_BYTES",
        "MAX_ID_BYTES", "MAX_RUNTIME_BYTES", "MAX_PROBE_STDOUT_BYTES",
        "MAX_PROBE_STDERR_BYTES", "MAX_ORACLE_BYTES",
    }, "fixed-pair owner")
    _require({"root", "tmpdir", "probe_tmpdir"} <= set(fixed_member_slots) and
             len(set(fixed_member_slots) - {"root", "tmpdir", "probe_tmpdir"}) == 13 and
             len(fixed_pair_slots) == 6,
             "fixed-pair owner path slot schema differs from its captured closed layout")

    pressure_tree = trees["pressure_pair"]
    pressure_member_slots = _exact_call_set(
        pressure_tree, "_validate_recipe_shape", "pressure-pair owner",
    )
    pressure_constants = _top_level_constants(pressure_tree, {
        "MAX_SOURCE5_CAPTURE_BYTES", "MAX_SOURCE5_CAPTURE_ENTRIES",
        "MAX_TRACE_BYTES", "MAX_SAMPLE_BYTES", "MAX_TERMINAL_BYTES",
        "MAX_TOTAL_ARTIFACT_BYTES", "PROBE_CAPTURE_MAX_OUTPUT_INODES",
        "MAX_PROBE_CAPTURE_TMPDIR_BYTES", "MAX_PROBE_CAPTURE_TMPDIR_INODES",
        "MAX_PROBE_CAPTURE_STDOUT_BYTES", "MAX_PROBE_CAPTURE_STDERR_BYTES",
        "MAX_PROBE_CAPTURE_RECEIPT_BYTES", "PROBE_CAPTURE_OWNER_RESULT_BYTES",
        "PROBE_CAPTURE_INVENTORY_BYTES", "PROBE_CAPTURE_FAILURE_BYTES",
        "PROBE_CAPTURE_MIN_OUTPUT_INODES",
    }, "pressure-pair owner")
    pressure_role_limits = _top_level_role_limits(
        pressure_tree, "SOURCE5_ROLE_LIMITS",
        _top_level_constant_pool(pressure_tree, "pressure-pair owner"),
        "pressure-pair owner",
    )
    _require({"root", "trace_directory", "finalization_request",
              "finalization_receipt"} <= set(pressure_member_slots),
             "pressure-pair member output schema differs from its exact captured layout")

    controller_tree = trees["source5_controller"]
    controller_cleanup_limits = _top_level_constants(controller_tree, {
        "MAX_SOURCE5_CLEANUP_SIGNAL_SNAPSHOTS",
        "MAX_SOURCE5_CLEANUP_ERROR_ENTRIES",
        "MAX_SOURCE5_CLEANUP_ERROR_TEXT_BYTES",
    }, "Source5 controller cleanup contract")
    fixed_cleanup_times = _top_level_numeric_constants(fixed_tree, {
        "TERM_GRACE_SECONDS", "KILL_REAP_SECONDS",
    }, "fixed-pair cleanup schedule")
    cleanup_poll_interval = _function_call_numeric_argument(
        fixed_tree, "_wait_for_process_group", "time", "sleep", 0,
        "fixed-pair cleanup schedule",
    )
    normal_cleanup_polls = int((fixed_cleanup_times["TERM_GRACE_SECONDS"] +
                                fixed_cleanup_times["KILL_REAP_SECONDS"]) /
                               cleanup_poll_interval) + 4
    emergency_cleanup_polls = int(fixed_cleanup_times["KILL_REAP_SECONDS"] /
                                  cleanup_poll_interval) + 4
    cleanup_source_shape = {
        "maximum_session_members_per_snapshot": fixed_limits["MAX_PROC_ENTRIES"],
        "maximum_pidfd_signal_entries_per_snapshot": fixed_limits["MAX_PROC_ENTRIES"],
        "maximum_signal_snapshots": controller_cleanup_limits[
            "MAX_SOURCE5_CLEANUP_SIGNAL_SNAPSHOTS"],
        "maximum_cleanup_errors": controller_cleanup_limits[
            "MAX_SOURCE5_CLEANUP_ERROR_ENTRIES"],
        "maximum_error_text_bytes": controller_cleanup_limits[
            "MAX_SOURCE5_CLEANUP_ERROR_TEXT_BYTES"],
        "normal_cleanup_poll_count": normal_cleanup_polls,
        "emergency_cleanup_poll_count": emergency_cleanup_polls,
        "term_grace_seconds": fixed_cleanup_times["TERM_GRACE_SECONDS"],
        "kill_reap_seconds": fixed_cleanup_times["KILL_REAP_SECONDS"],
        "cleanup_poll_interval_seconds": cleanup_poll_interval,
    }
    _require(cleanup_source_shape["maximum_cleanup_errors"] ==
             3 * normal_cleanup_polls + emergency_cleanup_polls + 32,
             "Source5 cleanup error count differs from the fixed-owner poll construction")
    pressure_path_slots = _assigned_literal(
        controller_tree, "_pressure_member_outputs", "names",
        "Source5 controller", dictionary=True,
    )
    _require(set(pressure_path_slots) == set(pressure_member_slots),
             "Source5 pressure output-path builder and strict owner schema disagree")

    soak_tree = trees["source5_soak"]
    soak_reader_tree = trees["soak_reader"]
    soak_expected_direct = _assigned_literal(
        soak_tree, "_declared_soak_output_inventory", "expected_direct",
        "Source5 Soak adapter", dictionary=False,
    )
    soak_reader_limits = _top_level_constants(soak_reader_tree, {
        "MAX_TERMINAL_BYTES", "MAX_SAMPLE_BYTES",
    }, "Soak readback owner")
    _require("stdout.log" in soak_expected_direct and
             "stderr.log" in soak_expected_direct and
             "soak-receipt.json" in soak_expected_direct,
             "Source5 Soak output allowlist omits an actual direct owner artifact")

    dispatcher_tree = trees["offline_dispatcher"]
    dispatcher_constants = _top_level_constants(dispatcher_tree, {
        "MAX_INDEX_BYTES", "MAX_CAPTURE_BYTES", "MAX_ENTRIES", "MAX_MAP_ENTRIES",
        "MAX_SOURCE_FILE_COUNT", "MAX_SOURCE_TOTAL_BYTES",
    }, "Source5 offline dispatcher")
    dispatcher_role_limits = _top_level_role_limits(
        dispatcher_tree, "ROLE_LIMITS",
        _top_level_constant_pool(dispatcher_tree, "Source5 offline dispatcher"),
        "Source5 offline dispatcher",
    )
    chronology_tree = trees["chronology"]
    chronology_constants = _top_level_constants(chronology_tree, {
        "MAX_SOURCE5_JOURNAL_EVENTS", "MAX_SOURCE5_JOURNAL_BYTES",
        "MAX_SOURCE5_JOURNAL_EVIDENCE_ENTRIES", "MAX_SOURCE5_JOURNAL_INDEX_BYTES",
        "MAX_COMPLETION_BYTES", "MAX_EVENT_BYTES", "MAX_PLAN_BYTES",
    }, "Source5 chronology")
    chronology_role_limits = _top_level_role_limits(
        chronology_tree, "SOURCE5_JOURNAL_ROLE_LIMITS",
        _top_level_constant_pool(chronology_tree, "Source5 chronology"),
        "Source5 chronology",
    )

    owner_rows = {
        role: {"path": OWNER_PATHS[role], "raw_sha256": _sha(raw_by_role[role]),
               "byte_count": len(raw_by_role[role])}
        for role in OWNER_PATHS
    }
    body = {
        "schema": SCHEMA,
        "source_manifest_sha256": source["manifest_sha256"],
        "owner_source_pins": owner_rows,
        "cleanup_source_shape": cleanup_source_shape,
        "fixed_pair": {
            "member_output_slots": fixed_member_slots,
            "pair_output_slots": fixed_pair_slots,
            "file_slots_per_pair": len(fixed_pair_slots) +
                2 * (len(set(fixed_member_slots) - {"root", "tmpdir", "probe_tmpdir"})),
            "tmpdir_roots_per_pair": 2 *
                len(set(fixed_member_slots) & {"tmpdir", "probe_tmpdir"}),
            "limits": fixed_limits,
        },
        "pressure_pair": {
            "member_output_slots": pressure_member_slots,
            "file_slots_per_member": len(set(pressure_member_slots) -
                {"root", "trace_directory"}),
            "source5_path_builder_slots": pressure_path_slots,
            "limits": pressure_constants,
            "role_byte_limits": pressure_role_limits,
            "dispatcher_role_byte_limits": dispatcher_role_limits,
            "chronology_role_byte_limits": chronology_role_limits,
        },
        "soak": {
            "declared_direct_output_names": soak_expected_direct,
            "reader_limits": soak_reader_limits,
            "dynamic_stream_paths_closed": False,
        },
        "transport_caps": {
            "dispatcher": dispatcher_constants,
            "chronology": chronology_constants,
        },
        "role_ceiling_conflicts": {
            "soak_terminal_owner_bytes": soak_reader_limits["MAX_TERMINAL_BYTES"],
            "dispatcher_soak_role_bytes": dispatcher_role_limits["source5_soak_artifact"],
            "chronology_soak_role_bytes": chronology_role_limits["source5_soak_artifact"],
            "requires_versioned_budget_role": (
                soak_reader_limits["MAX_TERMINAL_BYTES"] >
                dispatcher_role_limits["source5_soak_artifact"] or
                soak_reader_limits["MAX_TERMINAL_BYTES"] >
                chronology_role_limits["source5_soak_artifact"]
            ),
        },
        "exact_full_path_catalogue_complete": False,
        "execution_ready": False,
        "qualification_eligible": False,
    }
    return {**body, "owner_contract_sha256": _sha(_canonical(body))}


def validate_contract_summary(value: object) -> dict[str, Any]:
    """Reject a changed, partial, or caller-asserted owner profile."""
    _require(type(value) is dict and value.get("schema") == SCHEMA and
             value.get("exact_full_path_catalogue_complete") is False and
             value.get("execution_ready") is False and
             value.get("qualification_eligible") is False,
             "Source5 owner-contract profile cannot claim execution readiness")
    claimed = value.get("owner_contract_sha256")
    body = {key: item for key, item in value.items()
            if key != "owner_contract_sha256"}
    _require(type(claimed) is str and re.fullmatch(r"[0-9a-f]{64}", claimed) and
             claimed == _sha(_canonical(body)),
             "Source5 owner-contract profile semantic digest differs")
    return value


def bind_audit_budget_plan(audit_value: object, contract_value: object) -> dict[str, Any]:
    """Bind schedule audit to exact pinned owner limits, still fail-closed."""
    contract = validate_contract_summary(contract_value)
    _require(type(audit_value) is dict and
             audit_value.get("schema") ==
                 "allocatbelt.application-source5-host-evidence-budget-plan.v1" and
             audit_value.get("readiness") == {
                 "budget_complete": False, "execution_ready": False,
                 "component_gate_ready": False, "qualification_eligible": False,
             }, "Source5 schedule audit must remain a non-ready planning artifact")
    audit_body = {key: item for key, item in audit_value.items()
                  if key != "budget_plan_sha256"}
    _require(type(audit_value.get("budget_plan_sha256")) is str and
             audit_value["budget_plan_sha256"] == _sha(_canonical(audit_body)),
             "Source5 schedule audit semantic digest differs")
    source_manifest_sha = audit_value.get("original_pins", {}).get(
        "source_manifests", {}).get(audit_value.get("host_id"), {}).get(
            "semantic_sha256")
    _require(source_manifest_sha == contract["source_manifest_sha256"],
             "Source5 owner contract and schedule audit selected different source manifests")

    pinned = audit_value.get("producer_catalogue", {}).get("owner_schema_pins")
    _require(type(pinned) is dict,
             "Source5 schedule audit omitted its exact owner source pins")
    for role, row in contract["owner_source_pins"].items():
        audit_role = {
            "fixed_pair": "fixed_pair", "pressure_pair": "pressure_pair",
            "source5_controller": "source5_controller", "source5_soak": "source5_soak",
            "soak_reader": "soak_reader", "feedback_composer": "feedback_composer",
            "feedback_reader": "feedback_reader", "pressure_reader": "pressure_reader",
        }.get(role)
        if audit_role is None:
            continue
        expected = pinned.get(audit_role)
        _require(type(expected) is dict and
                 expected.get("path") == row["path"] and
                 expected.get("sha256") == row["raw_sha256"] and
                 expected.get("size") == row["byte_count"],
                 f"Source5 {role} owner contract differs from the budget audit's source pin")

    schedule = audit_value["schedule"]
    fixed_jobs = schedule["fixed_job_count"]
    pressure_jobs = schedule["pressure_job_count"]
    fixed_slots = contract["fixed_pair"]["file_slots_per_pair"]
    pressure_member_slots = contract["pressure_pair"]["file_slots_per_member"]
    # The owner outputs below are exact source-declared slots. This count is
    # intentionally separate from common inputs, dynamic TMP trees, analysis,
    # helper/job records, and ProbeV2 capture descendants.
    owner_slot_count = fixed_jobs * fixed_slots + pressure_jobs * (
        2 * pressure_member_slots + 2 + 2
    )
    blockers = list(audit_value["blockers"])
    blockers.extend([
        "source-pinned owner slots are profiled but the complete per-job path union/common-input deduplication is not yet emitted",
        "pressure material, random ProbeV2 capture IDs, Soak material output names, and retained TMP descendants are not yet bound before the first owner",
        "legacy request/index/origin and component replay do not carry this budget pin or consume chunked store/index records",
        "no caller-pinned whole-host byte/inode reservation exists for either private evidence root",
    ])
    body = {
        "schema": "allocatbelt.application-source5-host-evidence-budget.v1",
        "campaign_id": audit_value["campaign_id"],
        "host_id": audit_value["host_id"],
        "original_pins": audit_value["original_pins"],
        "schedule_audit": {
            "schema": audit_value["schema"],
            "budget_plan_sha256": audit_value["budget_plan_sha256"],
            "job_counts": schedule["job_counts"],
            "phase_job_list_sha256": schedule["phase_job_list_sha256"],
            "maximum_callback_events": schedule["maximum_callback_events"],
            "worst_case_journal_bytes": schedule["worst_case_journal_bytes"],
        },
        "owner_contract": contract,
        "declared_owner_output_slots": {
            "fixed_pair_jobs": fixed_jobs,
            "pressure_pair_jobs": pressure_jobs,
            "fixed_pair_files_per_job": fixed_slots,
            "pressure_pair_files_per_member": pressure_member_slots,
            "source_declared_slots_before_common_inputs_and_dynamic_roots": owner_slot_count,
            "exact_full_path_catalogue_complete": False,
        },
        "source_role_ceilings": {
            "soak_terminal_owner_bytes": contract["soak"]["reader_limits"][
                "MAX_TERMINAL_BYTES"],
            "dispatcher_soak_role_bytes": contract["role_ceiling_conflicts"][
                "dispatcher_soak_role_bytes"],
            "chronology_soak_role_bytes": contract["role_ceiling_conflicts"][
                "chronology_soak_role_bytes"],
        },
        "blockers": sorted(set(blockers)),
        "readiness": {
            "budget_complete": False, "execution_ready": False,
            "component_gate_ready": False, "qualification_eligible": False,
        },
    }
    return {**body, "budget_sha256": _sha(_canonical(body))}


def validate_budget_plan(value: object) -> dict[str, Any]:
    """Validate a persisted budget plan without converting it into authority."""
    _require(type(value) is dict and value.get("schema") ==
             "allocatbelt.application-source5-host-evidence-budget.v1" and
             value.get("readiness") == {
                 "budget_complete": False, "execution_ready": False,
                 "component_gate_ready": False, "qualification_eligible": False,
             }, "Source5 evidence budget cannot assert complete or ready")
    _require(validate_contract_summary(value.get("owner_contract")) is
             value.get("owner_contract"),
             "Source5 evidence budget owner contract is invalid")
    body = {key: item for key, item in value.items() if key != "budget_sha256"}
    _require(type(value.get("budget_sha256")) is str and
             value["budget_sha256"] == _sha(_canonical(body)),
             "Source5 evidence budget raw/semantic identity differs")
    return value
