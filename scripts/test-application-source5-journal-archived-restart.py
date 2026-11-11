#!/usr/bin/env python3
"""Native-only restart witnesses; synthetic prepared inputs and APP callbacks.

The journal parser, state machine, authorization validator, archive copy,
signature verification and exact reclaim are real. Prepared capacity, manifest,
budget and width preflight are explicitly mocked; this is not qualification.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sealed(value, field):
    body = {key: item for key, item in value.items() if key != field}
    return {**body, field: sha(canonical(body))}


def private(path):
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
    return path


def put(path, raw):
    private(path.parent)
    path.write_bytes(raw)
    path.chmod(0o600)
    return {"path": str(path), "raw_sha256": sha(raw)}


class ArchivedJournalRestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrono = load("restart_chronology", SCRIPTS / "application-campaign-chronology.py")
        cls.packet_tests = load("restart_archive_fixtures", SCRIPTS / "test-application-source5-evidence-transfer-packet.py")
        cls.packet_tests.PacketRoundTripTests.setUpClass()
        cls.archive = cls.packet_tests.archive
        cls.fixed = load("restart_fixed_source", SCRIPTS / "application-fixed-pair.py")
        cls.controller = load("restart_controller_source", SCRIPTS / "application-campaign.py")

    @contextmanager
    def case(self):
        c, a, fixtures = self.chrono, self.archive, self.packet_tests
        with tempfile.TemporaryDirectory(prefix="source5-journal-restart-") as temp, ExitStack() as stack:
            root = Path(temp).resolve()
            artifact = root / "artifacts"
            artifact.mkdir(mode=0o700)
            pair = artifact / "pair"
            pair.mkdir(mode=0o700)
            signer = fixtures.make_test_signer(root, stack, 4096)
            inputs = copy.deepcopy(fixtures.PacketRoundTripTests.source_inputs)
            job = next(item for item in inputs["plan"]["jobs"]["exploration"] if item["host_id"] == "host-a")
            job.update(ordinal=1, allocator="allocatbelt", comparison_kind="executor", mode="capacity")
            fixtures.budget_tests.repin_plan_case(inputs)
            plan_path = root / "plan.json"
            inputs["pins"]["plan"]["path"] = str(plan_path)
            plan_raw = canonical(inputs["plan"])
            put(plan_path, plan_raw)
            source_ref = inputs["pins"]["source_manifests"]["host-a"]
            original_pins = {"schema": c.CHRONOLOGY_SCHEMA, "campaign_id": "campaign-a",
                             "host_id": "host-a", "plan": inputs["pins"]["plan"],
                             "source_manifests": [{"host_id": "host-a", **source_ref,
                                "source_tree_sha256": inputs["sources"]["host-a"]["source"]["source_tree_sha256"]}]}
            records = []
            def append(event, details):
                previous = records[-1]["record_sha256"] if records else "0" * 64
                record = {"schema": c.JOURNAL_SCHEMA, "sequence": len(records) + 1,
                          "monotonic_ns": len(records) + 1, "campaign_id": "campaign-a",
                          "host_id": "host-a", "boot_id_sha256": "f" * 64,
                          "original_pins": original_pins, "event": event, "details": copy.deepcopy(details)}
                unsigned = {"previous_sha256": previous, "record": record}
                envelope = {**unsigned, "record_sha256": sha(canonical(unsigned))}
                records.append(envelope)
                return envelope["record_sha256"]
            registration = {"campaign_id": "campaign-a", "host_id": "host-a",
                "completion": {"path": str(root / "prepared.json"), "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64},
                "provenance": {"schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
                               "preparation_pin": {}, "final_spec_pin": {}, "final_plan_pin": {}},
                "host_completion": {"path": str(root / "capacity.json"), "raw_sha256": "3" * 64, "semantic_sha256": "4" * 64},
                "host_verification": {"path": str(root / "capacity-receipt.json"), "raw_sha256": "5" * 64, "receipt_sha256": "6" * 64},
                "capacity_ledger": {"path": str(root / "capacity.jsonl"), "raw_sha256": "7" * 64, "terminal_head": "8" * 64},
                "capacity_schedule_sha256": "9" * 64, "entries": [{} for _ in range(15)],
                "qualification_eligible": False, "controller_chronology_proven": False}
            registration_head = append("source5_prepared_capacity_registered", registration)
            files = []
            for relative in ("scripts/application-fixed-pair.py", "scripts/application-source5-evidence-archive.py"):
                path = SCRIPTS.parent / relative
                raw = path.read_bytes()
                files.append({"path": relative, "kind": "file", "mode": format(path.stat().st_mode, "o"),
                              "size": len(raw), "sha256": sha(raw)})
            helper_module = files[0]
            execution = copy.deepcopy(inputs["execution"])
            execution.update(artifact_root=str(artifact), output_root=str(root / "output"),
                modules={"host-a": {helper_module["path"]: {"path": helper_module["path"], "sha256": helper_module["sha256"]}}})
            execution["original_inputs"]["plan"] = {"artifact": {"path": str(plan_path), "raw_sha256": sha(plan_raw)},
                                                    "semantic_sha256": inputs["plan"]["plan_sha256"]}
            execution["prepared_capacity_registration"] = {"host_completion": registration["host_completion"],
                "completion": registration["completion"], "host_verification": registration["host_verification"],
                "ledger": registration["capacity_ledger"], "capacity_schedule_sha256": registration["capacity_schedule_sha256"],
                "registration_head": registration_head}
            inputs["execution"] = sealed(execution, "manifest_sha256")
            inputs["pins"]["execution_manifest"]["path"] = str(artifact / "execution.json")
            inputs = fixtures.attach_test_signer_context(inputs, "host-a", signer)
            execution, execution_raw = inputs["execution"], inputs["execution_raw"]
            execution_pin = put(artifact / "execution.json", execution_raw)
            producer = fixtures.budget_producer
            audit = producer.build_host_evidence_budget_plan(inputs["spec"], inputs["plan"], inputs["sources"],
                execution, inputs["host_id"], pins_value=inputs["pins"])
            # The archive fixture intentionally has one transport window.
            audit["schedule"].update(job_counts={"exploration": 1, "aa": 0, "confirmation": 0, "pressure": 0, "soak": 0},
                fixed_job_count=1, pressure_job_count=0, total_job_count=1,
                maximum_callback_events=13, worst_case_journal_bytes=13 * producer.MAX_EVENT_BYTES)
            audit = sealed(audit, "budget_plan_sha256")
            transport = fixtures.PacketRoundTripTests()._fixture(root, source_inputs=inputs, audit=audit,
                original_job=job, authorized_signer_fingerprint=signer["fingerprint"])
            members = self.fixed._member_descriptors(job, self.controller)
            mount = self.fixed._mount_identity(pair)
            mount_static = {key: mount[key] for key in ("mount_id", "major_minor", "mount_root", "mount_point",
                "filesystem_type", "mount_source", "device")}
            observed_sha = sha(b"synthetic prepared observed-host boundary")
            affinity = sorted(os.sched_getaffinity(0))
            netns = Path("/proc/self/ns/net").stat().st_ino
            source = copy.deepcopy(inputs["sources"]["host-a"])
            source["source"]["files"] = files
            overlay = sealed({"schema": a.FIXED_PAIR_OVERLAY_SCHEMA_V1, "campaign_id": "campaign-a", "host_id": "host-a",
                "spec": {}, "plan": {"pin": {"path": str(plan_path), "sha256": sha(plan_raw)},
                    "semantic_sha256": inputs["plan"]["plan_sha256"]},
                "sources": {"manifests": {}, "selected": {"host_id": "host-a", "root": str(SCRIPTS.parent),
                    "git_commit": "a" * 40, "source_tree_sha256": source["source"]["source_tree_sha256"], "build_sha256": "b" * 64},
                    "campaign_artifacts_root": str(artifact), "observed_host": {"pin": {"path": str(root / "observed.json"),
                        "sha256": observed_sha}, "host_fingerprint_sha256": "c" * 64, "controls_sha256": "d" * 64,
                        "process_affinity": affinity, "network_namespace_inode": netns},
                    "historical_runner_sha256": "e" * 64, "output_mount": mount_static},
                "execution_source": {}, "modules": {}, "job": {"value": job, "sha256": sha(canonical(job))},
                "runtime_bindings": {}, "members": [], "deadlines": {}, "artifact_budgets": {}, "output_root": str(pair)}, "overlay_sha256")
            overlay_pin = put(pair / "fixed-pair-execution-overlay.json", canonical(overlay))
            finals = []
            for ordinal in range(2):
                directory = pair / f"tmp-{ordinal}"
                directory.mkdir(mode=0o700)
                info = directory.stat()
                finals.append({"path": str(directory), "device": info.st_dev, "inode": info.st_ino, "mode": 0o700,
                    "mount": mount_static, "bytes_used": 0, "file_count": 0, "directory_count": 0,
                    "bytes_limit": 1024, "inode_limit": 8, "available_bytes": mount["available_bytes"],
                    "available_inodes": mount["available_inodes"]})
            receipt = sealed({"schema": a.FIXED_PAIR_EXECUTION_RECEIPT_SCHEMA_V1, "campaign_id": "campaign-a", "host_id": "host-a",
                "run_id": job["run_id"], "status": "valid_pair", "overlay_sha256": overlay["overlay_sha256"],
                "member_attempts": [{"ordinal": index, "tmpdir_final": final} for index, final in enumerate(finals)]}, "receipt_sha256")
            receipt_pin = put(pair / "execution-receipt.json", canonical(receipt))
            host_identity = sealed({"schema": a.FIXED_PAIR_HOST_IDENTITY_SCHEMA_V1, "host_id": "host-a",
                "observed_host_raw_sha256": observed_sha, "process_affinity": affinity,
                "network_namespace_inode": netns, "output_mount": mount}, "host_verification_sha256")
            host_receipt = sealed({"schema": a.FIXED_PAIR_HOST_RECEIPT_SCHEMA_V1, "strict_verified": True,
                "qualification_eligible": False, "execution_ready": False, "campaign_chronology_complete": False,
                "overlay_raw_sha256": overlay_pin["raw_sha256"], "execution_receipt_raw_sha256": receipt_pin["raw_sha256"],
                "execution_receipt_sha256": receipt["receipt_sha256"], "status": "valid_pair", "run_id": job["run_id"],
                "host_verification": host_identity}, "receipt_sha256")
            host_pin = {**put(artifact / "host-receipt.json", canonical(host_receipt)),
                        "host_verification_sha256": host_receipt["receipt_sha256"]}
            helper = {"schema": c.SOURCE5_HELPER_INPUT_SCHEMA, "scope": "final_frozen", "campaign_id": "campaign-a", "host_id": "host-a",
                "phase": "exploration", "job_index": 0, "job": job, "job_sha256": sha(canonical(job)), "members": members,
                "helper": {"path": helper_module["path"], "sha256": helper_module["sha256"], "entrypoint": "run_fixed_pair_overlay"},
                "payload": {"overlay_pin": {"path": overlay_pin["path"], "sha256": overlay_pin["raw_sha256"]}},
                "prerequisites": [], "outer_deadline_seconds": 30, "effective_timeout_seconds": 30}
            helper["input_snapshot_sha256"] = sha(canonical(helper))
            helper["qualification_eligible"] = False
            helper_pin = put(artifact / "helper.json", canonical(helper))
            tmp_budget = {"fixture": "mocked prepared resource-budget boundary"}
            details = {"campaign_id": "campaign-a", "host_id": "host-a", "phase": "exploration", "job_index": 0,
                "job": job, "job_sha256": sha(canonical(job)), "members": members, "members_sha256": sha(canonical(members)),
                "execution_manifest": execution_pin, "helper_input": helper_pin, "helper_module": helper_module,
                "capacity_registration_head": registration_head,
                "capacity_completion": {key: registration["host_completion"][key] for key in ("path", "raw_sha256")},
                "capacity_ledger_raw_sha256": registration["capacity_ledger"]["raw_sha256"],
                "capacity_terminal_head": registration["capacity_ledger"]["terminal_head"],
                "capacity_schedule_sha256": registration["capacity_schedule_sha256"], "prerequisites": [],
                "outer_deadline_seconds": 30, "effective_timeout_seconds": 30, "input_snapshot_sha256": helper["input_snapshot_sha256"],
                "output_root": str(pair), "qualification_eligible": False,
                "host_evidence_budget": transport["budget_pin"], "tmpdir_budget": tmp_budget}
            details["authorization_id"] = "source5-" + sha(canonical(details))[:48]
            auth_head = append("source5_authorized", details)
            starts, terminals, callback_starts, callback_terminals = [], [], [], []
            cleanup = {"cleanup_status": "verified", "leader_reaped": True,
                       "group_signal_after_leader_reap_count": 0, "cleanup_errors": []}
            for index, descriptor in enumerate(members):
                proof = {"proof": {"pid": 100 + index, "start_ticks": 200 + index}, "fixture": "synthetic APP callback; no APP was launched"}
                callback_starts.append(proof)
                starts.append(append("source5_app_started", {"authorization_id": details["authorization_id"], "member_index": index,
                    "descriptor": descriptor, "pid": 100 + index, "start_ticks": 200 + index,
                    "proof_sha256": sha(canonical(proof)), "proof": proof, "qualification_eligible": False}))
                terminal = {"authorization_id": details["authorization_id"], "member_index": index,
                    "descriptor": descriptor, "pid": 100 + index, "status": 0, "child_return_code": 0, "signal": None,
                    "cleanup": cleanup, "cleanup_sidecar": None, "terminal_monotonic_ns": 1000 + index, "qualification_eligible": False}
                terminals.append(append("source5_app_terminal", terminal))
                callback_terminals.append({"schema": "allocatbelt.application-fixed-pair-app-terminal.v1",
                    "overlay_sha256": overlay_pin["raw_sha256"], "campaign_id": "campaign-a", "host_id": "host-a",
                    "run_id": job["run_id"], "member_ordinal": index,
                    **{key: terminal[key] for key in ("descriptor", "pid", "status", "child_return_code", "signal", "cleanup", "cleanup_sidecar", "terminal_monotonic_ns")}})
            metrics = [{"fixture_member": 0}, {"fixture_member": 1}]
            terminal = {"authorization_id": details["authorization_id"], "state": "valid_pair", "blocked_reason": None,
                "component_sha256": sha(b"synthetic component"), "process_metrics_sha256": sha(canonical(metrics)),
                "started_count": 2, "terminal_count": 2, "qualification_eligible": False}
            terminal_head = append("source5_job_terminal", terminal)
            processes_pin = put(pair / "processes.tsv", b"synthetic process bytes\n")
            runtime_pin = put(pair / "runtime.json", b"{}\n")
            record = sealed({"schema": c.SOURCE5_JOB_RECORD_SCHEMA, "state": "valid_pair", "job": job,
                "pair_directory": str(pair), "process_metrics": metrics, "qualification_eligible": False,
                "evidence": {"kind": "source5_fixed_pair", "execution_manifest": execution_pin, "helper_input": helper_pin,
                    "helper_module": helper_module, "overlay": overlay_pin, "receipt": receipt_pin, "processes": processes_pin,
                    "runtime_bindings": runtime_pin, "host_receipt": host_pin,
                    "source_snapshot": {"artifact": {key: source_ref[key] for key in ("path", "raw_sha256")},
                        "semantic_sha256": source_ref["semantic_sha256"], "source_tree_sha256": source["source"]["source_tree_sha256"]}},
                "chronology": {"authorization_id": details["authorization_id"], "authorization_head": auth_head,
                    "app_started_heads": starts, "app_terminal_heads": terminals, "job_terminal_head": terminal_head,
                    "component_sha256": terminal["component_sha256"], "process_metrics_sha256": terminal["process_metrics_sha256"],
                    "app_start_events": callback_starts, "app_terminal_events": callback_terminals,
                    "member_processes": [{"descriptor": descriptor, "pid": 100 + index, "start_ticks": 200 + index,
                        "member_index": index} for index, descriptor in enumerate(members)]}}, "record_sha256")
            output = transport["output_root"]
            phase_root = output / "campaign-a" / "source5" / "host-a" / "exploration"
            record_raw = canonical(record)
            record_pin = put(phase_root / "job-records" / f"{job['run_id']}.json", record_raw)
            put(phase_root / "controller-ledger.jsonl", record_raw)
            payloads = [(helper_pin, "source5_helper_input", None), (overlay_pin, "fixed_pair_artifact", None),
                (receipt_pin, "component_receipt", receipt["receipt_sha256"]),
                (host_pin, "fixed_pair_host_receipt", host_receipt["receipt_sha256"]),
                (processes_pin, "process_ledger", None), (runtime_pin, "runtime_binding", None)]
            entries = sorted([{"origin_path": pin["path"], "role": role, "raw_sha256": pin["raw_sha256"],
                "semantic_sha256": semantic, "byte_count": Path(pin["path"]).stat().st_size}
                for pin, role, semantic in payloads], key=lambda row: row["origin_path"])
            metadata = output / "campaign-a" / "chronology" / "host-a" / "evidence-checkpoints" / "exploration"
            private(metadata)
            leaf = f"{job['ordinal']:06d}-{sha(canonical(job))}"
            context = {**transport["request"]["context"], "plan_pin": inputs["pins"]["plan"],
                       "execution_manifest_pin": inputs["pins"]["execution_manifest"]}
            owner_raw = {receipt_pin["path"]: canonical(receipt), host_pin["path"]: canonical(host_receipt)}
            request, request_pin = a.build_checkpoint_request(context, record_pin, record_raw, plan_raw, entries,
                owner_raw, metadata / f"{leaf}.request.json")
            archive_root = root / "private-archive" / "campaign-a" / "host-a" / "source5"
            private(archive_root)
            fd = os.open(archive_root, os.O_RDONLY | os.O_DIRECTORY)
            objects, stage_rows = [], []
            try:
                for row in entries:
                    object_id = a._object_identity(row["origin_path"], row["raw_sha256"])
                    remote, local = a._copy_object(fd, object_id, row["origin_path"], str(artifact), row)
                    remote["path"] = str(archive_root / "objects" / object_id)
                    objects.append({**row, "object_id": object_id, "object_pin": remote})
                    stage_rows.append({"origin_path": row["origin_path"], "object_id": object_id,
                                       "remote_object_pin": remote, "local_staged_file": local})
            finally:
                os.close(fd)
            object_manifest = sealed({"schema": a.OBJECT_MANIFEST_SCHEMA_V1, "campaign_id": "campaign-a", "host_id": "host-a",
                "phase": "exploration", "job_index": 0, "job_ordinal": 1, "job_sha256": sha(canonical(job)), "run_id": job["run_id"],
                "job_record_raw_sha256": sha(record_raw), "predecessor_ack_pin": None, "objects": objects,
                "object_count": len(objects), "payload_bytes": sum(row["byte_count"] for row in objects)}, "manifest_sha256")
            manifest_raw = canonical(object_manifest)
            manifest_pin = {"path": str(archive_root / "objects" / "manifests" / "exploration" / f"{leaf}.json"),
                "raw_sha256": sha(manifest_raw), "semantic_sha256": object_manifest["manifest_sha256"]}
            checkpoint = sealed({"schema": a.CHECKPOINT_SCHEMA_V1, "request_pin": request_pin,
                **{key: request[key] for key in ("context", "job_record_pin", "authorization", "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs", "entries")},
                "object_manifest_pin": manifest_pin}, "checkpoint_sha256")
            checkpoint_raw = canonical(checkpoint)
            checkpoint_pin = {"path": str(archive_root / "checkpoints" / "exploration" / f"{leaf}.json"),
                "raw_sha256": sha(checkpoint_raw), "semantic_sha256": checkpoint["checkpoint_sha256"]}
            validation_pin = {"path": str(archive_root / "validation" / "job-records" / "exploration" / f"{leaf}.json"),
                "origin_path": record_pin["path"], "raw_sha256": record_pin["raw_sha256"],
                "semantic_sha256": record["record_sha256"], "byte_count": len(record_raw)}
            reopen_sha = a._verify_archive_objects(object_manifest)
            durable = {"checkpoint_pin": checkpoint_pin, "object_manifest_pin": manifest_pin,
                       "object_reopen_sha256": reopen_sha, "job_record_validation": validation_pin}
            info = archive_root.stat()
            durable.update(commit_id=sha(canonical(durable)), archive_source5_directory={"path": str(archive_root),
                "device": info.st_dev, "inode": info.st_ino, "mode": 0o700},
                object_count=len(objects), payload_bytes=object_manifest["payload_bytes"])
            ack = sealed({"schema": a.ACK_SCHEMA_V1, "checkpoint_pin": checkpoint_pin, "object_manifest_pin": manifest_pin,
                "predecessor_ack_pin": None, "signer_fingerprint": signer["fingerprint"], "durable_commit": durable}, "ack_sha256")
            ack_raw = canonical(ack)
            ack_pin = {"path": str(archive_root / "acks" / "exploration" / f"{leaf}.json"),
                       "raw_sha256": sha(ack_raw), "semantic_sha256": ack["ack_sha256"]}
            signature_raw = a._gpg_sign(ack_raw, {"gpg_executable": signer["gpg_executable"], "gpg_homedir": signer["gpg_homedir"],
                "primary_fingerprint": signer["fingerprint"], "maximum_signature_bytes": 4096})
            signature_pin = {"path": str(archive_root / "acks" / "signatures" / "exploration" / f"{leaf}.sig"),
                             "raw_sha256": sha(signature_raw), "signer_fingerprint": signer["fingerprint"]}
            for destination, raw in ((manifest_pin["path"], manifest_raw), (checkpoint_pin["path"], checkpoint_raw),
                    (ack_pin["path"], ack_raw), (signature_pin["path"], signature_raw),
                    (validation_pin["path"], record_raw)):
                put(Path(destination), raw)
            for suffix, raw in (("checkpoint.json", checkpoint_raw), ("object-manifest.json", manifest_raw),
                                ("ack.json", ack_raw), ("ack.sig", signature_raw)):
                put(metadata / f"{leaf}.{suffix}", raw)
            stage = sealed({"schema": a.STAGE_MAP_SCHEMA_V1, "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin, "rows": stage_rows}, "stage_map_sha256")
            stage_raw = canonical(stage)
            stage_pin = {**put(metadata / f"{leaf}.stage-map.json", stage_raw), "semantic_sha256": stage["stage_map_sha256"]}
            arguments = (checkpoint_pin, checkpoint, checkpoint_raw, canonical(request), transport["budget_raw"],
                record_pin, record_raw, plan_raw, manifest_pin, object_manifest, manifest_raw, ack_pin, ack, ack_raw,
                signature_pin, signature_raw, transport["signer_context_pin"], transport["signer_context_raw"],
                transport["execution_manifest_pin"], transport["execution_manifest_raw"], stage_pin, stage, str(artifact), None)
            verified = a.verify_durable_ack(*arguments)
            def reclaim():
                return a.reclaim_acknowledged_local_paths(checkpoint, verified, stage, str(artifact),
                    checkpoint_raw=checkpoint_raw, request_raw=canonical(request), host_budget_raw=transport["budget_raw"],
                    job_record_bytes=record_raw, plan_bytes=plan_raw, object_manifest=object_manifest, manifest_raw=manifest_raw,
                    ack=ack, ack_raw=ack_raw, signature_raw=signature_raw,
                    signer_context_pin=transport["signer_context_pin"], signer_context_raw=transport["signer_context_raw"],
                    execution_manifest_pin=transport["execution_manifest_pin"], execution_manifest_raw=transport["execution_manifest_raw"])
            counts = {"source5_authorized": 1, "source5_app_started": 2, "source5_app_terminal": 2, "source5_job_terminal": 1}
            widths = {event: c.MAX_EVENT_BYTES for event in counts}
            projection = {"job_rows": {("exploration", 0): {"event_counts": counts, "failed_event_counts": counts,
                "maximum_event_bytes_by_kind": widths, "failed_event_bytes_by_kind": widths}},
                "fixed_event_widths": [{"event": "source5_prepared_capacity_registered", "phase": "registration", "count": 1,
                    "maximum_line_bytes": c.MAX_EVENT_BYTES}]}
            prepared = {"campaign_id": "campaign-a", "host_id": "host-a", "original_pins": original_pins,
                "plan": inputs["plan"], "plan_pin": {"path": str(plan_path), "sha256": sha(plan_raw)},
                "source_root": SCRIPTS.parent, "input_root": root / "inputs", "output_root": output,
                "source": source, "source_manifest_raw_refs": {"host-a": original_pins["source_manifests"][0]},
                "controller": self.controller, "spec": {"deadlines": {"outer_seconds": 30}, "rates": [1], "oracles": [1]},
                "source5_execution_schema": c.SOURCE5_EXECUTION_SCHEMA_V4, "source5_execution_manifest": execution,
                "source5_execution_manifest_pin": execution_pin, "source5_execution_manifest_raw_sha256": sha(execution_raw),
                "source5_journal_event_ceiling": 100, "source5_journal_byte_ceiling": 1 << 20,
                "source5_journal_width_projection": projection, "boot_id_sha256": "f" * 64}
            stack.enter_context(patch.object(c, "_validate_source5_prepared_capacity_registration", return_value=registration))
            stack.enter_context(patch.object(c, "_validate_source5_manifest_value", side_effect=lambda value, _raw, _prepared: value))
            stack.enter_context(patch.object(c, "_source5_host_budget_pin_and_value", return_value=(transport["budget_pin"], transport["budget"])))
            stack.enter_context(patch.object(c, "_source5_prepared_tmpdir_budget", return_value=tmp_budget))
            stack.enter_context(patch.object(c, "_source5_cleanup_limits_from_budget", return_value={}))
            lock = stack.enter_context(c.campaign_host_lock(output, "campaign-a", "host-a"))
            journal_path = c._journal_path(lock)
            def write_journal(selected=None):
                put(journal_path, b"".join(canonical(row) for row in (records if selected is None else selected)))
                c._LOCK_CACHED_STATES.pop(id(lock), None)
            write_journal()
            yield {"prepared": prepared, "lock": lock, "job": job, "record": record, "details": details, "helper": helper,
                "records": records, "write_journal": write_journal, "reclaim": reclaim, "entries": entries,
                "helper_path": Path(helper_pin["path"]), "ack_path": metadata / f"{leaf}.ack.json",
                "signature_path": metadata / f"{leaf}.ack.sig", "ledger_path": phase_root / "controller-ledger.jsonl",
                "record_path": Path(record_pin["path"]), "append": append}

    def test_restart_after_real_copy_sign_verify_and_reclaim(self):
        with self.case() as case:
            removed = case["reclaim"]()
            self.assertEqual(set(removed), {row["origin_path"] for row in case["entries"]})
            self.assertFalse(case["helper_path"].exists())
            self.assertTrue(case["record_path"].exists())
            state = self.chrono._read_journal(case["lock"], case["prepared"])
            finished = state["source5_finished"][("exploration", case["job"]["run_id"])]
            self.assertTrue(finished["archived_metadata_verified"])
            self.assertTrue(finished["component_replay_required"])
            self.assertEqual(state["record_count"], 7)

    def test_authorizer_accepts_raw_completion_projection_but_rejects_changed_semantic_pin(self):
        with self.case() as case:
            c = self.chrono
            state = c._empty_journal(case["prepared"]["original_pins"])
            registration_record = case["records"][0]
            state["prepared_capacity_registration"] = registration_record["record"]["details"]
            state["registration_head"] = registration_record["record_sha256"]
            self.assertEqual(set(case["details"]["capacity_completion"]), {"path", "raw_sha256"})
            self.assertEqual(set(state["prepared_capacity_registration"]["host_completion"]),
                             {"path", "raw_sha256", "semantic_sha256"})
            verified = c._validate_source5_authorization(case["details"], case["prepared"], state)
            self.assertEqual(verified["helper_input"]["job"], case["job"])
            path = Path(case["details"]["execution_manifest"]["path"])
            manifest = json.loads(path.read_bytes())
            manifest["prepared_capacity_registration"]["host_completion"]["semantic_sha256"] = "0" * 64
            manifest = sealed(manifest, "manifest_sha256")
            changed = {key: copy.deepcopy(value) for key, value in case["details"].items()
                       if key != "authorization_id"}
            changed["execution_manifest"] = put(path, canonical(manifest))
            changed["authorization_id"] = "source5-" + sha(canonical(changed))[:48]
            with self.assertRaisesRegex(c.ChronologyError, "prepared-capacity bridge registration"):
                c._validate_source5_authorization(changed, case["prepared"], state)

    def test_missing_ack_after_reclaim_requires_local_helper(self):
        with self.case() as case:
            case["reclaim"]()
            case["ack_path"].unlink()
            with self.assertRaisesRegex(self.chrono.ChronologyError, "helper input"):
                self.chrono._read_journal(case["lock"], case["prepared"])

    def test_unacknowledged_local_history_keeps_original_validation(self):
        with self.case() as case:
            case["ack_path"].unlink()
            state = self.chrono._read_journal(case["lock"], case["prepared"])
            self.assertNotIn("archived_metadata_verified", state["source5_finished"][("exploration", case["job"]["run_id"])])
            case["helper_path"].unlink()
            case["write_journal"]()
            with self.assertRaisesRegex(self.chrono.ChronologyError, "helper input"):
                self.chrono._read_journal(case["lock"], case["prepared"])

    def test_pending_authorization_cannot_use_later_archive(self):
        with self.case() as case:
            case["reclaim"]()
            case["write_journal"](case["records"][:2])
            with self.assertRaisesRegex(self.chrono.ChronologyError, "helper input"):
                self.chrono._read_journal(case["lock"], case["prepared"])

    def test_tampered_signature_never_falls_back_to_local_inputs(self):
        with self.case() as case:
            raw = case["signature_path"].read_bytes()
            put(case["signature_path"], raw[:-1] + bytes([raw[-1] ^ 1]))
            with self.assertRaisesRegex(self.chrono.ChronologyError, "historical Source5 signed ACK was rejected"):
                self.chrono._read_journal(case["lock"], case["prepared"])

    def test_changed_retained_ledger_or_record_fails_closed(self):
        for which in ("ledger_path", "record_path"):
            with self.subTest(which=which), self.case() as case:
                case["reclaim"]()
                altered = copy.deepcopy(case["record"])
                altered["process_metrics"][0]["fixture_member"] = 99
                put(case[which], canonical(sealed(altered, "record_sha256")))
                with self.assertRaisesRegex(self.chrono.ChronologyError, "differs from its retained phase ledger"):
                    self.chrono._read_journal(case["lock"], case["prepared"])

    def test_structural_analysis_is_explicitly_deferred_and_blocks_next_grant(self):
        with self.case() as case:
            case["reclaim"]()
            state = self.chrono._read_journal(case["lock"], case["prepared"])
            # A reduced phase projection tests only analysis recovery; the
            # signed Plan and first-job restart above retain the full fixture.
            prepared = {**case["prepared"], "plan": {"jobs": {"exploration": [case["job"]]}}}
            ids = [case["job"]["run_id"]]
            analysis = sealed({"schema": "allocatbelt.application-source5-phase-analysis.v1", "campaign_id": "campaign-a",
                "host_id": "host-a", "phase": "exploration", "job_count": 1, "job_set_sha256": sha(canonical(ids)),
                "job_evidence_complete": True, "numeric_gates_passed": True, "phase_gate_passed": True,
                "campaign_qualification_eligible": False, "analysis": {"fixture": "no numeric qualification claim"}}, "analysis_sha256")
            path = case["record_path"].parent.parent / "analysis.json"
            pin = put(path, canonical(analysis))
            details = {key: analysis[key] for key in self.chrono.DETAIL_FIELDS["source5_analysis"] if key != "analysis"}
            details["analysis"] = pin
            details["analysis_sha256"] = pin["raw_sha256"]
            self.chrono._check_event_semantics(state, "source5_analysis", details, "a" * 64, prepared, replay=True)
            self.assertTrue(state["source5_analyses"]["exploration"]["analysis_replay_required"])
            next_job = {"host_id": "host-a", "phase": "aa", "ordinal": 1,
                        "run_id": "next-original-aa", "allocator": "allocatbelt", "executor": "bounded"}
            prepared["plan"]["jobs"]["aa"] = [next_job]
            next_pair = private(case["helper_path"].parent / "next-aa")
            next_overlay = put(next_pair / "overlay.json", canonical({"output_root": str(next_pair)}))
            prerequisites = [{"phase": "exploration", "analysis": pin,
                              "analysis_sha256": pin["raw_sha256"], "event_head": "a" * 64}]
            next_members = self.fixed._member_descriptors(next_job, self.controller)
            next_helper = copy.deepcopy(case["helper"])
            next_helper.update(phase="aa", job=next_job, job_sha256=sha(canonical(next_job)), members=next_members,
                prerequisites=prerequisites, payload={"overlay_pin": {"path": next_overlay["path"], "sha256": next_overlay["raw_sha256"]}})
            next_helper["input_snapshot_sha256"] = sha(canonical(self.chrono._source5_input_body(next_helper)))
            next_helper_pin = put(next_pair / "helper.json", canonical(next_helper))
            next_auth = {key: copy.deepcopy(value) for key, value in case["details"].items() if key != "authorization_id"}
            next_auth.update(phase="aa", job=next_job, job_sha256=sha(canonical(next_job)), members=next_members,
                members_sha256=sha(canonical(next_members)), helper_input=next_helper_pin, prerequisites=prerequisites,
                input_snapshot_sha256=next_helper["input_snapshot_sha256"], output_root=str(next_pair))
            next_auth["authorization_id"] = "source5-" + sha(canonical(next_auth))[:48]
            checked = self.chrono._validate_source5_authorization(next_auth, prepared, state)
            self.assertEqual(checked["helper_input"]["job"], next_job)
            with self.assertRaisesRegex(self.chrono.ChronologyError, "requires fresh captured replay"):
                self.chrono._check_event_semantics(state, "source5_authorized", next_auth, "b" * 64, prepared, replay=False)


if __name__ == "__main__":
    unittest.main()
