#!/usr/bin/env python3
"""Filesystem-backed producer/full-validator tests for the prep-only budget.

This is an explicitly synthetic SourceV5 fixture.  It preserves the real
360-row selected-host Plan and runs the selected SourceH width, catalogue,
budget, restore, and full budget-validator algorithms.  The outer
capacity-generation/registration evidence is shape-only and no application
owner or campaign authorization is invoked.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent
CONTROLLER_PATH = SCRIPTS / "application-source5-campaign.py"
PREPARATORY_PATH = SCRIPTS / "application-source5-preparatory-budget.py"
EVIDENCE_BUDGET_PATH = SCRIPTS / "application-source5-evidence-budget.py"
EVIDENCE_CATALOGUE_PATH = SCRIPTS / "application-source5-evidence-catalogue.py"
RECIPE_TESTS_PATH = SCRIPTS / "test-application-soak-recipe.py"


def load_exact(path: Path, name: str) -> types.ModuleType:
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def write_private(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode,
    )
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def seal(value: dict, field: str, hash_function) -> dict:
    body = {key: item for key, item in value.items() if key != field}
    return {**body, field: hash_function(body)}


class PreparatoryProducerFixture:
    """Real local files and typed source pins around a synthetic outer setup."""

    def __init__(self, temporary_root: Path):
        self.temporary_root = temporary_root
        self.recipe_tests = load_exact(
            RECIPE_TESTS_PATH,
            f"source5_prep_recipe_fixture_{id(self):x}",
        )
        self.fixture = self.recipe_tests.SourceV5CliFixture(temporary_root)
        self.controller = load_exact(
            CONTROLLER_PATH, f"source5_prep_controller_{id(self):x}",
        )
        self.fixture_campaign = self.recipe_tests.campaign
        self.host_id = self.fixture.host_ids[0]
        self._expand_typed_source()
        self._freeze_empty_rate_plan()
        self._make_reserved_roots()
        self._make_observed_hosts()
        self._load_selected_modules()
        self._make_preparation_intent()
        self._make_capacity_shape()
        self._make_signer()
        try:
            self._make_context()
        except BaseException:
            self.close()
            raise

    def _expand_typed_source(self) -> None:
        source_root = self.fixture.root
        source_scripts = source_root / "scripts"
        source_scripts.mkdir(mode=0o700, exist_ok=True)
        for source in sorted(SCRIPTS.iterdir(), key=lambda item: item.name.encode()):
            if source.suffix not in {".py", ".sh"} or not source.is_file():
                continue
            target = source_scripts / source.name
            if target.exists() or target.is_symlink():
                target.unlink()
            shutil.copyfile(source, target)
            target.chmod(stat.S_IMODE(source.stat().st_mode))
        self.fixture._git(["git", "-C", str(source_root), "add", "-A"])
        self.fixture._git([
            "git", "-C", str(source_root), "commit", "-q",
            "-m", "synthetic preparatory SourceH fixture closure",
        ], env={
            **os.environ,
            "GIT_AUTHOR_DATE": "2003-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2003-01-01T00:00:00Z",
        })
        self.git_commit = self.fixture._git(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True,
        ).stdout.strip()
        self.source_tree_sha256, self.source_files = \
            self.fixture_campaign.source_inventory(source_root)
        self.module_pins = {
            row["path"]: {"path": row["path"], "sha256": row["sha256"]}
            for row in self.source_files
            if row["kind"] == "file" and row["path"].startswith("scripts/")
            and Path(row["path"]).suffix in {".py", ".sh"}
        }
        for host_id in self.fixture.host_ids:
            source_manifest = copy.deepcopy(self.fixture.manifests[host_id])
            source_manifest["source"].update({
                "git_commit": self.git_commit,
                "source_tree_sha256": self.source_tree_sha256,
                "files": self.source_files,
            })
            source_manifest["resource_domain_calibration"]["source"].update({
                "git_commit": self.git_commit,
                "source_tree_sha256": self.source_tree_sha256,
            })
            source_manifest["manifest_sha256"] = \
                self.fixture_campaign.digest_object(
                    source_manifest, "manifest_sha256",
                )
            path = self.fixture.manifest_paths[host_id]
            path.unlink()
            raw = self.fixture_campaign.canonical_bytes(source_manifest)
            write_private(path, raw)
            self.fixture.manifests[host_id] = source_manifest
            self.fixture.manifest_raw_shas[host_id] = digest(raw)

    def _freeze_empty_rate_plan(self) -> None:
        campaign = self.fixture_campaign
        self.spec = copy.deepcopy(self.fixture.spec)
        self.spec["rates"] = []
        self.spec["oracles"] = []
        observed_affinity = sorted(os.sched_getaffinity(0))
        self.observed_affinity = observed_affinity
        cpu_set = ",".join(str(cpu) for cpu in observed_affinity)
        cpu_model = "unknown"
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
        for host in self.spec["hosts"]:
            host["controls"]["cpu_set"] = cpu_set
            host["controls"]["kernel_release"] = os.uname().release
            host["controls"]["cpu_model"] = cpu_model
            host["host_fingerprint_sha256"] = digest(
                campaign.canonical_bytes(host["controls"]),
            )
        self.spec["source_manifests"] = [
            {
                "host_id": host_id,
                "relative_path": f"source/{host_id}.json",
                "sha256": self.fixture.manifests[host_id]["manifest_sha256"],
            }
            for host_id in self.fixture.host_ids
        ]
        self.spec_path = self.fixture.spec_path
        self.spec_path.unlink()
        self.spec_raw = campaign.canonical_bytes(self.spec)
        write_private(self.spec_path, self.spec_raw)
        self.spec_sha256 = digest(self.spec_raw)
        sources = dict(self.fixture.manifests)
        self.plan = campaign.freeze_plan(
            self.spec, sources, input_root=self.fixture.input_root,
        )
        jobs = [row for row in self.plan["jobs"]["exploration"]
                if row["host_id"] == self.host_id]
        if len(jobs) != 360:
            raise AssertionError(
                f"synthetic prep fixture must retain 360 selected jobs, got {len(jobs)}",
            )
        self.plan_path = self.fixture.plan_path
        self.plan_path.unlink()
        self.plan_raw = campaign.canonical_bytes(self.plan)
        write_private(self.plan_path, self.plan_raw)
        self.plan_file_sha256 = digest(self.plan_raw)
        self.spec_pin = {"path": str(self.spec_path), "raw_sha256": self.spec_sha256}
        self.plan_pin = {"path": str(self.plan_path), "raw_sha256": self.plan_file_sha256}
        self.spec_semantic = campaign.digest_object(self.spec)
        self.plan_semantic = self.plan["plan_sha256"]

    def _make_reserved_roots(self) -> None:
        self.artifact_root = self.temporary_root / "prep-artifacts"
        self.output_root = self.temporary_root / "prep-output"
        self.scratch_root = self.temporary_root / "prep-scratch"
        self.evidence_root = self.temporary_root / "prep-evidence-store"
        for root in (self.artifact_root, self.output_root,
                     self.scratch_root, self.evidence_root):
            root.mkdir(mode=0o700)
            root.chmod(0o700)

    def _make_observed_hosts(self) -> None:
        boot_raw = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
        affinity = sorted(os.sched_getaffinity(0))
        namespace_inode = os.stat("/proc/self/ns/net", follow_symlinks=False).st_ino
        self.observed_values = {}
        self.observed_pins = {}
        for host in self.spec["hosts"]:
            host_id = host["host_id"]
            controls = host["controls"]
            body = {
                "schema": "allocatbelt.application-capacity-host-context.v1",
                "host_id": host_id,
                "boot_id_sha256": digest(boot_raw),
                "controls_sha256": self.fixture_campaign.digest_object(controls),
                "controls": controls,
                "kernel_release": controls["kernel_release"],
                "cpu_model": controls["cpu_model"],
                "cpu_affinity": affinity,
                "network_namespace_inode": namespace_inode,
            }
            # Only the selected-host runtime reading is a live local fact.  The
            # other two are explicitly shape-only SourceV5 fixture rows.
            if body["cpu_affinity"] != self.observed_affinity:
                raise AssertionError("fixture Spec CPU set is not the observed affinity")
            raw = self.fixture_campaign.canonical_bytes(body)
            path = self.fixture.input_root / "observed-hosts" / f"{host_id}.json"
            write_private(path, raw)
            self.observed_values[host_id] = body
            self.observed_pins[host_id] = {
                "path": str(path), "raw_sha256": digest(raw),
            }

    def _write_setup_artifact(self, relative: str, value: dict) -> dict[str, str]:
        path = self.fixture.input_root / relative
        raw = self.fixture_campaign.canonical_bytes(value)
        write_private(path, raw)
        return {"path": str(path), "raw_sha256": digest(raw)}

    def _make_preparation_intent(self) -> None:
        source_pins = {}
        preparation_paths = self.inputs_module.PREPARATION_MODULE_PATHS
        for host_id in self.fixture.host_ids:
            source = self.fixture.manifests[host_id]
            source_ref = next(row for row in self.spec["source_manifests"]
                              if row["host_id"] == host_id)
            source_pins[host_id] = {
                "manifest": {
                    "relative_path": source_ref["relative_path"],
                    "raw_sha256": self.fixture.manifest_raw_shas[host_id],
                    "semantic_sha256": source_ref["sha256"],
                    "source_tree_sha256": source["source"]["source_tree_sha256"],
                },
                "modules": {
                    role: dict(self.module_pins[relative])
                    for role, relative in preparation_paths.items()
                },
                "artifacts": {
                    allocator: dict(pin)
                    for allocator, pin in source["artifacts"].items()
                },
            }
        observed_hosts = {
            host_id: {
                "relative_path": Path(self.observed_pins[host_id]["path"])
                    .relative_to(self.fixture.input_root).as_posix(),
                "raw_sha256": self.observed_pins[host_id]["raw_sha256"],
            }
            for host_id in self.fixture.host_ids
        }
        self.preparation_value = {
            "core": self.inputs_module.preparation_core_from_spec(self.spec),
            "source_pins": source_pins,
            "observed_hosts": observed_hosts,
        }
        path = self.fixture.input_root / "preparatory" / "preparation-intent.json"
        raw = self.fixture_campaign.canonical_bytes(self.preparation_value)
        write_private(path, raw)
        self.preparation_pin = {"path": str(path), "sha256": digest(raw)}

    def _make_capacity_shape(self) -> None:
        campaign_id = self.spec["campaign_id"]
        provenance = {
            "schema": "allocatbelt.application-source5-preparatory-capacity-provenance.v1",
            "preparation_pin": {
                "path": self.preparation_pin["path"],
                "raw_sha256": self.preparation_pin["sha256"],
            },
            "initial_spec_pin": dict(self.spec_pin),
            "initial_plan_pin": dict(self.plan_pin),
        }
        resource_budgets = {}
        for host_id in self.fixture.host_ids:
            body = {
                "schema": "synthetic-source5-resource-budget.v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "ceilings": {
                    "maximum_tmpdir_bytes": self.controller.MAX_ARTIFACT_BYTES,
                    "maximum_tmpdir_inodes": 4096,
                },
                "qualification_eligible": False,
            }
            raw_body = self.fixture_campaign.canonical_bytes(body)
            value = {**body, "resource_budget_sha256": digest(raw_body)}
            pin = self._write_setup_artifact(
                f"preparatory/resource-budget-{host_id}.json", value,
            )
            pin["semantic_sha256"] = value["resource_budget_sha256"]
            resource_budgets[host_id] = pin

        templates = self.plan["capacity_process_templates"]
        by_host = {
            host_id: [row for row in templates
                      if row.get("capacity_key", {}).get("host_id") == host_id]
            for host_id in self.fixture.host_ids
        }
        if any(len(rows) != 15 for rows in by_host.values()):
            raise AssertionError("Plan capacity templates do not retain 15 rows per host")
        preparations = []
        for host_id in self.fixture.host_ids:
            entries = []
            for index, template in enumerate(by_host[host_id]):
                entry_pins = {}
                for role in ("request", "artifact", "receipt"):
                    pin = self._write_setup_artifact(
                        f"preparatory/capacity/{host_id}/{index:02d}-{role}.json",
                        {"schema": "synthetic-capacity-entry.v1",
                         "host_id": host_id, "index": index, "role": role,
                         "template_sha256": digest(
                             self.fixture_campaign.canonical_bytes(template),
                         )},
                    )
                    entry_pins[role] = pin
                entries.append({"template": template, **entry_pins})
            schedule_sha = digest(self.fixture_campaign.canonical_bytes(entries))
            completion_pin = self._write_setup_artifact(
                f"preparatory/capacity/{host_id}/host-completion.json",
                {"schema": "synthetic-capacity-host-completion.v1",
                 "campaign_id": campaign_id, "host_id": host_id,
                 "entry_count": 15, "capacity_schedule_sha256": schedule_sha,
                 "qualification_eligible": False},
            )
            completion_pin["semantic_sha256"] = digest(
                self.fixture_campaign.canonical_bytes({
                    "schema": "synthetic-capacity-host-completion.v1",
                    "campaign_id": campaign_id, "host_id": host_id,
                    "entry_count": 15,
                    "capacity_schedule_sha256": schedule_sha,
                    "qualification_eligible": False,
                }),
            )
            receipt_raw = self.fixture_campaign.canonical_bytes({
                "schema": "synthetic-capacity-host-receipt.v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "capacity_schedule_sha256": schedule_sha,
                "qualification_eligible": False,
            })
            receipt_path = self.fixture.input_root / "preparatory" / "capacity" / host_id / "host-receipt.json"
            write_private(receipt_path, receipt_raw)
            host_verification = {
                "path": str(receipt_path), "raw_sha256": digest(receipt_raw),
                "receipt_sha256": digest(receipt_raw),
            }
            ledger_body = {
                "schema": "synthetic-capacity-registration-ledger.v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "capacity_schedule_sha256": schedule_sha,
                "qualification_eligible": False,
            }
            ledger_raw = self.fixture_campaign.canonical_bytes(ledger_body)
            ledger_path = self.fixture.input_root / "preparatory" / "capacity" / host_id / "capacity-ledger.json"
            write_private(ledger_path, ledger_raw)
            ledger = {
                "path": str(ledger_path), "raw_sha256": digest(ledger_raw),
                "terminal_head": digest(ledger_raw),
            }
            preparations.append({
                "host_id": host_id, "entries": entries,
                "completion": completion_pin,
                "completion_sha256": completion_pin["semantic_sha256"],
                "host_verification": host_verification,
                "ledger": ledger,
                "capacity_preparation_templates_sha256": schedule_sha,
            })
        generation_body = {
            "schema": "allocatbelt.application-source5-prepared-capacity-generation.v1",
            "campaign_id": campaign_id,
            "complete": True,
            "qualification_eligible": False,
            "capacity_preparations": preparations,
            "resource_budgets": resource_budgets,
        }
        generation_sha = digest(self.fixture_campaign.canonical_bytes(generation_body))
        generation_value = {**generation_body, "generation_sha256": generation_sha}
        generation_raw = self.fixture_campaign.canonical_bytes(generation_value)
        generation_path = self.fixture.input_root / "preparatory" / "capacity-generation.json"
        write_private(generation_path, generation_raw)
        self.generation_completion = {
            "path": str(generation_path), "raw_sha256": digest(generation_raw),
            "semantic_sha256": generation_sha,
        }
        self.generation = {
            **generation_value, "completion": self.generation_completion,
            "provenance": provenance,
        }
        selected = next(row for row in preparations if row["host_id"] == self.host_id)
        registration_body = {
            "schema": "synthetic-prepared-capacity-registration.v1",
            "campaign_id": campaign_id, "host_id": self.host_id,
            "completion": self.generation_completion,
            "host_completion": {
                **selected["completion"],
                "semantic_sha256": selected["completion_sha256"],
            },
            "host_verification": selected["host_verification"],
            "ledger": selected["ledger"],
            "capacity_schedule_sha256": selected[
                "capacity_preparation_templates_sha256"],
            "entries": selected["entries"],
            "qualification_eligible": False,
            "controller_chronology_proven": False,
        }
        registration_head = digest(self.fixture_campaign.canonical_bytes(registration_body))
        self.registration = {
            key: registration_body[key]
            for key in ("completion", "host_completion", "host_verification", "ledger",
                        "capacity_schedule_sha256")
        }
        self.registration["registration_head"] = registration_head

    def _make_signer(self) -> None:
        if not (shutil.which("gpg") and shutil.which("gpgv") and
                shutil.which("gpgconf")):
            raise unittest.SkipTest(
                "GPG, GPGV, and gpgconf are required for the pinned signer fixture",
            )
        home = self.temporary_root / "signer-home"
        home.mkdir(mode=0o700)
        self.signer_home = home
        subprocess.run([
            shutil.which("gpg"), "--batch", "--quiet", "--homedir", str(home),
            "--passphrase", "", "--quick-generate-key",
            "Source5 preparatory fixture <fixture@example.invalid>",
            "ed25519", "sign", "0",
        ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60)
        listing = subprocess.run([
            shutil.which("gpg"), "--batch", "--with-colons", "--fingerprint",
            "--homedir", str(home),
        ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30).stdout.decode("ascii")
        fingerprints = [row.split(":")[9] for row in listing.splitlines()
                        if row.startswith("fpr:")]
        if len(fingerprints) != 1:
            raise AssertionError("ephemeral fixture GPG key did not yield one primary fingerprint")
        fingerprint = fingerprints[0]
        exported = subprocess.run([
            shutil.which("gpg"), "--batch", "--quiet", "--homedir", str(home),
            "--export", fingerprint,
        ], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30).stdout
        keyring_path = self.temporary_root / "trusted-fixture.gpg"
        write_private(keyring_path, exported)
        gpgv_path = Path(shutil.which("gpgv")).resolve(strict=True)
        gpgv_raw = gpgv_path.read_bytes()
        signer_body = {
            "schema": self.controller.ARCHIVE_SIGNER_CONTEXT_SCHEMA_V1,
            "campaign_id": self.spec["campaign_id"], "host_id": self.host_id,
            "authorized_primary_fingerprint": fingerprint,
            "maximum_signature_bytes": 4096,
            "keyring_pin": {"path": str(keyring_path), "raw_sha256": digest(exported)},
            "gpgv_pin": {"path": str(gpgv_path), "raw_sha256": digest(gpgv_raw)},
            "signature_format": "binary_detached_primary_sha256_v1",
        }
        signer = {**signer_body,
                  "signer_context_sha256": digest(
                      self.fixture_campaign.canonical_bytes(signer_body),
                  )}
        signer_raw = self.fixture_campaign.canonical_bytes(signer)
        signer_path = self.temporary_root / "archive-signer-context.json"
        write_private(signer_path, signer_raw)
        self.signer_context = signer
        self.signer_pin = {
            "path": str(signer_path), "raw_sha256": digest(signer_raw),
            "semantic_sha256": signer["signer_context_sha256"],
        }

    def close(self) -> None:
        if not hasattr(self, "signer_home"):
            return
        subprocess.run([
            shutil.which("gpgconf"), "--homedir", str(self.signer_home),
            "--kill", "gpg-agent",
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)

    def _load_selected_modules(self) -> None:
        controller = self.controller
        source_root = self.fixture.root
        source = self.fixture.manifests[self.host_id]
        selected_context = {
            relative: pin for relative, pin in self.module_pins.items()
        }
        relatives = {
            "scripts/application-campaign.py",
            "scripts/application-campaign-inputs.py",
            "scripts/application-campaign-chronology.py",
            "scripts/application-fixed-pair.py",
            "scripts/application-pressure-pair.py",
            "scripts/application-byte-capacity.py",
            "scripts/application-feedback-readback.py",
            "scripts/application-source5-input-preparation.py",
            "scripts/application-source5-evidence-budget.py",
            "scripts/application-source5-evidence-catalogue.py",
            "scripts/application-source5-preparatory-budget.py",
        }
        self.modules = {}
        for relative in sorted(relatives):
            pin = selected_context[relative]
            source_path = source_root / relative
            raw, actual, info = controller.read_stable(
                source_path, f"synthetic typed Source module {relative}",
                controller.MAX_SCRIPT_BYTES,
            )
            typed_row = next(row for row in source["source"]["files"]
                             if row["path"] == relative)
            mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
            if (actual != pin["sha256"] or len(raw) != typed_row["size"] or
                    mode != typed_row["mode"]):
                raise AssertionError(f"fixture module {relative} changed its typed Source pin")
            module = controller._load_module(raw, source_path, relative.replace("/", "_"))
            module.__source5_typed_pin__ = dict(pin)
            self.modules[relative] = module
        self.campaign = self.modules["scripts/application-campaign.py"]
        self.chronology = self.modules["scripts/application-campaign-chronology.py"]
        self.fixed_pair = self.modules["scripts/application-fixed-pair.py"]
        self.pressure_pair = self.modules["scripts/application-pressure-pair.py"]
        self.inputs_module = self.modules["scripts/application-campaign-inputs.py"]
        self.input_preparation = self.modules[
            "scripts/application-source5-input-preparation.py"]
        self.budget_module = self.modules[
            EVIDENCE_BUDGET_PATH.relative_to(SCRIPTS.parent).as_posix()]
        self.catalogue_module = self.modules[
            EVIDENCE_CATALOGUE_PATH.relative_to(SCRIPTS.parent).as_posix()]
        self.prep_module = self.modules[
            PREPARATORY_PATH.relative_to(SCRIPTS.parent).as_posix()]

    def _make_context(self) -> None:
        controller = self.controller
        campaign = self.campaign
        host_order = [host["host_id"] for host in self.spec["hosts"]]
        source_pins = {
            host_id: {
                "path": str(self.fixture.manifest_paths[host_id]),
                "raw_sha256": self.fixture.manifest_raw_shas[host_id],
            }
            for host_id in host_order
        }
        source_refs = {
            host_id: {
                "artifact": {
                    "path": source_pins[host_id]["path"],
                    "raw_sha256": source_pins[host_id]["raw_sha256"],
                },
                "semantic_sha256": self.fixture.manifests[host_id]["manifest_sha256"],
            }
            for host_id in host_order
        }
        observed_hosts = {
            host_id: {"artifact": self.observed_pins[host_id]}
            for host_id in host_order
        }
        execution_sources = {
            host_id: {
                "source_root": str(self.fixture.root),
                "git_commit": self.git_commit,
                "source_tree_sha256": self.source_tree_sha256,
                "build_sha256": self.campaign.digest_object(
                    self.fixture.manifests[host_id]["build"],
                ),
            }
            for host_id in host_order
        }
        module_maps = {host_id: copy.deepcopy(self.module_pins)
                       for host_id in host_order}
        core = {
            "schema": controller.PREPARATORY_EXECUTION_SCHEMA,
            "campaign_id": self.spec["campaign_id"], "host_id": self.host_id,
            "hosts": host_order,
            "original_inputs": {
                "spec": {"artifact": self.spec_pin,
                         "semantic_sha256": self.spec_semantic},
                "plan": {"artifact": self.plan_pin,
                         "semantic_sha256": self.plan_semantic},
                "source_manifests": source_refs,
                "campaign_artifacts_root": str(self.fixture.oracle_root),
            },
            "execution_sources": execution_sources,
            "modules": module_maps,
            "observed_hosts": observed_hosts,
            "artifact_root": str(self.artifact_root),
            "output_root": str(self.output_root),
            "scope": controller.PREPARATORY_SCOPE,
            "phase_order": ["exploration"],
            "protocol_sha256": campaign.digest_object(self.spec["protocol"]),
            "preparatory_capacity_generation": {
                "completion": self.generation_completion,
                "provenance": self.generation["provenance"],
            },
            "preparatory_capacity_registration": self.registration,
            "archive_signer_contexts": {
                self.host_id: {
                    "artifact": {
                        "path": self.signer_pin["path"],
                        "raw_sha256": self.signer_pin["raw_sha256"],
                    },
                    "semantic_sha256": self.signer_pin["semantic_sha256"],
                },
            },
            "qualification_eligible": False,
        }
        basis = self.prep_module.build_execution_basis(core)
        source = self.fixture.manifests[self.host_id]
        owner_source_bytes = {
            path: (self.fixture.root / path).read_bytes()
            for path in self.catalogue_module.OWNER_PATHS.values()
        }
        owner_contract = self.catalogue_module.inspect_owner_evidence_contracts(
            source, owner_source_bytes,
        )
        with mock.patch.object(
                self.input_preparation, "read_preparation_intent",
                return_value=(self.preparation_value, self.fixture.manifests,
                             self.campaign, self.inputs_module)):
            prepared_host = \
                self.input_preparation.materialize_prepared_host_binding(
                    self.preparation_pin,
                    {"path": self.spec_pin["path"],
                     "sha256": self.spec_pin["raw_sha256"]},
                    self.fixture.root, self.fixture.input_root, self.host_id,
                )
        manifest_path = (self.artifact_root / self.spec["campaign_id"] /
                         "source5" / self.host_id /
                         "preparatory-execution-manifest-v1.json")
        self.context = controller.CampaignContext(
            manifest=core, manifest_pin={"path": str(manifest_path),
                                         "raw_sha256": "f" * 64},
            scope=controller.PREPARATORY_SCOPE, host_id=self.host_id,
            spec=self.spec, plan=self.plan, plan_raw=self.plan_raw,
            spec_pin=self.spec_pin, plan_pin=self.plan_pin,
            spec_semantic_sha256=self.spec_semantic,
            plan_semantic_sha256=self.plan_semantic,
            source_root=self.fixture.root, input_root=self.fixture.input_root,
            artifact_root=self.artifact_root, output_root=self.output_root,
            source=source, sources=self.fixture.manifests,
            source_manifest_pins=source_pins,
            observed_host_pin=self.observed_pins[self.host_id],
            capacity_completion={
                "artifact": {
                    "path": self.registration["host_completion"]["path"],
                    "raw_sha256": self.registration["host_completion"]["raw_sha256"],
                },
                "schedule_sha256": self.registration["capacity_schedule_sha256"],
                "ledger_raw_sha256": self.registration["ledger"]["raw_sha256"],
                "terminal_head": self.registration["ledger"]["terminal_head"],
                "registration_head": self.registration["registration_head"],
            },
            prepared_input_completion=None, campaign=self.campaign,
            chronology=self.chronology, fixed_pair=self.fixed_pair,
            pressure_pair=self.pressure_pair, modules=self.modules,
            owner_evidence_contract=owner_contract,
            archive_signer_context=self.signer_context,
            archive_signer_context_pin=self.signer_pin,
            preparatory_capacity_generation=self.generation,
            preparatory_capacity_registration=self.registration,
            preparatory_execution_basis_sha256=basis,
            fixed_spec_host_pin=prepared_host["fixed_spec_host_pin"],
            prepared_fixed_host_binding=prepared_host[
                "prepared_host_binding"],
            source5_archive_read_ordinal=0,
            source5_archive_read_event_count=0,
            source5_archive_read_previous_sha256="0" * 64,
            source5_archive_read_ledger_loaded=False,
            journal_width_tmpdir_budget={
                "resource_budget_pin": self.generation["resource_budgets"][self.host_id],
                "maximum_tmpdir_bytes": self.fixed_pair.MAX_TMPDIR_BYTES,
                "maximum_tmpdir_inodes": self.fixed_pair.MAX_TMPDIR_INODES,
            },
        )
        self.reservation_path = self.artifact_root / "storage-reservation.json"
        self.manifest_path = manifest_path

    def _reserve_from_exact_catalogue(self) -> None:
        context = self.context
        controller = self.controller
        campaign_id = self.spec["campaign_id"]
        roots = [
            (self.artifact_root, "artifact"),
            (self.output_root, "output"),
            (self.scratch_root, "scratch"),
            (self.evidence_root, "evidence_store"),
        ]
        preliminary_roots = [{
            "path": str(path), "role": role,
            "reserved_bytes": 1024 * 1024,
            "reserved_inodes": 1024,
            "filesystem_id": str(path.stat().st_dev),
        } for path, role in roots]
        reservation_value = self.budget_module.build_storage_reservation_value(
            campaign_id, self.host_id, preliminary_roots,
        )
        reservation_raw = self.budget_module._canonical(reservation_value)
        write_private(self.reservation_path, reservation_raw)
        reservation_pin = {
            "path": str(self.reservation_path),
            "raw_sha256": digest(reservation_raw),
            "semantic_sha256": reservation_value["reservation_sha256"],
            "byte_count": len(reservation_raw),
        }
        projection = controller._source5_preparatory_width_projection(context)
        width = projection["contract"]
        width_path = (self.artifact_root / campaign_id / "source5" /
                      self.host_id / "evidence-budget" /
                      "preparatory-journal-width-v1.json")
        width_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        width_raw = controller.canonical_bytes(width)
        width_sha = controller.write_new(
            width_path, width_raw, "synthetic prep fixture width contract",
        )
        width_pin = {"path": str(width_path), "raw_sha256": width_sha,
                     "semantic_sha256": width["contract_sha256"]}
        # Mirror the production builder's temporary width/budget context
        # before previewing path rows, then restore the prepared context so
        # the actual fixed-point producer starts from its original state.
        metadata_names = (
            "preparatory_width_contract", "preparatory_width_pin",
            "journal_width_contract", "journal_width_contract_pin",
            "journal_width_budget_pin", "preparatory_budget_pin",
            "host_evidence_budget_pin",
        )
        previous_metadata = {
            name: getattr(context, name) for name in metadata_names
        }
        budget_path = (width_path.parent /
                       "host-evidence-budget-preparatory-v1.json")
        placeholder_budget_pin = {
            "path": str(budget_path), "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
        }
        context.preparatory_width_contract = width
        context.preparatory_width_pin = width_pin
        context.journal_width_contract = width
        context.journal_width_contract_pin = width_pin
        context.journal_width_budget_pin = dict(placeholder_budget_pin)
        context.preparatory_budget_pin = dict(placeholder_budget_pin)
        context.host_evidence_budget_pin = dict(placeholder_budget_pin)
        try:
            path_rows, _job_rows, job_catalogue_pins, _archive_caps, _read_caps, _schedule, _control, _slots, catalogue_dir, scratch = \
                controller._source5_preparatory_path_rows(
                    context, reservation_value, reservation_pin, width_pin,
                    1,
                )
        finally:
            for name, value in previous_metadata.items():
                setattr(context, name, value)
        restored_metadata = {
            name: getattr(context, name) for name in metadata_names
        }
        if restored_metadata != previous_metadata:
            raise AssertionError(
                "temporary path-row preview metadata did not restore its previous values"
            )
        catalogue_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        catalogue = self.budget_module.write_path_catalogue_chunks(
            path_rows, catalogue_dir, scratch_directory_value=scratch,
        )
        policy = catalogue["retention_policy"]
        required_bytes = dict(policy["maximum_live_root_byte_bounds"])
        required_inodes = dict(policy["maximum_live_root_inode_bounds"])
        for row in reservation_value["roots"]:
            required_bytes.setdefault(row["path"], 0)
            required_inodes.setdefault(row["path"], 0)
        artifact_path = str(self.artifact_root)
        required_bytes[artifact_path] += sum(
            chunk["byte_count"] for chunk in catalogue["chunks"]
        )
        required_inodes[artifact_path] += len(catalogue["chunks"])
        scratch_path = str(self.scratch_root)
        required_bytes[scratch_path] = max(
            required_bytes[scratch_path],
            policy["persistent_root_byte_bounds"].get(scratch_path, 0) +
            catalogue["maximum_sort_scratch_bytes"],
        )
        required_inodes[scratch_path] = max(
            required_inodes[scratch_path],
            policy["persistent_root_inode_bounds"].get(scratch_path, 0) +
            catalogue["maximum_sort_scratch_inodes"],
        )
        # Remove the estimate catalogue before the real fixed-point producer;
        # the producer must start from its normal empty deterministic slot.
        controller._source5_discard_preparatory_catalogue_chunks(
            catalogue_dir, catalogue,
        )
        # The preflight estimate created the exact job-row files and width
        # document only to obtain source-derived catalogue bounds.  Remove
        # those declared setup outputs so the actual builder starts at its
        # normal pre-owner frontier and creates them itself.
        for pin in job_catalogue_pins.values():
            Path(pin["path"]).unlink()
        width_path.unlink()
        self.reservation_path.unlink()
        current_bytes = {}
        current_inodes = {}
        for path, _role in roots:
            byte_count = 0
            inode_count = 1
            for child in path.rglob("*"):
                info = child.lstat()
                inode_count += 1
                if stat.S_ISREG(info.st_mode):
                    byte_count += info.st_size
                elif stat.S_ISLNK(info.st_mode):
                    byte_count += len(os.readlink(child).encode("utf-8"))
            current_bytes[str(path)] = byte_count
            current_inodes[str(path)] = inode_count
        final_roots = []
        for path, role in roots:
            root_path = str(path)
            final_roots.append({
                "path": root_path, "role": role,
                "reserved_bytes": (required_bytes[root_path] +
                                   current_bytes[root_path] + 2 * 1024 * 1024),
                "reserved_inodes": (required_inodes[root_path] +
                                    current_inodes[root_path] + 256),
                "filesystem_id": str(path.stat().st_dev),
            })
        final_reservation = self.budget_module.build_storage_reservation_value(
            campaign_id, self.host_id, final_roots,
        )
        final_raw = self.budget_module._canonical(final_reservation)
        write_private(self.reservation_path, final_raw)
        same_device_required = {}
        for row in final_reservation["roots"]:
            same_device_required[row["filesystem_id"]] = \
                same_device_required.get(row["filesystem_id"], 0) + row["reserved_bytes"]
        for device, amount in same_device_required.items():
            path_on_device = next(path for path, _role in roots
                                  if str(path.stat().st_dev) == device)
            usage = os.statvfs(path_on_device)
            current_available = usage.f_bavail * usage.f_frsize
            if amount >= current_available:
                raise unittest.SkipTest(
                    "actual fixture filesystem lacks room for the complete source-derived prep reserve",
                )

    def build(self) -> dict:
        self._reserve_from_exact_catalogue()
        artifacts = self.controller._source5_preparatory_budget_ready_for_manifest(
            self.context, self.reservation_path,
        )
        core = self.controller._source5_preparatory_core_value(self.context)
        manifest_body = {
            **core,
            "preparatory_journal_width_contracts": {
                self.host_id: {
                    "artifact": {
                        "path": artifacts["width_pin"]["path"],
                        "raw_sha256": artifacts["width_pin"]["raw_sha256"],
                    },
                    "semantic_sha256": artifacts["width_pin"]["semantic_sha256"],
                },
            },
            "preparatory_host_budgets": {
                self.host_id: {
                    "artifact": {
                        "path": artifacts["budget_pin"]["path"],
                        "raw_sha256": artifacts["budget_pin"]["raw_sha256"],
                    },
                    "semantic_sha256": artifacts["budget_pin"]["semantic_sha256"],
                },
            },
            "preparatory_execution_basis_sha256":
                self.context.preparatory_execution_basis_sha256,
        }
        manifest = self.prep_module.seal_execution_manifest(manifest_body)
        manifest_raw = self.controller.canonical_bytes(manifest)
        write_private(self.manifest_path, manifest_raw)
        self.context.manifest = manifest
        self.context.manifest_pin = {
            "path": str(self.manifest_path), "raw_sha256": digest(manifest_raw),
        }
        self.controller._validate_source5_preparatory_profile_artifacts(
            self.context, artifacts["width"], artifacts["width_pin"],
            artifacts["budget"], artifacts["budget_raw"], artifacts["budget_pin"],
        )
        return {
            **artifacts, "manifest": manifest,
            "manifest_raw": manifest_raw,
            "source_manifest_raw": self.fixture_campaign.canonical_bytes(
                self.fixture.manifests[self.host_id],
            ),
        }

    def validator(self, budget: dict, manifest: dict, raw_catalogue: dict[str, bytes] | None = None) -> None:
        reader = self.controller._source5_preparatory_catalogue_row_reader(
            self.context, self.budget_module, budget["path_catalogue"],
        ) if raw_catalogue is None else _reader_for(raw_catalogue)
        self.prep_module.validate_host_evidence_budget_v1(
            budget,
            expected_campaign_id=self.spec["campaign_id"],
            expected_host_id=self.host_id,
            owner_catalogue_module=self.catalogue_module,
            expected_execution_basis_sha256=self.context.preparatory_execution_basis_sha256,
            expected_width_pin=self.context.preparatory_width_pin,
            expected_width=self.context.preparatory_width_contract,
            execution_manifest_raw=self.controller.canonical_bytes(manifest),
            source_manifest_raw=self.fixture_campaign.canonical_bytes(
                self.fixture.manifests[self.host_id],
            ),
            plan_raw=self.plan_raw,
            width_contract_raw=self.controller.canonical_bytes(
                self.context.preparatory_width_contract,
            ),
            catalogue_module=self.budget_module,
            campaign_module=self.campaign,
            input_preparation_module=self.input_preparation,
            spec_raw=self.controller.canonical_bytes(self.spec),
            catalogue_row_reader=reader,
        )


def _reader_for(chunks: dict[str, bytes]):
    def read(path: str, maximum_bytes: int) -> bytes:
        raw = chunks.get(path)
        if raw is None or len(raw) != maximum_bytes:
            raise OSError("fixture reader refused an undeclared catalogue chunk")
        return raw
    return read


def _budget_manifest_pair(fixture: PreparatoryProducerFixture,
                          budget: dict) -> dict:
    prep = fixture.prep_module
    manifest = copy.deepcopy(fixture.context.manifest)
    body = {key: value for key, value in manifest.items()
            if key != "manifest_sha256"}
    body["preparatory_host_budgets"] = {
        fixture.host_id: {
            "artifact": {
                "path": fixture.context.preparatory_budget_pin["path"],
                "raw_sha256": digest(fixture.controller.canonical_bytes(budget)),
            },
            "semantic_sha256": budget["budget_sha256"],
        },
    }
    return prep.seal_execution_manifest(body)


class PreparatoryProducerPathTests(unittest.TestCase):
    def test_real_360_job_builder_restore_and_full_validator_mutants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-full-producer-") as directory:
            fixture = PreparatoryProducerFixture(Path(directory))
            try:
                artifacts = fixture.build()
                budget = artifacts["budget"]
                self.assertEqual(len(fixture.context.plan["jobs"]["exploration"]), 1080)
                self.assertEqual(len(budget["read_schedule"]), 360)
                rows = list(fixture.budget_module.iter_path_catalogue_rows(
                    budget["path_catalogue"],
                ))
                self.assertEqual(len(rows), len({row["path"] for row in rows}))
                aggregate_rows = [row for row in rows
                                  if row["aggregate_id"] is not None]
                aggregate_by_run = {
                    job["run_id"]: "fixed-output-" +
                    digest(fixture.controller.canonical_bytes(job))
                    for job in fixture.controller._host_jobs(
                        fixture.context, "exploration",
                    )
                }
                aggregate_ids = {row["aggregate_id"]
                                 for row in aggregate_rows}
                self.assertEqual(set(aggregate_by_run.values()), aggregate_ids)
                self.assertEqual(len(aggregate_ids), 360)
                self.assertTrue(all(
                    len(aggregate_id) <= 96 and
                    aggregate_id[0].isalnum() and
                    all(character.isalnum() or character in "._-"
                        for character in aggregate_id)
                    for aggregate_id in aggregate_ids
                ))
                pair_limit = fixture.context.owner_evidence_contract[
                    "fixed_pair"]["limits"]["MAX_PAIR_OUTPUT_BYTES"]
                for run_id, aggregate_id in aggregate_by_run.items():
                    members = [row for row in aggregate_rows
                               if row["run_id"] == run_id]
                    self.assertTrue(members)
                    self.assertEqual(
                        {row["aggregate_id"] for row in members},
                        {aggregate_id},
                    )
                    self.assertEqual(
                        {row["aggregate_max_bytes"] for row in members},
                        {pair_limit},
                    )
                for malformed in ("fixed-output:bad", "x" * 97):
                    mutant = copy.deepcopy(aggregate_rows[0])
                    mutant["aggregate_id"] = malformed
                    with self.subTest(aggregate_id=malformed[:20]):
                        with self.assertRaises(
                                fixture.budget_module.BudgetPlanError):
                            fixture.budget_module._catalogue_row(
                                mutant, "mutated aggregate group row",
                            )
                directory_rows = [row for row in rows
                                  if row["role"] == "directory_node"]
                directory_paths = {row["path"] for row in directory_rows}
                selected_jobs = fixture.controller._host_jobs(
                    fixture.context, "exploration",
                )
                job_roots = {
                    str(fixture.artifact_root / fixture.spec["campaign_id"] /
                        "source5" / fixture.host_id / "job-artifacts" /
                        "exploration" / job["run_id"])
                    for job in selected_jobs
                }
                self.assertEqual(len(selected_jobs), 360)
                self.assertEqual(len(job_roots), 360)
                self.assertTrue(job_roots <= directory_paths)
                tree_roots = {row["path"] for row in rows
                              if row["kind"] == "tree" and
                              row["role"] != "directory_node"}
                self.assertTrue(directory_paths.isdisjoint(tree_roots))
                expected_directories = set()
                for row in rows:
                    storage_root = row["storage_root"]
                    if storage_root is None:
                        continue
                    path = Path(row["path"])
                    root = Path(storage_root)
                    self.assertTrue(path.is_relative_to(root))
                    current = path if row["role"] == "directory_node" else path.parent
                    while current.is_relative_to(root):
                        expected_directories.add(str(current))
                        if current == root:
                            break
                        current = current.parent
                self.assertEqual(directory_paths, expected_directories)
                for row in directory_rows:
                    path = Path(row["path"])
                    matching_roots = [root for root in job_roots
                                      if path.is_relative_to(Path(root))]
                    if matching_roots:
                        self.assertEqual(len(matching_roots), 1)
                        run_id = Path(matching_roots[0]).name
                        self.assertEqual(
                            (row["owner"], row["phase"], row["run_id"]),
                            ("fixed_pair", "exploration", run_id),
                        )
                    else:
                        self.assertEqual(
                            (row["owner"], row["phase"], row["run_id"]),
                            ("source5_controller", None, None),
                        )
                self.assertEqual(len(budget["schedule"]["maximum_job_record_bytes_by_ordinal"]), 360)
                self.assertEqual(len(fixture.context.source5_archive_read_schedule), 360)
                self.assertEqual(fixture.context.source5_archive_read_ordinal, 0)
                self.assertFalse(budget["readiness"]["qualification_eligible"])
                self.assertFalse(budget["readiness"]["full_horizon_execution_ready"])
                pilot_rows = [row for row in fixture.budget_module.iter_path_catalogue_rows(
                    budget["path_catalogue"],
                ) if row["role"] == "capacity_artifact" and
                    row["phase"] == "exploration" and
                    row["owner"] == "source5_controller"]
                self.assertEqual(len(pilot_rows), 1)
                pilot_row = pilot_rows[0]
                pilot_maximum = fixture.input_preparation.capacity_pilot_maximum_bytes(
                    fixture.spec, fixture.host_id, fixture.campaign.ALLOCATORS,
                    fixture.campaign.preregistration_digest(fixture.spec),
                )
                self.assertEqual(pilot_row, {
                    "path": str(fixture.output_root / fixture.spec["campaign_id"] /
                                "source5" / fixture.host_id / "exploration" /
                                "capacity-pilot.json"),
                    "kind": "file", "role": "capacity_artifact",
                    "host_id": fixture.host_id,
                    "max_bytes": pilot_maximum,
                    "max_file_bytes": pilot_maximum,
                    "max_inodes": 1,
                    "storage_root": str(fixture.output_root),
                    "owner": "source5_controller", "phase": "exploration",
                    "run_id": None, "member_index": None,
                    "aggregate_id": None, "aggregate_max_bytes": None,
                    "origin_pin": None,
                })
                fixture.validator(budget, artifacts["manifest"])

                swapped = copy.deepcopy(budget)
                owner = swapped["owner_contract"]
                pins = owner["owner_source_pins"]
                pins["fixed_pair"], pins["pressure_pair"] = (
                    pins["pressure_pair"], pins["fixed_pair"],
                )
                owner["owner_contract_sha256"] = digest(
                    fixture.controller.canonical_bytes({
                        key: value for key, value in owner.items()
                        if key != "owner_contract_sha256"
                    }),
                )
                swapped["budget_sha256"] = digest(
                    fixture.controller.canonical_bytes({
                        key: value for key, value in swapped.items()
                        if key != "budget_sha256"
                    }),
                )
                swapped_manifest = _budget_manifest_pair(fixture, swapped)
                with self.assertRaises(fixture.prep_module.PreparatoryBudgetError):
                    fixture.validator(swapped, swapped_manifest)

                rows = list(fixture.budget_module.iter_path_catalogue_rows(
                    budget["path_catalogue"],
                ))
                for mutated_role in (
                        "source5_archive_read_stage",
                        fixture.budget_module.SOURCE5_ARCHIVE_READ_CONTROL_ROLE):
                    mutated_rows = copy.deepcopy(rows)
                    selected = [row for row in mutated_rows
                                if row["role"] == mutated_role]
                    self.assertEqual(len(selected), 1)
                    selected[0]["max_bytes"] = 1
                    selected[0]["max_file_bytes"] = 1
                    if mutated_role == "source5_archive_read_stage":
                        selected[0]["max_inodes"] = 1
                    mutant_dir = (fixture.temporary_root / "mutant-catalogues" /
                                  mutated_role)
                    mutant_dir.mkdir(mode=0o700, parents=True)
                    mutant_catalogue = fixture.budget_module.write_path_catalogue_chunks(
                        mutated_rows, mutant_dir,
                        scratch_directory_value=fixture.scratch_root,
                    )
                    raw_chunks = {}
                    for chunk in mutant_catalogue["chunks"]:
                        raw, raw_sha, info = fixture.controller.read_stable(
                            Path(chunk["path"]),
                            "synthetic mutated prep catalogue chunk",
                            chunk["byte_count"], chunk["raw_sha256"],
                        )
                        self.assertTrue(stat.S_ISREG(info.st_mode))
                        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                        self.assertEqual(info.st_nlink, 1)
                        self.assertEqual(raw_sha, chunk["semantic_sha256"])
                        raw_chunks[chunk["path"]] = raw
                    mutant_budget = copy.deepcopy(budget)
                    mutant_budget["path_catalogue"] = mutant_catalogue
                    mutant_budget["budget_sha256"] = digest(
                        fixture.controller.canonical_bytes({
                            key: value for key, value in mutant_budget.items()
                            if key != "budget_sha256"
                        }),
                    )
                    mutant_manifest = _budget_manifest_pair(fixture, mutant_budget)
                    with self.subTest(role=mutated_role):
                        with self.assertRaises(fixture.prep_module.PreparatoryBudgetError):
                            fixture.validator(
                                mutant_budget, mutant_manifest, raw_chunks,
                            )

                def reject_capacity_catalogue_mutation(
                    mutation_name: str, mutated_rows: list[dict],
                ) -> None:
                    mutant_dir = (fixture.temporary_root / "mutant-catalogues" /
                                  f"capacity-pilot-{mutation_name}")
                    mutant_dir.mkdir(mode=0o700, parents=True)
                    mutant_catalogue = fixture.budget_module.write_path_catalogue_chunks(
                        mutated_rows, mutant_dir,
                        scratch_directory_value=fixture.scratch_root,
                    )
                    raw_chunks = {}
                    for chunk in mutant_catalogue["chunks"]:
                        raw, raw_sha, _info = fixture.controller.read_stable(
                            Path(chunk["path"]),
                            "synthetic capacity-pilot catalogue mutation",
                            chunk["byte_count"], chunk["raw_sha256"],
                        )
                        self.assertEqual(raw_sha, chunk["semantic_sha256"])
                        raw_chunks[chunk["path"]] = raw
                    mutant_budget = copy.deepcopy(budget)
                    mutant_budget["path_catalogue"] = mutant_catalogue
                    mutant_budget["budget_sha256"] = digest(
                        fixture.controller.canonical_bytes({
                            key: value for key, value in mutant_budget.items()
                            if key != "budget_sha256"
                        }),
                    )
                    mutant_manifest = _budget_manifest_pair(fixture, mutant_budget)
                    with self.subTest(capacity_pilot=mutation_name):
                        with self.assertRaises(
                                fixture.prep_module.PreparatoryBudgetError):
                            fixture.validator(
                                mutant_budget, mutant_manifest, raw_chunks,
                            )

                pilot_index = next(
                    index for index, row in enumerate(rows)
                    if row["path"] == pilot_row["path"]
                )
                omitted_pilot = copy.deepcopy(rows)
                omitted_pilot.pop(pilot_index)
                reject_capacity_catalogue_mutation("omitted", omitted_pilot)
                changed_path_pilot = copy.deepcopy(rows)
                changed_path_pilot[pilot_index]["path"] += ".changed"
                reject_capacity_catalogue_mutation("path", changed_path_pilot)
                changed_cap_pilot = copy.deepcopy(rows)
                changed_cap_pilot[pilot_index]["max_bytes"] -= 1
                changed_cap_pilot[pilot_index]["max_file_bytes"] -= 1
                reject_capacity_catalogue_mutation("cap", changed_cap_pilot)
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
