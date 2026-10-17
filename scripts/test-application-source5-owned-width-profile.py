#!/usr/bin/env python3
"""Focused contracts for the pre-manifest Source5 width/profile boundary."""
from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


CONTROLLER_PATH = Path(__file__).with_name("application-source5-campaign.py")
SCRIPTS_DIR = CONTROLLER_PATH.parent


def load_controller():
    return load_source_module(
        "source5_owned_width_profile_contract", CONTROLLER_PATH,
    )


def load_source_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {CONTROLLER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def module_function(tree: ast.Module, name: str) -> ast.FunctionDef:
    matches = [node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one module function {name}, got {len(matches)}")
    return matches[0]


class Source5OwnedWidthProfileContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_controller()
        cls.tree = ast.parse(
            CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH),
        )
        cls.campaign_inputs = load_source_module(
            "source5_owned_width_campaign_inputs_contract",
            SCRIPTS_DIR / "application-campaign-inputs.py",
        )
        cls.campaign_module = load_source_module(
            "source5_owned_width_campaign_contract",
            SCRIPTS_DIR / "application-campaign.py",
        )
        cls.inputprep = load_source_module(
            "source5_owned_width_inputprep_contract",
            SCRIPTS_DIR / "application-source5-input-preparation.py",
        )
        cls.soak = load_source_module(
            "source5_owned_width_soak_contract",
            SCRIPTS_DIR / "application-source5-soak.py",
        )
        cls.recipe_fixtures = load_source_module(
            "source5_owned_width_recipe_fixtures",
            SCRIPTS_DIR / "test-application-soak-recipe.py",
        )

    def test_public_builders_are_callable_with_closed_data_only_signatures(self) -> None:
        width = self.module.build_source5_prepared_exploration_width_pre_manifest_v1
        profile = self.module.build_source5_owned_replay_input_profile_v1
        self.assertTrue(callable(width))
        self.assertTrue(callable(profile))
        self.assertEqual(
            list(inspect.signature(width).parameters),
            ["prepared_inputs", "completion_pin", "provenance_v2",
             "pressure_material_index_pin", "soak_material_index_pin",
             "execution_manifest_path", "host_evidence_budget_path",
             "output_path"],
        )
        self.assertEqual(
            list(inspect.signature(profile).parameters),
            ["prepared_inputs", "value", "output_path"],
        )
        self.assertEqual(
            [p.name for p in inspect.signature(width).parameters.values()
             if p.kind is inspect.Parameter.KEYWORD_ONLY],
            ["execution_manifest_path", "host_evidence_budget_path", "output_path"],
        )
        self.assertEqual(
            [p.name for p in inspect.signature(profile).parameters.values()
             if p.kind is inspect.Parameter.KEYWORD_ONLY],
            ["output_path"],
        )
        legacy = inspect.signature(self.module.build_source5_journal_width_contract)
        self.assertEqual(
            list(legacy.parameters),
            ["context", "pressure_material_index", "soak_material_index",
             "host_evidence_budget_path", "output_path"],
        )
        self.assertTrue(all(
            parameter.default is inspect.Parameter.empty
            for parameter in legacy.parameters.values()
        ))

    def test_required_private_width_helpers_are_real_module_callables(self) -> None:
        names = (
            "_source5_width_is_data",
            "_source5_width_campaign_id",
            "_source5_width_selected_module_pins",
            "_source5_width_completion",
            "_source5_width_execution_manifest_pin",
            "_source5_width_capacity_completion",
            "_source5_width_original_pins",
            "_source5_width_tmpdir_budget",
            "_source5_width_cleanup_source_bytes",
            "_source5_width_soak_materials",
            "_source5_width_load_typed_modules",
            "_source5_width_raw3_pin",
            "_source5_width_root",
            "_source5_width_read_raw3_json",
            "_source5_width_body_semantic_sha256",
            "_source5_width_verify_raw3_body_pin",
            "_source5_width_validate_preparation_generation",
            "_source5_width_require_current_input_control",
            "_source5_width_check_soak_budget_binding",
            "_source5_width_validate_premanifest_soak_materials",
            "_source5_width_prepare_identity_inputs",
            "_source5_journal_width_materials",
            "_source5_journal_width_owner_pins",
            "_source5_width_data_from_context",
            "_source5_width_data_from_identity",
            "_source5_build_journal_width_v1",
            "_source5_width_future_slot_path",
            "_source5_catalogue_prepared_completion",
            "source5_journal_width_projection",
            "_source5_file_semantic_digest",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(self.module, name, None)))
                module_function(self.tree, name)

    def test_premanifest_soak_index_is_a_typed_data_only_producer(self) -> None:
        name = (
            "build_source5_prepared_exploration_soak_material_index_pre_manifest_v1"
        )
        producer = getattr(self.module, name, None)
        self.assertTrue(callable(producer))
        node = module_function(self.tree, name)
        self.assertEqual(
            list(inspect.signature(producer).parameters),
            ["prepared_inputs", "completion_pin", "provenance_v2",
             "parent_recipe_pin", "build_receipt_pin", "resource_budget_pin",
             "output_path"],
        )
        self.assertEqual(
            [parameter.name for parameter in
             inspect.signature(producer).parameters.values()
             if parameter.kind is inspect.Parameter.KEYWORD_ONLY],
            ["output_path"],
        )
        source = ast.unparse(node)
        for required in (
            "_source5_width_prepare_identity_inputs(",
            "_selected_prepared_host_binding(",
            "make_material_index(",
            "_source5_width_validate_premanifest_soak_materials(",
            "_source5_width_future_slot_path(", "write_new(",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for forbidden in (
            "CampaignContext", "create_soak_material_index(",
            "source5_execution_manifest",
            "execution_manifest_path", "prepared_exploration_proofs",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        output_calls = [
            call for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and
            call.func.id == "_source5_width_future_slot_path" and
            call.args and isinstance(call.args[0], ast.Name) and
            call.args[0].id == "output_path"
        ]
        self.assertEqual(len(output_calls), 1)
        self.assertEqual(ast.unparse(output_calls[0].args[2]), "artifact_root")
        common = module_function(
            self.tree, "_source5_width_validate_premanifest_soak_materials",
        )
        common_source = ast.unparse(common)
        for required in (
            "validate_material_index(",
            "_verify_build_receipt(", "_read_resource_budget_pin(",
            "_resource_budget_module_pin(",
            "_source5_width_check_soak_budget_binding(",
        ):
            with self.subTest(common_required=required):
                self.assertIn(required, common_source)
        self.assertIn("path.is_relative_to(artifact_root)", common_source)
        consumer = module_function(self.tree, "_source5_journal_width_materials")
        self.assertIn(
            "_source5_width_validate_premanifest_soak_materials(",
            ast.unparse(consumer),
        )
        minimal_prepared = next(
            value.value for value in ast.walk(common)
            if isinstance(value, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == "minimal_prepared"
                for target in value.targets)
        )
        self.assertEqual(
            {key.value for key in minimal_prepared.keys
             if isinstance(key, ast.Constant) and isinstance(key.value, str)},
            {"campaign_id", "host_id", "source_root", "source",
             "source_manifest_raw_refs", "prepared"},
        )
        self.assertIn("qualification_eligible", source)
        self.assertIn("index['materials_sha256']", source)

    def test_shared_premanifest_soak_verifier_checks_actual_receipt_pins(self) -> None:
        with tempfile.TemporaryDirectory(
                prefix="allocatbelt-source5-width-soak-verify-") as temporary:
            temp_root = Path(temporary)
            fixture = self.recipe_fixtures.SourceV5CliFixture(
                temp_root,
                aa_controls_override=(
                    self.recipe_fixtures.SourceV5CliFixture.
                    synthetic_a48_controls()
                ),
            )
            host_id = fixture.job["host_id"]
            recipe_path = fixture.output / "parent-recipe.json"
            receipt_path = fixture.output / "recipe-build-receipt.json"
            build = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "application-soak-recipe.py"),
                    "build", "--spec", str(fixture.spec_path),
                    "--spec-sha256", fixture.spec_sha256,
                    "--plan", str(fixture.plan_path),
                    "--plan-sha256", fixture.plan_sha256,
                    "--plan-file-sha256", fixture.plan_file_sha256,
                    "--job-run-id", fixture.job["run_id"],
                    "--source-root", str(fixture.root),
                    "--oracle-root", str(fixture.oracle_root),
                    "--ring-relative-path",
                    fixture.ring_path.relative_to(fixture.oracle_root).as_posix(),
                    "--ring-sha256", fixture.ring_sha256,
                    "--mode", "functional", "--duration-seconds", "2",
                    "--terminal-budget-bytes", str(2 * 1024 * 1024),
                    "--sample-budget-bytes", str(2 * 1024 * 1024),
                    "--construction-probe", str(fixture.construction_probe_path),
                    "--construction-probe-sha256",
                    fixture.construction_probe_sha256,
                    "--output", str(recipe_path),
                ],
                cwd="/", stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=180, check=False,
            )
            self.assertEqual(
                build.returncode, 0,
                build.stderr.decode("utf-8", errors="replace"),
            )
            receipt_value = json.loads(build.stdout.decode("utf-8"))
            receipt_path.write_bytes(build.stdout)

            def selected_module(relative: str):
                path = fixture.root / relative
                raw = path.read_bytes()
                record = next(
                    row for row in fixture.manifests[host_id]["source"]["files"]
                    if row["path"] == relative
                )
                self.assertEqual(self.module.sha256(raw), record["sha256"])
                self.assertEqual(len(raw), record["size"])
                return self.module._load_module(
                    raw, path, relative.replace("/", "_").replace(".", "_"),
                )

            selected_soak = selected_module("scripts/application-source5-soak.py")
            selected_readback = selected_module("scripts/application-soak-readback.py")

            def binding_for(selected_host: str) -> dict:
                body = {
                    "schema": "allocatbelt.application-source5-fixed-pair-host-binding.v1",
                    "host_id": selected_host,
                    "fixed_spec_host_pin": {
                        "path": str(fixture.spec_path),
                        "raw_sha256": fixture.spec_sha256,
                    },
                    "prepared_host_context_pin": {
                        "path": str(fixture.input_root / "host-context.json"),
                        "raw_sha256": "a" * 64,
                    },
                    "spec_host_semantic_sha256": "b" * 64,
                    "boot_id_sha256": "c" * 64,
                    "kernel_release": "synthetic-unit-fixture",
                    "controls_sha256": "d" * 64,
                    "process_affinity": [0],
                    "network_namespace_inode": 1,
                }
                return {
                    **body,
                    "binding_sha256": selected_soak.sha256(
                        selected_soak.canonical_bytes(body),
                    ),
                }

            completion = {
                "schema": "allocatbelt.application-source5-preparation-completion.v1",
                "source_manifests": {
                    selected_host: {
                        "path": str(fixture.manifest_paths[selected_host]),
                        "raw_sha256": fixture.manifest_raw_shas[selected_host],
                        "semantic_sha256": fixture.manifests[selected_host][
                            "manifest_sha256"],
                        "source_tree_sha256": fixture.manifests[selected_host][
                            "source"]["source_tree_sha256"],
                    }
                    for selected_host in fixture.host_ids
                },
                "pilots": [{
                    "host_id": selected_host,
                    "prepared_host_binding": binding_for(selected_host),
                } for selected_host in fixture.host_ids],
            }
            source_manifest_pins = {
                selected_host: {
                    "path": str(fixture.manifest_paths[selected_host]),
                    "raw_sha256": fixture.manifest_raw_shas[selected_host],
                    "semantic_sha256": fixture.manifests[selected_host][
                        "manifest_sha256"],
                }
                for selected_host in fixture.host_ids
            }
            identity = {
                "campaign_id": fixture.spec["campaign_id"],
                "host_id": host_id,
                "roots": {
                    "artifact_root": fixture.output,
                    "source_root": fixture.root,
                },
                "completion": completion,
                "observed_host_pin": binding_for(host_id)[
                    "prepared_host_context_pin"
                ],
                "jobs_by_phase": {"pressure": [], "soak": [fixture.job]},
                "modules": {
                    "scripts/application-source5-soak.py": selected_soak,
                    "scripts/application-soak-readback.py": selected_readback,
                },
                "source_manifest_pins": source_manifest_pins,
                "sources": fixture.manifests,
                "cohort_hosts": list(fixture.host_ids),
                "source": fixture.manifests[host_id],
                "spec_pin": {
                    "path": str(fixture.spec_path),
                    "raw_sha256": fixture.spec_sha256,
                },
                "spec_semantic_sha256": fixture.spec_sha256,
                "plan_pin": {
                    "path": str(fixture.plan_path),
                    "raw_sha256": fixture.plan_file_sha256,
                },
                "plan_semantic_sha256": fixture.plan_sha256,
            }
            recipe_pin = {
                "path": str(recipe_path),
                "raw_sha256": self.module.sha256(recipe_path.read_bytes()),
            }
            receipt_pin = {
                "path": str(receipt_path),
                "raw_sha256": self.module.sha256(receipt_path.read_bytes()),
            }
            binding = selected_soak._selected_prepared_host_binding(
                completion, host_id,
            )

            def index_for(selected_receipt_pin: dict) -> dict:
                return selected_soak.make_material_index(
                    identity["campaign_id"], host_id, fixture.job,
                    recipe_pin, selected_receipt_pin,
                    binding["binding_sha256"],
                )

            pressure_body = {
                "schema": self.module.PRESSURE_MATERIAL_INDEX_SCHEMA_V2,
                "campaign_id": identity["campaign_id"],
                "host_id": host_id,
                "jobs": {},
            }
            pressure_index = {
                **pressure_body,
                "manifest_sha256": self.module.sha256(
                    self.module.canonical_bytes(pressure_body),
                ),
            }
            pressure_path = fixture.output / "empty-pressure-index.json"
            pressure_raw = self.module.canonical_bytes(pressure_index)
            pressure_path.write_bytes(pressure_raw)
            pressure_pin = {
                "path": str(pressure_path),
                "raw_sha256": self.module.sha256(pressure_raw),
            }

            def write_soak_index(selected_receipt_pin: dict, name: str) -> dict:
                raw = self.module.canonical_bytes(index_for(selected_receipt_pin))
                path = fixture.output / name
                path.write_bytes(raw)
                return {"path": str(path), "raw_sha256": self.module.sha256(raw)}

            verified = self.module._source5_width_validate_premanifest_soak_materials(
                identity, index_for(receipt_pin),
            )
            self.assertEqual(verified["index"]["job"], fixture.job)
            self.assertEqual(
                verified["receipt_identity"]["build_receipt_sha256"],
                receipt_pin["raw_sha256"],
            )
            with self.assertRaisesRegex(
                    self.module.Source5CampaignError,
                    "requires its exact bounded Soak resource budget"):
                self.module._source5_journal_width_materials(
                    identity, pressure_pin,
                    write_soak_index(receipt_pin, "valid-v1-index.json"),
                )

            wrong_hash_pin = {**receipt_pin, "raw_sha256": "f" * 64}
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_width_validate_premanifest_soak_materials(
                    identity, index_for(wrong_hash_pin),
                )
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_journal_width_materials(
                    identity, pressure_pin,
                    write_soak_index(wrong_hash_pin, "wrong-receipt-pin-index.json"),
                )
            for field in (
                "spec_sha256", "plan_sha256",
                "source_manifest_semantic_sha256",
                "source_manifest_file_sha256", "source_tree_sha256",
            ):
                changed_receipt = dict(receipt_value)
                changed_receipt[field] = "f" * 64
                changed_path = fixture.output / f"receipt-with-wrong-{field}.json"
                changed_raw = self.module.canonical_bytes(changed_receipt)
                changed_path.write_bytes(changed_raw)
                changed_pin = {
                    "path": str(changed_path),
                    "raw_sha256": self.module.sha256(changed_raw),
                }
                with self.subTest(field=field), self.assertRaises(
                        self.module.Source5CampaignError):
                    self.module._source5_width_validate_premanifest_soak_materials(
                        identity, index_for(changed_pin),
                    )

    def _generation_join_fixture(self, input_root: Path) -> dict:
        hosts = ["agent-A", "agent-B"]
        refs = []
        source_pins = {}
        sources = {}
        source_manifest_pins = {}
        observed_hosts = {}
        for index, host in enumerate(hosts, 1):
            relative = f"sources/{host}.json"
            raw_sha = f"{index + 2:064x}"
            semantic_sha = f"{index + 4:064x}"
            tree_sha = f"{index + 6:064x}"
            refs.append({
                "host_id": host, "relative_path": relative,
                "sha256": semantic_sha,
            })
            source_pins[host] = {
                "manifest": {
                    "relative_path": relative, "raw_sha256": raw_sha,
                    "semantic_sha256": semantic_sha,
                    "source_tree_sha256": tree_sha,
                },
                "modules": {}, "artifacts": {},
            }
            sources[host] = {
                "manifest_sha256": semantic_sha,
                "source": {"source_tree_sha256": tree_sha},
            }
            source_manifest_pins[host] = {
                "path": str(input_root / relative),
                "raw_sha256": raw_sha,
                "semantic_sha256": semantic_sha,
            }
            observed_relative = f"hosts/{host}.json"
            observed_hosts[host] = {
                "relative_path": observed_relative,
                "raw_sha256": f"{index + 8:064x}",
            }
        spec = {
            "schema": self.campaign_inputs.SPEC_V3_SCHEMA,
            "campaign_id": "join-fixture-campaign",
            "runner_sha256": "a" * 64,
            "hosts": [{"host_id": host} for host in hosts],
            "cells": [], "protocol": {}, "runtime_binding": {},
            "phase_adapters": {}, "aa_controls": {}, "soak": {},
            "deadlines": {}, "source_manifests": refs,
            "rates": [], "oracles": [], "qualification_inputs": {},
        }
        core = self.campaign_inputs.preparation_core_from_spec(spec)
        preparation = {
            "core": core,
            "source_pins": source_pins,
            "observed_hosts": observed_hosts,
        }
        preparation_sources = copy.deepcopy(sources)
        host_id = hosts[0]
        observed_pin = {
            "path": str(input_root / observed_hosts[host_id]["relative_path"]),
            "raw_sha256": observed_hosts[host_id]["raw_sha256"],
        }
        observed = {"host_id": host_id}
        plan = {
            "spec_sha256": self.module.sha256(self.module.canonical_bytes(spec)),
            "source_manifests": {
                host: sources[host]["manifest_sha256"] for host in hosts
            },
        }
        plan_pin = {
            "path": str(input_root / "plan.json"),
            "raw_sha256": "b" * 64,
            "semantic_sha256": "c" * 64,
        }
        return {
            "prepared_inputs": {"host_id": host_id},
            "cohort_hosts": hosts, "spec": spec,
            "spec_semantic": plan["spec_sha256"], "plan": plan,
            "plan_pin": plan_pin, "plan_semantic": plan_pin["semantic_sha256"],
            "sources": sources, "source_manifest_pins": source_manifest_pins,
            "observed": observed, "observed_pin": observed_pin,
            "preparation": preparation,
            "preparation_sources": preparation_sources,
            "preparation_inputs": self.campaign_inputs,
            "inputprep": self.inputprep,
            "campaign_inputs": self.campaign_inputs,
            "input_root": input_root,
        }

    def _validate_generation_join(self, values: dict) -> None:
        self.module._source5_width_validate_preparation_generation(**values)

    def test_raw3_reader_separates_raw_hash_from_source_body_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            spec = {
                "schema": "allocatbelt.application-campaign-spec.v3",
                "campaign_id": "semantic-fixture",
            }
            spec_raw = self.module.canonical_bytes(spec)
            spec_path = root / "spec.json"
            spec_path.write_bytes(spec_raw)
            spec_pin = {
                "path": str(spec_path),
                "raw_sha256": self.module.sha256(spec_raw),
                "semantic_sha256": self.module.sha256(spec_raw),
            }
            spec_loaded, _spec_raw, _checked_spec_pin = \
                self.module._source5_width_read_raw3_json(
                    spec_pin, "Spec full-object semantic fixture", 4096,
                    root=root,
                )
            self.assertEqual(
                self.module.sha256(self.module.canonical_bytes(spec_loaded)),
                spec_pin["semantic_sha256"],
            )
            roles = (
                ("plan_sha256", "allocatbelt.application-campaign-plan.v3"),
                ("manifest_sha256", "allocatbelt.application-source-manifest.v5"),
                ("completion_sha256",
                 self.inputprep.PREPARED_BOUNDED_COMPLETION_SCHEMA),
                ("resource_budget_sha256",
                 self.campaign_inputs.SOURCE5_PREPARATION_RESOURCE_BUDGET_SCHEMA),
            )
            for index, (field, schema) in enumerate(roles):
                with self.subTest(field=field):
                    body = {"schema": schema, "payload": {"ordinal": index}}
                    envelope = {
                        **body,
                        field: self.module.sha256(self.module.canonical_bytes(body)),
                    }
                    raw = self.module.canonical_bytes(envelope)
                    path = root / f"{field}.json"
                    path.write_bytes(raw)
                    pin = {
                        "path": str(path),
                        "raw_sha256": self.module.sha256(raw),
                        "semantic_sha256": envelope[field],
                    }
                    loaded, loaded_raw, checked_pin = \
                        self.module._source5_width_read_raw3_json(
                            pin, field, 4096, root=root,
                        )
                    self.assertEqual((loaded, loaded_raw, checked_pin),
                                     (envelope, raw, pin))
                    self.assertNotEqual(pin["semantic_sha256"],
                                        self.module.sha256(raw))
                    self.assertEqual(
                        self.module._source5_width_verify_raw3_body_pin(
                            loaded, pin, field, field,
                        ),
                        pin["semantic_sha256"],
                    )
                    self.assertEqual(
                        self.module._source5_width_verify_raw3_body_pin(
                            loaded, pin, field, field,
                        ),
                        self.campaign_module.digest_object(loaded, field),
                    )
                    bad_pin = {**pin, "semantic_sha256": self.module.sha256(raw)}
                    with self.assertRaises(self.module.Source5CampaignError):
                        self.module._source5_width_verify_raw3_body_pin(
                            loaded, bad_pin, field, field,
                        )

    def test_generation_join_uses_actual_core_and_source_reference_validators(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            valid = self._generation_join_fixture(root)
            self._validate_generation_join(valid)
            failures = []

            def copy_inputs():
                # Keep the actual typed modules; copy only mutable fixture data.
                return copy.deepcopy(valid, {
                    id(module): module
                    for module in (self.campaign_inputs, self.inputprep)
                })

            bad_plan = copy_inputs()
            bad_plan["plan"]["spec_sha256"] = "f" * 64
            failures.append(bad_plan)
            bad_core = copy_inputs()
            bad_core["preparation"]["core"]["campaign_id"] = "another-campaign"
            failures.append(bad_core)
            bad_source = copy_inputs()
            host = bad_source["cohort_hosts"][0]
            bad_source["preparation"]["source_pins"][host]["manifest"]["raw_sha256"] = "f" * 64
            failures.append(bad_source)
            bad_observed = copy_inputs()
            bad_observed["preparation"]["observed_hosts"][host]["raw_sha256"] = "f" * 64
            failures.append(bad_observed)
            for index, value in enumerate(failures):
                with self.subTest(index=index):
                    with self.assertRaises(self.module.Source5CampaignError):
                        self._validate_generation_join(value)

    def test_public_identity_initializer_reaches_source_loading_boundary(self) -> None:
        class SourceLoadingReached(Exception):
            pass

        with tempfile.TemporaryDirectory(
                prefix="allocatbelt-source5-width-source-boundary-") as temporary:
            root = Path(temporary).resolve()
            source_root = root / "source"
            input_root = root / "inputs"
            artifact_root = root / "artifacts"
            output_root = root / "output"
            campaign_root = root / "campaign-artifacts"
            for path in (source_root, input_root, artifact_root,
                         output_root, campaign_root):
                path.mkdir(mode=0o700 if path in {artifact_root, output_root} else 0o755)
            (input_root / "sources").mkdir()
            hosts = ["agent-A", "agent-B"]
            source_values = {}
            source_pins = {}
            source_refs = []
            for index, host in enumerate(hosts, 1):
                base = {
                    "schema": "allocatbelt.application-source-manifest.v5",
                    "campaign_id": "initializer-boundary-campaign",
                    "host_id": host,
                    "source": {"source_tree_sha256": f"{index:064x}"},
                }
                source_semantic = self.module.sha256(
                    self.module.canonical_bytes(base),
                )
                source = {**base, "manifest_sha256": source_semantic}
                relative = f"sources/{host}.json"
                raw = self.module.canonical_bytes(source)
                path = input_root / relative
                path.write_bytes(raw)
                source_values[host] = source
                source_pins[host] = {
                    "pin": {
                        "path": str(path),
                        "raw_sha256": self.module.sha256(raw),
                        "semantic_sha256": source_semantic,
                    },
                    "value": source,
                }
                source_refs.append({
                    "host_id": host, "relative_path": relative,
                    "sha256": source_semantic,
                })
            spec = {
                "schema": "allocatbelt.application-campaign-spec.v3",
                "campaign_id": "initializer-boundary-campaign",
                "hosts": [{"host_id": host} for host in hosts],
                "source_manifests": source_refs,
                "rates": [{"fixture": True}],
                "oracles": [{"fixture": True}],
            }
            spec_raw = self.module.canonical_bytes(spec)
            spec_path = input_root / "campaign-spec.json"
            spec_path.write_bytes(spec_raw)
            spec_semantic = self.module.sha256(spec_raw)
            plan_body = {
                "schema": "allocatbelt.application-campaign-plan.v3",
                "campaign_id": spec["campaign_id"],
                "host_ids": hosts,
                "spec_sha256": spec_semantic,
                "source_manifests": {
                    host: source_values[host]["manifest_sha256"]
                    for host in hosts
                },
            }
            plan = {
                **plan_body,
                "plan_sha256": self.module.sha256(
                    self.module.canonical_bytes(plan_body),
                ),
            }
            plan_raw = self.module.canonical_bytes(plan)
            plan_path = input_root / "campaign-plan.json"
            plan_path.write_bytes(plan_raw)
            prepared_inputs = {
                "schema": self.module.SOURCE5_WIDTH_PREPARED_INPUTS_SCHEMA,
                "campaign_id": spec["campaign_id"],
                "host_id": hosts[0], "cohort_hosts": hosts,
                "roots": {
                    "source_root": str(source_root),
                    "input_root": str(input_root),
                    "artifact_root": str(artifact_root),
                    "output_root": str(output_root),
                    "campaign_artifacts_root": str(campaign_root),
                },
                "spec": {
                    "pin": {
                        "path": str(spec_path),
                        "raw_sha256": self.module.sha256(spec_raw),
                        "semantic_sha256": spec_semantic,
                    },
                    "value": spec,
                },
                "plan": {
                    "pin": {
                        "path": str(plan_path),
                        "raw_sha256": self.module.sha256(plan_raw),
                        "semantic_sha256": plan["plan_sha256"],
                    },
                    "value": plan,
                },
                "source_manifests": source_pins,
                "observed_host": {"pin": {}, "value": {}},
                "ancestor": None,
            }
            with patch.object(
                    self.module, "_source5_width_load_typed_modules",
                    side_effect=SourceLoadingReached):
                with self.assertRaises(SourceLoadingReached):
                    self.module._source5_width_prepare_identity_inputs(
                        prepared_inputs, {}, {},
                    )

    def test_current_input_width_policy_is_scoped_to_owned_v5(self) -> None:
        with tempfile.TemporaryDirectory(
                prefix="allocatbelt-source5-width-route-paths-") as temporary:
            root = Path(temporary).resolve()
            input_root = root / "inputs"
            artifact_root = root / "artifacts"
            input_root.mkdir()
            artifact_root.mkdir()
            legacy_width = artifact_root / "agent-A-width.json"
            width_raw = self.module.canonical_bytes({"schema": "legacy-v4-width"})
            legacy_width.write_bytes(width_raw)
            for legacy_route in ("legacy V4", "legacy V5"):
                legacy_path = self.module._source5_width_require_current_input_control(
                    legacy_width, input_root, f"{legacy_route} width",
                    owned_v5_profile_variant=False,
                )
                checked_raw, checked_sha, _info = self.module.read_stable(
                    legacy_path, f"{legacy_route} artifact-root width",
                    len(width_raw), self.module.sha256(width_raw),
                )
                self.assertEqual(checked_raw, width_raw)
                self.assertEqual(checked_sha, self.module.sha256(width_raw))
            owned_width = input_root / "agent-A-owned-width.json"
            self.assertEqual(
                self.module._source5_width_require_current_input_control(
                    owned_width, input_root, "owned V5 width",
                    owned_v5_profile_variant=True,
                ),
                owned_width,
            )
            with patch.object(
                    self.module, "read_stable",
                    side_effect=AssertionError("must refuse before reading")):
                with self.assertRaises(self.module.Source5CampaignError):
                    self.module._source5_width_require_current_input_control(
                        legacy_width, input_root, "owned V5 width",
                        owned_v5_profile_variant=True,
                    )

    def test_owned_premanifest_builders_reject_unexpected_authority_inputs_first(self) -> None:
        base = {
            "schema": self.module.SOURCE5_WIDTH_PREPARED_INPUTS_SCHEMA,
            "campaign_id": "closed-dto-campaign",
            "host_id": "agent-A",
            "cohort_hosts": ["agent-A", "agent-B"],
            "roots": {}, "spec": None, "plan": None,
            "source_manifests": {}, "observed_host": None,
            "ancestor": None,
        }
        for extra in ("manifest", "module", "provider", "reader", "proof"):
            prepared = {**base, extra: object()}
            with self.subTest(extra=extra), patch.object(
                    self.module, "_source5_width_root",
                    side_effect=AssertionError("DTO rejection must precede path reads")):
                with self.assertRaises(self.module.Source5CampaignError):
                    self.module.build_source5_prepared_exploration_width_pre_manifest_v1(
                        prepared, {}, {}, {}, {},
                        execution_manifest_path=Path("/unused/future.json"),
                        host_evidence_budget_path=Path("/unused/budget.json"),
                    )
                with self.assertRaises(self.module.Source5CampaignError):
                    self.module.build_source5_owned_replay_input_profile_v1(
                        prepared, {},
                    )

    def test_soak_budget_binding_rejects_each_stable_pin_mismatch(self) -> None:
        expected = {
            "campaign_id": "budget-bind-campaign",
            "host_id": "agent-A",
            "job_sha256": "1" * 64,
            "source_manifest": {
                "path": "/inputs/source.json",
                "raw_sha256": "2" * 64,
                "semantic_sha256": "3" * 64,
            },
            "source_tree_sha256": "4" * 64,
            "parent_recipe": {
                "path": "/artifacts/recipe.json",
                "raw_sha256": "5" * 64,
            },
            "build_receipt": {
                "path": "/artifacts/receipt.json",
                "raw_sha256": "6" * 64,
            },
            "prepared_host_binding_sha256": "7" * 64,
            "observed_host": {
                "path": "/inputs/observed.json",
                "raw_sha256": "8" * 64,
            },
            "monitor_owner": {
                "path": "scripts/application-fixed-pair.py",
                "raw_sha256": "9" * 64, "mode": "100644", "size": 1024,
            },
            "soak_adapter": {
                "path": "scripts/application-source5-soak.py",
                "raw_sha256": "a" * 64, "mode": "100644", "size": 2048,
            },
            "soak_reader": {
                "path": "scripts/application-soak-readback.py",
                "raw_sha256": "b" * 64, "mode": "100644", "size": 4096,
            },
        }
        self.assertIsNone(
            self.module._source5_width_check_soak_budget_binding(
                copy.deepcopy(expected), expected,
            ),
        )
        for key in (
            "job_sha256", "source_manifest", "source_tree_sha256",
            "parent_recipe", "build_receipt",
            "prepared_host_binding_sha256", "observed_host",
            "monitor_owner", "soak_adapter", "soak_reader",
        ):
            changed = copy.deepcopy(expected)
            if type(changed[key]) is dict:
                first = next(iter(changed[key]))
                changed[key][first] = "f" * 64
            else:
                changed[key] = "f" * 64
            with self.subTest(key=key), self.assertRaises(
                    self.module.Source5CampaignError):
                self.module._source5_width_check_soak_budget_binding(
                    changed, expected,
                )

    def test_raw2_width_consumer_rejects_repinned_noncanonical_soak_bytes_first(self) -> None:
        with tempfile.TemporaryDirectory(
                prefix="allocatbelt-source5-width-noncanonical-index-") as temporary:
            artifact_root = Path(temporary).resolve()
            campaign_id = "canonicality-campaign"
            host_id = "agent-A"
            job = {
                "phase": "soak", "run_id": "soak-canonicality-0",
                "host_id": host_id, "ordinal": 0,
            }
            index = self.soak.make_material_index(
                campaign_id, host_id, job,
                {"path": str(artifact_root / "recipe.json"),
                 "raw_sha256": "1" * 64},
                {"path": str(artifact_root / "receipt.json"),
                 "raw_sha256": "2" * 64},
                "3" * 64,
            )
            canonical = self.module.canonical_bytes(index)
            duplicate_key = (
                canonical[:-2] + b',"campaign_id":' +
                self.module.canonical_bytes(campaign_id) + b'}'
            )
            raw_variants = (
                b" " + canonical + b"\n",
                duplicate_key,
            )
            pressure_body = {
                "schema": self.module.PRESSURE_MATERIAL_INDEX_SCHEMA_V2,
                "campaign_id": campaign_id,
                "host_id": host_id,
                "jobs": {},
            }
            pressure_index = {
                **pressure_body,
                "manifest_sha256": self.module.sha256(
                    self.module.canonical_bytes(pressure_body),
                ),
            }
            pressure_raw = self.module.canonical_bytes(pressure_index)
            pressure_path = artifact_root / "pressure-index.json"
            pressure_path.write_bytes(pressure_raw)
            pressure_pin = {
                "path": str(pressure_path),
                "raw_sha256": self.module.sha256(pressure_raw),
            }
            identity = {
                "roots": {"artifact_root": artifact_root},
                "campaign_id": campaign_id,
                "host_id": host_id,
                "jobs_by_phase": {"pressure": [], "soak": [job]},
            }
            for ordinal, raw in enumerate(raw_variants):
                self.assertEqual(json.loads(raw), index)
                path = artifact_root / f"noncanonical-{ordinal}.json"
                path.write_bytes(raw)
                soak_pin = {
                    "path": str(path),
                    "raw_sha256": self.module.sha256(raw),
                }
                with self.subTest(ordinal=ordinal), patch.object(
                        self.module,
                        "_source5_width_validate_premanifest_soak_materials",
                        side_effect=AssertionError(
                            "serialization must fail before semantic validation",
                        )) as validator:
                    with self.assertRaises(self.module.Source5CampaignError):
                        self.module._source5_journal_width_materials(
                            identity, pressure_pin, soak_pin,
                        )
                    validator.assert_not_called()

    def test_owned_v5_width_and_profile_controls_use_current_input_root(self) -> None:
        width = module_function(
            self.tree,
            "build_source5_prepared_exploration_width_pre_manifest_v1",
        )
        width_output_calls = [
            node for node in ast.walk(width)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == "_source5_width_future_slot_path" and node.args and
            isinstance(node.args[0], ast.Name) and
            node.args[0].id == "output_path"
        ]
        self.assertEqual(len(width_output_calls), 1)
        self.assertEqual(ast.unparse(width_output_calls[0].args[2]), "input_root")
        profile = ast.unparse(module_function(
            self.tree, "build_source5_owned_replay_input_profile_v1",
        ))
        self.assertIn(
            "output_path.is_relative_to(identity['roots']['input_root'])",
            profile,
        )
        self.assertNotIn(
            "output_path.is_relative_to(identity['roots']['artifact_root'])",
            profile,
        )
        load = ast.unparse(module_function(self.tree, "load_context"))
        self.assertIn("profile_path.is_relative_to(input_root)", load)
        self.assertIn("_source5_width_require_current_input_control(", load)
        self.assertIn(
            "owned_v5_profile_variant = 'prepared_replay_inputs' in manifest",
            load,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            input_root = root / "inputs"
            artifact_root = root / "artifacts"
            input_root.mkdir()
            artifact_root.mkdir()
            self.assertEqual(
                self.module._source5_width_future_slot_path(
                    input_root / "width-v2.json", "test width", input_root,
                ),
                input_root / "width-v2.json",
            )
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_width_future_slot_path(
                    artifact_root / "width-v2.json", "test width", input_root,
                )

    def test_legacy_width_adapter_keeps_bounded_guard_and_old_data_fallbacks(self) -> None:
        wrapper = ast.unparse(module_function(
            self.tree, "build_source5_journal_width_contract",
        ))
        adapter = ast.unparse(module_function(
            self.tree, "_source5_width_data_from_context",
        ))
        self.assertIn("context.manifest.get('schema') in BOUNDED_EXECUTION_SCHEMAS", wrapper)
        self.assertIn("'completion'", adapter)
        self.assertIn("'completion': generation['completion']", adapter)
        self.assertNotIn("registration['completion']", adapter)
        self.assertIn("Path(budget_pin['path'])", adapter)
        self.assertIn("getattr(context, 'spec_raw', None)", adapter)
        self.assertIn("getattr(context, 'prepared_exploration_proofs', None)", adapter)

    def test_legacy_authorization_bytes_keep_the_selected_budget_pin_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            campaign_id = "legacy-width-campaign"
            host_id = "agent-A"
            budget_dir = root / campaign_id / "source5" / host_id / "evidence-budget"
            requested_budget = budget_dir / "host-evidence-budget-v2.json"
            pinned_budget = budget_dir / "host-evidence-budget-v3.json"
            budget_pin = {
                "path": str(pinned_budget), "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            }
            helper_path = "scripts/application-source5-soak.py"
            helper_sha = "c" * 64
            spec_value = {"deadlines": {"soak_outer_seconds": 7}}
            spec_raw = self.module.canonical_bytes(spec_value)
            spec_raw_sha = self.module.sha256(spec_raw)
            completion_pin = {
                "path": str(root / "prepared-inputs-completion.json"),
                "raw_sha256": "d" * 64, "semantic_sha256": "e" * 64,
            }
            source_value = {
                "manifest_sha256": "f" * 64,
                "source": {"files": [{
                    "path": helper_path, "kind": "file", "mode": "100644",
                    "sha256": helper_sha, "size": 128,
                }]},
            }
            module_pins = {
                helper_path: {"path": helper_path, "sha256": helper_sha},
            }
            soak_module = SimpleNamespace(
                soak_descriptor=lambda job: {"run_id": job["run_id"]},
            )
            registration = {
                "host_completion": {
                    "path": str(root / "host-completion.json"),
                    "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64,
                },
                "host_verification": {
                    "path": str(root / "host-verification.json"),
                    "raw_sha256": "3" * 64,
                },
                "ledger": {
                    "path": str(root / "ledger.jsonl"),
                    "raw_sha256": "4" * 64, "terminal_head": "5" * 64,
                },
                "capacity_schedule_sha256": "6" * 64,
                "registration_head": "7" * 64,
            }
            context = SimpleNamespace(
                scope="final_frozen", host_id=host_id, campaign_id=campaign_id,
                manifest={
                    "schema": self.module.EXECUTION_SCHEMA_V4,
                    "campaign_id": campaign_id, "hosts": [host_id],
                    "modules": {host_id: module_pins},
                    "original_inputs": {"campaign_artifacts_root": str(root)},
                    "prepared_input_generation": {
                        "completion": completion_pin,
                        "provenance": {"schema": "legacy-provenance"},
                    },
                    "prepared_capacity_registration": registration,
                },
                manifest_pin={"path": str(root / "manifest.json"),
                              "raw_sha256": "8" * 64},
                prepared_input_completion={
                    "capacity_preparations": [{
                        "host_id": host_id, "entries": [{"ordinal": 1}],
                    }],
                },
                source=source_value,
                sources={host_id: source_value},
                source_manifest_pins={host_id: {
                    "path": str(root / "source.json"),
                    "raw_sha256": "9" * 64,
                }},
                source_root=root, input_root=root, artifact_root=root,
                output_root=root,
                spec=spec_value,
                spec_pin={"path": str(root / "spec.json"),
                          "raw_sha256": spec_raw_sha},
                spec_semantic_sha256="b" * 64,
                plan={}, plan_raw=b"{}", plan_pin={"path": str(root / "plan.json"),
                                                   "raw_sha256": "c" * 64},
                plan_semantic_sha256="d" * 64,
                observed_host_pin={"path": str(root / "observed.json"),
                                   "raw_sha256": "e" * 64},
                campaign=None, chronology=SimpleNamespace(JOURNAL_SCHEMA="journal.v1"),
                fixed_pair=None, pressure_pair=None,
                modules={helper_path: soak_module},
                owner_evidence_contract={}, capacity_completion={
                    "artifact": {"path": str(root / "capacity.json"),
                                 "raw_sha256": "f" * 64},
                    "ledger_raw_sha256": "0" * 64,
                    "terminal_head": "1" * 64,
                    "schedule_sha256": "2" * 64,
                    "registration_head": registration["registration_head"],
                },
                journal_width_budget_pin=budget_pin,
                host_evidence_budget_pin=None,
                journal_width_soak_materials={
                    "value": {}, "parent_recipe_value": {},
                    "resource_budget_value": {},
                },
                journal_width_observed_host={},
                journal_width_cleanup_source_bytes=None,
            )
            materials = {
                "pressure_material_index_pin": {"path": str(root / "pressure.json"),
                                                "raw_sha256": "3" * 64},
                "pressure_material_index": {},
                "soak_material_index_pin": {"path": str(root / "soak.json"),
                                            "raw_sha256": "4" * 64},
                "soak_material_index": {},
                "soak_parent_recipe": {}, "soak_resource_budget": {},
            }
            original_pins = {"observed_host": {"boot_id_sha256": "5" * 64}}
            job = {
                "host_id": host_id, "run_id": "soak-run", "ordinal": 1,
                "phase": "soak", "profile": "profile-A", "allocator": "allocatbelt",
            }
            with patch.object(
                    self.module, "_source5_original_pins_for_context",
                    return_value=original_pins), patch.object(
                    self.module, "_source5_journal_jobs",
                    return_value=[]), patch.object(
                    self.module, "_source5_journal_prepared_tmpdir_budget",
                    return_value={"resource_budget_pin": budget_pin}):
                data_a = self.module._source5_width_data_from_context(
                    context, materials, requested_budget,
                )
                data_b = self.module._source5_width_data_from_context(
                    context, materials, budget_dir / "host-evidence-budget-v4.json",
                )
            self.assertEqual(data_a.spec_raw, spec_raw)
            self.assertEqual(
                self.module.sha256(data_a.spec_raw),
                context.spec_pin["raw_sha256"],
            )
            self.assertEqual(data_a.host_evidence_budget_path, pinned_budget)
            self.assertEqual(data_b.host_evidence_budget_path, pinned_budget)
            details_a, _members_a = self.module._source5_journal_authorization_details(
                data_a, "soak", 0, job, original_pins,
            )
            details_b, _members_b = self.module._source5_journal_authorization_details(
                data_b, "soak", 0, job, original_pins,
            )
            self.assertEqual(
                self.module.canonical_bytes(details_a),
                self.module.canonical_bytes(details_b),
            )
            self.assertEqual(
                details_a["host_evidence_budget"]["path"], str(pinned_budget),
            )

    def test_width_data_record_has_no_manifest_or_authority_slots(self) -> None:
        names = {field.name for field in fields(self.module._Source5JournalWidthData)}
        for forbidden in (
            "manifest", "manifest_pin", "scope", "lock", "journal_state",
            "proof", "proofs", "authority", "ready",
        ):
            self.assertNotIn(forbidden, names)

    def test_future_slot_accepts_a_normal_concrete_pathlib_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            slot = root / "future-manifest.json"
            self.assertEqual(
                self.module._source5_width_future_slot_path(
                    slot, "test future slot", root,
                ),
                slot,
            )

    def test_prepared_input_builder_uses_the_exact_data_only_dto(self) -> None:
        signature = inspect.signature(
            self.module.build_source5_prepared_exploration_width_pre_manifest_v1,
        )
        self.assertFalse({
            "module", "modules", "provider", "reader", "callback",
            "manifest", "manifest_pin", "scope", "proof", "ready",
        } & set(signature.parameters))
        identity = module_function(
            self.tree, "_source5_width_prepare_identity_inputs",
        )
        dto_fields = None
        for node in ast.walk(identity):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                    node.func.id == "exact" and len(node.args) >= 2 and
                    isinstance(node.args[0], ast.Name) and
                    node.args[0].id == "prepared_inputs_value"):
                dto_fields = ast.literal_eval(node.args[1])
                break
        self.assertEqual(dto_fields, {
            "schema", "campaign_id", "host_id", "cohort_hosts", "roots",
            "spec", "plan", "source_manifests", "observed_host", "ancestor",
        })

    def test_code_is_not_embedded_in_a_large_top_level_string(self) -> None:
        top_level_strings = [
            node for node in self.tree.body
            if isinstance(node, ast.Expr) and
            isinstance(node.value, ast.Constant) and
            type(node.value.value) is str
        ]
        self.assertEqual(len(top_level_strings), 1)
        self.assertLess(len(top_level_strings[0].value.value), 2048)
        self.assertIsInstance(self.tree.body[-1], ast.If)
        self.assertEqual(ast.unparse(self.tree.body[-1].test), "__name__ == '__main__'")

    def test_v5_load_keeps_structural_completion_out_of_replay_field(self) -> None:
        load = module_function(self.tree, "load_context")
        calls = {
            node.func.id if isinstance(node.func, ast.Name) else
            ast.unparse(node.func)
            for node in ast.walk(load) if isinstance(node, ast.Call)
        }
        self.assertNotIn("_source5_validate_prepared_exploration_context", calls)
        result_call = next(
            node for node in ast.walk(load)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == "CampaignContext"
        )
        keywords = {item.arg: item.value for item in result_call.keywords}
        self.assertEqual(
            ast.unparse(keywords["prepared_input_completion"]),
            "None if schema == EXECUTION_SCHEMA_V5 else prepared_completion",
        )
        self.assertIn("prepared_input_completion_structural", keywords)
        self.assertIn("prepared_replay_input_profile", keywords)
        self.assertEqual(
            ast.unparse(keywords["lineage_artifact_reader"]),
            "None if schema == EXECUTION_SCHEMA_V5 else lineage_artifact_reader",
        )
        v5_branches = [
            node for node in ast.walk(load)
            if isinstance(node, ast.If) and
            ast.unparse(node.test) == "schema == EXECUTION_SCHEMA_V5"
        ]
        structural_branch = max(
            v5_branches,
            key=lambda node: sum(1 for _ in ast.walk(node)),
        )
        structural_calls = {
            node.func.id if isinstance(node.func, ast.Name) else
            ast.unparse(node.func)
            for statement in structural_branch.body
            for node in ast.walk(statement)
            if isinstance(node, ast.Call)
        }
        self.assertIn("read_json", structural_calls)
        self.assertNotIn("verify_prepared_inputs_completion", structural_calls)
        self.assertIn(
            "preparation._prepared_input_replay_arguments", structural_calls,
        )
        self.assertTrue(callable(self.module._source5_catalogue_prepared_completion))

    def test_v5_catalogue_uses_only_structural_data_and_a_separate_64mib_cap(self) -> None:
        v5 = self.module.EXECUTION_SCHEMA_V5
        structural = {"schema": "structural-only"}
        context = SimpleNamespace(
            manifest={"schema": v5}, prepared_input_completion=None,
            prepared_input_completion_structural=structural,
        )
        self.assertIs(
            self.module._source5_catalogue_prepared_completion(context), structural,
        )
        context.prepared_input_completion = {"schema": "must-not-win"}
        with self.assertRaises(self.module.Source5CampaignError):
            self.module._source5_catalogue_prepared_completion(context)
        self.assertEqual(
            self.module.SOURCE5_PREPARED_INPUT_COMPLETION_MAX_BYTES,
            64 * 1024 * 1024,
        )
        semantic = module_function(self.tree, "_source5_file_semantic_digest")
        semantic_source = ast.unparse(semantic)
        self.assertIn("SOURCE5_PREPARED_INPUT_COMPLETION_MAX_BYTES", semantic_source)
        catalogue = module_function(self.tree, "_source5_path_catalogue_records")
        self.assertIn(
            "SOURCE5_PREPARED_INPUT_COMPLETION_MAX_BYTES",
            ast.unparse(catalogue),
        )


if __name__ == "__main__":
    unittest.main()
