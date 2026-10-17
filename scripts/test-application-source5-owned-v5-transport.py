#!/usr/bin/env python3
"""Structural V5 transport fixtures; these never establish SourceA authority."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parent


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, digit="a"):
    return {"path": path, "raw_sha256": digit * 64, "semantic_sha256": digit * 64}


def wrapper(value):
    return {"artifact": {key: value[key] for key in ("path", "raw_sha256")},
            "semantic_sha256": value["semantic_sha256"]}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPT_DIR / name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PreparedV5TransportProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = load("application-source5-evidence-archive.py")
        cls.packet = load("application-source5-evidence-transfer-packet.py")
        cls.targets = (cls.archive, cls.packet)

    def fixture(self, owned=True):
        signer = pin("/inputs/signer-a.json", "b")
        execution = {
            "schema": "allocatbelt.application-source5-campaign-execution.v5",
            "campaign_id": "campaign-a", "hosts": ["host-a", "host-b"],
            "original_inputs": {}, "execution_sources": {}, "modules": {},
            "observed_hosts": {}, "artifact_root": "/artifacts", "output_root": "/output",
            "phase_order": ["exploration", "aa", "confirmation", "fixed_analysis",
                            "pressure", "pressure_analysis", "soak", "final_analysis"],
            "protocol_sha256": "a" * 64,
            "qualification_eligible": False, "scope": "final_prepared_exploration_reuse",
            "prepared_input_generation": {}, "prepared_capacity_registration": {},
            "archive_signer_contexts": {
                "host-a": wrapper(signer), "host-b": wrapper(pin("/inputs/signer-b.json", "c")),
            },
            "journal_width_contracts": {
                host: wrapper(pin("/inputs/width-" + host + ".json", "d"))
                for host in ("host-a", "host-b")
            },
        }
        if owned:
            execution["prepared_replay_inputs"] = {
                host: pin("/inputs/replay-" + host + ".json", "e")
                for host in ("host-a", "host-b")
            }
        execution["manifest_sha256"] = digest(canonical(execution))
        raw = canonical(execution)
        execution_pin = {"path": "/inputs/execution.json", "raw_sha256": digest(raw),
                         "semantic_sha256": execution["manifest_sha256"]}
        context = {"campaign_id": "campaign-a", "host_id": "host-a",
                   "execution_manifest_pin": execution_pin}
        return execution, raw, execution_pin, signer, context

    def repin(self, execution):
        body = {key: value for key, value in execution.items() if key != "manifest_sha256"}
        execution["manifest_sha256"] = digest(canonical(body))
        return {"path": "/inputs/execution.json", "raw_sha256": digest(canonical(execution)),
                "semantic_sha256": execution["manifest_sha256"]}

    def test_exact_owned_profile_map_is_data_only(self):
        for module in self.targets:
            value, *_ = self.fixture()
            before = copy.deepcopy(value)
            with patch.object(module, "_read_absolute_private_file", create=True,
                              side_effect=AssertionError("profile IO")), \
                    patch.object(module, "_read_regular_absolute", create=True,
                                 side_effect=AssertionError("profile IO")):
                self.assertEqual(module._prepared_execution_replay_profile_fields_v1(value),
                                 {"prepared_replay_inputs"})
            self.assertEqual(value, before)
            self.assertNotIn("verified", value)

    def test_legacy_v5_has_no_owned_profile_field(self):
        for module in self.targets:
            value, *_ = self.fixture(owned=False)
            self.assertEqual(module._prepared_execution_replay_profile_fields_v1(value), set())

    def test_owned_profile_map_rejects_wrong_cohort_pin_or_alias(self):
        cases = (
            lambda value: value["prepared_replay_inputs"].pop("host-b"),
            lambda value: value["prepared_replay_inputs"].update({"extra": pin("/extra")}),
            lambda value: value["prepared_replay_inputs"]["host-a"].update({"proof": True}),
            lambda value: value["prepared_replay_inputs"]["host-a"].update({"path": "relative"}),
            lambda value: value["prepared_replay_inputs"]["host-a"].update({"raw_sha256": True}),
            lambda value: value["prepared_replay_inputs"].update({
                "host-b": copy.deepcopy(value["prepared_replay_inputs"]["host-a"])}),
            lambda value: value.update({"hosts": ["host-a", "host-a"]}),
            lambda value: value.update({"hosts": ["host-a", "host-b", "host-c"]}),
            lambda value: value.update({"schema": "allocatbelt.application-source5-campaign-execution.v4"}),
        )
        for module in self.targets:
            for index, mutate in enumerate(cases):
                with self.subTest(module=module.__name__, case=index):
                    value, *_ = self.fixture()
                    mutate(value)
                    with self.assertRaises(ValueError):
                        module._prepared_execution_replay_profile_fields_v1(value)

    def test_v5_signer_binding_accepts_only_structural_identity(self):
        for module in self.targets:
            for owned in (False, True):
                value, _, execution_pin, signer, context = self.fixture(owned)
                self.assertIsNone(module._validate_prepared_execution_signer_binding_v1(
                    value, execution_pin, signer, context))
                self.assertNotIn("replay_scope", value)

    def test_v5_signer_requires_widths_without_caller_opt_in(self):
        for module in self.targets:
            value, _, execution_pin, signer, context = self.fixture()
            del value["journal_width_contracts"]
            with self.assertRaises(ValueError):
                module._validate_prepared_execution_signer_binding_v1(
                    value, execution_pin, signer, context)

    def test_v5_signer_rejects_exact_identity_scope_digest_and_extra_fields(self):
        cases = (
            lambda value: value.update({"scope": "final_prepared_bounded"}),
            lambda value: value.update({"campaign_id": "other"}),
            lambda value: value.update({"hosts": ["host-b", "host-c"]}),
            lambda value: value.update({"qualification_eligible": True}),
            lambda value: value.update({"manifest_sha256": "f" * 64}),
            lambda value: value.update({"verified": True}),
            lambda value: value["archive_signer_contexts"]["host-a"].update({"semantic_sha256": "f" * 64}),
            lambda value: value["journal_width_contracts"]["host-a"].update({"path": "/flat-pin"}),
        )
        for module in self.targets:
            for index, mutate in enumerate(cases):
                with self.subTest(module=module.__name__, case=index):
                    value, _, execution_pin, signer, context = self.fixture()
                    mutate(value)
                    if index != 4:  # Preserve the deliberately corrupted self digest.
                        execution_pin = self.repin(value)
                        context["execution_manifest_pin"] = execution_pin
                    with self.assertRaises(ValueError):
                        module._validate_prepared_execution_signer_binding_v1(
                            value, execution_pin, signer, context)

    def test_archive_actual_signer_dispatch_supports_both_v5_shapes(self):
        for owned in (False, True):
            _, raw, execution_pin, signer, context = self.fixture(owned)
            for require_width in (False, True):
                self.assertEqual(self.archive._validate_execution_manifest_signer_context(
                    raw, execution_pin, signer, context,
                    require_width_contract=require_width), execution_pin)
        value, _, _, signer, context = self.fixture()
        del value["journal_width_contracts"]
        execution_pin = self.repin(value)
        context["execution_manifest_pin"] = execution_pin
        with self.assertRaises(ValueError):
            self.archive._validate_execution_manifest_signer_context(
                canonical(value), execution_pin, signer, context,
                require_width_contract=False)

    def test_packet_actual_signer_dispatch_supports_both_v5_shapes(self):
        module = self.packet
        for owned in (False, True):
            value, _, _, _, context = self.fixture(owned)
            body = {
                "schema": module.ARCHIVE_SIGNER_CONTEXT_SCHEMA,
                "campaign_id": "campaign-a", "host_id": "host-a",
                "authorized_primary_fingerprint": "A" * 40,
                "maximum_signature_bytes": 4096,
                "keyring_pin": {"path": "/keys/keyring.gpg", "raw_sha256": "a" * 64},
                "gpgv_pin": {"path": "/usr/bin/gpgv", "raw_sha256": "b" * 64},
                "signature_format": "binary_detached_primary_sha256_v1",
            }
            signer_value = {**body, "signer_context_sha256": digest(canonical(body))}
            signer_raw = canonical(signer_value)
            signer = {"path": "/inputs/signer-a.json", "raw_sha256": digest(signer_raw),
                      "semantic_sha256": signer_value["signer_context_sha256"]}
            value["archive_signer_contexts"]["host-a"] = wrapper(signer)
            execution_pin = self.repin(value)
            context.update({"execution_manifest_pin": execution_pin,
                            "authorized_signer_fingerprint": "A" * 40})
            for require_width in (False, True):
                result = module._validate_archive_signer_context(
                    signer_raw, signer, context, 4096, execution_pin, canonical(value),
                    require_width_contract=require_width)
                self.assertEqual(result["execution_manifest_pin"], execution_pin)
                self.assertNotIn("replay_scope", result)

    def test_v4_cannot_import_owned_profile_extension(self):
        for module in self.targets:
            value, *_ = self.fixture()
            value["schema"] = "allocatbelt.application-source5-campaign-execution.v4"
            with self.assertRaises(ValueError):
                module._prepared_execution_replay_profile_fields_v1(value)


if __name__ == "__main__":
    unittest.main()
