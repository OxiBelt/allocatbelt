#!/usr/bin/env python3
"""Remote-only tests for the independent fixed runtime receipt contract."""
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

loader = importlib.machinery.SourceFileLoader(
    "runtime_readback", str(Path(__file__).with_name("application-runtime-readback.py"))
)
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def recipe(
    *,
    executor="allocatbelt",
    workload="cpu",
    profile="steady",
    mode="open_loop",
    rate=100_000,
    arrivals=1000,
    family="fixed_policy",
):
    return {
        "schema": module.RECIPE_SCHEMA,
        "identity": {
            "report_nonce": "a" * 32,
            "run_id": "fixed-run-1",
            "allocator": "allocatbelt",
            "executor": executor,
            "source_sha256": "1" * 64,
            "binary_sha256": "2" * 64,
            "comparison_family": family,
            "resource_ceiling_sha256": "3" * 64,
            "policy_sha256": "4" * 64,
        },
        "run": {
            "workload": workload,
            "profile": profile,
            "mode": mode,
            "rate_per_second": rate,
            "arrivals": arrivals,
        },
        "fixed_global_control_baseline": 4096,
    }


def fixture(*, executor="allocatbelt", workload="cpu", profile="steady", mode="open_loop"):
    run_recipe = recipe(
        executor=executor,
        workload=workload,
        profile=profile,
        mode=mode,
        rate=None if mode == "capacity" else 100_000,
        arrivals=5000 if mode == "capacity" else 1000,
    )
    expected = module.build_fixed_expectation(run_recipe)
    contract = expected["contract"]
    fields = module._expectation_rows(expected)
    baseline = contract["fixed_global_control_baseline"]
    setup_control = baseline + 4096
    fields["configuration.setup_global_control"] = str(setup_control)

    for stage in module.STAGES:
        for owner in module.OWNERS:
            for dimension, ceiling in contract["ceilings"].items():
                fields[f"{stage}.{owner}.ceiling.{dimension}"] = str(ceiling)
                fields[f"{stage}.{owner}.limit.{dimension}"] = str(ceiling)
                if dimension == "control":
                    used = 4096 if owner == "tenant" else setup_control
                else:
                    used = 0
                fields[f"{stage}.{owner}.used.{dimension}"] = str(used)
            fields[f"{stage}.{owner}.live_tenants"] = "1"

        for name, bound in contract["scope_limits"].items():
            fields[f"{stage}.scope.{name}"] = str(bound)
        for name in ("managed_memory", "disk_operations", "network_operations"):
            fields[f"{stage}.scope.{name}_used"] = "0"

        for direction, bucket in contract["byte_buckets"].items():
            for field, value in (
                ("bytes_per_second", bucket["bytes_per_second"]),
                ("ceiling_bytes_per_second", bucket["ceiling_bytes_per_second"]),
                ("burst_bytes", bucket["burst_bytes"]),
                ("ceiling_burst_bytes", bucket["ceiling_burst_bytes"]),
                ("available_bytes", bucket["burst_bytes"] if stage == "setup" else 0),
                ("reserved_bytes", 0),
                ("reservations", 0),
                ("max_reservations", bucket["max_reservations"]),
            ):
                fields[f"{stage}.io.{direction}_{field}"] = str(value)

    fields.update(
        {
            "after_release.global.live_tenants": "0",
            "after_release.global.used.control": str(baseline),
            "after_release.expected_global_control_baseline": str(baseline),
            "after_release.control_matches_fixed_baseline": "true",
        }
    )
    return fields, expected


def receipt_text(fields):
    return (
        f"schema\t{module.SCHEMA}\n"
        + "".join(f"{key}\t{value}\n" for key, value in sorted(fields.items()))
    )


class ReadbackTests(unittest.TestCase):
    def test_zero_control_baseline_is_refused(self):
        value = recipe()
        value["fixed_global_control_baseline"] = 0
        with self.assertRaises(module.ReadbackError):
            module.build_fixed_expectation(value)

    def test_retained_global_control_covers_its_baseline_and_joined_tenant(self):
        for stage in module.STAGES:
            fields, expected = fixture()
            fields[f"{stage}.global.used.control"] = "0"
            with self.subTest(stage=stage), self.assertRaises(module.ReadbackError):
                module.validate_runtime_readback(fields, expected)
        fields, expected = fixture()
        baseline = expected["contract"]["fixed_global_control_baseline"]
        tenant = int(fields["after_shutdown.tenant.used.control"])
        fields["after_shutdown.global.used.control"] = str(baseline + tenant - 1)
        with self.assertRaises(module.ReadbackError):
            module.validate_runtime_readback(fields, expected)

    def test_complete_bounded_and_tokio_fixed_receipts_validate(self):
        for executor in ("allocatbelt", "tokio-1.53.1"):
            with self.subTest(executor=executor):
                fields, expected = fixture(executor=executor, workload="disk")
                result = module.validate_runtime_readback(fields, expected)
                self.assertTrue(result["validated"])
                self.assertEqual(result["field_count"], len(fields))
                self.assertEqual(set(fields), self.expected_complete_registry(expected))
                self.assertEqual(
                    expected["contract"]["configuration"]["blocking_disk_adapter_constructed"],
                    "true" if executor == "tokio-1.53.1" else "false",
                )

    def test_emitter_static_registry_is_exact_and_complete(self):
        fields, expected = fixture()
        contract = expected["contract"]
        self.assertEqual(
            set(contract["identity"]),
            {
                "report_nonce",
                "run_id",
                "allocator",
                "executor",
                "source_sha256",
                "binary_sha256",
                "comparison_family",
                "resource_ceiling_sha256",
                "policy_sha256",
                "profile",
                "workload",
                "hashes_are_echoed_bindings_not_self_proof",
            },
        )
        self.assertEqual(
            set(module._flatten("configuration", contract["configuration"]))
            - {
                "configuration.domain_ceiling." + key
                for key in contract["configuration"].get("domain_ceiling", {})
            },
            {
                "configuration.mode",
                "configuration.rate_per_second",
                "configuration.arrivals",
                "configuration.async_workers",
                "configuration.logical_window",
                "configuration.trace_duration_ns",
                "configuration.pulse_rate_per_second",
                "configuration.task_ceiling",
                "configuration.resource_policy",
                "configuration.feedback_enabled",
                "configuration.network_direction",
                "configuration.managed_memory_limit_bytes",
                "configuration.disk_operation_limit",
                "configuration.network_operation_limit",
                "configuration.fixed_global_control_baseline",
                "configuration.blocking_disk_adapter_constructed",
            },
        )
        self.assertEqual(
            set(contract["accounting"]),
            {
                "cpu",
                "tasks",
                "managed_payload",
                "disk_operations",
                "disk_bytes",
                "network_operations",
                "network_bytes",
                "opaque_runtime_allocations",
                "receipt_writer_storage",
            },
        )
        self.assertEqual(
            set(contract["kernel"]),
            {
                "cpu_rounds",
                "memory_initial_bytes",
                "memory_grown_bytes",
                "memory_seed",
                "disk_bytes",
                "disk_offset",
                "disk_seed",
                "http_body_bytes",
                "mixed_interleave",
            },
        )
        self.assertIn("configuration.setup_global_control", fields)
        self.assertEqual(
            set(fields) - set(module._expectation_rows(expected)),
            self.expected_complete_registry(expected) - set(module._expectation_rows(expected)),
        )

    def expected_complete_registry(self, expected):
        fields, _ = fixture(
            executor=expected["recipe"]["identity"]["executor"],
            workload=expected["recipe"]["run"]["workload"],
            profile=expected["recipe"]["run"]["profile"],
            mode=expected["recipe"]["run"]["mode"],
        )
        return set(fields)

    def test_workload_limits_and_worker_profile_are_derived(self):
        expected_limits = {
            "cpu": (0, 0, 0),
            "memory": (163_840, 0, 0),
            "http": (141_312, 0, 16),
            "disk": (1_573_000, 8, 0),
            "mixed": (1_638_536, 8, 16),
        }
        profiles = {"mixed": "mixed"}
        for workload, (memory, disk, network) in expected_limits.items():
            profile = profiles.get(workload, "steady")
            value = module.build_fixed_expectation(
                recipe(workload=workload, profile=profile)
            )
            contract = value["contract"]
            self.assertEqual(
                contract["ceilings"],
                {
                    "cpu": 4,
                    "memory": memory,
                    "disk": disk,
                    "network": network,
                    "tasks": 64,
                    "control": 67_108_864,
                },
            )
            self.assertEqual(
                contract["scope_limits"],
                {
                    "managed_memory_limit": memory,
                    "disk_operation_limit": disk,
                    "network_operation_limit": network,
                },
            )
        oversubscribed = module.build_fixed_expectation(
            recipe(profile="oversubscribed")
        )
        self.assertEqual(oversubscribed["contract"]["ceilings"]["cpu"], 2)
        self.assertEqual(oversubscribed["contract"]["configuration"]["async_workers"], "2")

    def test_capacity_and_burst_values_follow_the_application_recipe(self):
        capacity = module.build_fixed_expectation(
            recipe(mode="capacity", rate=None, arrivals=5000, profile="burst")
        )
        self.assertEqual(capacity["contract"]["configuration"]["rate_per_second"], "0")
        self.assertEqual(capacity["contract"]["configuration"]["pulse_rate_per_second"], "0")
        self.assertEqual(
            capacity["contract"]["configuration"]["trace_duration_ns"],
            "30000000000",
        )
        burst = module.build_fixed_expectation(
            recipe(profile="burst", rate=1000, arrivals=2501)
        )
        self.assertEqual(burst["contract"]["configuration"]["pulse_rate_per_second"], "4000")
        self.assertEqual(
            burst["contract"]["configuration"]["trace_duration_ns"],
            "3000000000",
        )

    def test_static_and_varying_field_maps_cannot_change_the_contract(self):
        mutations = (
            lambda value: value.update(static_fields={}),
            lambda value: value.update(varying_fields={}),
            lambda value: value["contract"]["configuration"].pop("mode"),
            lambda value: value["contract"].update(static_fields={"configuration.mode": "capacity"}),
        )
        for mutate in mutations:
            fields, expected = fixture()
            mutate(expected)
            with self.assertRaises(module.ReadbackError):
                module.validate_runtime_readback(fields, expected)

    def test_nested_boolean_type_and_forged_recipe_are_rejected(self):
        fields, expected = fixture()
        bad = copy.deepcopy(expected)
        bad["contract"]["ceilings"]["cpu"] = True
        with self.assertRaises(module.ReadbackError):
            module.validate_runtime_readback(fields, bad)
        for mutate in (
            lambda value: value["recipe"]["run"].update(arrivals=True),
            lambda value: value["recipe"]["run"].update(rate_per_second=False),
            lambda value: value["recipe"]["run"].update(workload="impossible"),
            lambda value: value["recipe"]["run"].update(profile="mixed"),
            lambda value: value["recipe"].update(fixed_global_control_baseline=True),
        ):
            bad = copy.deepcopy(expected)
            mutate(bad)
            with self.assertRaises(module.ReadbackError):
                module.validate_runtime_readback(fields, bad)

    def test_forged_workload_profile_mode_and_executor_labels_fail(self):
        invalid_recipes = (
            recipe(workload="cpu", profile="mixed"),
            recipe(workload="mixed", profile="steady"),
            recipe(mode="capacity", rate=1, arrivals=5000),
            recipe(mode="capacity", rate=None, arrivals=1000),
            recipe(profile="burst", rate=250_000_001),
            recipe(profile="safety_overload", mode="capacity", rate=None, arrivals=5000),
            recipe(executor="arbitrary-runtime"),
        )
        for value in invalid_recipes:
            with self.subTest(run=value["run"]):
                with self.assertRaises(module.ReadbackError):
                    module.build_fixed_expectation(value)
        fields, expected = fixture()
        for key, value in (
            ("identity.profile", "oversubscribed"),
            ("identity.workload", "disk"),
            ("configuration.mode", "capacity"),
            ("configuration.rate_per_second", "999"),
        ):
            altered = dict(fields)
            altered[key] = value
            with self.assertRaises(module.ReadbackError):
                module.validate_runtime_readback(altered, expected)

    def test_pressure_fails_closed_until_policy_support_is_approved(self):
        with self.assertRaisesRegex(module.ReadbackError, "supports fixed-policy receipts only"):
            module.build_fixed_expectation(recipe(family="external_pressure"))
        fields, expected = fixture()
        fields["identity.comparison_family"] = "external_pressure"
        with self.assertRaisesRegex(module.ReadbackError, "supports fixed-policy receipts only"):
            module.validate_runtime_readback(fields, expected)

    def test_exact_domains_configured_capacities_and_hard_bounds(self):
        for key, value in (
            ("setup.tenant.ceiling.cpu", "8"),
            ("setup.tenant.limit.cpu", "3"),
            ("after_drain.global.used.tasks", "1"),
            ("setup.scope.managed_memory_limit", "1"),
            ("setup.scope.disk_operations_used", "1"),
            ("setup.io.disk_ceiling_bytes_per_second", "17179869183"),
            ("setup.io.upload_ceiling_burst_bytes", "65535"),
            ("setup.io.download_max_reservations", "63"),
            ("setup.io.disk_available_bytes", "65537"),
        ):
            fields, expected = fixture()
            fields[key] = value
            with self.subTest(key=key), self.assertRaises(module.ReadbackError):
                module.validate_runtime_readback(fields, expected)

    def test_setup_global_control_is_bound_to_snapshot_and_independent_baseline(self):
        mutations = (
            ("configuration.setup_global_control", "8191"),
            ("setup.global.used.control", "4096"),
            ("setup.tenant.used.control", "100000000"),
            ("after_release.global.used.control", "4097"),
            ("after_release.global.live_tenants", "1"),
            ("after_release.control_matches_fixed_baseline", "false"),
        )
        for key, value in mutations:
            fields, expected = fixture()
            fields[key] = value
            with self.subTest(key=key), self.assertRaises(module.ReadbackError):
                module.validate_runtime_readback(fields, expected)

    def test_missing_extra_duplicate_and_malformed_receipt_rows_are_refused(self):
        fields, expected = fixture()
        with self.assertRaises(module.ReadbackError):
            module.validate_runtime_readback({key: value for key, value in fields.items() if key != "kernel.cpu_rounds"}, expected)
        extra = dict(fields)
        extra["configuration.unreviewed_capacity"] = "1"
        with self.assertRaises(module.ReadbackError):
            module.validate_runtime_readback(extra, expected)

        valid = receipt_text(fields)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.tsv"
            path.write_text(valid)
            self.assertEqual(module.read_receipt(path), fields)
            malformed = (
                valid[:-1],
                valid + "identity.run_id\tfixed-run-1\n",
                valid.replace("setup.global.used.cpu\t0", "setup.global.used.cpu\t0\textra"),
                valid.replace("schema\t" + module.SCHEMA, "schema\twrong-schema"),
            )
            for text in malformed:
                path.write_text(text)
                with self.assertRaises(module.ReadbackError):
                    module.read_receipt(path)

    def test_json_duplicate_keys_size_bound_and_campaign_canonical_newline(self):
        fields, expected = fixture()
        encoded = module.canonical_bytes(expected)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertFalse(encoded.endswith(b"\n\n"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_text('{"schema":"one","schema":"two"}')
            with self.assertRaisesRegex(module.ReadbackError, "duplicate JSON key"):
                module._read_json_object(path, "test artifact")
            path.write_text(" " * (module.MAX_ARTIFACT_BYTES + 1))
            with self.assertRaisesRegex(module.ReadbackError, "size bound"):
                module._read_json_object(path, "test artifact")

    def test_fixed_recipe_kernel_inputs_and_bucket_contract_are_frozen(self):
        expected = module.build_fixed_expectation(recipe())
        contract = expected["contract"]
        self.assertEqual(
            contract["kernel"],
            {
                "cpu_rounds": "50000",
                "memory_initial_bytes": "4096",
                "memory_grown_bytes": "8192",
                "memory_seed": str(0x243F6A8885A308D3),
                "disk_bytes": "196625",
                "disk_offset": "4096",
                "disk_seed": str(0xA4093822299F31D0),
                "http_body_bytes": "4096",
                "mixed_interleave": "cpu,memory,http,disk",
            },
        )
        self.assertEqual(
            contract["byte_buckets"],
            {
                direction: {
                    "bytes_per_second": 17_179_869_184,
                    "ceiling_bytes_per_second": 17_179_869_184,
                    "burst_bytes": 65_536,
                    "ceiling_burst_bytes": 65_536,
                    "max_reservations": 64,
                }
                for direction in ("disk", "upload", "download")
            },
        )


if __name__ == "__main__":
    unittest.main()
