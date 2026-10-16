"""Profile/core schema tests; SourceV5 input-evidence verification is mocked.

Preparation intents use the actual schema validator and real private files.
Synthetic host metadata here is not application or performance evidence.
"""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixtures = load("two_kvm_profile_campaign_fixtures", "test-application-campaign.py")
preparation_fixtures = load("two_kvm_profile_preparation_fixtures", "test-application-source5-input-preparation.py")
campaign = fixtures.campaign
inputs = preparation_fixtures.inputs


class QualificationProfileTests(unittest.TestCase):
    def fixture(self):
        spec, sources = fixtures.spec_fixture()
        spec["schema"] = campaign.SPEC_SCHEMA_V3
        spec["qualification_profile"] = campaign.TWO_KVM_QUALIFICATION_PROFILE
        spec["hosts"] = spec["hosts"][1:]
        ids = {host["host_id"] for host in spec["hosts"]}
        sources = {host: source for host, source in sources.items() if host in ids}
        for source in sources.values():
            source["schema"] = campaign.SOURCE_SCHEMA_V5
            source["feedback_policy"] = {"policy_sha256": spec["runtime_binding"]["feedback_policy_sha256"]}
            source["manifest_sha256"] = campaign.digest_object(
                {key: value for key, value in source.items() if key != "manifest_sha256"})
        spec["source_manifests"] = [
            {**row, "sha256": sources[row["host_id"]]["manifest_sha256"]}
            for row in spec["source_manifests"] if row["host_id"] in ids]
        spec["qualification_inputs"] = {"fixture_input_evidence_boundary": True}
        return spec, sources

    def validate(self, spec, sources):
        boundary = types.SimpleNamespace(
            InputError=RuntimeError,
            validate_qualification_inputs=lambda *_args, **_kwargs: {
                "evidence_supplied": False, "capacity_evidence_supplied_count": 0,
                "capacity_evidence_pins_checked": False,
                "capacity_evidence_validation_complete": False,
                "qualification_inputs_pins_checked": False,
                "qualification_inputs_validation_complete": False,
            })
        with mock.patch.object(campaign, "campaign_inputs_source_sha256", return_value="a" * 64), \
                mock.patch.object(campaign, "campaign_inputs_module", return_value=boundary):
            return campaign.validate_spec(spec, sources)

    def test_absent_profile_keeps_legacy_three_host_matrix(self):
        spec, sources = fixtures.spec_fixture()
        self.assertEqual(campaign.qualification_host_count(spec), 3)
        self.assertEqual(len(campaign.validate_spec(spec, sources)["host_ids"]), 3)
        spec["hosts"] = spec["hosts"][1:]
        with self.assertRaisesRegex(campaign.CampaignError, "exactly three"):
            campaign.validate_spec(spec, sources)

    def test_explicit_profile_requires_spec_v3_and_exact_selector(self):
        for value in (None, "", "unknown", 2, True, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(campaign.CampaignError):
                    campaign.qualification_host_count({"schema": campaign.SPEC_SCHEMA_V3,
                                                       "qualification_profile": value})
        with self.assertRaises(campaign.CampaignError):
            campaign.qualification_host_count({"schema": campaign.SPEC_SCHEMA,
                                               "qualification_profile": campaign.TWO_KVM_QUALIFICATION_PROFILE})

    def test_two_kvm_matrix_has_unchanged_numerical_gates_and_false_readiness(self):
        spec, sources = self.fixture()
        checked = self.validate(spec, sources)
        self.assertEqual(checked["host_ids"], ["host-2", "host-3"])
        self.assertEqual(checked["cell_count"], 15)
        self.assertFalse(checked["full_gate_ready"])
        self.assertFalse(checked["capacity_evidence_validation_complete"])
        self.assertEqual(spec["protocol"]["soak_seconds"], 10800)
        self.assertEqual(spec["protocol"]["allocator_min_capacity_ratio"], 1.05)
        self.assertEqual(spec["protocol"]["allocator_max_p99_ratio"], 0.95)
        self.assertEqual(spec["protocol"]["bootstrap_draws"], 50000)

    def test_one_or_three_hosts_cannot_use_two_kvm_profile(self):
        for count in (1, 3):
            spec, sources = self.fixture()
            spec["hosts"] = spec["hosts"][:1] if count == 1 else spec["hosts"] + [copy.deepcopy(spec["hosts"][0])]
            with self.subTest(count=count), self.assertRaisesRegex(campaign.CampaignError, "exactly two"):
                self.validate(spec, sources)

    def test_two_kvm_profile_rejects_bare_metal_venue(self):
        spec, sources = self.fixture()
        spec["hosts"][0]["venue"] = "bare_metal"
        with self.assertRaisesRegex(campaign.CampaignError, "two KVM guests"):
            self.validate(spec, sources)

    def test_duplicate_host_cannot_replace_missing_guest(self):
        spec, sources = self.fixture()
        spec["hosts"][1] = copy.deepcopy(spec["hosts"][0])
        with self.assertRaisesRegex(campaign.CampaignError, "duplicate host"):
            self.validate(spec, sources)

    def test_source_references_must_cover_exact_selected_guests(self):
        for mutation in ("missing", "extra", "duplicate", "foreign"):
            spec, sources = self.fixture()
            rows = spec["source_manifests"]
            if mutation == "missing":
                rows.pop()
            elif mutation == "extra":
                rows.append(copy.deepcopy(rows[0]))
            elif mutation == "duplicate":
                rows[1] = copy.deepcopy(rows[0])
            else:
                sources["foreign-host"] = sources["host-2"]
            with self.subTest(mutation=mutation), self.assertRaises(campaign.CampaignError):
                self.validate(spec, sources)

    def test_selector_is_bound_by_preregistration_digest(self):
        spec, _sources = self.fixture()
        before = campaign.preregistration_digest(spec)
        del spec["qualification_profile"]
        self.assertNotEqual(before, campaign.preregistration_digest(spec))

    def test_pilot_ordinals_remain_360_per_host_without_mutating_spec(self):
        spec, _sources = self.fixture()
        before = campaign.canonical_bytes(spec)
        all_jobs = campaign.build_jobs(spec, "exploration")
        self.assertEqual(len(all_jobs), 720)
        for host in spec["hosts"]:
            jobs = [job for job in all_jobs if job["host_id"] == host["host_id"]]
            self.assertEqual(len(jobs), 360)
            self.assertEqual(len({job["run_id"] for job in jobs}), 360)
            self.assertTrue(all(job["mode"] == "capacity" for job in jobs))
        self.assertEqual(campaign.canonical_bytes(spec), before)


class QualificationPreparationCoreTests(unittest.TestCase):
    def fixture(self):
        fixture, spec = preparation_fixtures.preparation_fixture()
        keep = {"host-2", "host-3"}
        spec["schema"] = campaign.SPEC_SCHEMA_V3
        spec["qualification_inputs"] = {}
        spec["qualification_profile"] = campaign.TWO_KVM_QUALIFICATION_PROFILE
        spec["hosts"] = [host for host in spec["hosts"] if host["host_id"] in keep]
        spec["source_manifests"] = [row for row in spec["source_manifests"] if row["host_id"] in keep]
        fixture["core"] = inputs.preparation_core_from_spec(spec)
        for key in ("source_pins", "observed_hosts"):
            fixture[key] = {host: value for host, value in fixture[key].items() if host in keep}
        for key in ("capacity_templates", "condition_intensities"):
            fixture[key] = [row for row in fixture[key] if row["host_id"] in keep]
        return fixture, spec

    def test_profile_survives_core_v3_and_intent_roundtrip(self):
        fixture, spec = self.fixture()
        core = fixture["core"]
        self.assertEqual(core["schema"], inputs.SOURCE5_PREPARATION_CORE_SCHEMA_V3)
        self.assertEqual(inputs._validate_preparation_core(core), core)
        with tempfile.TemporaryDirectory(prefix="two-kvm-profile-intent-") as temporary:
            output = Path(temporary) / "preparation.json"
            sealed = inputs.build_preparation_intent(
                core, fixture["source_pins"], fixture["observed_hosts"],
                fixture["capacity_templates"], fixture["condition_intensities"], output)
            value = inputs.json.loads(output.read_bytes())
            checked = inputs.validate_preparation_intent(value)
            self.assertEqual(value["core"], inputs.preparation_core_from_spec(spec))
            self.assertEqual(checked["capacity_template_count"], 30)
            self.assertEqual(checked["condition_intensity_count"], 30)
            self.assertEqual(sealed["host_ids"], ["host-2", "host-3"])
            self.assertTrue(all(flag is False for flag in value["eligibility"].values()))

    def test_legacy_core_shapes_do_not_accept_new_selector(self):
        fixture, _spec = preparation_fixtures.preparation_fixture()
        core = {"schema": inputs.SOURCE5_PREPARATION_CORE_SCHEMA, **fixture["core"]}
        inputs._validate_preparation_core(core)
        core["qualification_profile"] = campaign.TWO_KVM_QUALIFICATION_PROFILE
        with self.assertRaises(inputs.InputError):
            inputs._validate_preparation_core(core)

    def test_core_v3_rejects_unknown_or_missing_selector(self):
        for mutation in (None, "unknown", "missing"):
            fixture, _spec = self.fixture()
            core = fixture["core"]
            if mutation == "missing":
                del core["qualification_profile"]
            else:
                core["qualification_profile"] = mutation
            with self.subTest(mutation=mutation), self.assertRaises(inputs.InputError):
                inputs._validate_preparation_core(core)

    def test_new_profile_preserves_optional_existing_floor_slot(self):
        _fixture, spec = self.fixture()
        for value in (None, inputs.CAPACITY_FLOOR_POLICY_ID):
            with self.subTest(value=value):
                spec["capacity_floor_policy_id"] = value
                core = inputs.preparation_core_from_spec(spec)
                self.assertIn("capacity_floor_policy_id", core)
                self.assertEqual(core["capacity_floor_policy_id"], value)
                inputs._validate_preparation_core(core)

    def test_core_profile_change_is_not_an_allowed_bridge_fill(self):
        fixture, spec = self.fixture()
        frozen = campaign.canonical_bytes(fixture["core"])
        spec["rates"] = [{"fixture": "future-rate-evidence"}]
        spec["oracles"] = [{"fixture": "future-oracle-evidence"}]
        self.assertEqual(campaign.canonical_bytes(inputs.preparation_core_from_spec(spec)), frozen)
        del spec["qualification_profile"]
        self.assertNotEqual(campaign.canonical_bytes(inputs.preparation_core_from_spec(spec)), frozen)


if __name__ == "__main__":
    unittest.main()
