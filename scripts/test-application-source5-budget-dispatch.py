"""Closed budget dispatch tests; numeric producer verification is separate."""
import copy
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

path = Path(__file__).with_name("application-campaign-chronology.py")
spec = importlib.util.spec_from_file_location("source5_budget_dispatch_tests", path)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def budget(version="v3", width=True):
    fields = (m.SOURCE5_HOST_BUDGET_V3_FIELDS if version == "v3" else
              m.SOURCE5_HOST_BUDGET_V2_WIDTH_FIELDS if width else
              m.SOURCE5_HOST_BUDGET_V2_LEGACY_FIELDS)
    result = {name: None for name in fields}
    result["schema"] = m.SOURCE5_HOST_BUDGET_SCHEMA_V3 if version == "v3" else m.SOURCE5_HOST_BUDGET_SCHEMA_V2
    if width:
        result["execution_manifest_schema"] = m.SOURCE5_EXECUTION_SCHEMA_V4
    if version == "v3":
        result["admission_profile"] = m.SOURCE5_HOST_BUDGET_V3_ADMISSION_PROFILE
    return result


class BudgetDispatchTests(unittest.TestCase):
    def test_legacy_v2_exact_thirteen_fields_remain_non_width(self):
        self.assertFalse(m._source5_host_budget_width_bound(budget("v2", False)))

    def test_width_v2_exact_fifteen_fields_remain_width(self):
        self.assertTrue(m._source5_host_budget_width_bound(budget("v2")))

    def test_v3_requires_exact_sixteen_field_profile(self):
        self.assertTrue(m._source5_host_budget_width_bound(budget()))

    def test_v3_rejects_missing_foreign_or_extra_profile_fields(self):
        for mutation in ("missing", "foreign", "extra"):
            with self.subTest(mutation=mutation):
                value = budget()
                if mutation == "missing":
                    value.pop("admission_profile")
                elif mutation == "foreign":
                    value["admission_profile"] = "caller_ready"
                else:
                    value["imported"] = True
                with self.assertRaisesRegex(m.ChronologyError, "exact width-v4"):
                    m._source5_host_budget_width_bound(value)

    def test_v2_cannot_promote_itself_by_adding_v3_profile(self):
        value = budget("v2")
        value["admission_profile"] = m.SOURCE5_HOST_BUDGET_V3_ADMISSION_PROFILE
        with self.assertRaisesRegex(m.ChronologyError, "exact schema/field"):
            m._source5_host_budget_width_bound(value)

    def test_other_schema_cannot_reuse_a_known_field_set(self):
        value = budget("v2", False)
        value["schema"] = "foreign"
        with self.assertRaisesRegex(m.ChronologyError, "exact schema/field"):
            m._source5_host_budget_width_bound(value)

    def test_v3_rejects_non_v4_execution(self):
        value = budget()
        value["execution_manifest_schema"] = m.SOURCE5_EXECUTION_SCHEMA_V3
        with self.assertRaisesRegex(m.ChronologyError, "exact width-v4"):
            m._source5_host_budget_width_bound(value)

    def test_legacy_source_module_keeps_original_positional_call(self):
        module = SimpleNamespace(validate_host_evidence_budget_v2=mock.Mock(return_value="legacy"))
        value = budget("v2", False)
        self.assertEqual(m._source5_validate_budget_with_captured_inputs(module, value, None, None), "legacy")
        module.validate_host_evidence_budget_v2.assert_called_once_with(value)

    def test_width_v2_passes_exact_captured_inputs_to_original_validator(self):
        module = SimpleNamespace(validate_host_evidence_budget_v2=mock.Mock(return_value="width"))
        value, reader = budget("v2"), object()
        self.assertEqual(m._source5_validate_budget_with_captured_inputs(module, value, b"width", reader), "width")
        module.validate_host_evidence_budget_v2.assert_called_once_with(
            value, journal_width_contract_raw=b"width", catalogue_row_reader=reader)

    def test_v3_invokes_only_actual_selected_source_v3_validator(self):
        module = SimpleNamespace(validate_host_evidence_budget_v2=mock.Mock(),
                                 validate_host_evidence_budget_v3=mock.Mock(return_value="v3"))
        value, reader = budget(), object()
        before = copy.deepcopy(value)
        self.assertEqual(m._source5_validate_budget_with_captured_inputs(module, value, b"width", reader), "v3")
        module.validate_host_evidence_budget_v2.assert_not_called()
        module.validate_host_evidence_budget_v3.assert_called_once_with(
            value, journal_width_contract_raw=b"width", catalogue_row_reader=reader)
        self.assertEqual(value, before)

    def test_v3_cannot_fall_back_to_legacy_validator(self):
        module = SimpleNamespace(validate_host_evidence_budget_v2=mock.Mock())
        with self.assertRaisesRegex(m.ChronologyError, "lacks the exact v3"):
            m._source5_validate_budget_with_captured_inputs(module, budget(), b"width", object())
        module.validate_host_evidence_budget_v2.assert_not_called()

    def test_v3_requires_exact_immutable_width_bytes(self):
        for value in (None, "width", bytearray(b"width")):
            with self.subTest(value=value):
                module = SimpleNamespace(validate_host_evidence_budget_v3=mock.Mock())
                with self.assertRaisesRegex(m.ChronologyError, "exact v3"):
                    m._source5_validate_budget_with_captured_inputs(module, budget(), value, object())
                module.validate_host_evidence_budget_v3.assert_not_called()

    def test_source_numeric_validator_failure_is_preserved(self):
        module = SimpleNamespace(validate_host_evidence_budget_v3=mock.Mock(side_effect=ValueError("catalogue pin mismatch")))
        with self.assertRaisesRegex(ValueError, "catalogue pin mismatch"):
            m._source5_validate_budget_with_captured_inputs(module, budget(), b"width", object())


if __name__ == "__main__":
    unittest.main()
