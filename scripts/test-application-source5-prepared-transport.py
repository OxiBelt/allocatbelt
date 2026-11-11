#!/usr/bin/env python3
"""Dependency-copy components, without budget admission or GPG authority."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


packet = load('prepared_transport_packet', 'application-source5-evidence-transfer-packet.py')
archive = load('prepared_transport_archive', 'application-source5-evidence-archive.py')


def pin(path, raw, semantic=None):
    return {'path': path, 'raw_sha256': packet._sha(raw),
            'semantic_sha256': packet._sha(raw) if semantic is None else semantic}


def fixture(root):
    # Only the six-copy envelope is exercised. These documents intentionally
    # are not a complete execution-ready Spec, budget, or source manifest.
    source = packet._canonical({'schema': packet.SOURCE_MANIFEST_SCHEMA_V5})
    plan = packet._canonical({'schema': 'allocatbelt.application-campaign-plan.v3'})
    spec = packet._canonical({'schema': 'allocatbelt.application-campaign-spec.v3',
                              'qualification_profile': 'two_kvm_hosts_v1'})
    width = packet._canonical({'schema': 'allocatbelt.application-source5-journal-width-contract.v2'})
    origin = '/absent-original-host/metadata'
    source_pins = {host: pin(f'{origin}/{host}-source.json', source) for host in ('host-a', 'host-b')}
    plan_pin, spec_pin, width_pin = [pin(f'{origin}/{name}.json', raw)
                                    for name, raw in [('plan', plan), ('spec', spec), ('width', width)]]
    execution = {key: None for key in (
        'schema campaign_id hosts original_inputs execution_sources modules observed_hosts artifact_root '
        'output_root phase_order protocol_sha256 qualification_eligible manifest_sha256 scope '
        'prepared_input_generation prepared_capacity_registration archive_signer_contexts journal_width_contracts'
    ).split()}
    execution.update(schema=packet.PREPARED_EXPLORATION_EXECUTION_SCHEMA,
                     scope=packet.PREPARED_EXPLORATION_SCOPE,
                     campaign_id='campaign', hosts=['host-a', 'host-b'], qualification_eligible=False,
                     original_inputs={'spec': {'artifact': {k: spec_pin[k] for k in ('path', 'raw_sha256')},
                                               'semantic_sha256': spec_pin['semantic_sha256']},
                                      'plan': {'artifact': {k: plan_pin[k] for k in ('path', 'raw_sha256')},
                                               'semantic_sha256': plan_pin['semantic_sha256']},
                                      'source_manifests': {}, 'campaign_artifacts_root': '/absent-original-host/oracles'})
    execution['manifest_sha256'] = packet._sha(packet._canonical({k: v for k, v in execution.items() if k != 'manifest_sha256'}))
    execution_raw = packet._canonical(execution)
    execution_pin = pin(f'{origin}/execution.json', execution_raw, execution['manifest_sha256'])
    budget = {key: None for key in packet.HOST_BUDGET_FIELDS_V3}
    budget.update(schema=packet.HOST_BUDGET_SCHEMA_V4,
                  admission_profile=packet.PREPARED_EXPLORATION_ADMISSION_PROFILE,
                  execution_manifest_schema=packet.PREPARED_EXPLORATION_EXECUTION_SCHEMA,
                  campaign_id='campaign', host_id='host-a', journal_width_contract_pin=width_pin,
                  original_pins={'spec': spec_pin, 'plan': plan_pin, 'execution_manifest': execution_pin,
                                 'source_manifests': source_pins, 'source_tree_sha256': 'a' * 64,
                                 'prepared_exploration': {host: {
                                     name: {'path': f'{origin}/old/{host}/{name}.json', 'raw_sha256': 'b' * 64}
                                     for name in ('bridge_header', 'record_index')
                                 } for host in source_pins}})
    budget['budget_sha256'] = packet._sha(packet._canonical({k: v for k, v in budget.items() if k != 'budget_sha256'}))
    budget_raw = packet._canonical(budget)
    budget_pin = pin(f'{origin}/budget.json', budget_raw, budget['budget_sha256'])
    context, pins = packet._prepared_exploration_primary_context(budget, budget_pin)
    payloads = [source, plan, budget_raw, execution_raw, width, spec]
    cache = root / 'cache'
    cache.mkdir(mode=0o700)
    entries = []
    for index, (item, raw) in enumerate(zip(pins, payloads, strict=True)):
        local = cache / f'{index}.json'
        local.write_bytes(raw)
        local.chmod(0o600)
        entries.append({'origin_pin': item, 'local_path': str(local)})
    mapping = {'schema': packet.DEPENDENCY_LOCAL_MAP_SCHEMA,
               'campaign_id': 'campaign', 'host_id': 'host-a', 'entries': entries}
    mapping['map_sha256'] = packet._sha(packet._canonical(mapping))
    return budget, budget_raw, budget_pin, context, mapping, cache, payloads


class PreparedTransportTests(unittest.TestCase):
    def read(self, case, mapping=None):
        budget, raw, pin_value, context, saved, root, _ = case
        return packet._read_root_prepared_exploration_dependencies(
            budget, raw, pin_value, context, packet._canonical(saved if mapping is None else mapping), root)

    def reseal(self, mapping):
        mapping['map_sha256'] = packet._sha(packet._canonical({k: v for k, v in mapping.items() if k != 'map_sha256'}))

    def test_exact_final_six_are_reopened_without_any_origin_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = fixture(Path(temporary))
            result = self.read(case)
            self.assertEqual(result, (case[3], case[6][0], case[6][1], case[6][3], case[6][4], case[6][5]))
            archive_result = archive._read_root_prepared_exploration_dependencies(
                case[0], case[1], case[2], case[3], packet._canonical(case[4]), case[5])
            self.assertEqual(archive_result, result)
            self.assertFalse(Path('/absent-original-host/metadata').exists())
            self.assertEqual(archive._prepared_exploration_primary_context(case[0], case[2]),
                             packet._prepared_exploration_primary_context(case[0], case[2]))

    def test_old_versions_and_wrong_profile_do_not_enter_final_six_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = fixture(Path(temporary))
            for module in (packet, archive):
                for key, value in [('schema', packet.HOST_BUDGET_SCHEMA_V3),
                                   ('admission_profile', 'preparatory_exploration_360_v1'),
                                   ('execution_manifest_schema', packet.EXECUTION_SCHEMA_V4)]:
                    changed = copy.deepcopy(case[0]);changed[key] = value
                    with self.assertRaises(ValueError):
                        module._prepared_exploration_primary_context(changed, case[2])

    def test_exact_cohort_and_unique_ancestor_and_primary_origins_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = fixture(Path(temporary))
            mutations = []
            changed = copy.deepcopy(case[0]);changed['original_pins']['prepared_exploration'].pop('host-b');mutations.append(changed)
            changed = copy.deepcopy(case[0]);changed['original_pins']['prepared_exploration']['host-b']['bridge_header'] = changed['original_pins']['prepared_exploration']['host-a']['bridge_header'];mutations.append(changed)
            changed = copy.deepcopy(case[0]);changed['original_pins']['spec'] = changed['original_pins']['plan'];mutations.append(changed)
            for changed in mutations:
                for module in (packet, archive):
                    with self.assertRaises(ValueError):
                        module._prepared_exploration_primary_context(changed, case[2])

    def test_five_copies_extra_copy_and_reordered_map_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = fixture(Path(temporary))
            for mutate in ('missing', 'extra', 'order'):
                mapping = copy.deepcopy(case[4])
                if mutate == 'missing':mapping['entries'].pop()
                elif mutate == 'extra':mapping['entries'].append(copy.deepcopy(mapping['entries'][0]))
                else:mapping['entries'][4],mapping['entries'][5] = mapping['entries'][5],mapping['entries'][4]
                self.reseal(mapping)
                with self.assertRaises(packet.TransferPacketError):self.read(case,mapping)

    def test_corrupt_copy_symlink_and_hardlink_are_rejected(self):
        for mutation in ('bytes', 'symlink', 'hardlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                case = fixture(Path(temporary));target = Path(case[4]['entries'][5]['local_path'])
                if mutation == 'bytes':target.write_bytes(b'bad bytes')
                elif mutation == 'symlink':target.unlink();target.symlink_to(Path(case[4]['entries'][0]['local_path']))
                else:os.link(target,case[5]/'extra-link')
                with self.assertRaises((packet.TransferPacketError,OSError)):self.read(case)

    def test_root_replacement_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            case = fixture(Path(temporary));original = packet._read_regular_absolute;called = False
            def replace(path,maximum,label):
                nonlocal called
                result = original(path,maximum,label)
                if not called:
                    called = True
                    old = case[5].with_name('old-cache');case[5].rename(old);case[5].mkdir(mode=0o700)
                    for child in old.iterdir():
                        target = case[5]/child.name;target.write_bytes(child.read_bytes());target.chmod(0o600)
                return result
            with patch.object(packet,'_read_regular_absolute',side_effect=replace):
                with self.assertRaisesRegex(packet.TransferPacketError,'custody changed'):self.read(case)


if __name__ == '__main__':
    unittest.main()
