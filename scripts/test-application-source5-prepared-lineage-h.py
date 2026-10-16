#!/usr/bin/env python3
"""Controller components; SourceA lock/GPG boundary is explicitly mocked."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


controller = load('lineage_controller_component', 'application-source5-campaign.py')
budget = load('lineage_controller_budget', 'application-source5-evidence-budget.py')
profiles = load('lineage_controller_profiles', 'test-application-two-kvm-adapters.py')


class PreparatoryLineageControllerTests(unittest.TestCase):
    def context(self, root):
        output = root / 'output'
        output.mkdir(mode=0o700)
        source_path = SCRIPTS / 'application-source5-prepared-lineage.py'
        raw = source_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        relative = controller.SOURCE5_PREPARED_LINEAGE_SOURCE_PATH
        mode = f'{stat.S_IFMT(source_path.stat().st_mode) | stat.S_IMODE(source_path.stat().st_mode):06o}'
        spec = profiles.TwoKvmProfilePropagationTests.full_horizon_spec()
        return types.SimpleNamespace(
            manifest={'schema': controller.PREPARATORY_EXECUTION_SCHEMA,
                      'campaign_id': spec['campaign_id'],
                      'modules': {'kvm-a': {relative: {'path': relative, 'sha256': digest}}}},
            scope=controller.PREPARATORY_SCOPE, host_id='kvm-a', output_root=output,
            source_root=SCRIPTS.parent,
            source={'source': {'files': [{'path': relative, 'kind': 'file', 'mode': mode,
                                         'sha256': digest, 'size': len(raw)}]}},
            modules={controller.EVIDENCE_BUDGET_SOURCE_PATH: budget},
            plan={'jobs': {'exploration': profiles.campaign.build_jobs(spec, 'exploration')}},
            manifest_pin={'path': str(root / 'execution.json'), 'raw_sha256': 'a' * 64},
        )

    def test_source_pinned_projection_reserves_two_global_files_without_job_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            rows = controller._source5_preparatory_lineage_output_rows(context)
            self.assertEqual(set(rows), {'header', 'index'})
            self.assertNotEqual(rows['header']['path'], rows['index']['path'])
            for row in rows.values():
                self.assertEqual(row['role'], 'preparation')
                self.assertIsNone(row['run_id'])
                self.assertIsNone(row['phase'])
                self.assertEqual(row['max_inodes'], 1)
                self.assertEqual(row['max_bytes'], row['max_file_bytes'])
                self.assertEqual(row['storage_root'], str(context.output_root))
            self.assertFalse(Path(rows['header']['path']).exists())
            self.assertFalse(Path(rows['index']['path']).exists())

    def test_projection_requires_actual_source_inventory_pin_before_module_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            relative = controller.SOURCE5_PREPARED_LINEAGE_SOURCE_PATH
            context.manifest['modules']['kvm-a'][relative]['sha256'] = '0' * 64
            with self.assertRaises(controller.Source5CampaignError):
                controller._source5_preparatory_lineage_output_rows(context)

    def test_actual_catalogue_chunks_bind_both_output_rows_and_exact_caps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            projected = controller._source5_preparatory_lineage_output_rows(context)
            valid = list(projected.values())
            changed = copy.deepcopy(valid)
            changed[0]['max_bytes'] -= 1
            changed[0]['max_file_bytes'] -= 1
            extra = copy.deepcopy(valid[0])
            extra['path'] += '.unexpected'
            # A real catalogue also needs a bounded owner group from which
            # its archive closure is derived. This synthetic row reserves no
            # measured APP output and lives outside the lineage directory.
            owner_row = {
                **valid[0], 'path': str(context.output_root / 'synthetic-owner-window' / 'data'),
                'role': 'normal_app_output', 'owner': 'fixed_pair',
                'phase': 'exploration', 'run_id': context.plan['jobs']['exploration'][0]['run_id'],
                'max_bytes': 17, 'max_file_bytes': 17,
            }
            for index, rows in enumerate((valid, valid[:1], changed, valid + [extra])):
                directory = root / f'catalogue-{index}'
                directory.mkdir(mode=0o700)
                catalogue = budget.write_path_catalogue_chunks([owner_row, *rows], directory)
                if index == 0:
                    self.assertEqual(controller._source5_validate_preparatory_lineage_catalogue(
                        context, catalogue, budget), projected)
                else:
                    with self.assertRaises(controller.Source5CampaignError):
                        controller._source5_validate_preparatory_lineage_catalogue(context, catalogue, budget)

    def test_cli_requires_explicit_raw_and_semantic_pilot_pins(self):
        parser = controller._parser()
        base = ['seal-preparatory-lineage', '--manifest', '/private/execution.json',
                '--host-id', 'kvm-a', '--pilot', '/private/pilot.json']
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(base)
        args = parser.parse_args(base + ['--pilot-raw-sha256', 'a' * 64,
                                        '--pilot-semantic-sha256', 'b' * 64])
        self.assertEqual(args.command, 'seal-preparatory-lineage')
        self.assertEqual(args.pilot_raw_sha256, 'a' * 64)
        self.assertEqual(args.pilot_semantic_sha256, 'b' * 64)

    def test_locked_sourcea_boundary_preserves_counts_and_checks_real_output_bytes(self):
        for mutation in (None, 'eligibility', 'path', 'bytes'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                context = self.context(root)
                rows = controller._source5_preparatory_lineage_output_rows(context)
                lock = object()
                calls = []

                @contextlib.contextmanager
                def host_lock(*args):
                    self.assertEqual(args, (context.output_root, context.manifest['campaign_id'], context.host_id))
                    yield lock

                def sealer(actual_lock, execution_pin, *, pilot_pin):
                    # Only this SourceA boundary is mocked. Real private output
                    # files, catalogue caps, pins and readback checks remain.
                    self.assertIs(actual_lock, lock)
                    self.assertEqual(execution_pin, controller.api_pin(context.manifest_pin))
                    calls.append(pilot_pin)
                    result = {
                        'schema': 'allocatbelt.application-source5-prepared-exploration-lineage-seal.v1',
                        'campaign_id': context.manifest['campaign_id'], 'host_id': context.host_id,
                        'job_count': 360, 'callback_count': 2160,
                        'initial_journal_head': 'c' * 64, 'initial_journal_record_count': 2161,
                        'component_replay_required': True, 'fresh_sourcea_gpg_replay_required': True,
                        'qualification_eligible': False,
                    }
                    for name, role in (('bridge_header', 'header'), ('record_index', 'index')):
                        path = Path(rows[role]['path'])
                        missing = []
                        cursor = path.parent
                        while not cursor.exists():
                            missing.append(cursor)
                            cursor = cursor.parent
                        for directory in reversed(missing):
                            directory.mkdir(mode=0o700)
                        raw = b'{"synthetic_controller_boundary":true}\n'
                        path.write_bytes(raw)
                        path.chmod(0o600)
                        result[name] = {'path': str(path), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
                    if mutation == 'eligibility':
                        result['qualification_eligible'] = True
                    elif mutation == 'path':
                        result['bridge_header']['path'] += '.changed'
                    elif mutation == 'bytes':
                        Path(result['record_index']['path']).write_bytes(b'changed')
                    return result

                context.chronology = types.SimpleNamespace(
                    campaign_host_lock=host_lock,
                    seal_source5_preparatory_exploration_bridge_locked=sealer,
                )
                pilot = {'path': str(context.output_root / context.manifest['campaign_id'] /
                                      'source5' / context.host_id / 'exploration' / 'capacity-pilot.json'),
                         'raw_sha256': 'd' * 64, 'semantic_sha256': 'e' * 64}
                if mutation is None:
                    result = controller.seal_source5_preparatory_lineage(context, pilot)
                    self.assertFalse(result['qualification_eligible'])
                else:
                    with self.assertRaises(controller.Source5CampaignError):
                        controller.seal_source5_preparatory_lineage(context, pilot)
                self.assertEqual(calls, [pilot])


if __name__ == '__main__':
    unittest.main()
