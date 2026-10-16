#!/usr/bin/env python3
"""Closed byte IO and Source-owned prep validation; no APP or authority claim."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


archive = load('preparatory_byte_archive', 'application-source5-evidence-archive.py')


def catalogue_case(origin='/absent-captured-origin/catalogue.jsonl'):
    raw = b'{"catalogue-component":1}\n'
    digest = hashlib.sha256(raw).hexdigest()
    descriptor = {'path': origin, 'raw_sha256': digest, 'semantic_sha256': digest,
                  'byte_count': len(raw), 'row_count': 1,
                  'first_path': '/origin/first', 'last_path': '/origin/first'}
    return {'path_catalogue': {'chunks': [descriptor]}}, descriptor, raw


class CapturedCatalogueByteTests(unittest.TestCase):
    def test_reads_exact_source_descriptor_without_origin_or_cache_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            origin = Path(temporary) / 'origin.jsonl'
            origin.symlink_to(Path(temporary) / 'missing-target')
            budget, descriptor, raw = catalogue_case(str(origin))
            calls = []
            def read(pin, maximum):
                calls.append((pin, maximum))
                return raw
            reader = archive._source_budget_catalogue_reader(
                budget, None, None, root_local=True, captured_artifact_reader=read)
            self.assertEqual(reader(str(origin), len(raw)), raw)
            self.assertEqual(calls, [({'path': str(origin),
                                      'raw_sha256': descriptor['raw_sha256']}, len(raw))])
            self.assertEqual(os.readlink(origin), str(Path(temporary) / 'missing-target'))
            self.assertEqual({path.name for path in Path(temporary).iterdir()}, {'origin.jsonl'})

    def test_refuses_unknown_origin_size_and_tampered_callback_bytes(self):
        budget, descriptor, raw = catalogue_case()
        for payload in (raw + b'X', raw[:-1], b'X' * len(raw), bytearray(raw), None):
            with self.subTest(payload_type=type(payload).__name__):
                reader = archive._source_budget_catalogue_reader(
                    budget, None, None, root_local=True,
                    captured_artifact_reader=lambda pin, maximum: payload)
                with self.assertRaises(archive.EvidenceArchiveError):
                    reader(descriptor['path'], len(raw))
        calls = []
        def read(pin, maximum):
            calls.append(pin)
            return raw
        reader = archive._source_budget_catalogue_reader(
            budget, None, None, root_local=True, captured_artifact_reader=read)
        for origin, size in [('/other-origin', len(raw)), (descriptor['path'], len(raw) - 1),
                             (descriptor['path'], True)]:
            with self.assertRaises(archive.EvidenceArchiveError):
                reader(origin, size)
        self.assertEqual(calls, [])

    def test_callback_failure_never_falls_back_to_present_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            origin = Path(temporary) / 'origin.jsonl'
            budget, descriptor, raw = catalogue_case(str(origin))
            origin.write_bytes(raw)
            origin.chmod(0o600)
            def missing(pin, maximum):
                raise FileNotFoundError('not captured')
            reader = archive._source_budget_catalogue_reader(
                budget, None, None, root_local=True, captured_artifact_reader=missing)
            with self.assertRaisesRegex(archive.EvidenceArchiveError, 'unavailable'):
                reader(descriptor['path'], len(raw))

    def test_path_maps_and_ambient_mode_cannot_be_mixed_with_closed_bytes(self):
        budget, descriptor, raw = catalogue_case()
        for root_local, paths, root in [(False, None, None),
                                        (True, {}, None),
                                        (True, None, '/cache')]:
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._source_budget_catalogue_reader(
                    budget, paths, root, root_local=root_local,
                    captured_artifact_reader=lambda pin, maximum: raw)
        for key, value in [('semantic_sha256', '0' * 64), ('byte_count', 0)]:
            changed = copy.deepcopy(budget)
            changed['path_catalogue']['chunks'][0][key] = value
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._source_budget_catalogue_reader(
                    changed, None, None, root_local=True,
                    captured_artifact_reader=lambda pin, maximum: raw)


class SourcePreparatoryByteProfileTests(unittest.TestCase):
    def test_full_source_profile_survives_hidden_old_dependencies_and_catalogue(self):
        # Real producer/validator algorithms and local files around explicitly
        # synthetic outer registration evidence. No APP, signature or gate.
        producer = load('preparatory_byte_producer',
                        'test-application-source5-preparatory-producer.py')
        with tempfile.TemporaryDirectory(prefix='prep-byte-profile-') as temporary:
            fixture = producer.PreparatoryProducerFixture(Path(temporary))
            try:
                artifacts = fixture.build()
                manifest = artifacts['manifest']
                budget = artifacts['budget']
                budget_raw = artifacts['budget_raw']
                source_pin = budget['original_pins']['source_manifests'][fixture.host_id]
                plan_pin = budget['original_pins']['initial_plan']
                spec_pin = budget['original_pins']['initial_spec']
                execution_pin = {'path': str(fixture.manifest_path),
                                 'raw_sha256': hashlib.sha256(artifacts['manifest_raw']).hexdigest(),
                                 'semantic_sha256': manifest['manifest_sha256']}
                context = {'schema': archive.CONTEXT_SCHEMA_V1,
                           'campaign_id': fixture.spec['campaign_id'], 'host_id': fixture.host_id,
                           'source_manifest_pin': {key: source_pin[key] for key in
                                                   ('path', 'raw_sha256', 'semantic_sha256')},
                           'plan_pin': plan_pin, 'resource_budget_pin': artifacts['budget_pin'],
                           'execution_manifest_pin': execution_pin, 'phase': 'exploration',
                           'job_index': 0, 'predecessor_ack_pin': None,
                           'authorized_signer_fingerprint': fixture.context.archive_signer_context[
                               'authorized_primary_fingerprint']}
                captured = {spec_pin['path']: fixture.spec_raw}
                for item in budget['path_catalogue']['chunks']:
                    captured[item['path']] = Path(item['path']).read_bytes()
                hidden = [Path(spec_pin['path']), Path(plan_pin['path']),
                          Path(source_pin['path']), *map(Path, captured)]
                for index, path in enumerate(dict.fromkeys(hidden)):
                    if path.is_file():
                        path.rename(path.with_name(path.name + '.hidden-' + str(index)))
                calls = []
                def read(pin, maximum):
                    raw = captured.get(pin['path'])
                    if (raw is None or len(raw) > maximum or
                            hashlib.sha256(raw).hexdigest() != pin['raw_sha256']):
                        raise OSError('outside exact captured bytes')
                    calls.append(pin['path'])
                    return raw
                result = archive.validate_preparatory_budget_profile_v1(
                    budget_raw, context,
                    source_manifest_raw=artifacts['source_manifest_raw'],
                    execution_manifest_raw=artifacts['manifest_raw'], plan_raw=fixture.plan_raw,
                    journal_width_contract_raw=fixture.controller.canonical_bytes(artifacts['width']),
                    captured_preparatory_artifact_reader=read, root_local=True)
                self.assertEqual(result['budget'], budget)
                self.assertIn(spec_pin['path'], calls)
                self.assertTrue(all(item['path'] in calls
                                    for item in budget['path_catalogue']['chunks']))
                self.assertFalse(Path(spec_pin['path']).exists())
                self.assertFalse(Path(plan_pin['path']).exists())
                self.assertFalse(Path(source_pin['path']).exists())
            finally:
                fixture.close()


if __name__ == '__main__':
    unittest.main()
