"""Held replay orchestration tests; prepared/GPG/numeric boundaries are explicit mocks.

A separate case uses the real captured-file reader and absent origin names.
These tests do not qualify a real APP pair, Soak, or full prepared campaign.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


def load(name, filename):
    path=Path(__file__).with_name(filename)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


class Provider:
    def __init__(self, suppress=False):
        self.uses=[];self.active=False;self.closed=0;self.suppress=suppress
    def open_view(self,job,purpose,*,use):
        parent=self
        class Manager:
            def __enter__(self):
                if parent.active:raise AssertionError('overlapping single-stage view')
                parent.active=True;parent.uses.append((job['run_id'],purpose,use));return {'run_id':job['run_id']}
            def __exit__(self,*exc):
                parent.active=False;parent.closed+=1;return parent.suppress
        return Manager()


class HeldCapturedRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=load('held_records_root_tests','application-campaign-chronology.py')
    @contextlib.contextmanager
    def case(self, counts=None):
        m=self.m;counts=counts or {'confirmation':2,'pressure':2}
        jobs={phase:[{'phase':phase,'host_id':'host','run_id':f'{phase}-{i}','ordinal':i,
                       **({'predecessor_run_ids':[f'confirmation-{i}']} if phase=='pressure' else {})}
                     for i in range(counts.get(phase,0))]
              for phase in ('exploration','aa','confirmation','pressure','soak')}
        records={};pins={};finished={}
        for phase,values in jobs.items():
            for job in values:
                run=job['run_id'];metrics=[{'run':run,'member':i} for i in range(1 if phase=='soak' else 2)]
                c={'component_sha256':'c'*64,'process_metrics_sha256':hashlib.sha256(m.canonical_bytes(metrics)).hexdigest()}
                evidence={'recipe':{'path':'/abs/recipe','raw_sha256':'a'*64},'overlay':{'path':'/abs/overlay','raw_sha256':'b'*64},
                          'readback':{'path':'/abs/readback','raw_sha256':'d'*64},'processes':{'path':'/abs/processes','raw_sha256':'e'*64},
                          'host_receipt':{'path':'/abs/host','raw_sha256':'f'*64,'receipt_sha256':'1'*64}}
                record={'job':job,'state':'valid_soak' if phase=='soak' else 'valid_pair','record_sha256':'2'*64,
                        'pair_directory':'/abs/output','process_metrics':metrics,'chronology':c,'evidence':evidence}
                if phase=='pressure':
                    c['component_sha256']=hashlib.sha256(m.canonical_bytes({
                        'schema':'allocatbelt.application-source5-pressure-component.v1','validated':True,'qualification_eligible':False,
                        **{name:evidence[name] for name in ('recipe','overlay','readback','processes')},'pressure_metrics':metrics})).hexdigest()
                records[run]=record;pins[run]={'path':'/abs/'+run,'raw_sha256':hashlib.sha256(m.canonical_bytes(record)).hexdigest()}
                finished[(phase,run)]={'details':{'job':job},'state':record['state']}
        lock=SimpleNamespace();provider=Provider()
        controller=SimpleNamespace(validate_phase_ledger=mock.Mock())
        prepared={'host_id':'host','plan':{'jobs':jobs},'controller':controller}
        state={'source5_pending':None,'source5_cleanup_blocked':False,'source5_failed_owner_window':False,
               'head':'3'*64,'source5_seen_jobs':set(finished),'source5_finished':finished}
        manifest={'schema':m.SOURCE5_EXECUTION_SCHEMA_V4};manifest_pin={'path':'/abs/manifest','sha256':'4'*64}
        def retained(job,*args):return records[job['run_id']],pins[job['run_id']],finished[(job['phase'],job['run_id'])]
        def proof(_lock,_pin,record_pin,*,captured_evidence):
            run=next(run for run,pin in pins.items() if pin==record_pin);record=records[run]
            return {'record':record_pin,'record_sha256':record['record_sha256'],'process_metrics':record['process_metrics'],
                    'metrics_sha256':record['chronology']['process_metrics_sha256'],'job_terminal_head':'5'*64}
        def pressure(recipe,output,readback,host_receipt,**kwargs):
            run=kwargs['captured_evidence']['run_id'];return {'pressure_metrics':records[run]['process_metrics']}
        owner=SimpleNamespace(verify_pressure_pair_with_captured_outputs=mock.Mock(side_effect=pressure))
        with contextlib.ExitStack() as stack:
            patches=[('_lock_token_is_live',mock.Mock(return_value=True)),
                     ('_prepare_source5_context',mock.Mock(return_value=(manifest,prepared,state,manifest_pin))),
                     ('_source5_archived_journal_ledger',mock.Mock(side_effect=lambda _p,phase:{j['run_id']:'x' for j in jobs[phase]})),
                     ('_source5_captured_record_held',mock.Mock(side_effect=retained)),
                     ('_source5_captured_authority_held',mock.Mock(side_effect=lambda view,*a:view)),
                     ('_source5_analysis_epoch',mock.Mock(return_value='6'*64)),
                     ('verify_source5_completed_fixed_phase_locked',mock.Mock(side_effect=proof)),
                     ('_source5_issue_captured_pressure_context_held',mock.Mock(return_value=object())),
                     ('_source5_captured_pressure_inputs',mock.Mock(return_value=({}, {}, {'parsed':'recipe'}, {}))),
                     ('_source5_captured_source_module',mock.Mock(return_value=owner))]
            installed={name:stack.enter_context(mock.patch.object(m,name,value)) for name,value in patches}
            yield SimpleNamespace(m=m,lock=lock,provider=provider,prepared=prepared,state=state,jobs=jobs,records=records,
                                  pins=pins,pin=manifest_pin,controller=controller,owner=owner,patches=installed)
    def replay(self,c,phase,final=False):
        return c.m.replay_source5_phase_records_captured_held(c.lock,c.pin,phase,captured_read_context=c.provider,
                  analysis_phase='final_analysis' if final else None)
    def test_pressure_predecessor_precedes_each_owner_with_one_stage(self):
        with self.case() as c:
            self.assertEqual(self.replay(c,'pressure'),[c.records[j['run_id']] for j in c.jobs['pressure']])
            self.assertEqual(c.provider.uses,[('confirmation-0','pressure_analysis','pressure_predecessor'),
                ('pressure-0','pressure_analysis','phase_analysis'),('confirmation-1','pressure_analysis','pressure_predecessor'),
                ('pressure-1','pressure_analysis','phase_analysis')]);self.assertEqual(c.provider.closed,4)
    def test_owner_receives_actual_module_lock_and_parsed_recipe(self):
        with self.case() as c:
            self.replay(c,'pressure');args,kwargs=c.owner.verify_pressure_pair_with_captured_outputs.call_args
            self.assertEqual(args[0],{'parsed':'recipe'});self.assertIs(kwargs['chronology_module'],c.m)
            self.assertIs(kwargs['lock'],c.lock)
    def test_provider_cannot_suppress_binding_failure(self):
        with self.case({'confirmation':1}) as c:
            c.provider.suppress=True;c.patches['_source5_captured_authority_held'].side_effect=c.m.ChronologyError('binding rejected')
            with self.assertRaisesRegex(c.m.ChronologyError,'binding rejected'):self.replay(c,'confirmation')
            self.assertFalse(c.provider.active);self.assertEqual(c.provider.closed,1)
    def test_owner_numeric_difference_fails_and_closes_view(self):
        with self.case({'confirmation':1}) as c:
            c.patches['verify_source5_completed_fixed_phase_locked'].side_effect=None
            c.patches['verify_source5_completed_fixed_phase_locked'].return_value={'record':c.pins['confirmation-0'],'process_metrics':[], 'metrics_sha256':'0'*64}
            with self.assertRaisesRegex(c.m.ChronologyError,'complete metrics'):self.replay(c,'confirmation')
            self.assertEqual(c.provider.closed,1)
    def test_incomplete_original_ledger_is_rejected_before_io(self):
        with self.case({'confirmation':1}) as c:
            c.patches['_source5_archived_journal_ledger'].side_effect=None;c.patches['_source5_archived_journal_ledger'].return_value={}
            with self.assertRaisesRegex(c.m.ChronologyError,'every original ordinal'):self.replay(c,'confirmation')
            self.assertEqual(c.provider.uses,[])
    def test_dirty_owner_window_is_rejected_before_io(self):
        with self.case({'confirmation':1}) as c:
            c.state['source5_pending']='active'
            with self.assertRaisesRegex(c.m.ChronologyError,'clean completed'):self.replay(c,'confirmation')
            self.assertEqual(c.provider.uses,[])
    def test_final_order_does_not_allow_confirmation_first(self):
        with self.case({'confirmation':1}) as c:
            with self.assertRaisesRegex(c.m.ChronologyError,'dependency order'):self.replay(c,'confirmation',True)
            self.assertEqual(c.provider.uses,[])
    def test_final_pressure_reuses_only_complete_same_pass_fixed_proofs(self):
        with self.case({'exploration':1,'aa':1,'confirmation':2,'pressure':2}) as c:
            for phase in ('exploration','aa','confirmation','pressure'):self.replay(c,phase,True)
            self.assertTrue(all(use=='final_replay' for _run,_purpose,use in c.provider.uses))
            self.assertEqual(c.patches['verify_source5_completed_fixed_phase_locked'].call_count,4)
            self.assertEqual(c.owner.verify_pressure_pair_with_captured_outputs.call_count,2)
    def test_final_journal_change_expires_prior_fixed_proofs(self):
        with self.case({'exploration':1,'aa':1,'confirmation':1,'pressure':1}) as c:
            for phase in ('exploration','aa','confirmation'):self.replay(c,phase,True)
            c.state['head']='changed'
            with self.assertRaisesRegex(c.m.ChronologyError,'dependency order'):self.replay(c,'pressure',True)
    def test_final_another_provider_cannot_reuse_fixed_proofs(self):
        with self.case({'exploration':1,'aa':1,'confirmation':1,'pressure':1}) as c:
            for phase in ('exploration','aa','confirmation'):self.replay(c,phase,True)
            c.provider=Provider()
            with self.assertRaisesRegex(c.m.ChronologyError,'dependency order'):self.replay(c,'pressure',True)
    def test_context_constructor_and_foreign_issuer_fail_closed(self):
        m=self.m
        with self.assertRaises(m.ChronologyError):m.Source5CapturedPressurePredecessorContext()
        with self.assertRaises(m.ChronologyError):m.validate_source5_pressure_predecessor_context(
            object(),lock=object(),authorization_context={},recipe_pin={},output_root='/abs')
    def test_real_captured_json_reads_absent_origin_and_checks_raw_pin(self):
        m=self.m;fixed=load('held_records_real_capture_reader','application-fixed-pair.py')
        with tempfile.TemporaryDirectory(prefix='held-capture-') as temporary:
            root=Path(temporary);stage=root/'stage';stage.mkdir(mode=0o700);origin=root/'gone.json'
            raw=m.canonical_bytes({'value':'strict bytes'});path=stage/'object';path.write_bytes(raw);path.chmod(0o400)
            pin={'path':str(origin),'raw_sha256':hashlib.sha256(raw).hexdigest()}
            refs={str(origin):{'origin_path':str(origin),'path':str(path),'role':'helper','host_id':'host','raw_sha256':pin['raw_sha256'],
                              'semantic_sha256':None,'byte_count':len(raw),'maximum_bytes':len(raw)}}
            view={'objects':refs,'stage_root':str(stage)}
            self.assertEqual(m._source5_captured_json(pin,'actual captured JSON',view,fixed,4096),{'value':'strict bytes'})
            self.assertFalse(origin.exists())
            with self.assertRaisesRegex(m.ChronologyError,'original raw pin'):
                m._source5_captured_json({**pin,'raw_sha256':'0'*64},'bad raw pin',view,fixed,4096)


    def test_final_certificate_keeps_only_bounded_identity_fields(self):
        with self.case({'exploration':1,'aa':1,'confirmation':1,'pressure':1}) as c:
            for phase in ('exploration','aa','confirmation'):self.replay(c,phase,True)
            entry=c.m._SOURCE5_CAPTURED_PHASE_PASSES[c.provider]['confirmation']['confirmation-0']
            self.assertLessEqual(len(entry),16*1024)
            self.assertEqual(set(json.loads(entry)),{'record','record_sha256','metrics_sha256','job_terminal_head'})
    def test_final_local_record_mutation_invalidates_numeric_certificate(self):
        with self.case({'exploration':1,'aa':1,'confirmation':1,'pressure':1}) as c:
            for phase in ('exploration','aa','confirmation'):self.replay(c,phase,True)
            c.records['confirmation-0']['process_metrics'][0]['run']='tampered'
            with self.assertRaisesRegex(c.m.ChronologyError,'changed after its complete fixed replay'):
                self.replay(c,'pressure',True)


class CapturedPressureHelperBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=load('held_pressure_helper_root_tests','application-campaign-chronology.py')
        cls.fixed=load('held_pressure_helper_capture_reader','application-fixed-pair.py')

    @contextlib.contextmanager
    def fixture(self, extra_payload=False, changed_receipt=False):
        m=self.m
        with tempfile.TemporaryDirectory(prefix='held-helper-capture-') as temporary:
            root=Path(temporary);stage=root/'stage';stage.mkdir(mode=0o700);objects={}
            def capture(name,value):
                origin=str(root/'removed'/name);raw=m.canonical_bytes(value);local=stage/name
                local.write_bytes(raw);local.chmod(0o400);sha=hashlib.sha256(raw).hexdigest()
                objects[origin]={'origin_path':origin,'path':str(local),'role':'source5_helper_input','host_id':'host',
                                 'raw_sha256':sha,'semantic_sha256':None,'byte_count':len(raw),'maximum_bytes':len(raw)}
                return {'path':origin,'raw_sha256':sha}
            job={'phase':'pressure','host_id':'host','run_id':'original-pressure','ordinal':0,'predecessor_run_ids':['fixed-original']}
            overlay={'chronology':{'journal_head':'1'*64}};overlay_pin=capture('overlay.json',overlay)
            recipe={'job':{'value':job},'execution_overlay':{'artifact':overlay_pin}};recipe_pin=capture('recipe.json',recipe)
            expected_host=str(root/'artifacts/campaign/source5/host/pressure-host-receipts/original-pressure.json')
            helper_module={'path':'scripts/application-pressure-pair.py','sha256':'2'*64,'size':100,'mode':'100755','kind':'file'}
            payload={'schema':m.SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2,'recipe_pin':recipe_pin,'output_root':str(root/'output'),
                     'probe_capture_bundle':{},'host_receipt_path':str(root/'wrong-receipt') if changed_receipt else expected_host}
            if extra_payload:payload['unexpected']='field'
            body={'schema':m.SOURCE5_HELPER_INPUT_SCHEMA,'scope':'final_frozen','campaign_id':'campaign','host_id':'host',
                  'phase':'pressure','job_index':0,'job':job,'job_sha256':hashlib.sha256(m.canonical_bytes(job)).hexdigest(),
                  'members':[{'member':0},{'member':1}],
                  'helper':{'path':helper_module['path'],'sha256':helper_module['sha256'],'entrypoint':'run_pressure_pair_locked'},
                  'payload':payload,'prerequisites':[],'outer_deadline_seconds':100,'effective_timeout_seconds':100}
            snapshot=hashlib.sha256(m.canonical_bytes(body)).hexdigest()
            helper={**body,'input_snapshot_sha256':snapshot,'qualification_eligible':False};helper_pin=capture('helper.json',helper)
            details={**{k:body[k] for k in ('campaign_id','host_id','phase','job_index','job','job_sha256','members','prerequisites',
                       'outer_deadline_seconds','effective_timeout_seconds')},'helper_module':helper_module,'helper_input':helper_pin,
                     'output_root':payload['output_root'],'input_snapshot_sha256':snapshot}
            prepared={'source5_execution_manifest':{'artifact_root':str(root/'artifacts')},'campaign_id':'campaign','host_id':'host'}
            view={'stage_root':str(stage),'objects':objects,'owner_host_receipt_pin':{'path':expected_host}}
            with mock.patch.object(m,'_source5_captured_source_module',return_value=self.fixed):
                yield m,prepared,details,view,helper,recipe_pin,recipe,overlay

    def test_real_capture_helper_recipe_overlay_survive_absent_origins(self):
        with self.fixture() as (m,prepared,details,view,helper,recipe_pin,recipe,overlay):
            self.assertEqual(m._source5_captured_pressure_inputs(prepared,details,view),(helper,recipe_pin,recipe,overlay))
            self.assertTrue(all(not Path(origin).exists() for origin in view['objects']))
    def test_raw_pinned_helper_cannot_change_authorization_snapshot(self):
        with self.fixture() as (m,prepared,details,view,*_):
            details['input_snapshot_sha256']='0'*64
            with self.assertRaisesRegex(m.ChronologyError,'frozen input snapshot'):
                m._source5_captured_pressure_inputs(prepared,details,view)
    def test_valid_raw_snapshot_cannot_add_bounded_payload_field(self):
        with self.fixture(extra_payload=True) as (m,prepared,details,view,*_):
            with self.assertRaisesRegex(m.ChronologyError,'payload'):
                m._source5_captured_pressure_inputs(prepared,details,view)
    def test_valid_raw_snapshot_cannot_move_strict_host_receipt(self):
        with self.fixture(changed_receipt=True) as (m,prepared,details,view,*_):
            with self.assertRaisesRegex(m.ChronologyError,'receipt destination'):
                m._source5_captured_pressure_inputs(prepared,details,view)


class HeldPhaseAnalysisMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.m=load('held_phase_metadata_tests','application-campaign-chronology.py')
    @contextlib.contextmanager
    def case(self):
        m=self.m
        with tempfile.TemporaryDirectory(prefix='held-phase-meta-') as temporary:
            root=Path(temporary);phases=('exploration','aa','fixed_analysis','pressure_analysis','soak')
            jobs={};finished={};events={};docs={};heads=[]
            for index,phase in enumerate(phases):
                source_phase={'fixed_analysis':'confirmation','pressure_analysis':'pressure'}.get(phase,phase)
                job={'phase':source_phase,'host_id':'host','run_id':source_phase+'-original'};jobs[source_phase]=[job]
                finished[(source_phase,job['run_id'])]={'state':'valid_soak' if phase=='soak' else 'valid_pair'}
                job_sha=hashlib.sha256(m.canonical_bytes([job['run_id']])).hexdigest()
                body={'schema':'allocatbelt.application-source5-phase-analysis.v1','campaign_id':'campaign','host_id':'host',
                      'phase':phase,'job_count':1,'job_set_sha256':job_sha,'job_evidence_complete':True,
                      'numeric_gates_passed':True,'phase_gate_passed':True,'campaign_qualification_eligible':False,
                      'result':{'fixture':'real canonical phase document'}}
                value={**body,'analysis_sha256':hashlib.sha256(m.canonical_bytes(body)).hexdigest()}
                raw=m.canonical_bytes(value);path=root/(phase+'.json');path.write_bytes(raw);path.chmod(0o600)
                raw_sha=hashlib.sha256(raw).hexdigest();head=hashlib.sha256(('event-'+phase).encode()).hexdigest();heads.append(head)
                details={key:body[key] for key in m.DETAIL_FIELDS['source5_analysis']-{'analysis','analysis_sha256'}}
                events[phase]={**details,'analysis':{'path':str(path),'raw_sha256':raw_sha},'analysis_sha256':raw_sha,
                               'event_head':head,'analysis_replay_required':True};docs[phase]=(path,value,raw)
            prepared={'campaign_id':'campaign','host_id':'host','plan':{'jobs':jobs}}
            state={'source5_pending':None,'source5_cleanup_blocked':False,'source5_failed_owner_window':False,
                   'source5_analyses':events,'source5_finished':finished,'journal_heads':heads}
            manifest={'schema':m.SOURCE5_EXECUTION_SCHEMA_V4};pin={'path':str(root/'manifest.json'),'sha256':'1'*64}
            with m.campaign_host_lock(root,'campaign','host') as lock:
                with mock.patch.object(m,'_prepare_source5_context',return_value=(manifest,prepared,state,pin)):
                    yield m,lock,pin,state,docs
    def test_metadata_binds_actual_raw_pins_and_event_heads_without_clearing_deferral(self):
        with self.case() as (m,lock,pin,state,docs):
            before=copy.deepcopy(state)
            rows=m.source5_phase_analysis_events_held(lock,pin)
            self.assertEqual([row['phase'] for row in rows],['exploration','aa','fixed_analysis','pressure_analysis','soak'])
            for row in rows:
                prior=state['source5_analyses'][row['phase']]
                self.assertEqual(row,{key:prior[key] for key in ('phase','analysis','analysis_sha256','event_head')})
                self.assertNotEqual(row['analysis_sha256'],docs[row['phase']][1]['analysis_sha256'])
            self.assertEqual(before,state)
            rows[0]['analysis']['path']='mutated detached return'
            self.assertEqual(before,state)
    def test_metadata_rejects_semantic_digest_as_raw_event_digest(self):
        with self.case() as (m,lock,pin,state,docs):
            state['source5_analyses']['soak']['analysis_sha256']=docs['soak'][1]['analysis_sha256']
            with self.assertRaisesRegex(m.ChronologyError,'durable chronology event'):
                m.source5_phase_analysis_events_held(lock,pin)
    def test_metadata_rejects_event_head_outside_own_journal(self):
        with self.case() as (m,lock,pin,state,docs):
            state['source5_analyses']['aa']['event_head']='f'*64
            with self.assertRaisesRegex(m.ChronologyError,'actual retained journal'):
                m.source5_phase_analysis_events_held(lock,pin)
    def test_metadata_rejects_tampered_retained_analysis_file(self):
        with self.case() as (m,lock,pin,state,docs):
            path,value,_raw=docs['pressure_analysis'];path.write_bytes(m.canonical_bytes({**value,'numeric_gates_passed':False}));path.chmod(0o600)
            with self.assertRaises(m.ChronologyError):m.source5_phase_analysis_events_held(lock,pin)


class HeldAnalysisPublicWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.m=load('held_public_wrapper_tests','application-campaign-chronology.py')
    @contextlib.contextmanager
    def lock_case(self):
        with tempfile.TemporaryDirectory(prefix='held-public-wrapper-') as temporary:
            with self.m.campaign_host_lock(Path(temporary),'campaign','host') as lock:
                yield lock
    def test_phase_wrapper_holds_actual_plain_operation_mutex(self):
        m=self.m;provider=object();pin={'fixture':'manifest pin'}
        with self.lock_case() as lock:
            def replay(actual_lock,actual_pin,phase,**kwargs):
                self.assertIs(actual_lock,lock);self.assertEqual(actual_pin,pin);self.assertEqual(phase,'pressure')
                self.assertTrue(lock._operation_lock.locked());self.assertIs(kwargs['captured_read_context'],provider)
                self.assertNotIn('analysis_phase',kwargs);return [{'phase':phase}]
            with mock.patch.object(m,'replay_source5_phase_records_captured_held',side_effect=replay):
                result=m.replay_source5_phase_records_captured_locked(lock,pin,'pressure',captured_read_context=provider)
            self.assertEqual(result,[{'phase':'pressure'}]);self.assertFalse(lock._operation_lock.locked())
    def test_final_wrapper_keeps_one_mutex_and_provider_for_all_five_phases(self):
        m=self.m;provider=object();phases=['exploration','aa','confirmation','pressure','soak'];calls=[]
        with self.lock_case() as lock:
            def replay(actual_lock,pin,phase,**kwargs):
                self.assertIs(actual_lock,lock);self.assertTrue(lock._operation_lock.locked())
                self.assertIs(kwargs['captured_read_context'],provider);self.assertEqual(kwargs['analysis_phase'],'final_analysis')
                calls.append(phase);return [{'phase':phase}]
            with mock.patch.object(m,'replay_source5_phase_records_captured_held',side_effect=replay):
                result=m.replay_source5_final_records_captured_locked(lock,{},captured_read_context=provider)
            self.assertEqual(calls,phases);self.assertEqual(result,{p:[{'phase':p}] for p in phases})
            self.assertFalse(lock._operation_lock.locked())
    def test_final_wrapper_propagates_owner_failure_and_releases_mutex(self):
        m=self.m;calls=[]
        with self.lock_case() as lock:
            def replay(_lock,_pin,phase,**kwargs):
                self.assertTrue(lock._operation_lock.locked());calls.append(phase)
                if phase=='pressure':raise m.ChronologyError('actual owner failure')
                return []
            with mock.patch.object(m,'replay_source5_phase_records_captured_held',side_effect=replay):
                with self.assertRaisesRegex(m.ChronologyError,'actual owner failure'):
                    m.replay_source5_final_records_captured_locked(lock,{},captured_read_context=object())
            self.assertEqual(calls,['exploration','aa','confirmation','pressure']);self.assertFalse(lock._operation_lock.locked())
    def test_closed_lock_cannot_invoke_either_wrapper(self):
        m=self.m
        with self.lock_case() as lock:pass
        with mock.patch.object(m,'replay_source5_phase_records_captured_held') as replay:
            with self.assertRaises(m.ChronologyError):
                m.replay_source5_phase_records_captured_locked(lock,{},'pressure',captured_read_context=object())
            with self.assertRaises(m.ChronologyError):
                m.replay_source5_final_records_captured_locked(lock,{},captured_read_context=object())
            replay.assert_not_called()


if __name__=='__main__':unittest.main()
