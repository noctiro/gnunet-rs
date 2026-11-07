#!/usr/bin/env python3
"""Pure negative controls for the maintained reactor acceptance predicates."""
import copy,itertools,tempfile,unittest
from pathlib import Path
import reactor_verify as v
class Tools(unittest.TestCase):
    def test_empty_runtime_witness_is_rejected(self):
        with self.assertRaises(ValueError):v.test_names('',36,v.REQUIRED)
    def test_missing_runtime_witness_is_rejected(self):
        names=sorted(v.REQUIRED)[:-1]
        with self.assertRaises(ValueError):v.test_names(''.join('test '+n+' ... ok\n'for n in names),36,v.REQUIRED)
    def test_duplicate_runtime_witness_is_rejected(self):
        names=sorted(v.REQUIRED);names[-1]=names[0]
        with self.assertRaises(ValueError):v.test_names(''.join('test '+n+' ... ok\n'for n in names),36,v.REQUIRED)
    def test_added_deleted_changed_source_paths_are_detected(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);a=root/'a.rs';a.write_text('a');before=v.snapshot(v.files(root));b=root/'b.md';b.write_text('b');self.assertNotEqual(before,v.snapshot(v.files(root)));b.unlink();self.assertEqual(before,v.snapshot(v.files(root)));a.write_text('changed');self.assertNotEqual(before,v.snapshot(v.files(root)));a.unlink();self.assertNotEqual(before,v.snapshot(v.files(root)))
    def test_output_source_or_ancestor_is_rejected(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);source=root/'source';source.mkdir()
            for output in [root,source,source/'child']:
                with self.assertRaises(ValueError):v.require_disjoint(output,[source])
    def good_reference(self):
        return {'status':'passed','source_unchanged':True,'kind':'unmodified-official-c-arm-reference-build','upstream':{'revision':v.PIN,'tag':'v0.29.1'},'source':'/owned/source','build':'/owned/build','commands':[{'name':'meson-setup','exit_code':0,'argv':['meson','setup','/owned/build','/owned/source']}]}
    def test_reference_wrong_source_or_build_is_rejected(self):
        for key,index in [('source',3),('build',2)]:
            value=self.good_reference();value[key]='/other'
            with self.assertRaises(ValueError):v.validate_reference_details(value,'/owned/source')
            value=self.good_reference();value['commands'][0]['argv'][index]='/other'
            with self.assertRaises(ValueError):v.validate_reference_details(value,'/owned/source')
    def test_reference_failed_setup_is_rejected(self):
        value=self.good_reference();value['commands'][0]['exit_code']=1
        with self.assertRaises(ValueError):v.validate_reference_details(value,'/owned/source')
    def test_reference_wrong_revision_is_rejected(self):
        value=self.good_reference();value['upstream']['revision']='0'*40
        with self.assertRaises(ValueError):v.validate_reference_details(value,'/owned/source')
    def test_reference_wrong_kind_is_rejected(self):
        value=self.good_reference();value['kind']='extracted-component'
        with self.assertRaises(ValueError):v.validate_reference_details(value,'/owned/source')
    def test_dependency_feature_change_is_detected(self):
        base={'name':'test','version':'0.1.0','edition':'2024','license':'MPL-2.0','rust_version':'1.99.1','features':{},'dependencies':[{'name':'dep','req':'=1.0.0','source':None,'kind':None,'rename':None,'optional':False,'uses_default_features':False,'target':None,'path':'/owned/dep','features':[]}]}
        changed=copy.deepcopy(base);changed['dependencies'][0]['features']=['alloc'];self.assertNotEqual(v.package_contract(base),v.package_contract(changed));changed=copy.deepcopy(base);changed['dependencies'][0]['source']='different';self.assertNotEqual(v.package_contract(base),v.package_contract(changed))
    def test_pair_empty_or_duplicate_actual_cases_is_rejected(self):
        rows=[]
        for server,actor,profile in itertools.product(('normal','rust'),('c','rust'),('unix','tcp4')):
            done={'event':'done','failed':0,'monitors':4}if actor=='c'else{'event':'done','results':9,'helper_children':0,'canceled_callback_suppressed':True,'repeat_connections':2}
            rows.append({'server':server,'actor':actor,'profile':profile,'actor_exit':0,'daemon_exit':0,'only_owned_endpoint':True,'natural_process_cleanup':True,'events':[done,{'event':'stop-arm','status':2,'result':None}]})
        good={'status':'passed','inputs_unchanged':True,'case_count':8,'cases':rows};v.pair_cases(good)
        for changed in [dict(good,cases=[]),dict(good,cases=[rows[0]]*8)]:
            with self.assertRaises(ValueError):v.pair_cases(changed)
        changed=copy.deepcopy(good);changed['cases'][0]['events']=[]
        with self.assertRaises(ValueError):v.pair_cases(changed)
if __name__=='__main__':unittest.main(verbosity=2)
