#!/usr/bin/env python3
"""Additional live-verifier negative controls; never an empty suite success."""
import copy, unittest
from live_witnesses import tests, commands, readpoint, daemon, monitor, COMMAND_LABELS
class Boundaries(unittest.TestCase):
    def test_empty_named_rust_suite_rejected(self):
        with self.assertRaises(ValueError):tests('',set())
    def test_missing_or_duplicate_named_rust_case_rejected(self):
        for text in ['test a ... ok\n','test a ... ok\ntest a ... ok\n']:
            with self.assertRaises(ValueError):tests(text,{'a','b'})
    def test_exact_named_rust_case_accepted(self):
        self.assertEqual(tests('test a ... ok\ntest b ... ok\n',{'a','b'}),['a','b'])
    def test_empty_command_profiles_rejected(self):
        with self.assertRaises(ValueError):commands({'status':'passed','inputs':{'x':'a'},'inputs_unchanged':True,'cases':[],'paired_cases':36})
    def test_late_nonzero_json_actor_rejected(self):
        doc={'status':'passed','inputs':{'x':'a'},'inputs_unchanged':True,'paired_cases':36,'cases':[{'label':name,'matched':True,'observations':{'c':{'exit_code':0},'rust':{'exit_code':0}}}for name in COMMAND_LABELS]}
        commands(doc);doc['cases'][0]['observations']['rust']['exit_code']=7
        with self.assertRaises(ValueError):commands(doc)
    def test_wrong_command_label_rejected(self):
        doc={'status':'passed','inputs':{'x':'a'},'inputs_unchanged':True,'paired_cases':36,'cases':[{'label':name,'matched':True,'observations':{'c':{'exit_code':0},'rust':{'exit_code':0}}}for name in COMMAND_LABELS]};doc['cases'][0]['label']='unreviewed'
        with self.assertRaises(ValueError):commands(doc)
    def test_tcp_fence_connection_rejected(self):
        doc={'status':'passed','inputs':{'x':'a'},'inputs_unchanged':True,'actors':[{'actor':actor,'exit_code':0,'events':[{'event':'done','confirmed':1,'listed':1,'failed':0}]}for actor in ['c','rust']],'daemon_exit':0,'replacement_tcp_accepted':0,'actual_daemon_tcp_port':0,'isolation':{'system_services':False,'base_entries':[],'binary_sections':[],'actual_native_list_counts':[0,0]}}
        readpoint(doc);doc['replacement_tcp_accepted']=1
        with self.assertRaises(ValueError):readpoint(doc)
    def test_nonempty_daemon_service_inventory_rejected(self):
        doc={'status':'passed','inputs':{'x':'a'},'inputs_unchanged':True,'cases':[{'profile':p,'daemon_exit':0,'rust_exit':0,'events':[{'event':'row','kind':'Initial','name':n}for n in ['finished','empty-prefix','running']]}for p in ['unix','tcp4']]}
        daemon(doc);doc['cases'][0]['events'].append({'event':'row','kind':'Initial','name':'foreign'})
        with self.assertRaises(ValueError):daemon(doc)
    def test_normal_c_monitor_empty_trace_rejected(self):
        with self.assertRaises(ValueError):monitor({'status':'observed-normal-C-only','exit_code':0,'inputs':{'x':'a'},'inputs_unchanged':True,'events':[]})
    def test_missing_input_commitment_rejected(self):
        with self.assertRaises(ValueError):commands({'status':'passed','paired_cases':36})
if __name__=='__main__':unittest.main(verbosity=2)
