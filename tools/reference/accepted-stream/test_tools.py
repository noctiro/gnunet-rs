#!/usr/bin/env python3
"""Pure harness guards: synthetic rows are not native policy evidence."""
import copy
import itertools
import sys
import tempfile
import unittest
from pathlib import Path
sys.dont_write_bytecode=True
import verify
sys.path.insert(0,str(Path(__file__).resolve().parent))
import observe


def package():
    return {'name':'unit','version':'0.1.0','edition':'2024','license':'MPL-2.0','rust_version':'1.99.1','features':{'default':[]},'dependencies':[{'name':'gnunet-native','req':'*','source':None,'kind':None,'rename':None,'optional':False,'uses_default_features':False,'target':None,'path':'/native','features':[]}]}


def test_output():
    names=sorted(n for g in verify.inventory()['groups'].values()for n in g['tests'])
    documents=['src/lib.rs - Borrow (line '+str(i)+')'+(' - compile fail'if i<3 else '')for i in range(4)]
    return '\n'.join('test '+n+' ... ok'for n in names+documents)



def rows():
    options={'nodelay':4,'nonblocking':1,'cloexec':1,'keepalive':0,'reuseaddr':4,'type':1,'linger_on':0,'linger_seconds':0,'nosigpipe':1}
    c=[];r=[]
    for family,preset,mode,opt in itertools.product(['v4','v6'],['default','off','on'],['address','null-address'],['O0','O2']):
        listener=dict(options,nodelay=0 if preset=='off'else 4)
        c.append({'actor':'normal-c','family':family,'preset':preset,'accept_mode':mode,'optimization':opt,'listener':listener,'accepted_fd':6,'fd_setsize':1024,'accepted':dict(options),'actual_payload':True})
    for family,preset,mode in itertools.product(['v4','v6'],['default','off','on'],['poll','wrapper','canonical']):
        accepted={k:(int(bool(v))if k in {'nodelay','reuseaddr'}else v)for k,v in options.items()if k!='nosigpipe'}
        if mode!='canonical'and preset!='on':accepted['nodelay']=0
        native=dict(options,nodelay=accepted['nodelay'],nosigpipe=0 if preset=='off'and mode!='canonical'else 1,cloexec=0)
        accepted['native_readonly_duplicate']=native
        r.append({'actor':'rust-public','family':family,'preset':preset,'accept_mode':mode,'listener':{},'accepted_fd':8,'fd_setsize':1024,'before_wrapper':copy.deepcopy(accepted)if mode=='wrapper'else None,'accepted':accepted,'actual_payload':True})
    return c,r


class Guards(unittest.TestCase):
    def test_file_addition_and_deletion_change_discovered_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='canonical-guard-')as root:
            root=Path(root);p=root/'one';p.write_text('a');before=verify.snapshot(verify.files(root));q=root/'two';q.write_text('b')
            self.assertNotEqual(before,verify.snapshot(verify.files(root)));q.unlink();self.assertEqual(before,verify.snapshot(verify.files(root)));p.unlink();self.assertNotEqual(before,verify.snapshot(verify.files(root)))
    def test_dependency_contract_preserves_all_semantic_fields(self):
        p=package();baseline=verify.contract(p,Path('/native'))
        for key,value in {'req':'=0.2.0','source':'registry+changed','kind':'dev','rename':'alias','optional':True,'uses_default_features':True,'target':'cfg(unix)','features':['changed']}.items():
            with self.subTest(key=key):
                changed=copy.deepcopy(p);changed['dependencies'][0][key]=value;self.assertNotEqual(baseline,verify.contract(changed,Path('/native')))
        changed=copy.deepcopy(p);changed['features']['extra']=[];self.assertNotEqual(baseline,verify.contract(changed,Path('/native')))
    def test_native_dependency_role_rejects_foreign_path(self):
        with self.assertRaises(ValueError):verify.contract(package(),Path('/foreign'))
        self.assertEqual(verify.local_roles({'packages':[{'name':'one','source':None,'id':'one','manifest_path':'/root/a/Cargo.toml'}]},Path('/root')),{'one':'a/Cargo.toml'})
        row={'name':'same','source':None,'id':'one','manifest_path':'/root/a/Cargo.toml'}
        with self.assertRaises(ValueError):verify.local_roles({'packages':[row,dict(row,id='two',manifest_path='/root/b/Cargo.toml')]},Path('/root'))
    def test_missing_or_changed_full_root_lints_are_visible(self):
        text='[workspace.lints.rust]\nwarnings="deny"\n[workspace.lints.clippy]\nunwrap_used="deny"\n[workspace.lints.rustdoc]\nbroken_intra_doc_links="deny"\n'
        baseline=verify.lint(text,'workspace.lints.')
        self.assertNotEqual(baseline,verify.lint(text.replace('unwrap_used="deny"','unwrap_used="warn"'),'workspace.lints.'))
        with self.assertRaises(ValueError):verify.lint(text.replace('[workspace.lints.clippy]','[other]'),'workspace.lints.')
    def test_runtime_missing_duplicate_and_required_new_case_rejected(self):
        good=test_output();self.assertEqual(len(verify.tests(good)[0]),87)
        for changed in [good.replace('test '+verify.inventory()['groups']['ipc']['tests'][0]+' ... ok\n',''),good+'\ntest '+verify.inventory()['groups']['ipc']['tests'][0]+' ... ok',good.replace(sorted(verify.NEW_TESTS)[0].split('::')[-1],'fake_case')]:
            with self.assertRaises(ValueError):verify.tests(changed)
    def test_docs_require_all_four_and_three_compile_fail_controls(self):
        good=test_output()
        for changed in [good.replace(' - compile fail',''),good+'\ntest src/lib.rs - Extra (line 1) ... ok']:
            with self.assertRaises(ValueError):verify.tests(changed)
    def test_audited_source_content_change_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='canonical-audit-')as root:
            root=Path(root);p=root/'network.c';p.write_text('exact source');a={'files':[{'origin':'upstream','relative':'network.c','sha256':verify.sha(p)}]}
            self.assertEqual(verify.audit_inputs(a,{'packages':[]},root,root),{p.resolve()});p.write_text('changed')
            with self.assertRaises(ValueError):verify.audit_inputs(a,{'packages':[]},root,root)
    def test_audit_traversal_unknown_role_and_missing_registry_rejected(self):
        for row in [{'origin':'upstream','relative':'../network.c'},{'origin':'upstream','relative':'/network.c'},{'origin':'unknown','relative':'a'},{'origin':'registry','relative':'a','package':'absent','version':'1.0.0'}]:
            with self.assertRaises(ValueError):verify.audit_inputs({'files':[row]},{'packages':[]},Path('/source'),Path('/sysroot'))
    def test_output_overlap_blocks_source_and_ancestor(self):
        protected=Path('/tmp/guard-source')
        for out in [protected,protected/'out',protected.parent]:
            with self.assertRaises(ValueError):verify.output_guard(out,[protected])
        verify.output_guard(Path('/tmp/separate-output'),[protected])
    def test_exact_observation_sets_reject_duplicate_and_empty_rows(self):
        c,r=rows();self.assertEqual(len(observe.observations(c,r)),8)
        for a,b in [(c[:-1]+[c[0]],r),(c,r[:-1]+[r[0]]),([],[])]:
            with self.assertRaises(ValueError):observe.observations(a,b)
    def test_payload_actor_and_original_fd_evidence_are_required(self):
        for field,value in [('actual_payload',False),('actor','fabricated'),('accepted_fd',-1),('accepted_fd',1024)]:
            c,r=rows();c[0][field]=value
            with self.assertRaises(ValueError):observe.observations(c,r)
    def test_canonical_option_mismatch_and_impure_wrapper_rejected(self):
        c,r=rows();canonical=next(row for row in r if row['accept_mode']=='canonical');canonical['accepted']['nodelay']=0
        with self.assertRaises(ValueError):observe.observations(c,r)
        c,r=rows();wrapper=next(row for row in r if row['accept_mode']=='wrapper');wrapper['before_wrapper']['cloexec']=0
        with self.assertRaises(ValueError):observe.observations(c,r)

if __name__=='__main__':unittest.main()
