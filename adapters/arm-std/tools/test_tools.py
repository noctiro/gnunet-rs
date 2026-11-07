#!/usr/bin/env python3
"""Local fail-closed tool boundaries; no sockets, accounts or DNS."""
import copy,json,pathlib,sys,tempfile,unittest
from reference import validate_data,PINNED_REVISION,sha
from _common import require_disjoint_output,local_snapshot,require_lint_contract
from witnesses import require_test_output,require_actor,require_stdio,require_docs,STDIO_CASES,C_NULL_READY,C_OCCUPIED_STDERR


def actor():
    return {'exit_code':0,'target':{'nonempty':True},'caller':[{'event':'result','status':0,'result':2},{'event':'reaped','exit':0,'signal':0},{'event':'done','callbacks':1,'children':1,'failed':0}]}


def stdio():
    rows=[]
    for closed,flags,clo in sorted(STDIO_CASES):
        original=(closed|clo)&flags
        target={'types':[(-1 if original&(1<<fd)else 4096 if flags&(1<<fd)else 8192)for fd in range(3)],'access':[(-1 if original&(1<<fd)else 0 if fd==0 else 1)for fd in range(3)],'flags':[(-1 if original&(1<<fd)else 0)for fd in range(3)],'readiness_fd':12,'readiness_type':4096,'readiness_cloexec':False,'readiness_nonblock':True,'readiness_close_errno':0}
        rust=actor();rust['target']=target;native=copy.deepcopy(rust);case=(closed,flags,clo)
        if case in C_NULL_READY:native['target'].update(readiness_type=8192,readiness_nonblock=False)
        if case in C_OCCUPIED_STDERR or case in {(7,4,0),(7,5,0)}:
            for key,value in [('types',4096 if case in C_OCCUPIED_STDERR else 8192),('access',1),('flags',0)]:native['target'][key][2]=value
        rows.append({'closed':closed,'stdio':flags,'cloexec':clo,'matched':native['target']==rust['target'],'observations':{'c':native,'rust':rust}})
    return {'status':'observed_native_differences','cases':rows,'matched_cases':62,'differences':[{}for _ in range(18)]}


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name).resolve();self.source=self.root/'source';self.source.mkdir();build=self.root/'build';build.mkdir();prefix=self.root/'prefix';(prefix/'lib').mkdir(parents=True)
        files=[]
        for name in ['libgnunetarm.2.dylib','libgnunetutil.23.dylib']:
            path=prefix/'lib'/name;path.write_bytes(name.encode());files.append({'path':str(path),'sha256':sha(path)})
        config=build/'gnunet_private_config.h';config.write_bytes(b'actual private compile profile');commands=build/'compile_commands.json';commands.write_text('[]')
        self.state={'revision':PINNED_REVISION,'tag':'v0.29.1','tracked_files':2,'tracked_sources_clean':True,'tracked_input_sha256':'1'*64,'gitlinks':[]}
        self.receipt={'kind':'unmodified-official-c-arm-reference-build','status':'passed','source_unchanged':True,'upstream':self.state,'commands':[{'name':'meson-setup','argv':['meson','setup',str(build),str(self.source)]}],'build':str(build),'prefix':str(prefix),'libraries':files,'generated_config':{'path':str(config),'sha256':sha(config)},'compile_commands':{'path':str(commands),'sha256':sha(commands)},'runtime_environment':{'GNUNET_PREFIX':str(prefix),'DYLD_LIBRARY_PATH':str(prefix/'lib'),'LD_LIBRARY_PATH':str(prefix/'lib')}}
    def test_normal_declared_positive_control(self):
        self.assertEqual(len(validate_data(self.receipt,self.source,self.state)),4)
    def test_wrong_revision_even_jointly_changed_state_refused(self):
        receipt=copy.deepcopy(self.receipt);receipt['upstream']['revision']='0'*40
        with self.assertRaises(ValueError):validate_data(receipt,self.source,receipt['upstream'])
    def test_changed_normal_library_refused(self):
        pathlib.Path(self.receipt['libraries'][0]['path']).write_bytes(b'late changed library')
        with self.assertRaises(ValueError):validate_data(self.receipt,self.source,self.state)
    def test_changed_compile_configuration_refused(self):
        pathlib.Path(self.receipt['generated_config']['path']).write_bytes(b'changed profile')
        with self.assertRaises(ValueError):validate_data(self.receipt,self.source,self.state)
    def test_changed_compile_database_and_source_refused(self):
        pathlib.Path(self.receipt['compile_commands']['path']).write_text('[{}]')
        with self.assertRaises(ValueError):validate_data(self.receipt,self.source,self.state)
        receipt=copy.deepcopy(self.receipt);receipt['compile_commands']['sha256']=sha(receipt['compile_commands']['path']);state=copy.deepcopy(self.state);state['tracked_input_sha256']='2'*64
        with self.assertRaises(ValueError):validate_data(receipt,self.source,state)
    def test_output_overlap_and_existing_directory_refused(self):
        with self.assertRaises(ValueError):require_disjoint_output(self.source/'out',[self.source])
        with self.assertRaises(ValueError):require_disjoint_output(self.root,[self.source])
        with self.assertRaises(FileExistsError):require_disjoint_output(self.source,[])
    def test_valid_json_nonzero_child_exit_is_not_success(self):
        row=actor();require_actor(row);row['exit_code']=7
        with self.assertRaises(ValueError):require_actor(row)
        process=__import__('subprocess').run([sys.executable,'-c','import json;print(json.dumps({"valid":True}));raise SystemExit(7)'],capture_output=True)
        self.assertEqual(json.loads(process.stdout),{'valid':True});self.assertEqual(process.returncode,7)
    def test_empty_missing_duplicate_test_names_refused(self):
        require_test_output('test a ... ok\ntest b ... ok\n',{'a','b'})
        for output in ['', 'test a ... ok\n','test a ... ok\ntest a ... ok\n']:
            with self.assertRaises(ValueError):require_test_output(output,{'a','b'})
        with self.assertRaises(ValueError):require_test_output('',set())
    def test_docs_use_actual_selected_workspace_prefix_and_unique_controls(self):
        labels=['src/control.rs - negative (line 1) - compile fail','src/control.rs - positive (line 2)','src/monitor_host.rs - negative (line 3) - compile fail','src/monitor_host.rs - positive (line 4)']
        text=''.join('test '+name+' ... ok\n'for name in labels)
        self.assertEqual(require_docs(text),labels)
        prefix='adapters/arm-std/'
        workspace=''.join('test '+prefix+name+' ... ok\n'for name in labels)
        self.assertEqual(require_docs(workspace,prefix),[prefix+name for name in labels])
        for invalid in [text,workspace.replace('monitor_host.rs','other.rs'),workspace.replace(labels[1],labels[0])]:
            with self.assertRaises(ValueError):require_docs(invalid,prefix)
    def test_complete_root_lint_policy_cannot_be_replaced_with_warnings_only(self):
        package=self.root/'pkg';package.mkdir();manifest=package/'Cargo.toml'
        policy='[workspace.lints.rust]\nwarnings="deny"\n\n[workspace.lints.clippy]\nunwrap_used="deny"\n\n'
        (self.root/'Cargo.toml').write_text('[workspace]\n'+policy+'[workspace.dependencies]\n')
        metadata={'workspace_root':str(self.root)}
        manifest.write_text('[package]\nname="x"\n')
        with self.assertRaises(ValueError):require_lint_contract(package,self.root,metadata)
        manifest.write_text('[package]\nname="x"\n[lints]\nworkspace=true\n')
        self.assertTrue(require_lint_contract(package,self.root,metadata)['inherited_from_reviewed_workspace'])
        with self.assertRaises(ValueError):require_lint_contract(package,self.root,{'workspace_root':str(package)})
        manifest.write_text('[package]\nname="x"\n'+policy.replace('[workspace.lints.','[lints.'))
        self.assertFalse(require_lint_contract(package,self.root,metadata)['inherited_from_reviewed_workspace'])
        manifest.write_text(manifest.read_text().replace('unwrap_used="deny"','unwrap_used="allow"'))
        with self.assertRaises(ValueError):require_lint_contract(package,self.root,metadata)
    def test_stdio_positive_explicit_differences_and_missing_case_refused(self):
        document=stdio();require_stdio(document);document['cases'].pop()
        with self.assertRaises(ValueError):require_stdio(document)
    def test_stdio_unsafe_pipe_or_falsely_matched_difference_refused(self):
        for mutation in ['unsafe','allmatched','unknownfield']:
            document=stdio()
            if mutation=='unsafe':document['cases'][0]['observations']['rust']['target']['readiness_fd']=1
            elif mutation=='allmatched':next(row for row in document['cases']if not row['matched'])['matched']=True
            else:next(row for row in document['cases']if not row['matched'])['observations']['c']['target']['readiness_close_errno']=9
            with self.assertRaises(ValueError):require_stdio(document)
    def test_snapshot_includes_nonrust_src_additions_deletions_and_workspace_lock(self):
        package=self.root/'pkg';(package/'src').mkdir(parents=True);(package/'Cargo.toml').write_text('[package]\nname="fixture"\n');(self.root/'Cargo.toml').write_text('[workspace]\n');(self.root/'Cargo.lock').write_text('locked');(package/'src'/'x.rs').write_text('');data=package/'src'/'data.bin';data.write_bytes(b'include_bytes material')
        metadata={'workspace_root':str(self.root),'packages':[{'id':'fixture','manifest_path':str(package/'Cargo.toml'),'source':None}],'resolve':{'nodes':[{'id':'fixture','dependencies':[]}]}}
        _,before=local_snapshot(metadata,package,package/'tools');self.assertIn(str(data),before);self.assertIn(str(self.root/'Cargo.lock'),before);extra=package/'src'/'new.txt';extra.write_bytes(b'new');_,added=local_snapshot(metadata,package,package/'tools');self.assertNotEqual(before,added);extra.unlink();data.unlink();_,removed=local_snapshot(metadata,package,package/'tools');self.assertNotEqual(before,removed)


if __name__=='__main__':unittest.main(verbosity=2)
