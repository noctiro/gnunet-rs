#!/usr/bin/env python3
"""Fresh additional ARM live/configuration/branch proof; no owner promotion.

Run after dependency/source freeze. All actual sockets and children are privately
owned; the normal daemon only sees an explicitly empty base and owned fixtures.
No old M8 count or receipt is substituted for a fresh execution.
"""
import argparse, json, os, pathlib, re, subprocess, sys, time
from _common import local_snapshot, require_disjoint_output, workspace_root, require_lint_contract, sha, unchanged
from reference import load
import live_witnesses as witness

TOOL_TESTS={
 'test_empty_command_profiles_rejected','test_empty_named_rust_suite_rejected',
 'test_exact_named_rust_case_accepted','test_late_nonzero_json_actor_rejected',
 'test_missing_input_commitment_rejected','test_missing_or_duplicate_named_rust_case_rejected',
 'test_nonempty_daemon_service_inventory_rejected','test_normal_c_monitor_empty_trace_rejected',
 'test_tcp_fence_connection_rejected','test_wrong_command_label_rejected',
}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
    p.add_argument('--repo',type=pathlib.Path)
    for name in ['source','reference','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--cargo',default='cargo');p.add_argument('--toolchain',default='1.99.1')
    a=p.parse_args();package=a.package.resolve();repo=a.repo.resolve()if a.repo else workspace_root(package);tools=pathlib.Path(__file__).resolve().parent;manifest=package/'Cargo.toml';cargo=[a.cargo,'+'+a.toolchain];locked=['--manifest-path',str(manifest),'--offline','--locked'];env=os.environ.copy();env['CARGO_BUILD_JOBS']='2'
    argv=cargo+['metadata',*locked,'--format-version','1'];meta=subprocess.run(argv,cwd=package,env=env,capture_output=True,timeout=180)
    if meta.returncode:raise RuntimeError('locked metadata failed: '+meta.stderr.decode())
    metadata=json.loads(meta.stdout);ref,normal=load(a.reference,a.source,repo)
    protected=[package,tools,repo,pathlib.Path(metadata['workspace_root']),a.source,a.reference.resolve().parent,pathlib.Path(ref['build']),pathlib.Path(ref['prefix'])]
    protected.extend(pathlib.Path(row['manifest_path']).parent for row in metadata['packages']if row['source']is None)
    out=require_disjoint_output(a.output,protected);out.mkdir();(out/'metadata.stdout').write_bytes(meta.stdout);(out/'metadata.stderr').write_bytes(meta.stderr)
    selected,inputs=local_snapshot(metadata,package,tools)
    if selected['name']!='gnunet-arm-host':raise ValueError('actual gnunet-arm-host package required')
    result={'status':'failed','owner_promotion':False,'scope':'additional live CLIENT configuration and ARM client/monitor branch witnesses; global PROGRAM Resolver broker/ARM daemon/CLI/testing completion not claimed','package':str(package),'inputs':inputs,'normal_inputs':normal,'commands':[{'label':'metadata','argv':argv,'exit_code':0}]};start=time.monotonic();bins={};nested=[]
    def run(label,argv,limit=180):
        argv=list(map(str,argv));child=subprocess.run(argv,cwd=package,env=env,capture_output=True,timeout=limit);(out/(label+'.stdout')).write_bytes(child.stdout);(out/(label+'.stderr')).write_bytes(child.stderr);result['commands'].append({'label':label,'argv':argv,'exit_code':child.returncode})
        if child.returncode:raise RuntimeError(label+' exit '+str(child.returncode)+': '+child.stderr.decode()[-1600:])
        return child.stdout.decode()
    def receipt(label,validator):
        path=out/label/'result.json';doc=json.loads(path.read_text());value=validator(doc)
        if not unchanged(doc['inputs']):raise ValueError(label+' executed input no longer current')
        nested.append(doc);return {'receipt':str(path),'sha256':sha(path),'witnesses':value}
    try:
        result['root_lint_contract']=require_lint_contract(package,repo,metadata)
        run('tool-boundaries',[sys.executable,'-B',tools/'test_live_tools.py']);boundary=(out/'tool-boundaries.stderr').read_text();names=re.findall(r'^(test_\w+) \([^\n]+\) \.\.\. ok$',boundary,re.MULTILINE)
        if len(names)!=10 or set(names)!=TOOL_TESTS or 'Ran 10 tests'not in boundary or not boundary.rstrip().endswith('OK'):raise ValueError('exact ten nonempty live tool controls required')
        result['tool_boundary_checks']=names
        target=out/'cargo-target';common=['--package',selected['name'],'--target-dir',str(target)]
        run('cargo-version',cargo+['--version','--verbose']);run('fmt',cargo+['fmt','--manifest-path',manifest,'--package',selected['name'],'--check'])
        run('clippy',cargo+['clippy',*locked,*common,'--all-targets','--','-D','warnings'])
        run('build',cargo+['build',*locked,*common,'--bins','--examples'])
        paths={'helper':target/'debug/gnunet-arm-spawn-helper','local':target/'debug/examples/local_owner','daemon':target/'debug/examples/daemon_owner','configuration':target/'debug/examples/configuration_owner','fixture':target/'debug/examples/arm_fixture'}
        bins={str(path):sha(path)for path in paths.values()};result['fresh_rust_binaries']=dict(bins);env['ARM_FIXTURE']=str(paths['fixture'])
        result['rust_live']=witness.tests(run('live-tests',cargo+['test',*locked,*common,'--test','live_configuration','--','--nocapture']),witness.LIVE_TESTS)
        result['rust_branches']=witness.tests(run('branch-tests',cargo+['test',*locked,*common,'--test','loopback','--','--nocapture']),witness.LOOP_TESTS)
        result['rust_local_sampling']=witness.tests(run('local-sampling',cargo+['test',*locked,*common,'--test','local_start',witness.LOCAL_TEST,'--','--exact','--nocapture']),{witness.LOCAL_TEST})
        shared=['--repo',repo,'--source',a.source,'--reference',a.reference]
        run('command-paired',[sys.executable,'-B',tools/'command_compare.py',*shared,'--rust',paths['local'],'--helper',paths['helper'],'--output',out/'command-paired'],100);result['commands_paired']=receipt('command-paired',witness.commands)
        run('monitor-native',[sys.executable,'-B',tools/'configuration_observe.py',*shared,'--output',out/'monitor-native'],20);result['native_mutable_monitor']=receipt('monitor-native',witness.monitor)
        run('readpoint-paired',[sys.executable,'-B',tools/'client_configuration_compare.py',*shared,'--rust',paths['configuration'],'--helper',paths['helper'],'--output',out/'readpoint-paired'],60);result['readpoints_paired']=receipt('readpoint-paired',witness.readpoint)
        run('normal-daemon',[sys.executable,'-B',tools/'daemon_compare.py',*shared,'--rust',paths['daemon'],'--helper',paths['helper'],'--output',out/'normal-daemon'],50);result['normal_daemon']=receipt('normal-daemon',witness.daemon)
        after,normal_after=load(a.reference,a.source,repo);_,after_inputs=local_snapshot(metadata,package,tools)
        result['inputs_unchanged']=after_inputs==inputs;result['normal_inputs_unchanged']=ref==after and normal==normal_after;result['executed_binaries_unchanged']=all(sha(path)==value for path,value in bins.items());result['nested_inputs_unchanged']=all(unchanged(doc['inputs'])for doc in nested)
        if not all(result[key]for key in ['inputs_unchanged','normal_inputs_unchanged','executed_binaries_unchanged','nested_inputs_unchanged']):raise ValueError('source/file-set/settings/native/executed binary changed during proof')
        result['status']='passed'
    except Exception as error:result['failure']=type(error).__name__+': '+str(error)
    result['elapsed_seconds']=time.monotonic()-start;(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'result':str(out/'result.json'),'failure':result.get('failure')}));return 0 if result['status']=='passed'else 1

if __name__=='__main__':raise SystemExit(main())
