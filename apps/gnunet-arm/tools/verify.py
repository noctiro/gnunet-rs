#!/usr/bin/env python3
"""Portable, offline and local-only finite official ARM CLI proof.

Python 3.9. Output and Cargo target are fresh/disjoint. Re-discover reachable
source file sets, complete root lint policy and normal historical C inputs both
before and after. No service owner or generic PROGRAM completion is inferred.
"""
import argparse, hashlib, json, os, pathlib, subprocess, sys, time
from _common import local_snapshot, require_disjoint_output, require_lint_contract, sha
from normal_reference import load
from checks import require_inventory, require_receipt, require_rust

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
    for name in ['repo','source','reference','output']:parser.add_argument('--'+name,type=pathlib.Path,required=True)
    parser.add_argument('--cargo',default='cargo');parser.add_argument('--toolchain',default='1.99.1')
    args=parser.parse_args();package=args.package.resolve();repo=args.repo.resolve();tools=pathlib.Path(__file__).resolve().parent;manifest=package/'Cargo.toml';reference=json.loads(args.reference.read_text())
    output=require_disjoint_output(args.output,[package,repo,args.source,args.reference.resolve().parent,pathlib.Path(reference['build']),pathlib.Path(reference['prefix'])]);output.mkdir(parents=True)
    environment=os.environ.copy();environment.update(CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(output/'cargo-target'),PYTHONDONTWRITEBYTECODE='1')
    for key in ['POSIXLY_CORRECT','LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE']:environment.pop(key,None)
    cargo=[args.cargo,'+'+args.toolchain];pinned=['--manifest-path',str(manifest),'--offline','--locked'];target=['--target-dir',str(output/'cargo-target')]
    result={'status':'failed','scope':'finite official ARM CLI argv/business phases/actual normal daemon/native entry evidence; generic PROGRAM, other platform/deployment profiles and complete ARM owner remain pending','commands':[],'owner_promotion':False,'whole_repository_source_freeze_claimed':False,'build_settings':{key:environment.get(key)for key in ['CARGO_BUILD_JOBS','CARGO_TARGET_DIR','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC','RUSTDOC','RUSTUP_TOOLCHAIN','MACOSX_DEPLOYMENT_TARGET','SDKROOT']}};started=time.monotonic();binaries={}
    def run(label,argv,timeout=180):
        argv=[str(item)for item in argv];child=subprocess.run(argv,cwd=package,env=environment,capture_output=True,timeout=timeout);stdout=output/(label+'.stdout');stderr=output/(label+'.stderr');stdout.write_bytes(child.stdout);stderr.write_bytes(child.stderr);result['commands'].append({'label':label,'argv':argv,'exit_code':child.returncode,'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr)})
        if child.returncode:raise RuntimeError(label+' returned '+str(child.returncode)+': '+child.stderr.decode(errors='replace')[-1800:])
        return child.stdout.decode()
    def normal_inputs():
        receipt,inputs=load(args.reference,args.source,repo)
        for name in ['client','service']:
            row=receipt['artifacts'][name]
            if sha(row['path'])!=row['sha256']:raise ValueError('normal '+name+' artifact changed')
            inputs[row['path']]=row['sha256']
        return receipt,inputs
    try:
        metadata=json.loads(run('metadata',cargo+['metadata',*pinned,'--format-version','1']))
        selected,inputs=local_snapshot(metadata,package,tools)
        if selected['name']!='gnunet-arm-cli':raise ValueError('actual gnunet-arm-cli package required')
        lint_contract=require_lint_contract(package,repo,metadata);normal,normal_before=normal_inputs()
        inventory=json.loads((package/'inventory.json').read_text());require_inventory(inventory)
        for path,digest in inventory['source_inputs'].items():
            if sha(args.source/path)!=digest:raise ValueError('pinned official CLI dependency changed: '+path)
        result.update(inputs=inputs,normal_inputs=normal_before,root_lint_contract=lint_contract,inventory_sha256=sha(package/'inventory.json'))
        run('tool-controls',[sys.executable,'-B',tools/'test_tools.py'])
        controls=(output/'tool-controls.stderr').read_text()
        if 'Ran 9 tests'not in controls or not controls.rstrip().endswith('OK'):raise ValueError('nine actual nonempty tool controls missing')
        result['tool_controls']=9
        run('cargo-version',cargo+['--version','--verbose']);run('rustc-version',['rustc','+'+args.toolchain,'--version','--verbose']);run('python-version',[sys.executable,'--version']);run('cc-version',['cc','--version'])
        common=['--package',selected['name'],*target]
        run('fmt',cargo+['fmt','--manifest-path',manifest,'--package',selected['name'],'--check'])
        run('clippy',cargo+['clippy',*pinned,*common,'--all-targets','--','-D','warnings'])
        tests=run('rust-tests',cargo+['test',*pinned,*common,'--lib','--test','semantics','--','--nocapture']);result['named_rust_tests']=require_rust(tests)
        run('docs',cargo+['doc',*pinned,*common,'--no-deps'])
        run('build',cargo+['build',*pinned,*common,'--bins'])
        # The staging package contains a test-only forwarding helper binary.
        # In the real workspace the existing arm-std helper owns this bin name.
        if not any(row['name']=='gnunet-arm-spawn-helper'and 'bin'in row['kind']for row in selected['targets']):
            run('build-helper',cargo+['build','--manifest-path',repo/'Cargo.toml','--offline','--locked','--package','gnunet-arm-host','--bin','gnunet-arm-spawn-helper',*target])
        rust=output/'cargo-target/debug/gnunet-arm';helper=output/'cargo-target/debug/gnunet-arm-spawn-helper'
        binaries={str(path):sha(path)for path in [rust,helper]};result['fresh_rust_binaries']=dict(binaries)
        groups=[('argv','argv_compare.py'),('literal','paired.py'),('normal-daemon','daemon_compare.py'),('signals','signals_compare.py'),('stdio','stdio_compare.py'),('local-daemon','local_daemon_compare.py'),('logs','log_compare.py')]
        witnesses={}
        for label,filename in groups:
            run(label,[sys.executable,'-B',tools/filename,'--reference',args.reference,'--rust',rust,'--output',output/label],timeout=120)
            path=output/label/'result.json';receipt=json.loads(path.read_text());require_receipt(label,receipt);witnesses[label]={'path':str(path),'sha256':sha(path),'scope':receipt['scope']}
        after_meta=json.loads(run('metadata-after',cargo+['metadata',*pinned,'--format-version','1']));_,after_inputs=local_snapshot(after_meta,package,tools);after_normal,normal_after=normal_inputs()
        result['inputs_unchanged']=inputs==after_inputs;result['dependency_graph_unchanged']=metadata==after_meta;result['normal_inputs_unchanged']=normal==after_normal and normal_before==normal_after;result['actual_rust_binaries_unchanged']=all(sha(path)==digest for path,digest in binaries.items());result['complete_lint_contract_unchanged']=lint_contract==require_lint_contract(package,repo,after_meta)
        if not all(result[key]for key in ['inputs_unchanged','dependency_graph_unchanged','normal_inputs_unchanged','actual_rust_binaries_unchanged','complete_lint_contract_unchanged']):raise ValueError('source/file-set/settings/normal C/binary input changed')
        result.update(status='completed_with_explicit_pending',checks_passed=True,witnesses=witnesses,actual_unmodified_c_source=True,full_generic_PROGRAM_complete=False,explicit_safe_differences=inventory['explicit_safe_differences'],pending=inventory['pending'])
    except Exception as error:result['failure']=type(error).__name__+': '+str(error)
    result['elapsed_seconds']=time.monotonic()-started;(output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'checks_passed':result.get('checks_passed',False),'failure':result.get('failure'),'result':str(output/'result.json')}));return 0 if result.get('checks_passed')is True else 1
if __name__=='__main__':raise SystemExit(main())
