#!/usr/bin/env python3
"""Fresh local-only proof of the ARM client host, without owner promotion.

Pinned Cargo, locked/offline dependencies, at most two build jobs, output-local
target, full reachable local src/file-set/settings commitments, normal C receipt
validation, actual original PID waits, explicit 62/18 native matrix outcomes.
"""
import argparse,json,os,pathlib,re,subprocess,sys,time
from _common import local_snapshot,require_disjoint_output,workspace_root,sha,require_lint_contract
from reference import load
from witnesses import SHORT_RUST,LONG_RUST,PROCESS_RUST,SHARED_PROCESS_RUST,RUNTIME_ORIGINAL_RUST,RUNTIME_SUPPLEMENTARY_RUST,require_test_output,require_docs,require_stdio


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--repo',type=pathlib.Path)
    for name in ['source','reference','output']:parser.add_argument('--'+name,type=pathlib.Path,required=True)
    parser.add_argument('--cargo',default='cargo');parser.add_argument('--toolchain',default='1.99.1')
    args=parser.parse_args();package=args.package.resolve();repo=args.repo.resolve()if args.repo else workspace_root(package);tools=pathlib.Path(__file__).resolve().parent;manifest=package/'Cargo.toml';cargo=[args.cargo,'+'+args.toolchain];pinned=['--manifest-path',str(manifest),'--offline','--locked'];environment=os.environ.copy();environment['CARGO_BUILD_JOBS']='2'
    meta_argv=cargo+['metadata',*pinned,'--format-version','1'];meta=subprocess.run(meta_argv,cwd=package,env=environment,capture_output=True,timeout=180)
    if meta.returncode:raise RuntimeError('locked metadata failed: '+meta.stderr.decode())
    metadata=json.loads(meta.stdout);reference,normal=load(args.reference,args.source,repo)
    output=require_disjoint_output(args.output,[package,tools,repo,pathlib.Path(metadata['workspace_root']),args.source,args.reference.resolve().parent,pathlib.Path(reference['build']),pathlib.Path(reference['prefix'])]);output.mkdir();(output/'metadata.stdout').write_bytes(meta.stdout);(output/'metadata.stderr').write_bytes(meta.stderr)
    selected,inputs=local_snapshot(metadata,package,tools)
    if selected['name']!='gnunet-arm-host':raise ValueError('actual gnunet-arm-host package required')
    lint_contract=require_lint_contract(package,repo,metadata)
    result={'status':'failed','scope':'shared native process port plus original ARM client/monitor/ARM-self regression; full ARM daemon/CLI/testing and global owner completion remain pending','package':str(package),'inputs':inputs,'normal_inputs':normal,'commands':[{'label':'metadata','argv':meta_argv,'exit_code':0}],'build_settings':{key:environment.get(key)for key in ['CARGO_BUILD_JOBS','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC','RUSTDOC','RUSTUP_TOOLCHAIN','MACOSX_DEPLOYMENT_TARGET','SDKROOT']},'owner_promotion':False};started=time.monotonic();binaries={}
    def run(label,argv,timeout=180):
        argv=[str(item)for item in argv];child=subprocess.run(argv,cwd=package,env=environment,capture_output=True,timeout=timeout);(output/(label+'.stdout')).write_bytes(child.stdout);(output/(label+'.stderr')).write_bytes(child.stderr);result['commands'].append({'label':label,'argv':argv,'exit_code':child.returncode})
        if child.returncode:raise RuntimeError(label+' returned '+str(child.returncode)+': '+child.stderr.decode()[-1200:])
        return child.stdout.decode()
    try:
        run('tool-boundaries',[sys.executable,'-B',tools/'test_tools.py']);boundary=(output/'tool-boundaries.stderr').read_text()
        if 'Ran 13 tests'not in boundary or not boundary.rstrip().endswith('OK'):raise ValueError('13 real nonempty tool controls missing')
        result['tool_boundary_checks']=13
        result['root_lint_contract']=lint_contract
        run('cargo-version',cargo+['--version','--verbose']);run('fmt',cargo+['fmt','--manifest-path',manifest,'--package',selected['name'],'--check'])
        target=output/'cargo-target';common=['--package',selected['name'],'--target-dir',target]
        run('clippy',cargo+['clippy',*pinned,*common,'--all-targets','--','-D','warnings'])
        run('build',cargo+['build',*pinned,*common,'--bins','--examples'])
        binary_paths={'helper':target/'debug/gnunet-arm-spawn-helper','owner':target/'debug/examples/local_owner','public_owner':target/'debug/examples/public_owner','fixture':target/'debug/examples/arm_fixture','process_owner':target/'debug/examples/process_owner'}
        binaries={str(path):sha(path)for path in binary_paths.values()};result['fresh_rust_binaries']=dict(binaries)
        # All actual local fixtures are this fresh Rust executable. Separate
        # normal-C probes below use independently compiled plain-C targets.
        environment['ARM_FIXTURE']=str(binary_paths['fixture'])
        # New live-only branches have their own mandatory supplementary suite.
        # Preserve every original client witness while the five shared native
        # witnesses now execute in their actual runtime package, not a copied lib.
        from live_witnesses import LOOP_TESTS,LOCAL_TEST
        client_expected=SHORT_RUST-SHARED_PROCESS_RUST
        skip=sorted((LOOP_TESTS-client_expected)|{LOCAL_TEST})
        filters=[item for name in skip for item in ['--skip',name]]
        short=run('short-tests',cargo+['test',*pinned,*common,'--test','local_start','--test','loopback','--','--nocapture',*filters])
        client_names=require_test_output(short,client_expected)
        native=run('shared-native-tests',cargo+['test','--manifest-path',repo/'Cargo.toml','--offline','--locked','--package','gnunet-service-runtime','--target-dir',target,'--lib','--','--nocapture'])
        shared_names=require_test_output(native,SHARED_PROCESS_RUST|RUNTIME_ORIGINAL_RUST|RUNTIME_SUPPLEMENTARY_RUST)
        result['shared_runtime_rust_checks']=shared_names
        result['short_rust_checks']=sorted(set(client_names)|(set(shared_names)&SHARED_PROCESS_RUST))
        if set(result['short_rust_checks'])!=SHORT_RUST:raise ValueError('original client/shared native witness set incomplete')
        process_tests=run('process-tests',cargo+['test',*pinned,*common,'--test','process','--','--nocapture']);result['process_rust_checks']=require_test_output(process_tests,PROCESS_RUST)
        source_root=pathlib.Path(metadata['workspace_root']).resolve()
        source_prefix='' if package==source_root else package.relative_to(source_root).as_posix()+'/'
        docs=run('docs',cargo+['test',*pinned,*common,'--doc']);result['borrowed_lifetime_docs']=require_docs(docs,source_prefix)
        long=run('actual-sixty-seconds',cargo+['test',*pinned,*common,'--test','local_start',LONG_RUST,'--','--exact','--ignored','--nocapture'],timeout=95);require_test_output(long,{LONG_RUST});observations=[json.loads(line)for line in long.splitlines()if line.startswith('{')]
        if len(observations)!=1 or not 60_000_000<=observations[0].get('actual_deadline_us',0)<63_000_000 or observations[0].get('child_alive_at_callback')is not True or observations[0].get('actual_exit')!=0:raise ValueError('original 60s/actual owned 65s lifecycle witness missing')
        result['long_lifecycle']=observations[0]
        errno_binary=output/'native-errno';run('errno-build',['cc',tools/'native_errno.c','-o',errno_binary]);binaries[str(errno_binary)]=sha(errno_binary);result['fresh_native_errno_binary']={'path':str(errno_binary),'sha256':sha(errno_binary)};errno=json.loads(run('errno-actual',[errno_binary]));
        if errno.get('init')!=0 or errno.get('destroy')!=0 or errno.get('invalid_adddup2')!=errno.get('EBADF')or errno['EBADF']<=0:raise ValueError('actual POSIX positive errno convention missing')
        result['actual_positive_errno']=errno
        shared=['--repo',repo,'--source',args.source,'--reference',args.reference]
        run('public-paired',[sys.executable,'-B',tools/'public_suite.py',*shared,'--observer',binary_paths['public_owner'],'--output',output/'public-paired'],timeout=90);public=json.loads((output/'public-paired/result.json').read_text())
        if public.get('status')!='passed' or public.get('paired_profile_count')!=3 or {row['profile']for row in public.get('profiles',[])}!={'canonical','padding','unknown'}or not all(row['matched']for row in public['profiles']):raise ValueError('three actual C/R public API profiles missing')
        result['public_api_paired_profiles']=3
        local=[*shared,'--package',package,'--rust',binary_paths['owner'],'--helper',binary_paths['helper']]
        run('stdio-observations',[sys.executable,'-B',tools/'stdio_compare.py',*local,'--output',output/'stdio-observations'],timeout=100);stdio=json.loads((output/'stdio-observations/result.json').read_text());result['native_stdio']=require_stdio(stdio)
        run('signal-paired',[sys.executable,'-B',tools/'signal_compare.py',*local,'--output',output/'signal-paired'],timeout=100);signals=json.loads((output/'signal-paired/result.json').read_text())
        if signals.get('status')!='passed'or len(signals.get('cases',[]))!=8 or {(row['profile'],row['stdio'])for row in signals['cases']}!={(profile,flags)for profile in ['ignore','default']for flags in [0,7,8,15]}or not all(row['matched']for row in signals['cases']):raise ValueError('eight actual full-host signal profiles missing')
        result['full_host_signal_pairs']=8
        run('generic-process-paired',[sys.executable,'-B',tools/'process_compare.py',*shared,'--package',package,'--output',output/'generic-process-paired'],timeout=120);generic=json.loads((output/'generic-process-paired/result.json').read_text())
        expected_process={'simple-raw','empty-argv','directory-late-exec','not-executable','late-interpreter','control-one-byte','control-epipe','control-default-sigpipe','two-queued-listeners'}
        if generic.get('status')!='passed' or generic.get('case_count')!=9 or {row['label']for row in generic.get('cases',[])}!=expected_process or not all(row['matched']for row in generic['cases']):raise ValueError('actual shared-process nine paired cases missing')
        result['generic_process_pairs']=9
        run('source-kill-write-seams',[sys.executable,'-B',tools/'process_write_seams.py',*shared,'--output',output/'source-kill-write-seams'],timeout=30);seams=json.loads((output/'source-kill-write-seams/result.json').read_text())
        if seams.get('status')!='passed' or seams.get('kind')!='source-extracted-process-kill-finite-write-seams' or seams.get('case_count')!=2 or {row['write_class']for row in seams.get('cases',[])}!={'eintr','zero'} or not all(row['write_calls']==1 and row['actual_signal']==15 and row['native_kill_fallback']is True for row in seams['cases']):raise ValueError('explicit source-extracted finite-write seams missing')
        result['source_extracted_kill_write_seams']=2
        # This label remains separate from unchanged-library process observations.
        after,normal_after=load(args.reference,args.source,repo);_,after_inputs=local_snapshot(metadata,package,tools);result['inputs_unchanged']=after_inputs==inputs;result['normal_inputs_unchanged']=reference==after and normal==normal_after;result['executed_binaries_unchanged']=all(sha(path)==value for path,value in binaries.items())
        if not all(result[key]for key in ['inputs_unchanged','normal_inputs_unchanged','executed_binaries_unchanged']):raise ValueError('source/file-set/settings/native/binary input changed')
        result['status']='completed_with_explicit_native_differences';result['checks_passed']=True;result['native_equivalence']=False;result['receipts']={str(path):sha(path)for path in output.rglob('result.json')}
    except Exception as error:result['failure']=type(error).__name__+': '+str(error)
    result['elapsed_seconds']=time.monotonic()-started;(output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'checks_passed':result.get('checks_passed',False),'native_matches':result.get('native_stdio',{}).get('native_matches'),'explicit_native_differences':result.get('native_stdio',{}).get('native_known_differences'),'failure':result.get('failure'),'result':str(output/'result.json')}));return 0 if result.get('checks_passed')is True else 1


if __name__=='__main__':raise SystemExit(main())
