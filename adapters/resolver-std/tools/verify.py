#!/usr/bin/env python3
"""Verify the integrated Resolver host/app with owned loopback and normal C.

Generated targets and receipts remain under a fresh output. No C library or
source is rebuilt; the fixture alone accepts explicit owned machine-file bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

PACKAGE = Path(__file__).resolve().parents[1]
REPOSITORY = PACKAGE.parents[1]
APP = REPOSITORY/'apps/gnunet-service-resolver'
REQUIRED = {
    'actual_wall_clock_timer_wakes_no_upstream_lookup_after_thirty_seconds',
    'queued_start_never_mints_after_deadline_and_unrelated_buffered_eof_is_cleaned',
    'consumed_datagram_waits_behind_real_tx_pressure_then_recovers_on_drive',
    'actual_consumed_dns_capacity_error_retains_datagram_and_original_owner',
    'genuine_socket_backpressure_retains_effect_ticket_across_canceled_drive',
    'actual_ipc_no_upstream_uses_original_thirty_second_monotonic_deadline',
    'expired_queued_start_cannot_deadlock_full_effects_with_older_timeouts',
    'eof_cleans_more_than_one_effect_budget_without_external_wakeup',
    'rx_clock_failure_discards_only_undated_packet_then_new_response_recovers',
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['build-receipt','output']:
        parser.add_argument('--'+name,type=Path,required=True)
    a=parser.parse_args();out=a.output.resolve()
    for source in [PACKAGE,APP]:
        if out.is_relative_to(source) or source.is_relative_to(out):
            parser.error('output and source must be disjoint')
    out.mkdir(parents=True,exist_ok=False);started=time.monotonic()
    target=out/'target';cargo=['cargo','+1.99.1'];base=['--manifest-path',str(REPOSITORY/'Cargo.toml'),'--target-dir',str(target),'--offline','--locked']
    report={'status':'failed','scope':'Integrated real Resolver Unix/TCP/UDP host and foreground app; generic startup/full owner acceptance remain separate','commands':[]}
    def run(label,argv,timeout=180,env=None):
        before=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=REPOSITORY,env=env,capture_output=True,timeout=timeout)
        for suffix,data in [('stdout',p.stdout),('stderr',p.stderr)]: (out/(label+'.'+suffix)).write_bytes(data)
        report['commands'].append({'label':label,'argv':list(map(str,argv)),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-before,'stdout_sha256':sha(out/(label+'.stdout')),'stderr_sha256':sha(out/(label+'.stderr'))})
        if p.returncode:raise RuntimeError(label+' failed; see '+str(out/(label+'.stderr')))
        return p.stdout.decode()
    try:
        metadata=json.loads(run('metadata',cargo+['metadata','--manifest-path',REPOSITORY/'Cargo.toml','--offline','--locked','--format-version','1']))
        inputs={}
        for package in metadata['packages']:
            if package['source'] is not None:continue
            manifest=Path(package['manifest_path']);directory=manifest.parent
            paths=[manifest,*[p for p in (directory/'src').rglob('*') if p.is_file()]]
            for name in ['build.rs','README.md']:
                if (directory/name).is_file():paths.append(directory/name)
            if directory==PACKAGE:
                paths.extend(p for sub in ['tools','tests','examples'] for p in (directory/sub).rglob('*') if p.is_file())
            inputs.update({str(p):sha(p) for p in paths if '__pycache__' not in p.parts})
        for p in [REPOSITORY/'Cargo.toml',REPOSITORY/'Cargo.lock',REPOSITORY/'rust-toolchain.toml',a.build_receipt.resolve()]:inputs[str(p)]=sha(p)
        report['source_inputs']=inputs
        names=[name for source in sorted((PACKAGE/'tests').glob('*.rs')) for name in re.findall(r'#\[test\]\s*fn\s+(\w+)',source.read_text())]
        assert len(names)==16 and len(set(names))==16 and REQUIRED<=set(names),'actual test obligations changed; re-review coverage'
        run('format',cargo+['fmt','--all','--','--check'])
        run('clippy',cargo+['clippy',*base,'-p','gnunet-resolver-host','-p','gnunet-service-resolver','--all-targets','--','-D','warnings'])
        run('build-app',cargo+['build',*base,'-p','gnunet-service-resolver'])
        run('build-fixture',cargo+['build',*base,'-p','gnunet-resolver-host','--example','fixture'])
        built={str(p):sha(p) for p in [target/'debug/gnunet-service-resolver',target/'debug/examples/fixture']}
        report['fresh_build_artifacts']=built
        text=run('actual-socket-tests',cargo+['test',*base,'-p','gnunet-resolver-host','--tests','--','--test-threads=1'],timeout=90)
        passed=re.findall(r'^test (\w+) \.\.\. ok$',text,re.M)
        assert len(passed)==len(names) and set(passed)==set(names),'actual socket test witnesses missing'
        report['rust_tests']={'passed':len(passed),'actual_names':passed,'actual_wall_clock_thirty_seconds':True}
        environment=dict(os.environ,RUSTDOCFLAGS='-D warnings')
        run('rustdoc',cargo+['doc',*base,'-p','gnunet-resolver-host','-p','gnunet-service-resolver','--no-deps'],env=environment)
        cdir=out/'normal-c-client'
        run('normal-c-build',[sys.executable,'-B',PACKAGE/'tools/build_probe.py','--package',PACKAGE,'--build-receipt',a.build_receipt,'--output',cdir])
        cbuild=json.loads((cdir/'result.json').read_text());assert cbuild['exit_code']==0 and cbuild['inputs_unchanged']
        built[str(cdir/'public-client')]=sha(cdir/'public-client')
        assert all(sha(p)==h for p,h in built.items()),'fresh artifacts changed before execution'
        run('normal-c-process',[sys.executable,'-B',PACKAGE/'tools/process_oracle.py','--package',PACKAGE,'--build-receipt',a.build_receipt,'--client',cdir/'public-client','--service',target/'debug/examples/fixture','--output',out/'process'],timeout=60)
        proof=json.loads((out/'process/result.json').read_text());assert proof['status']=='passed' and len(proof['cases'])==15 and all(c['passed'] for c in proof['cases'])
        assert proof['binaries']=={p:h for p,h in built.items() if p in {str(target/'debug/examples/fixture'),str(cdir/'public-client')}},'executed process inputs differ from fresh artifacts'
        report['normal_c_process']={'checks':15,'receipt':'process/result.json','sha256':sha(out/'process/result.json'),'normal_library':proof['normal_C_library']}
        binary=target/'debug/gnunet-service-resolver';env={k:v for k,v in os.environ.items() if not k.startswith('LISTEN_')}
        for name in ['help','version']:run('foreground-'+name,[binary,'--'+name],env=env)
        assert all(sha(p)==h for p,h in built.items()),'fresh artifacts changed during execution'
        run('production-app-smoke',[sys.executable,'-B',PACKAGE/'tools/app_smoke.py','--repository',REPOSITORY,'--output',out/'production-app-smoke'],timeout=180)
        production=json.loads((out/'production-app-smoke/result.json').read_text());assert production['status']=='passed' and len(production['checks'])==15 and production['inputs_unchanged']
        report['production_app_process']={'checks':15,'receipt':'production-app-smoke/result.json','sha256':sha(out/'production-app-smoke/result.json'),'fresh_app':production['fresh_app']}
        report['artifacts']=built
        report['inputs_unchanged']=all(sha(p)==h for p,h in inputs.items());assert report['inputs_unchanged'],'source changed'
        report['source_input_count']=len(inputs);report['status']='passed'
    except Exception as e:report['failure']=type(e).__name__+': '+str(e)
    report['elapsed_seconds']=time.monotonic()-started
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'result':str(out/'result.json'),'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
