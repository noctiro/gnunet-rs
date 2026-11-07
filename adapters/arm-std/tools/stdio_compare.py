#!/usr/bin/env python3
"""Actual normal C ARM-self public start versus full Rust Host, low stdio matrix.
Only new exec parents change their own stdio/signal state. The target is plain C
and samples before opening any report file or GNUnet/Rust initialization.
"""
import argparse
import json
import os
import pathlib
import subprocess
import time
from reference import load,compile_probe,sha


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--repo',type=pathlib.Path,required=True)
    parser.add_argument('--source',type=pathlib.Path,required=True)
    parser.add_argument('--reference',type=pathlib.Path,required=True)
    parser.add_argument('--rust',type=pathlib.Path,required=True)
    parser.add_argument('--helper',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    args=parser.parse_args()
    package,output=args.package.resolve(),args.output.resolve()
    reference,normal_inputs=load(args.reference,args.source,args.repo)
    for protected in [package,args.repo.resolve(),args.source.resolve(),args.reference.resolve().parent,pathlib.Path(reference['prefix']),pathlib.Path(reference['build'])]:
        if output==protected or output in protected.parents or protected in output.parents:
            raise ValueError('output overlaps an input tree')
    output.mkdir(exist_ok=False)
    caller=output/'normal-local-owner';target=output/'stdio-target'
    compilation=compile_probe(package/'tools/local_owner.c',caller,reference)
    compiled=subprocess.run(['cc',str(package/'tools/stdio_child.c'),'-o',str(target)],capture_output=True)
    (output/'target-compile.stderr').write_bytes(compiled.stderr)
    if compiled.returncode:raise RuntimeError(compiled.stderr.decode())
    inputs={**normal_inputs,**{str(p):sha(p)for p in [caller,target,args.rust,args.helper,package/'tools/local_owner.c',package/'tools/stdio_child.c',pathlib.Path(__file__).resolve(),pathlib.Path(__file__).with_name('reference.py')]}}
    environment={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))}
    environment.update(reference['runtime_environment'],LC_ALL='C')
    base=output/'base';base.mkdir();environment['GNUNET_BASE_CONFIG']=str(base)
    rows=[];differences=[];started=time.monotonic()
    cases=[(closed,flags,0)for closed in range(8)for flags in range(8)]
    cases.extend((0,flags,clo)for flags in [0,7,8,15]for clo in [1,2,4,7])
    for closed,flags,clo in cases:
        directory=output/f'close-{closed}-flags-{flags}-clo-{clo}';directory.mkdir()
        trace=directory/'target.json';config=directory/'arm.conf'
        config.write_text('[arm]\nUNIXPATH = '+str(directory/'absent.sock')+'\nBINARY = '+str(target)+'\nOPTIONS = --output '+str(trace)+'\n[TESTING]\nWEAKRANDOM = YES\n')
        observations={}
        for actor in ['c','rust']:
            if trace.exists():trace.unlink()
            record=directory/(actor+'-owner.jsonl')
            if actor=='c':argv=[str(caller),str(config),'start',str(flags),'default',str(record),str(closed),str(clo)]
            else:argv=[str(args.rust),str(config),'start',str(flags),'default',str(args.helper),str(record),str(closed),str(clo)]
            child=subprocess.Popen(argv,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:stdout,stderr=child.communicate(input=b'abc',timeout=8)
            finally:
                if child.poll()is None:child.kill();child.communicate(timeout=2)
            (directory/(actor+'.stdout')).write_bytes(stdout);(directory/(actor+'.stderr')).write_bytes(stderr)
            if child.returncode!=0:raise RuntimeError((actor,closed,flags,clo,child.returncode,stderr.decode()))
            events=[json.loads(line)for line in record.read_text().splitlines()]
            result=next(row for row in events if row['event']=='result')
            done=next(row for row in events if row['event']=='done')
            if result['status']!=0 or result['result']!=2 or done['callbacks']!=1 or done['children']!=1 or done['failed']:
                raise ValueError('wrong actual local startup result')
            wait=[row for row in events if row['event']=='reaped']
            if len(wait)!=1 or wait[0]['exit']!=0 or wait[0]['signal']!=0:
                raise ValueError('created target did not naturally exit/reap')
            observed=json.loads(trace.read_text())
            (directory/(actor+'-target.json')).write_text(json.dumps(observed,indent=2)+'\n')
            if actor=='rust' and (observed['readiness_fd']<3 or observed['readiness_type']!=4096 or observed['readiness_cloexec'] or not observed['readiness_nonblock'] or observed['readiness_close_errno']!=0):
                raise ValueError('Rust readiness inheritance lost')
            observations[actor]={'target':observed,'caller':events,'argv':argv,'exit_code':child.returncode}
        normalize=lambda observation:{key:value for key,value in observation.items()if key!='readiness_fd'}
        matched=normalize(observations['c']['target'])==normalize(observations['rust']['target'])
        if not matched:
            differences.append({'closed':closed,'stdio':flags,'cloexec':clo,'fields':{key:{actor:observations[actor]['target'][key]for actor in ['c','rust']}for key in observations['c']['target']if key!='readiness_fd' and observations['c']['target'][key]!=observations['rust']['target'][key]}})
        expected_closed=(closed|clo)&flags&7
        for fd in range(3):
            if expected_closed&(1<<fd)and observations['rust']['target']['types'][fd]!=-1:
                raise ValueError('inherited closed stdio was silently reopened')
        rows.append({'closed':closed,'stdio':flags,'cloexec':clo,'matched':matched,'observations':observations})
    after,after_inputs=load(args.reference,args.source,args.repo)
    if reference!=after or normal_inputs!=after_inputs or any(sha(path)!=digest for path,digest in inputs.items()):
        raise ValueError('source/build/binary changed during actual matrix')
    result={'status':'observed_native_differences'if differences else'passed','differences':differences,'matched_cases':len(rows)-len(differences),'scope':'actual normal GNUNET_ARM_request_service_start versus actual Rust Host local-start and target startup stdio/signal/readiness; no daemon/testing owner promotion','cases':rows,'closed_stdio_cases':64,'additional_cloexec_cases':16,'actual_exec_parent_count':len(rows)*2,'normal_reference_unchanged':True,'inputs':inputs,'inputs_unchanged':True,'normal_c_compilation':compilation,'elapsed_seconds':time.monotonic()-started}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'matched_cases':result['matched_cases'],'native_differences':len(differences),'exec_parents':len(rows)*2,'result':str(output/'result.json')}))


if __name__=='__main__':main()
