#!/usr/bin/env python3
"""Actual normal C ARM-self and complete Rust host signal-inheritance chains."""
import argparse,json,os,pathlib,subprocess
from reference import load,compile_probe,sha
from _common import require_disjoint_output
from witnesses import require_actor


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
    for name in ['repo','source','reference','rust','helper','output']:parser.add_argument('--'+name,type=pathlib.Path,required=True)
    args=parser.parse_args();package=args.package.resolve()
    reference,normal=load(args.reference,args.source,args.repo)
    output=require_disjoint_output(args.output,[package,args.repo,args.source,args.reference.resolve().parent,pathlib.Path(reference['prefix']),pathlib.Path(reference['build'])]);output.mkdir()
    caller=output/'normal-local-owner';target=output/'plain-target';compilation=compile_probe(package/'tools/local_owner.c',caller,reference)
    compiled=subprocess.run(['cc',str(package/'tools/stdio_child.c'),'-o',str(target)],capture_output=True)
    if compiled.returncode:raise RuntimeError(compiled.stderr.decode())
    inputs={**normal,**{str(path.resolve()):sha(path)for path in [caller,target,args.rust,args.helper,package/'tools/local_owner.c',package/'tools/stdio_child.c',pathlib.Path(__file__),package/'tools/reference.py',package/'tools/_common.py',package/'tools/witnesses.py']}}
    environment={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_'))};environment.update(reference['runtime_environment'],LC_ALL='C');base=output/'base';base.mkdir();environment['GNUNET_BASE_CONFIG']=str(base)
    rows=[]
    for profile in ['ignore','default']:
        for flags in [0,7,8,15]:
            directory=output/(profile+'-'+str(flags));directory.mkdir();trace=directory/'target.json';config=directory/'arm.conf';config.write_text('[arm]\nUNIXPATH = '+str(directory/'absent.sock')+'\nBINARY = '+str(target)+'\nOPTIONS = --output '+str(trace)+'\n[TESTING]\nWEAKRANDOM = YES\n');observations={}
            for actor in ['c','rust']:
                if trace.exists():trace.unlink()
                record=directory/(actor+'-owner.jsonl');argv=([str(caller),str(config),'start',str(flags),profile,str(record),'0']if actor=='c'else[str(args.rust),str(config),'start',str(flags),profile,str(args.helper),str(record),'0'])
                process=subprocess.Popen(argv,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:stdout,stderr=process.communicate(input=b'abc',timeout=8)
                finally:
                    if process.poll()is None:process.kill();process.communicate(timeout=2)
                (directory/(actor+'.stdout')).write_bytes(stdout);(directory/(actor+'.stderr')).write_bytes(stderr)
                observation={'exit_code':process.returncode,'target':json.loads(trace.read_text()),'caller':[json.loads(line)for line in record.read_text().splitlines()],'argv':argv};require_actor(observation)
                (directory/(actor+'-target.json')).write_text(json.dumps(observation['target'],indent=2)+'\n');observations[actor]=observation
            normalize=lambda row:{key:value for key,value in row.items()if key!='readiness_fd'}
            if normalize(observations['c']['target'])!=normalize(observations['rust']['target']):raise ValueError('full host signal/descriptor trace differs')
            if any(observation['target']['pipe']!=profile or not observation['target']['mask'] for observation in observations.values()):raise ValueError('actual signal profile/mask missing')
            rows.append({'profile':profile,'stdio':flags,'matched':True,'observations':observations})
    after,normal_after=load(args.reference,args.source,args.repo)
    if reference!=after or normal!=normal_after or any(sha(path)!=value for path,value in inputs.items()):raise ValueError('actual source/build/binary inputs changed')
    result={'status':'passed','scope':'actual public ARM-self C and Rust Host/helper/target signal profiles with inherited blocked SIGUSR1; not service readiness or daemon/testing owner completion','cases':rows,'paired_profiles':8,'actual_exec_parents':16,'inputs':inputs,'inputs_unchanged':True,'compilation':compilation};(output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','paired_profiles':8,'result':str(output/'result.json')}))


if __name__=='__main__':main()
