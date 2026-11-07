#!/usr/bin/env python3
"""Run all eight unchanged C public ARM APIs versus the real Rust MQ owner.
Only the suite's private Unix peer is contacted. No ARM daemon is started.
"""
import argparse
import json
import pathlib
import subprocess
import sys
from reference import load,sha


def main():
    parser=argparse.ArgumentParser()
    for name in ['repo','source','reference','observer','output']:
        parser.add_argument('--'+name,type=pathlib.Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    ref,normal=load(args.reference,args.source,args.repo)
    package=pathlib.Path(__file__).resolve().parents[1]
    for protected in [package,args.repo.resolve(),args.source.resolve(),args.reference.resolve().parent,pathlib.Path(ref['prefix']),pathlib.Path(ref['build'])]:
        if output==protected or output in protected.parents or protected in output.parents:
            raise ValueError('output overlaps an input tree')
    output.mkdir(exist_ok=False)
    inputs={**normal,str(args.observer.resolve()):sha(args.observer)}
    for source in sorted((package/'tools').glob('*')):
        if source.is_file():inputs[str(source)]=sha(source)
    rows=[]
    for profile,flags in [('canonical',[]),('padding',['--nonzero-padding']),('unknown',['--unknown-types'])]:
        paired={}
        for actor in ['c','rust']:
            destination=output/(profile+'-'+actor)
            argv=[sys.executable,'-B',str(package/'tools/public_compare.py'),'--repo',str(args.repo),'--source',str(args.source),'--reference',str(args.reference),'--observer',str(args.observer),'--actor',actor,'--output',str(destination),*flags]
            run=subprocess.run(argv,capture_output=True,timeout=20)
            (output/(profile+'-'+actor+'.stdout')).write_bytes(run.stdout)
            (output/(profile+'-'+actor+'.stderr')).write_bytes(run.stderr)
            if run.returncode:raise RuntimeError((argv,run.returncode,run.stderr.decode()))
            receipt=json.loads((destination/'result.json').read_text())
            if receipt.get('success')is not True or receipt.get('actor')!=actor or receipt.get('events')!=14 or receipt.get('wire_frames')!=7 or receipt.get('owner_exit')!=0:
                raise ValueError('actual nonempty public-owner witness missing')
            paired[actor]={'result':str(destination/'result.json'),'sha256':sha(destination/'result.json'),'events':json.loads((destination/'events.json').read_text()),'wire':json.loads((destination/'wire.json').read_text())}
        for channel in ['monitor','control']:
            select=lambda events:[event for event in events if (event['event']=='monitor')==(channel=='monitor')]
            if select(paired['c']['events'])!=select(paired['rust']['events']):
                raise ValueError(('callback owner trace differs',profile,channel))
        # Monitor/control socket acceptance order may differ. Exact operation
        # frames and their ordering on the control stream remain identical.
        projection=lambda rows:[{k:v for k,v in row.items()if k!='peer'}for row in rows if row['type']!=14]
        if projection(paired['c']['wire'])!=projection(paired['rust']['wire']):
            raise ValueError(('actual control bytes differ',profile))
        rows.append({'profile':profile,'matched':True,'actors':paired})
    after,normal_after=load(args.reference,args.source,args.repo)
    if ref!=after or normal!=normal_after or any(sha(path)!=digest for path,digest in inputs.items()):
        raise ValueError('suite source/build/binary inputs changed')
    result={'status':'passed','scope':'actual public C ARM API8 against isolated literal peer versus actual Rust ClientHost/MonitorHost; no native spawn/daemon/testing owner promotion','profiles':rows,'paired_profile_count':3,'actual_callback_count_per_actor_per_profile':14,'actual_frame_count_per_actor_per_profile':7,'inputs':inputs,'inputs_unchanged':True}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'passed','profiles':3,'result':str(output/'result.json')}))


if __name__=='__main__':main()
