#!/usr/bin/env python3
"""Build normal official config/config-diff targets in a NEW isolated prefix.

Reuses the maintained normal Meson reference setup/dependency recipe. Never
modifies an existing receipt build, library, executable or installed system.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/reference'))
from build_reference import build_reference,run_logged,save,sha256,source_state

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--prefix',required=True,type=Path);p.add_argument('--deps-prefix',type=Path);p.add_argument('--meson',default=shutil.which('meson') or 'meson',type=Path);p.add_argument('--ninja',type=Path);p.add_argument('--jobs',default=4,type=int)
    a=p.parse_args()
    if not 1<=a.jobs<=64:p.error('jobs must be 1..64')
    if a.output.exists() or a.prefix.exists():p.error('both output and prefix must be new')
    status=build_reference(a)
    if status:return status
    base=json.loads((a.output/'build-result.json').read_text());report={'schema':1,'kind':'normal-c-configuration-tools','status':'failed','base_receipt':str((a.output/'build-result.json').resolve()),'base_receipt_sha256':sha256(a.output/'build-result.json'),'upstream':base['upstream'],'commands':[]}
    try:
        env=dict(os.environ);env.update(base['build_environment'])
        if a.ninja:env['NINJA']=str(a.ninja.resolve())
        result=run_logged(a.output,'configuration-targets',[str(a.meson),'compile','-C',base['build'],'-j',str(a.jobs),'gnunet-config','gnunet-config-diff'],env)
        report['commands'].append(result)
        if result['exit_code']:raise ValueError('normal configuration target build failed')
        report['artifacts']={}
        for name in ['gnunet-config','gnunet-config-diff']:
            original=Path(base['build'])/'src/cli/util'/name;staged=a.prefix/'bin'/name;shutil.copy2(original,staged)
            if sha256(original)!=sha256(staged):raise ValueError('staging changed normal executable')
            report['artifacts'][name]={'build_path':str(original),'path':str(staged.resolve()),'sha256':sha256(original)}
        if source_state(a.source)!=base['upstream']:raise ValueError('reference sources changed')
        for row in [*base['artifacts'].values(),*base['libraries'],*base['default_configurations']]:
            if sha256(row['path'])!=row['sha256']:raise ValueError('normal base artifact changed during extra target build')
        report['status']='passed'
    except Exception as error:report['failure']=type(error).__name__+': '+str(error)
    save(a.output/'configuration-result.json',report)
    print(json.dumps({'status':report['status'],'receipt':str(a.output/'configuration-result.json'),'failure':report.get('failure')}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
