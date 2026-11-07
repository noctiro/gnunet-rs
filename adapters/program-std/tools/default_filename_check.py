#!/usr/bin/env python3
"""Fresh normal public filename oracle; no files under /etc are created/read.
Only lookup for a unique nonexistent name is attempted; both owned children
must return None when HOME/XDG are absent. Historical difference is separate.
"""
import argparse,json,os,subprocess
from pathlib import Path
from _common import sha,require_disjoint_output
from normal_reference import load,compile_probe
BASE=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','rust','output']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();r,before=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir(parents=True);inputs=[Path(__file__),BASE/'reference/default_filename.c',a.rust,a.repo/'adapters/config-std/src/project.rs'];files={str(p.resolve()):sha(p)for p in inputs};compiled=compile_probe(BASE/'reference/default_filename.c',out/'normal-default',r);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))and k not in ['HOME','XDG_CONFIG_HOME','LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE']};env.update(r['runtime_environment']);env['LC_ALL']='C';marker='owned-program-never-present-'+str(os.getpid());rows=[]
 for label,binary in [('c',out/'normal-default'),('rust',a.rust)]:
  child=subprocess.run([str(binary),marker],env=env,capture_output=True,timeout=4);(out/(label+'.stdout')).write_bytes(child.stdout);(out/(label+'.stderr')).write_bytes(child.stderr);rows.append({'actor':label,'exit':child.returncode,'stdout_hex':child.stdout.hex(),'stderr_hex':child.stderr.hex()})
 _,after=load(a.reference,a.source,a.repo);unchanged=before==after and files=={str(p.resolve()):sha(p)for p in inputs};matched=all(row['exit']==0 and row['stdout_hex']==b'NONE\n'.hex()and not row['stderr_hex']for row in rows)
 value={'status':'passed'if unchanged and matched else'failed','scope':'HOME/XDG missing and unique nonexistent default candidate; current fixed Rust public method matches normal C None; no files under /etc created or read beyond failed metadata lookup','rows':rows,'compiled':compiled,'inputs':files,'inputs_unchanged':unchanged,'normal_inputs':before,'rust_conformance_for_this_case':matched};(out/'result.json').write_text(json.dumps(value,indent=2)+'\n');print(json.dumps({'status':value['status'],'result':str(out/'result.json')}));return 0 if value['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
