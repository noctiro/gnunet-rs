#!/usr/bin/env python3
"""C-only public PROGRAM lifecycle observations; never a Rust equality claim."""
import argparse,json,os,subprocess,time
from pathlib import Path
from _common import sha,require_disjoint_output
from normal_reference import load,compile_probe
BASE=Path(__file__).resolve().parents[1]
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','output']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();r,normal=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir(parents=True);binary=out/'normal-program';protected=[Path(__file__),BASE/'reference/program.c',a.reference];before={str(p.resolve()):sha(p)for p in protected};compiled=compile_probe(BASE/'reference/program.c',binary,r);save(out/'compile.json',compiled)
 if before!={str(p.resolve()):sha(p)for p in protected}:raise ValueError('caller input changed during compile')
 expected_binary=sha(binary);base=out/'empty-base';base.mkdir();env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_'))and k not in ['LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE','POSIXLY_CORRECT']};env.update(r['runtime_environment']);env.update(LC_ALL='C',GNUNET_BASE_CONFIG=str(base));cases=[('direct',b'100ms',b'2s',{'OWNED_DIRECT':'1'},[5_000_000]),('scheduled-ready',b'100ms',b'2s',{},[2_000_000]),('scheduled-shutdown-before-tick',b'100ms',b'2s',{'OWNED_SHUTDOWN':'1'},[5_000_000]),('disabled-interval',b'0',b'2s',{},[5_000_000]),('disabled-delta',b'100ms',b'0',{},[5_000_000]),('missing-delta',b'100ms',None,{},[5_000_000]),('forever-interval',b'forever',b'2s',{},[2_000_000]),('repeat-persistent-speedup',b'100ms',b'2s',{'OWNED_REPEAT':'1'},[2_000_000,4_000_000])];rows=[]
 try:
  for name,interval,delta,extra,expected in cases:
   directory=out/name;directory.mkdir();home=directory/'home';home.mkdir();config=directory/'program.conf';config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\n[TESTING]\nWEAKRANDOM = YES\nskew_offset = 5000000\nskew_variance = 0\nSPEEDUP_INTERVAL = '+interval+b'\n'+(b'SPEEDUP_DELTA = '+delta+b'\n'if delta is not None else b''));current=env.copy();current.update(extra);current.update(HOME=str(home),XDG_CONFIG_HOME=str(directory/'xdg'));started=time.monotonic();child=subprocess.run([b'owned-program',b'-c',os.fsencode(config),b'-L',b'ERROR'],executable=os.fsencode(binary),env=current,stdin=subprocess.DEVNULL,capture_output=True,timeout=4);elapsed=time.monotonic()-started;(directory/'stdout').write_bytes(child.stdout);(directory/'stderr').write_bytes(child.stderr)
   if child.returncode or child.stderr:raise ValueError(('actual normal PROGRAM failed',name,child.returncode,child.stderr))
   lines=child.stdout.splitlines();returns=[line for line in lines if line.startswith(b'RETURN ')];tasks=[line for line in lines if line.startswith(b'TASK ')];offsets=[int(line.split()[-1])for line in returns]
   if offsets!=expected or len(tasks)!=len(expected)or any(b' OFFSET 5000000 FILE 'not in line for line in tasks)or any(not line.startswith(b'RETURN 1 CALLS ')for line in returns):raise ValueError(('source scheduler observation mismatch',name,child.stdout))
   rows.append({'name':name,'actual_C_offsets_after_run':offsets,'actual_task_initial_offset':5000000,'tasks':len(tasks),'exit':child.returncode,'elapsed_seconds':elapsed});save(out/'progress.json',rows)
  _,after=load(a.reference,a.source,a.repo)
  if normal!=after or before!={str(p.resolve()):sha(p)for p in protected}or sha(binary)!=expected_binary:raise ValueError('normal/caller/binary changed')
  result={'status':'passed','scope':'C-only normal unmodified public PROGRAM_run2 lifecycle/scheduler/SPEEDUP observations; no Rust PROGRAM/runtime completion credit','cases':len(rows),'rows':rows,'normal_inputs':normal,'compiled':compiled,'inputs_unchanged':True,'Rust_equivalence':False,'no_external_DNS_or_network':True}
 except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'cases':len(rows),'Rust_equivalence':False}))
if __name__=='__main__':main()
