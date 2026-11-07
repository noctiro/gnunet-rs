#!/usr/bin/env python3
"""Defined-safe normal public PROGRAM lifecycle versus actual Rust runtime.
Only owned tmp configs are loaded. The actual shared Resolver context is selected
but neither participant issues any DNS request or opens a network socket.
"""
import argparse,json,os,shutil,subprocess,time
from pathlib import Path
from _common import sha,require_disjoint_output,local_snapshot,require_lint_contract
from normal_reference import load,compile_probe
BASE=Path(__file__).resolve().parents[1]
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def metadata(toolchain):
 env=os.environ.copy();env['CARGO_TARGET_DIR']=str(BASE/'target')
 return json.loads(subprocess.check_output(['cargo','+'+toolchain,'metadata','--manifest-path',str(BASE/'Cargo.toml'),'--offline','--locked','--all-features','--format-version','1'],env=env))
def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','rust','output']:p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--toolchain',default='1.99.1');a=p.parse_args();r,normal=load(a.reference,a.source,a.repo);md=metadata(a.toolchain);policy=require_lint_contract(BASE,a.repo,md);_,inputs=local_snapshot(md,BASE,BASE/'tools');inputs[str(a.rust.resolve())]=sha(a.rust);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir(parents=True);save(out/'inputs-before.json',inputs);rust=out/'rust-program';shutil.copyfile(a.rust,rust);rust.chmod(0o700);c=out/'normal-program';compiled=compile_probe(BASE/'reference/program.c',c,r);save(out/'compile.json',compiled)
 _,compile_inputs=local_snapshot(metadata(a.toolchain),BASE,BASE/'tools');compile_inputs[str(a.rust.resolve())]=sha(a.rust)
 if compile_inputs!=inputs or sha(rust)!=sha(a.rust):raise ValueError('source or binary changed during compile')
 actors={str(c):sha(c),str(rust):sha(rust)};base=out/'empty-base';base.mkdir();env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_'))and k not in ['LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE','POSIXLY_CORRECT']};env.update(r['runtime_environment']);env.update(LC_ALL='C',GNUNET_BASE_CONFIG=str(base));cases=[('direct',b'100ms',b'2s',{'OWNED_DIRECT':'1'},[5_000_000]),('scheduled-ready',b'100ms',b'2s',{},[2_000_000]),('scheduled-shutdown-before-tick',b'100ms',b'2s',{'OWNED_SHUTDOWN':'1'},[5_000_000]),('disabled-interval',b'0',b'2s',{},[5_000_000]),('disabled-delta',b'100ms',b'0',{},[5_000_000]),('missing-delta',b'100ms',None,{},[5_000_000]),('forever-interval',b'forever',b'2s',{},[2_000_000]),('repeat-persistent-speedup',b'100ms',b'2s',{'OWNED_REPEAT':'1'},[2_000_000,4_000_000])];rows=[];result={'status':'not-run'}
 try:
  for name,interval,delta,extra,expected in cases:
   directory=out/name;directory.mkdir();home=directory/'home';home.mkdir();config=directory/'program.conf';config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\n[TESTING]\nWEAKRANDOM = YES\nskew_offset = 5000000\nskew_variance = 0\nSPEEDUP_INTERVAL = '+interval+b'\n'+(b'SPEEDUP_DELTA = '+delta+b'\n'if delta is not None else b''));current=env.copy();current.update(extra);current.update(HOME=str(home),XDG_CONFIG_HOME=str(directory/'xdg'));observed=[]
   for label,binary in [('c',c),('rust',rust)]:
    started=time.monotonic();child=subprocess.run([b'owned-program',b'-c',os.fsencode(config),b'-L',b'ERROR'],executable=os.fsencode(binary),env=current,stdin=subprocess.DEVNULL,capture_output=True,timeout=4);elapsed=time.monotonic()-started;(directory/(label+'.stdout')).write_bytes(child.stdout);(directory/(label+'.stderr')).write_bytes(child.stderr)
    if child.returncode or child.stderr:raise ValueError(('participant failed',label,name,child.returncode,child.stderr))
    lines=child.stdout.splitlines();returns=[line for line in lines if line.startswith(b'RETURN ')];tasks=[line for line in lines if line.startswith(b'TASK ')];offsets=[int(line.split()[-1])for line in returns]
    if offsets!=expected or len(tasks)!=len(expected)or any(b' OFFSET 5000000 FILE 'not in line for line in tasks)or any(not line.startswith(b'RETURN 1 CALLS ')for line in returns):raise ValueError(('source observation mismatch',label,name,child.stdout))
    observed.append({'actor':label,'offsets':offsets,'tasks':len(tasks),'exit':child.returncode,'stdout_hex':child.stdout.hex(),'elapsed_seconds':elapsed})
   equal=observed[0]['stdout_hex']==observed[1]['stdout_hex'];rows.append({'name':name,'matched':equal,'observed':observed});save(out/'progress.json',rows)
   if not equal:raise ValueError(('actual trace mismatch',name))
  _,after=load(a.reference,a.source,a.repo);_,new_inputs=local_snapshot(metadata(a.toolchain),BASE,BASE/'tools');new_inputs[str(a.rust.resolve())]=sha(a.rust)
  if normal!=after or inputs!=new_inputs or actors!={p:sha(Path(p))for p in actors}:raise ValueError('normal/local sources or actual actors changed')
  result={'status':'passed','scope':'8 defined-safe normal unchanged public PROGRAM_run2 lifecycle profiles; exact main/return/config/args/offset bytes versus actual Rust preparation, shared Resolver connect port, caller-polled scoped runtime and speedup stop; no all-SCHEDULER/locale/global logging completion credit','profiles':len(rows),'rows':rows,'normal_inputs':normal,'compiled':compiled,'inputs':inputs,'actors':actors,'root_lint_policy':policy,'inputs_unchanged':True,'no_DNS_or_network_request':True}
 except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows)}))
if __name__=='__main__':main()
