#!/usr/bin/env python3
"""Normal public conf_and_options/DAEMON: actual scheduler callback phases.
Only owned configs and in-process registered callbacks; no process/service spawn.
"""
import argparse,json,os,shutil,subprocess,time
from pathlib import Path
from _common import sha,local_snapshot,require_disjoint_output,require_lint_contract
from normal_reference import load,compile_probe
from logging_compare import date_boundary
BASE=Path(__file__).resolve().parents[1]
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def canonical(data,pid,before,after):
 rows=[];dates=[]
 for line in data.splitlines():
  if line==b'PID '+str(pid).encode():continue
  if line.startswith(b'R '):
   kind,component,date,body=line[2:].split(b' ',3);component=bytes.fromhex(component.decode());date=bytes.fromhex(date.decode());body=bytes.fromhex(body.decode());stem,actual=component.rsplit(b'-',1)
   if stem!=b'util-program'or actual!=str(pid).encode():raise ValueError('unexpected phase-source/PID')
   dates.append(date_boundary(date,before,after));rows.append(['R',int(kind),stem.decode(),body.hex()])
  else:rows.append(line.decode())
 return rows,dates

def main():
 p=argparse.ArgumentParser()
 for key in ['repo','source','reference','rust','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--toolchain',default='1.99.1');a=p.parse_args();cargo=['cargo','+'+a.toolchain,'metadata','--manifest-path',str(BASE/'Cargo.toml'),'--offline','--locked','--all-features','--format-version','1'];environment={**os.environ,'CARGO_TARGET_DIR':str(BASE/'target')};md=json.loads(subprocess.check_output(cargo,env=environment));_,inputs=local_snapshot(md,BASE,BASE/'tools');inputs[str(a.rust.resolve())]=sha(a.rust);policy=require_lint_contract(BASE,a.repo,md);r,normal=load(a.reference,a.source,a.repo);roots=[Path(row['manifest_path']).parent for row in md['packages']if row['source']is None];out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix']),*roots]);out.mkdir();rows=[];result={'status':'not-run'}
 try:
  c=out/'normal-program-daemon';compiled=compile_probe(BASE/'reference/program_daemon.c',c,r);save(out/'compile.json',compiled);rust=out/'rust-program-daemon';shutil.copy2(a.rust,rust);binaries={str(c):sha(c),str(rust):sha(rust)};env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','OWNED_','LISTEN_','DYLD_','LD_'))and k not in ['POSIXLY_CORRECT','JOURNAL_STREAM']};env.update(r['runtime_environment']);env.update(LC_ALL='C',GNUNET_FORCE_LOG='util-program;;;;DEBUG/;;;;NONE',GNUNET_ARGS='--ordinary-program-only-ignored')
  cases=[('provided','provided',[],2),('provided-ignored-config','provided',['-c','@MISSING','-d'],2),('bare-existing-scope','bare',[],2),('nullable-cfg','null',[],2),('callback-registration-next-round','repeat',[],5),('help','provided',['--help'],0),('version','provided',['--version'],0),('unknown-option','provided',['--not-an-option'],0)]
  for name,mode,args,expected in cases:
   folder=out/name;folder.mkdir();home=folder/'home';home.mkdir();base=folder/'base';base.mkdir();current=env.copy();current.update(HOME=str(home),XDG_CONFIG_HOME=str(home),GNUNET_BASE_CONFIG=str(base),OWNED_DAEMON_MODE=mode)
   if expected==0:current['OWNED_OPTIONS_STOP']='1'
   args=[str(folder/'missing.conf')if v=='@MISSING'else v for v in args];actors=[]
   for label,binary in [('c',c),('rust',rust)]:
    before=time.time_ns()//1000;child=subprocess.Popen([b'owned-daemon',*map(os.fsencode,args)],executable=os.fsencode(binary),env=current,cwd=folder,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=child.communicate(timeout=5);after=time.time_ns()//1000;(folder/(label+'.stdout')).write_bytes(stdout);(folder/(label+'.stderr')).write_bytes(stderr)
    if child.returncode:raise ValueError(('actual helper actor failure',name,label,child.returncode,stderr))
    events,dates=canonical(stdout,child.pid,before,after);task_rows=[v for v in events if isinstance(v,str)and v.startswith('TASK ')]
    if len(task_rows)!=expected:raise ValueError(('source task phases missing',name,label,task_rows))
    actors.append({'actor':label,'pid':child.pid,'exit_code':child.returncode,'events':events,'dates':dates,'stderr_hex':stderr.hex()})
   matched=all(actors[0][key]==actors[1][key]for key in ['events','stderr_hex']);rows.append({'name':name,'matched':matched,'actors':actors});save(out/'progress.json',rows)
   if not matched:raise ValueError(('actual source helper phase/option/output mismatch',name))
  _,after=local_snapshot(json.loads(subprocess.check_output(cargo,env=environment)),BASE,BASE/'tools');after[str(a.rust.resolve())]=sha(a.rust);_,new_normal=load(a.reference,a.source,a.repo)
  if inputs!=after or normal!=new_normal or any(sha(path)!=digest for path,digest in binaries.items()):raise ValueError('actual source/normal library/participant changed')
  result={'status':'passed','profiles':len(rows),'actual_C_R_actors':len(rows)*2,'scope':'normal unchanged public DAEMON register/main and PROGRAM conf_and_options; real source scheduler callbacks/newest-first/repeated callback-time registration/null config, existing scheduler scope, help/version/error/ignored cfg and GNUNET_ARGS; only util-program phase logs selected by explicit same force policy, not full SCHEDULER/service credit','rows':rows,'inputs':inputs,'normal_inputs':normal,'compiled':compiled,'binaries':binaries,'root_lint_policy':policy,'inputs_unchanged':True}
 except Exception as e:result={'status':'failed','error':str(e),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows)}))
if __name__=='__main__':main()
