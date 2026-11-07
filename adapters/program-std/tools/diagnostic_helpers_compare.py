#!/usr/bin/env python3
"""Normal common_logging helper operations and actual Rust byte/value results.
No C hex2b, malformed time/base32, arbitrary-pointer or nonterminated Unix case.
"""
import argparse,json,os,re,shutil,subprocess,time
from pathlib import Path
from _common import sha,local_snapshot,require_disjoint_output,require_lint_contract
from normal_reference import load,compile_probe
from logging_compare import date_boundary
BASE=Path(__file__).resolve().parents[1]
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def canonical(data,pid,before,after,cfile):
 rows=[];dates=[]
 for line in data.splitlines():
  if line==b'PID '+str(pid).encode():continue
  if line.startswith(b'R '):
   level,component,date,body=line[2:].split(b' ',3);component=bytes.fromhex(component.decode());date=bytes.fromhex(date.decode());body=bytes.fromhex(body.decode());stem,suffix=component.rsplit(b'-',1)
   if stem!=b'owned-helper'or suffix!=str(pid).encode():raise ValueError('actual helper logger PID/component invalid')
   dates.append(date_boundary(date,before,after));m=re.fullmatch(rb'Assertion failed at (.+):982[.]\n',body)
   if m:
    if m[1]!=(cfile if cfile is not None else b'common_logging.c'):raise ValueError('actual normal source macro filename invalid')
    body=b'Assertion failed at <actual-bound-common_logging.c>:982.\n'
   rows.append(['R',int(level),stem.decode(),body.hex()])
  else:rows.append(line.decode())
 return rows,dates

def main():
 p=argparse.ArgumentParser()
 for key in ['repo','source','reference','rust','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--toolchain',default='1.99.1');a=p.parse_args();env=os.environ.copy();env['CARGO_TARGET_DIR']=str(BASE/'target');metadata_cmd=['cargo','+'+a.toolchain,'metadata','--manifest-path',str(BASE/'Cargo.toml'),'--offline','--locked','--all-features','--format-version','1'];md=json.loads(subprocess.check_output(metadata_cmd,env=env));_,inputs=local_snapshot(md,BASE,BASE/'tools');inputs[str(a.rust.resolve())]=sha(a.rust);policy=require_lint_contract(BASE,a.repo,md);r,normal=load(a.reference,a.source,a.repo);roots=[Path(row['manifest_path']).parent for row in md['packages']if row['source']is None];out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix']),*roots]);out.mkdir();result={'status':'not-run'};observed=[]
 try:
  c=out/'normal-diagnostic-helpers';compiled=compile_probe(BASE/'reference/diagnostic_helpers.c',c,r);save(out/'compile.json',compiled);rust=out/'rust-diagnostic-helpers';shutil.copy2(a.rust,rust);binaries={str(c):sha(c),str(rust):sha(rust)};db=json.loads(Path(r['compile_commands']['path']).read_text());selected=[v for v in db if v['file'].endswith('/common_logging.c')]
  if len(selected)!=1:raise ValueError('normal common TU ambiguous')
  cfile=os.fsencode(selected[0]['file']);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','OWNED_','LISTEN_','DYLD_','LD_'))and k not in ['JOURNAL_STREAM','LANGUAGE']};env.update(r['runtime_environment']);env['LC_ALL']='C'
  for label,binary in [('c',c),('rust',rust)]:
   before=time.time_ns()//1000;child=subprocess.Popen([str(binary)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=child.communicate(timeout=5);after=time.time_ns()//1000;(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
   if child.returncode or stderr:raise ValueError(('actual helper participant failure',label,child.returncode,stderr))
   events,dates=canonical(stdout,child.pid,before,after,cfile if label=='c'else None);observed.append({'actor':label,'pid':child.pid,'exit_code':child.returncode,'events':events,'dates':dates})
  matched=observed[0]['events']==observed[1]['events']
  if not matched:raise ValueError('actual public helper byte/operation trace differs')
  _,after=local_snapshot(json.loads(subprocess.check_output(metadata_cmd,env={**os.environ,'CARGO_TARGET_DIR':str(BASE/'target')})),BASE,BASE/'tools');after[str(a.rust.resolve())]=sha(a.rust);_,after_normal=load(a.reference,a.source,a.repo)
  if inputs!=after or normal!=after_normal or any(sha(p)!=h for p,h in binaries.items()):raise ValueError('actual helper source/library/binary changed')
  result={'status':'passed','normal_pairs':1,'actual_C_R_actors':2,'actual_rows':len(observed[0]['events']),'scope':'normal unchanged common_logging hash/pubkey/peer/UUID/native address, async scope save/restore/fresh OS call, bounded print_bytes, config_missing/invalid and log_skip checked reset; no statistical entropy proof or C hex2b/abort credit','actors':observed,'inputs':inputs,'normal_inputs':normal,'binaries':binaries,'compiled':compiled,'root_lint_policy':policy,'inputs_unchanged':True,'C_hex2b_executed':False}
 except Exception as e:result={'status':'failed','error':str(e),'actors':observed};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'actual_rows':result['actual_rows']}))
if __name__=='__main__':main()
