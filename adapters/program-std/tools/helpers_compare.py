#!/usr/bin/env python3
"""Actual normal C/Rust factory/destination/partial-error comparisons."""
import argparse,json,os,subprocess
from pathlib import Path
from _common import sha,require_disjoint_output
from normal_reference import load,compile_probe
BASE=Path(__file__).resolve().parents[1]
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def profiles():
 cases=[[],['-f'],['-nnn'],['-VnV'],['-u','0'],['-u','4294967295'],['-u','-1'],['-u','  -1'],['-u','12x'],['-u',''],['-u',' +123 '],['-t','65535'],['-t','65536'],['-t','-1'],['-t','12x'],['-g','18446744073709551615'],['-g','-1'],['-g','12x'],['-s',''],['-s',b'raw\xff'],['-s','first','-s','last'],['-F','relative'],['-F','~/relative'],['-F',''],['-c','relative'],['-l','logs/file'],['-L','not-validated'],['-R','2s'],['-R','2 h 3 m'],['-R','forever'],['-A','10000'],['-A','9999'],['-A','2026'],['-A','2026-10'],['-A','2026-10-27'],['-A','2026-10-27 08:23:45'],['-A','end of time'],['-A','bad'],['-A','10000 '],['-S','10000'],['-S','end of time'],['-S','bad'],['-T','+2s'],['-T','-2 s'],['-T',' +2s'],['-T','forever'],['-b','OOOOO'],['-b','ZZZZZ'],['-b','00001'],['-b','0'],['-b','000000'],['--help'],['--version'],['-h','-f'],['-f','-h'],['-u','12x','-f']]
 rows=[{'args':row}for row in cases]
 rows.extend({'args':row,'modifiers':True}for row in [[],['-f'],['-n'],['-nn'],['-f','-n']])
 rows.extend({'args':row,'missing_home':True}for row in [['-F','~/value'],['-c','~/value'],['-F','/owned/previous-name','-F','~/value'],['-c','/owned/previous-name','-c','~/value']])
 return rows

def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','rust','output']:p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();r,normal=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[BASE,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix'])]);out.mkdir(parents=True);protected=[Path(__file__),BASE/'reference/helpers.c',*list((BASE/'src').rglob('*.rs')),a.rust];before={str(p.resolve()):sha(p)for p in protected};binary=out/'normal-helpers';compiled=compile_probe(BASE/'reference/helpers.c',binary,r);save(out/'compile.json',compiled)
 if before!={str(p.resolve()):sha(p)for p in protected}:raise ValueError('factory/caller changed during compile')
 csha=sha(binary);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_','OWNED_'))and k not in ['POSIXLY_CORRECT','LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE']};env.update(r['runtime_environment']);env['LC_ALL']='C';runtime=out/'runtime';runtime.mkdir();home=runtime/'home';home.mkdir();env.update(HOME=str(home),PWD=str(runtime),XDG_CONFIG_HOME=str(runtime/'xdg'));rows=[]
 try:
  for index,case in enumerate(profiles()):
   # Conservative source-defined allowlist: do not execute known uninitialized
   # relative-output or signed-negative-shift C paths, even to test a rejection.
   for spelling,allowed in [('-R',{'2s','2 h 3 m','forever'}),('-T',{'+2s','-2 s',' +2s','forever'})]:
    if spelling in case['args'] and case['args'][case['args'].index(spelling)+1]not in allowed:raise ValueError('unsafe/unreviewed C relative input blocked')
   if '-b'in case['args'] and any(ch not in '0123456789ABCDEFGHJKMNPQRSTVWXYZILOUabcdefghjkmnpqrstvwxyzilou'for ch in case['args'][case['args'].index('-b')+1]):raise ValueError('nonfinal invalid-base32 C paths blocked')
   directory=out/str(index);directory.mkdir();current=env.copy()
   if case.get('modifiers'):current['OWNED_HELPER_MODIFIERS']='1'
   if case.get('missing_home'):current.pop('HOME',None);current['OWNED_HELPER_DIAGNOSTICS']='1'
   actors=[]
   for label,exe in [('c',binary),('rust',a.rust)]:
    child=subprocess.run([b'owned-helpers']+[os.fsencode(v)for v in case['args']],executable=os.fsencode(exe),env=current,cwd=runtime,stdin=subprocess.DEVNULL,capture_output=True,timeout=4);(directory/(label+'.stdout')).write_bytes(child.stdout);(directory/(label+'.stderr')).write_bytes(child.stderr)
    if child.returncode:raise ValueError(('factory observer process failed',label,index,child.returncode))
    actors.append({'exit':child.returncode,'stdout_hex':child.stdout.hex(),'stderr_hex':child.stderr.hex()})
   rows.append({'case':{**case,'args':[os.fsencode(v).hex()for v in case['args']]},'matched':actors[0]==actors[1],'c':actors[0],'rust':actors[1]});save(out/'progress.json',rows)
   if actors[0]!=actors[1]:raise ValueError('actual helper mismatch case '+str(index))
  _,after=load(a.reference,a.source,a.repo)
  if normal!=after or before!={str(p.resolve()):sha(p)for p in protected}or sha(binary)!=csha:raise ValueError('source/caller/binary changed')
  result={'status':'passed','profiles':len(rows),'scope':'normal public GETOPT helper factories vs actual Rust owned bindings; exact parse return/mutation/partial-failure/value bytes/help/error transcripts; no malformed-relative, invalid-character base32, scanf mathematical-overflow or unsafe C pointer experiments','rows':rows,'compiled':compiled,'normal_inputs':normal,'inputs_unchanged':True,'full_locale_or_process_install_credited':False}
 except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows)}))
if __name__=='__main__':main()
