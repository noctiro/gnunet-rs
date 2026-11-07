#!/usr/bin/env python3
"""Normal public GETOPT callback/context/permutation/cleaner comparison.
No C pointer misuse, terminal ambiguous -W NULL printf, or source edits.
"""
import argparse,json,os,subprocess
from pathlib import Path
from _common import sha,require_disjoint_output
from normal_reference import load,compile_probe
BASE=Path(__file__).resolve().parents[1]
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def cases():
 rows=[]
 def add(profile,args,posix=False):rows.append({'profile':profile,'args':args,'posix':posix})
 for args in [[],['-a'],['--alpha'],['--al'],['-aa'],['-abv'],['--beta=v'],['--bet','v'],['-b','-a'],['-b'],['--beta'],['-z'],['--unknown'],['--alpha=x'],['--=oops'],['left','-a','middle','-b','value','right'],['left','--','-a'],['-a','--','tail'],['-x'],['-xx'],['-x','-a'],['-b','fail','-a'],['-a',b'\xff'],['left','-a','-z','tail']]:add('base',args)
 for args in [['left','-a'],['-z'],['-a','tail','-b','v']]:add('base',args,True)
 for args in [[],['-a'],['-m'],['-x'],['-x','-m'],['-b','fail']]:add('mandatory',args)
 for args in [['--optional'],['--optional=v'],['--optional','value'],['-o'],['-ov'],['-o','v']]:add('optional',args)
 for args in [['--first'],['--second','v'],['--alpha'],['-a'],['--second'],['--first','--alpha']]:add('longonly',args)
 for args in [['-z'],['--unknown'],['-a','-z']]:add('question',args)
 for args in [['left','-a'],['-a+'],['-a','-+'],['-a','left','-b','v']]:add('require',args)
 for args in [['left','-a','right'],['-a-'],['-a','--minus','middle']]:add('return',args)
 for args in [['-Walpha'],['-W','alpha'],['-W','unknown'],['-W','beta','value'],['-W','alpha=v'],['-W','beta'],['-W','bet','safe-filler'],['-W']]:add('W',args)
 return rows

def main():
 ap=argparse.ArgumentParser()
 for name in ['repo','source','reference','rust','output']:ap.add_argument('--'+name,type=Path,required=True)
 args=ap.parse_args();receipt,normal_before=load(args.reference,args.source,args.repo);out=require_disjoint_output(args.output,[BASE,args.repo,args.source,args.reference.resolve().parent,Path(receipt['build']),Path(receipt['prefix'])]);out.mkdir(parents=True)
 protected=[Path(__file__),BASE/'reference/getopt.c',*list((BASE/'src').rglob('*.rs')),args.rust];before={str(p.resolve()):sha(p)for p in protected};c=out/'normal-getopt';compiled=compile_probe(BASE/'reference/getopt.c',c,receipt);save(out/'compile.json',compiled)
 if before!={str(p.resolve()):sha(p)for p in protected}:raise ValueError('input changed during caller compilation')
 csha=sha(c);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))and k not in ['POSIXLY_CORRECT','LD_PRELOAD','DYLD_INSERT_LIBRARIES','DYLD_FORCE_FLAT_NAMESPACE']};env.update(receipt['runtime_environment']);env['LC_ALL']='C';rows=[]
 try:
  for index,case in enumerate(cases()):
   current=env.copy();current['OWNED_GETOPT_PROFILE']=case['profile']
   if case['posix']:current['POSIXLY_CORRECT']=''
   directory=out/str(index);directory.mkdir();actors=[]
   for label,binary in [('c',c),('rust',args.rust)]:
    argv=[b'owned-parser']+[os.fsencode(value)for value in case['args']];result=subprocess.run(argv,executable=os.fsencode(binary),env=current,stdin=subprocess.DEVNULL,capture_output=True,timeout=4);(directory/(label+'.stdout')).write_bytes(result.stdout);(directory/(label+'.stderr')).write_bytes(result.stderr)
    if result.returncode:raise ValueError(('observer process failure',index,label,result.returncode))
    actors.append({'exit':result.returncode,'stdout_hex':result.stdout.hex(),'stderr_hex':result.stderr.hex()})
   rows.append({'case':{'profile':case['profile'],'posix':case['posix'],'argv_hex':[os.fsencode(v).hex()for v in case['args']]},'matched':actors[0]==actors[1],'c':actors[0],'rust':actors[1]});save(out/'progress.json',rows)
   if actors[0]!=actors[1]:raise ValueError('GETOPT source mismatch case '+str(index))
  _,normal_after=load(args.reference,args.source,args.repo)
  if normal_before!=normal_after or sha(c)!=csha or before!={str(p.resolve()):sha(p)for p in protected}:raise ValueError('caller/source/tools/normal inputs changed')
  result={'status':'passed','scope':'actual unmodified public GNUNET_GETOPT_run; exact callback name/value/currentArgument/partially permuted argv and final argv/return/cleaners/stdout/stderr; metadata edge spellings use safe callbacks, no undefined C terminal -W ambiguity experiment','cases':len(rows),'rows':rows,'normal_inputs':normal_before,'compiled':compiled,'rust_binary_sha256':sha(args.rust),'inputs_unchanged':True,'complete_PROGRAM_or_helpers_credited':False}
 except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'cases':len(rows)}))
if __name__=='__main__':main()
