#!/usr/bin/env python3
"""Actual normal C ARM-self command/exec oracle against the complete Rust host.
No shell is invoked, malformed C inputs with known allocation/NULL UB are excluded.
All executables, PATH candidates, configuration/home and readiness markers are owned.
"""
import argparse,json,os,pathlib,shutil,subprocess
from reference import load,compile_probe,sha
from _common import require_disjoint_output


def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','rust','helper','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 a=p.parse_args();package=pathlib.Path(__file__).resolve().parents[1];ref,normal=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[package,a.repo,a.source,a.reference.resolve().parent,pathlib.Path(ref['prefix']),pathlib.Path(ref['build'])]);out.mkdir();caller=out/'normal-local-owner';compile_row=compile_probe(package/'tools/local_owner.c',caller,ref);target=out/'owned-target';compiled=subprocess.run(['cc',str(package/'tools/command_fixture.c'),'-o',str(target)],capture_output=True)
 if compiled.returncode:raise RuntimeError(compiled.stderr.decode())
 inputs={**normal,**{str(path.resolve()):sha(path)for path in [caller,target,a.rust,a.helper,pathlib.Path(__file__),package/'tools/local_owner.c',package/'tools/command_fixture.c',package/'examples/local_owner.rs']}}
 base=out/'base';base.mkdir();private_prefix=out/'prefix'
 for relative in ['bin','lib/gnunet/libexec','libexec/gnunet','share/gnunet/config','share/locale']:(private_prefix/relative).mkdir(parents=True,exist_ok=True)
 for relative in ['lib/gnunet/libexec/native-relative','libexec/gnunet/native-relative']:shutil.copy2(target,private_prefix/relative)
 cases=[{'label':'basic','expect':2,'child':0,'target':True}]
 for label,value in [('words','alpha beta'),('spaces','  alpha   beta  '),('tab','alpha\tbeta'),('quoted-middle','before "file name.conf" after'),('quoted-empty','before "" after'),('escaped-space',r'one\ two after'),('escaped-quote',r'one\"two after'),('backslashes',r'one\\two after'),('double-quoted',r'before "one\\two" after'),('unicode','label-ß 空'),('shell-literal','semi; colon | amp & star* $ARM_OWNED_OPTIONS')]:cases.append({'label':'options-'+label,'options':value,'expect':2,'child':0,'target':True})
 for label,weak,host in [('absent',None,None),('yes','YES',None),('mixed','yEs',None),('no','NO',None),('invalid','invalid',None),('host-empty','YES',''),('host-present','YES','owned-host-file')]:cases.append({'label':'daemon-'+label,'weak':weak,'hostfile':host,'expect':2,'child':0,'target':True})
 for label,value in [('relative','owned.conf'),('space','file name.conf'),('home','$HOME/owned.conf')]:cases.append({'label':'config-'+label,'config':value,'expect':2,'child':0,'target':True})
 for label,prefix in [('absolute',str(target)),('empty',''),('dollar','$ARM_OWNED_PREFIX')]:cases.append({'label':'prefix-'+label,'prefix':prefix,'expect':2,'child':0,'target':True})
 cases.extend([{'label':'binary-relative-libexec','binary':'native-relative','private_prefix':True,'expect':2,'child':0,'target':True},{'label':'missing-binary','binary':None,'expect':7,'child':None,'target':False},{'label':'nonexecutable','special':'nonexec','expect':8,'child':None,'target':False},{'label':'directory-late-exec','special':'directory','expect':2,'child':1,'target':False},{'label':'missing-interpreter-late-exec','special':'interpreter','expect':2,'child':1,'target':False},{'label':'actual-target-exit3','exit':3,'expect':2,'child':3,'target':True},{'label':'ready-byte-before-eof','byte':True,'expect':2,'child':0,'target':True},{'label':'path-first-nonexec','path':'nonexec','expect':8,'child':None,'target':False},{'label':'path-directory-then-executable','path':'directory','expect':2,'child':0,'target':True},{'label':'path-no-entry','path':'missing','expect':8,'child':None,'target':False},{'label':'prefix-dot-relative','path':'dot','expect':2,'child':0,'target':True}])
 environment={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_','ARM_COMMAND_'))};environment.update(ref['runtime_environment'],GNUNET_BASE_CONFIG=str(base),LC_ALL='C');rows=[]
 for case in cases:
  directory=out/case['label'];directory.mkdir();home=directory/'home';home.mkdir();record_target=directory/'target.json';released=directory/'released';ack=directory/'callback-ack';cfg=directory/'arm.conf';values={'UNIXPATH':str(directory/'absent.sock'),'BINARY':str(target),'OPTIONS':case.get('options','')};env={**environment,'HOME':str(home),'ARM_COMMAND_OUTPUT':str(record_target),'ARM_COMMAND_RELEASE':str(released),'ARM_COMMAND_EXIT':str(case.get('exit',0)),'ARM_OWNED_PREFIX':str(target),'ARM_OWNED_OPTIONS':'unquoted option'}
  if 'binary'in case:values['BINARY']=case['binary']
  if 'prefix'in case:values['PREFIX']=case['prefix']
  if 'config'in case:values['CONFIG']=case['config']
  if case.get('private_prefix'):env['GNUNET_PREFIX']=str(private_prefix)
  if case.get('byte'):env.update(ARM_COMMAND_READY_BYTE='1',ARM_COMMAND_ACK=str(ack))
  if case.get('special'):
   special=directory/'special'
   if case['special']=='directory':special.mkdir()
   elif case['special']=='nonexec':special.write_text('not executable')
   else:special.write_text('#!/gnunet-owned-missing-interpreter\n');special.chmod(0o700)
   values['BINARY']=str(special)
  if case.get('path'):
   first=directory/'first';second=directory/'second';first.mkdir();second.mkdir();shutil.copy2(target,second/'owned-wrapper')
   if case['path']=='nonexec':(first/'owned-wrapper').write_text('not executable')
   elif case['path']=='directory':(first/'owned-wrapper').mkdir()
   elif case['path']=='dot':shutil.copy2(target,directory/'owned-wrapper')
   env['PATH']=str(first)+':'+str(second)if case['path']!='missing'else str(first)
   values['PREFIX']='./owned-wrapper'if case['path']=='dot'else'owned-wrapper'
  weak=case.get('weak','YES');hostfile=case.get('hostfile');text='[arm]\n'+''.join(key+' = '+value+'\n'for key,value in values.items()if value is not None)+'[TESTING]\n'+('WEAKRANDOM = '+weak+'\n'if weak is not None else'')+('HOSTFILE = '+hostfile+'\n'if hostfile is not None else'');cfg.write_text(text);observations={}
  for actor in ['c','rust']:
   for path in [record_target,released,ack]:
    if path.exists():path.unlink()
   record=directory/(actor+'-owner.jsonl');argv=[str(caller),str(cfg),'start','0','default',str(record),'0']if actor=='c'else[str(a.rust),str(cfg),'start','0','default',str(a.helper),str(record),'0'];process=subprocess.Popen(argv,cwd=directory,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   try:stdout,stderr=process.communicate(input=b'',timeout=8)
   finally:
    if process.poll()is None:process.kill();process.communicate(timeout=2)
   (directory/(actor+'.stdout')).write_bytes(stdout);(directory/(actor+'.stderr')).write_bytes(stderr)
   if process.returncode:raise RuntimeError((case['label'],actor,process.returncode,stderr.decode()))
   events=[json.loads(line)for line in record.read_text().splitlines()];result=[row for row in events if row['event']=='result'];done=[row for row in events if row['event']=='done'];wait=[row for row in events if row['event']=='reaped']
   if len(result)!=1 or result[0]['status']!=0 or result[0]['result']!=case['expect']or len(done)!=1 or done[0]['callbacks']!=1 or done[0]['failed']!=0:raise ValueError((case['label'],actor,'wrong actual public callback',events))
   expected_children=int(case['child']is not None)
   if done[0]['children']!=expected_children or len(wait)!=expected_children or any(row['exit']!=case['child']or row['signal']!=0 for row in wait):raise ValueError((case['label'],actor,'wrong actual original child exit',events))
   target_observation=json.loads(record_target.read_text())if record_target.exists()else None
   if bool(target_observation)!=case['target']:raise ValueError((case['label'],actor,'target exec observation missing',events))
   if target_observation:
    (directory/(actor+'-target.json')).write_text(json.dumps(target_observation,indent=2)+'\n');target_observation.pop('pid')
    if target_observation['readiness_type']!=4096 or not target_observation['readiness_nonblock']or target_observation['readiness_cloexec']:raise ValueError('real readiness write owner invalid')
   if case.get('byte'):
    value=result[0].get('release_observed')if actor=='c'else next(row['release_observed']for row in events if row['event']=='callback-release')
    if value is not False or not released.exists()or not ack.exists():raise ValueError('byte callback did not precede actual EOF with later natural exit')
   observations[actor]={'exit_code':process.returncode,'result':result[0]['result'],'children':expected_children,'target':target_observation,'events':events,'argv':argv}
  if observations['c']['result']!=observations['rust']['result']or observations['c']['target']!=observations['rust']['target']:raise ValueError((case['label'],'native defined command behavior differs',observations))
  if case['label']=='options-shell-literal':
   arguments=[bytes.fromhex(value)for value in observations['c']['target']['argv']]
   if b'unquoted'not in arguments or b'option'not in arguments or any(b'$ARM_OWNED_OPTIONS'in value for value in arguments):raise ValueError('OPTIONS dollar expansion not actually observed')
  if case['label'].startswith('daemon-')or case['label']=='basic':
   expected_d=not(weak is not None and weak.upper()=='YES'and hostfile is None);arguments=[bytes.fromhex(value)for value in observations['c']['target']['argv']]
   if (b'-d'in arguments)!=expected_d:raise ValueError('native daemon argument rule not observed')
  rows.append({'label':case['label'],'matched':True,'expected_public_result':case['expect'],'target_required':case['target'],'observations':observations,'config_sha256':sha(cfg)})
 after,normal_after=load(a.reference,a.source,a.repo)
 if ref!=after or normal!=normal_after or any(sha(path)!=value for path,value in inputs.items()):raise ValueError('source/library/binary changed')
 result={'status':'passed','scope':'actual normal C ARM-self command/exec/daemon-argument/readiness versus actual Rust Host; no daemonization or successful service readiness claim','cases':rows,'paired_cases':len(rows),'inputs':inputs,'inputs_unchanged':True,'normal_compilation':compile_row,'C_UB_inputs_executed':False};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','paired_cases':len(rows),'result':str(out/'result.json')}))


if __name__=='__main__':main()
