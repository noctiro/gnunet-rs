#!/usr/bin/env python3
"""Actual C/Rust public clients versus unchanged C/real Rust ARM daemon processes.
This finite pair is not a full daemon/CLI certification. It builds actual actors;
no response peer, extracted service function or production libgnunet FFI is used.
"""
import argparse,json,os,socket,subprocess,sys,time,hashlib
from pathlib import Path
PACKAGE=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def overlap(a,b):a,b=Path(a).resolve(),Path(b).resolve();return a==b or a.is_relative_to(b) or b.is_relative_to(a)
def main():
 global PACKAGE
 p=argparse.ArgumentParser(description=__doc__)
 for key in ['repository','upstream','reference','output']:p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--package',type=Path,default=PACKAGE)
 a=p.parse_args();PACKAGE=a.package.resolve();repo=a.repository.resolve();out=a.output.resolve();upstream=a.upstream.resolve();reference_path=a.reference.resolve()
 for protected in [repo,PACKAGE,upstream,reference_path.parent]:
  if overlap(out,protected):raise ValueError('output overlaps source/reference')
 out.mkdir(exist_ok=False);sys.path.insert(0,str(repo/'adapters/arm-std/tools'));import reference
 ref,normal=reference.load(reference_path,upstream,repo);commands=[]
 def run(label,argv,cwd=repo,timeout=180):
  start=time.monotonic();done=subprocess.run(list(map(str,argv)),cwd=cwd,capture_output=True,timeout=timeout);(out/(label+'.stdout')).write_bytes(done.stdout);(out/(label+'.stderr')).write_bytes(done.stderr);commands.append({'name':label,'argv':list(map(str,argv)),'cwd':str(cwd),'exit':done.returncode,'seconds':time.monotonic()-start})
  if done.returncode:raise RuntimeError(label+': '+done.stderr.decode())
  return done
 def discover():
  r,current=reference.load(reference_path,upstream,repo)
  if r!=ref or current!=normal:raise ValueError('normal reference changed')
  paths={Path(path).resolve() for path in normal}
  paths.update([repo/'Cargo.toml',repo/'Cargo.lock',repo/'rust-toolchain.toml',repo/'adapters/arm-std/examples/daemon_owner.rs',repo/'adapters/arm-std/tools/daemon_fixture.c',repo/'adapters/arm-std/tools/reference.py'])
  metadata=json.loads(subprocess.check_output(['cargo','+1.99.1','metadata','--offline','--locked','--manifest-path',str(PACKAGE/'Cargo.toml'),'--format-version=1'],cwd=repo))
  roots=[PACKAGE,repo/'adapters/arm-std']+[Path(item['manifest_path']).resolve().parent for item in metadata['packages'] if item['source']is None]
  for root in roots:
   for path in root.rglob('*'):
    if path.is_file()and not any(part in ['target','.git','__pycache__']for part in path.relative_to(root).parts) and (path.suffix in ['.rs','.md','.toml','.c','.py','.json','.in']or path.name=='Cargo.lock'):paths.add(path.resolve())
  return {str(path):sha(path)for path in sorted(paths)if path.is_file()}
 before=discover();(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
 run('candidate-fresh',['cargo','+1.99.1','build','--offline','--locked','--manifest-path',PACKAGE/'Cargo.toml','--target-dir',out/'candidate-target','--bins','-j','1'])
 run('helper-fresh',['cargo','+1.99.1','build','--offline','--locked','--manifest-path',repo/'Cargo.toml','--target-dir',out/'candidate-target','-p','gnunet-arm-host','--bin','gnunet-arm-spawn-helper','-j','1'])
 run('client-fresh',['cargo','+1.99.1','build','--offline','--locked','--manifest-path',repo/'Cargo.toml','--target-dir',out/'client-target','-p','gnunet-arm-host','--example','daemon_owner','-j','1'])
 rust_daemon=out/'candidate-target/debug/gnunet-arm-reactor-daemon-fixture';helper=out/'candidate-target/debug/gnunet-arm-spawn-helper';rust_client=out/'client-target/debug/examples/daemon_owner';c_client=out/'normal-public-client';compile_client=reference.compile_probe(PACKAGE/'tools/reactor_client.c',c_client,ref)
 child=out/'owned-managed-child';run('target-compile',['cc',PACKAGE/'tools/reactor_target.c','-Wall','-Wextra','-Werror','-o',child])
 normal_daemon=Path(ref['artifacts']['service']['path']);assert sha(normal_daemon)==ref['artifacts']['service']['sha256']
 artifacts={str(path):sha(path)for path in [rust_daemon,helper,rust_client,c_client,child,normal_daemon]};cases=[];base=out/'base';base.mkdir();home=out/'home';home.mkdir();xdg=out/'xdg';xdg.mkdir()
 env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(ref['runtime_environment'],GNUNET_BASE_CONFIG=str(base),HOME=str(home),XDG_CONFIG_HOME=str(xdg),LC_ALL='C')
 for server in ['normal','rust']:
  for actor in ['c','rust']:
   for profile in ['unix','tcp4']:
    directory=out/(server+'-'+actor+'-'+profile);directory.mkdir();endpoint=directory/'arm.sock';cfg=directory/'server.conf';clientcfg=directory/'client.conf';ready=directory/'ready';child_ready=directory/'child-ready';port=0
    if profile=='tcp4':
     with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    cfg.write_text('[paths]\nGNUNET_HOME = '+str(directory/'home')+'\nDEFAULTCONFIG = '+str(cfg)+'\n[arm]\nUNIXPATH = '+str(endpoint)+'\nPORT = '+str(port)+'\nHOSTNAME = 127.0.0.1\nBINDTO = 127.0.0.1\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\nGLOBAL_PREFIX =\nGLOBAL_POSTFIX =\n[TESTING]\nWEAKRANDOM = YES\n'+''.join('['+name+']\nTYPE = SIMPLE\nBINARY = configured-'+name+'\nPREFIX = '+(''if name=='empty-prefix'else str(child))+'\nOPTIONS = '+('3000'if name=='running'else'0')+'\nRUN_PER_USER = YES\nIMMEDIATE_START = NO\nSTART_ON_DEMAND = NO\n'for name in ['finished','empty-prefix','running']))
    clientcfg.write_text('[arm]\n'+('UNIXPATH = '+str(endpoint)+'\nPORT = 0\nHOSTNAME = localhost\n'if profile=='unix'else'PORT = '+str(port)+'\nHOSTNAME = 127.0.0.1\n'))
    env['GNUNET_ARM_PAIR_CHILD_READY']=str(child_ready)
    stdout=open(directory/'daemon.stdout','wb');stderr=open(directory/'daemon.stderr','wb');daemon=None;client=None
    try:
     argv=[str(normal_daemon),'-c',str(cfg)]if server=='normal'else[str(rust_daemon),str(cfg),str(helper),str(ready)];daemon=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr);deadline=time.monotonic()+5
     while True:
      if daemon.poll()is not None:raise RuntimeError((server,actor,profile,'early daemon exit',daemon.returncode))
      probe=socket.socket(socket.AF_UNIX if profile=='unix'else socket.AF_INET,socket.SOCK_STREAM);probe.settimeout(.05)
      try:probe.connect(str(endpoint)if profile=='unix'else('127.0.0.1',port));break
      except (FileNotFoundError,ConnectionRefusedError,TimeoutError):
       if time.monotonic()>deadline:raise TimeoutError('owned daemon endpoint')
       time.sleep(.005)
      finally:probe.close()
     actor_argv=[str(c_client),str(clientcfg),str(child_ready)]if actor=='c'else[str(rust_client),str(clientcfg),str(helper)];client=subprocess.Popen(actor_argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);actor_stdout,actor_stderr=client.communicate(timeout=16);(directory/'client.stdout').write_bytes(actor_stdout);(directory/'client.stderr').write_bytes(actor_stderr)
     if client.returncode:raise RuntimeError((server,actor,profile,'client exit',client.returncode,actor_stderr.decode(),actor_stdout.decode()))
     events=[json.loads(line)for line in actor_stdout.splitlines()];done=[row for row in events if row['event']=='done'];assert len(done)==1
     if actor=='c':
      assert done[0]['failed']==0 and done[0]['monitors']>=4
      assert not any(row['event']in ['watchdog','canceled-callback']for row in events)
      assert [(row['event'],row.get('result'))for row in events if row['event']in ['start','stop']]==[('start',2),('stop',0)]
      assert [(row['phase'],row['status'],row['exit'])for row in events if row['event']=='row'and row['name']=='running']==[(0,0,0),(3,2,15)]
     else:assert done[0]['results']==9 and done[0]['helper_children']==0 and done[0]['canceled_callback_suppressed'] and done[0]['repeat_connections']>=2
     stop=[row for row in events if row['event']=='stop-arm'];assert len(stop)==1 and (stop[0]['status'],stop[0]['result'])in[(0,0),(2,None)]
     code=daemon.wait(timeout=5);assert code==0
     assert not endpoint.exists() and not ready.exists()
     cases.append({'server':server,'actor':actor,'profile':profile,'daemon_argv':argv,'daemon_exit':code,'actor_argv':actor_argv,'actor_exit':client.returncode,'events':events,'self_stop':stop[0],'config_sha256':sha(cfg),'client_config_sha256':sha(clientcfg),'only_owned_endpoint':True,'natural_process_cleanup':True})
    finally:
     if client is not None and client.poll()is None:client.kill();client.communicate(timeout=2)
     if daemon is not None and daemon.poll()is None:
      daemon.terminate()
      try:daemon.wait(timeout=5)
      except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=2)
     stdout.close();stderr.close()
 after=discover();(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n');assert before==after,'source file added/deleted/changed';assert all(sha(path)==digest for path,digest in artifacts.items()),'executed artifact changed'
 result={'status':'passed','scope':'finite actual C/Rust public ARM clients versus unchanged normal C and actual Rust daemon reactor, owned Unix and numeric-loopback TCP; no full generic PROGRAM/CLI/ARM testing certification','cases':cases,'case_count':len(cases),'normal_reference':str(reference_path),'normal_C_client_compile':compile_client,'fresh_binary_sha256':artifacts,'commands':commands,'inputs_unchanged':True,'input_manifest_sha256':sha(out/'inputs-before.json'),'owner_verified_promotion':False};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','cases':len(cases),'result':str(out/'result.json')}))
if __name__=='__main__':main()
