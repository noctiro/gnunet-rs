#!/usr/bin/env python3
"""Actual C/Rust CLI commands controlling separate unchanged normal C daemons.
Every home/config/listener and managed test child belongs to this finite run.
"""
import argparse,hashlib,json,os,socket,subprocess,tempfile,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def call(binary,config,arguments,env,directory,name):
 args=[b'gnunet-arm',b'-c',os.fsencode(config),b'-L',b'ERROR']+[os.fsencode(x)for x in arguments]
 r=subprocess.run(args,executable=os.fsencode(binary),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
 (directory/(name+'.stdout')).write_bytes(r.stdout);(directory/(name+'.stderr')).write_bytes(r.stderr)
 return {'arguments':[os.fsencode(a).hex()for a in arguments],'exit':r.returncode,'stdout_hex':r.stdout.hex(),'stderr_hex':r.stderr.hex()}
def actor(binary,profile,env,service,target,directory):
 directory.mkdir();runtime=tempfile.TemporaryDirectory(prefix='garem-',dir='/private/tmp');owned=Path(runtime.name);home=owned/'home';home.mkdir();endpoint=owned/'arm.sock';server=directory/'server.conf';client=directory/'client.conf';port=0
 if profile=='tcp4':
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM)as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
 common='[PATHS]\nGNUNET_HOME = '+str(home)+'\nDEFAULTCONFIG = '+str(server)+'\n[arm]\nPORT = '+str(port)+'\nHOSTNAME = 127.0.0.1\nBINDTO = 127.0.0.1\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\nGLOBAL_PREFIX =\nGLOBAL_POSTFIX =\n[TESTING]\nWEAKRANDOM = YES\n'
 server.write_text(common+'[arm]\nUNIXPATH = '+str(endpoint)+'\n'+''.join('['+name+']\nTYPE = SIMPLE\nBINARY = configured-'+name+'\nPREFIX = '+(''if name=='empty-prefix'else str(target))+'\nOPTIONS = 0\nRUN_PER_USER = YES\nIMMEDIATE_START = NO\nSTART_ON_DEMAND = NO\n'for name in ['finished','empty-prefix','running']))
 client.write_text('[PATHS]\nGNUNET_HOME = '+str(home)+'\n[arm]\n'+('UNIXPATH = '+str(endpoint)+'\n'if profile=='unix'else'PORT = '+str(port)+'\nHOSTNAME = 127.0.0.1\n'))
 env=env.copy();env.update(HOME=str(owned/'user'),XDG_CONFIG_HOME=str(owned/'xdg'),XDG_CACHE_HOME=str(owned/'cache'),XDG_DATA_HOME=str(owned/'data'),XDG_RUNTIME_DIR=str(owned/'run'))
 for name in ['user','xdg','cache','data','run']:(owned/name).mkdir(mode=0o700)
 output=open(directory/'daemon.stdout','wb');error=open(directory/'daemon.stderr','wb');process=None;steps=[];probes=[]
 try:
  process=subprocess.Popen([str(service),'-c',str(server)],env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=error)
  until=time.monotonic()+4
  while time.monotonic()<until:
   if process.poll()is not None:raise RuntimeError(('daemon exited before listener',process.returncode))
   with socket.socket(socket.AF_UNIX if profile=='unix'else socket.AF_INET,socket.SOCK_STREAM)as probe:
    probe.settimeout(.05)
    try:probe.connect(str(endpoint)if profile=='unix'else('127.0.0.1',port));break
    except (FileNotFoundError,ConnectionRefusedError,TimeoutError):time.sleep(.01)
  else:raise RuntimeError('owned normal daemon not ready')
  for name,arguments in [('initial-list',['-aI']),('unknown-init',['-i','does-not-exist']),('already-stopped-kill',['-k','running']),('start-finished',['-i','finished'])]:steps.append({'name':name,**call(binary,client,arguments,env,directory,name)})
  initial=bytes.fromhex(steps[0]['stdout_hex']).splitlines()
  if steps[0]['exit'] or steps[0]['stderr_hex'] or initial[:2]!=[b'All services:',b'(stopped: 3)'] or len(initial)!=5 or {line.split(b' (binary=',1)[0]for line in initial[2:]}!={b'finished',b'empty-prefix',b'running'}:raise ValueError(('normal daemon registry contains unexpected services',initial))
  for attempt in range(30):
   observation=call(binary,client,['-aI'],env,directory,'finished-probe-'+str(attempt));probes.append(observation)
   if b"finished (binary='configured-finished', status=finished)"in bytes.fromhex(observation['stdout_hex']):break
   time.sleep(.01)
  else:raise RuntimeError('real managed child did not reach finished')
  steps.append({'name':'list-after-real-child',**probes[-1]})
  for name,arguments in [('real-start-failure',['-i','empty-prefix']),('unknown-kill',['-k','does-not-exist']),('end',['-e','-T','2s'])]:steps.append({'name':name,**call(binary,client,arguments,env,directory,name)})
  if any(row['exit']!=0 for row in steps):raise ValueError('unexpected actual CLI status')
  exit=process.wait(timeout=4)
  if exit!=0:raise ValueError(('normal daemon did not naturally stop',exit))
  output.flush();actual_children=[json.loads(line)for line in (directory/'daemon.stdout').read_text().splitlines()if line.startswith('{')]
  if not any(row.get('event')=='actual-managed-child'and row.get('pid',0)>0 and row.get('argvhex',[None])[0]==b'configured-finished'.hex()for row in actual_children):raise ValueError('actual managed child trace missing')
  return {'steps':steps,'actual_managed_children':actual_children,'normal_daemon_exit':exit,'normal_daemon_pid':process.pid,'actual_finished_probe_commands':len(probes),'owned_endpoint':str(endpoint)if profile=='unix'else['127.0.0.1',port],'server_config_sha256':sha(server),'client_config_sha256':sha(client)}
 finally:
  if process is not None and process.poll()is None:
   process.terminate()
   try:process.wait(timeout=3)
   except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
  output.close();error.close();runtime.cleanup()
def main():
 parser=argparse.ArgumentParser()
 for name in ['reference','rust','output']:parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args();out=args.output.resolve();out.mkdir(exist_ok=False);r=json.loads(args.reference.read_text());normal=Path(r['artifacts']['client']['path']);service=Path(r['artifacts']['service']['path']);assert sha(normal)==r['artifacts']['client']['sha256']and sha(service)==r['artifacts']['service']['sha256']
 target=out/'owned-managed-child';build=subprocess.run(['cc',str(BASE/'tools/owned_child.c'),'-o',str(target)],capture_output=True);(out/'child-compile.stderr').write_bytes(build.stderr)
 if build.returncode:raise RuntimeError(build.stderr.decode())
 compiled_binary_sha256=sha(target);env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(r['runtime_environment']);env.update(LC_ALL='C',GNUNET_ARGS='');base=out/'base';base.mkdir();env['GNUNET_BASE_CONFIG']=str(base);rows=[]
 try:
  for profile in ['unix','tcp4']:
   directory=out/profile;directory.mkdir();c=actor(normal,profile,env,service,target,directory/'c');rust=actor(args.rust,profile,env,service,target,directory/'rust');same=c['steps']==rust['steps'];rows.append({'profile':profile,'matched_cli_steps':same,'c':c,'rust':rust});save(out/'progress.json',rows)
   if not same:raise ValueError('normal daemon CLI transcript differs '+profile)
  if sha(target)!=compiled_binary_sha256:raise RuntimeError('actual compiled native fixture changed')
  result={'status':'passed','actual_compiled_binary_sha256':compiled_binary_sha256,'actual_compiled_binary_unchanged':True,'scope':'actual source-built normal C ARM daemon plus real owned SIMPLE child, full C/Rust CLI entrypoints; no simulated responses','cases':rows,'normal_daemon_processes':4,'paired_cli_steps_per_profile':len(rows[0]['c']['steps']),'normal_daemon_sha256':sha(service),'normal_cli_sha256':sha(normal),'rust_cli_sha256':sha(args.rust),'only_owned_local_listeners_and_configuration':True}
 except Exception as error:result={'status':'failed','error':str(error),'cases':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows),'result':str(out/'result.json')}))
if __name__=='__main__':main()
