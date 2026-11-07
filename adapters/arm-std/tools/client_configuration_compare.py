#!/usr/bin/env python3
"""C/Rust live CLIENT read points against one owned, zero-service C daemon.
The earlier both-service-modes launch was rejected before execution. This narrower
case explicitly disables system services, uses a private empty base directory,
passes one explicit private config with no BINARY/include sections and asserts
empty real service inventory. Only numeric loopback/owned Unix sockets are used.
"""
import argparse,json,os,pathlib,socket,subprocess,time
from reference import load,compile_probe,sha
from _common import require_disjoint_output
p=argparse.ArgumentParser()
for name in ['repo','source','reference','rust','helper','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
a=p.parse_args();package=pathlib.Path(__file__).resolve().parents[1];ref,normal=load(a.reference,a.source,a.repo);out=require_disjoint_output(a.output,[package,a.repo,a.source,a.reference.resolve().parent,pathlib.Path(ref['build']),pathlib.Path(ref['prefix'])]);out.mkdir();caller=out/'normal-client-configuration';compilation=compile_probe(package/'tools/client_configuration.c',caller,ref);service=ref['artifacts']['service'];binary=pathlib.Path(service['path'])
if sha(binary)!=service['sha256']:raise ValueError('normal service binary changed')
inputs={**normal,**{str(path.resolve()):sha(path)for path in [caller,binary,a.rust,a.helper,pathlib.Path(__file__),package/'tools/client_configuration.c',package/'examples/configuration_owner.rs']}}
base=out/'empty-base';base.mkdir();home=out/'home';home.mkdir();xdg=out/'xdg';xdg.mkdir();environment={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_','ARM_COMMAND_','ARM_CONFIG_'))};environment.update(ref['runtime_environment'],GNUNET_BASE_CONFIG=str(base),HOME=str(home),XDG_CONFIG_HOME=str(xdg),LC_ALL='C');endpoint=out/'actual-arm.sock';old_unix=out/'old-absent.sock'
reservation=socket.socket(socket.AF_INET,socket.SOCK_STREAM);reservation.bind(('127.0.0.1',0));old_port=reservation.getsockname()[1]
fence=socket.socket(socket.AF_INET,socket.SOCK_STREAM);fence.bind(('127.0.0.1',0));fence.listen(4);fence.settimeout(.02);new_port=fence.getsockname()[1]
config=out/'zero-managed-services.conf';text='[paths]\nGNUNET_HOME = '+str(home)+'\nDEFAULTCONFIG = '+str(config)+'\n[arm]\nUNIXPATH = '+str(endpoint)+'\nPORT = 0\nHOSTNAME = 127.0.0.1\nBINDTO = 127.0.0.1\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\nGLOBAL_PREFIX =\nGLOBAL_POSTFIX =\n[TESTING]\nWEAKRANDOM = YES\n'
if 'BINARY'in text or '@'in text or list(base.iterdir()):raise ValueError('zero-service isolation preflight failed')
config.write_text(text);daemon=None;actor=None;log=open(out/'daemon.stdout','wb');err=open(out/'daemon.stderr','wb');rows=[]
try:
 daemon=subprocess.Popen([str(binary),'-c',str(config)],env=environment,stdin=subprocess.DEVNULL,stdout=log,stderr=err);until=time.monotonic()+5
 while time.monotonic()<until:
  if daemon.poll()is not None:raise RuntimeError('normal daemon exited before ready')
  probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  try:probe.connect(str(endpoint));break
  except (FileNotFoundError,ConnectionRefusedError):time.sleep(.01)
  finally:probe.close()
 else:raise RuntimeError('normal Unix listener never ready')
 for kind in ['c','rust']:
  args=[str(old_unix),str(endpoint),str(old_port),str(new_port)];argv=[str(caller),*args]if kind=='c'else[str(a.rust),*args,str(a.helper)];actor=subprocess.Popen(argv,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:stdout,stderr=actor.communicate(timeout=17)
  finally:
   if actor.poll()is None:actor.kill();actor.communicate(timeout=2)
  (out/(kind+'.stdout')).write_bytes(stdout);(out/(kind+'.stderr')).write_bytes(stderr)
  if actor.returncode:raise RuntimeError((kind,actor.returncode,stderr.decode()))
  events=[json.loads(line)for line in stdout.splitlines()];expected=[{'event':'port-updated'},{'event':'unix-updated'},{'event':'connection','status':1,'unix_updated':True},{'event':'list','status':0,'count':0,'unix_updated':True},{'event':'done','confirmed':1,'listed':1,'failed':0}]
  if events!=expected:raise ValueError((kind,'TCP cache/per-attempt Unix or original queued LIST differs',events))
  try:
   unexpected,_=fence.accept();unexpected.close();raise ValueError('cached TCP changed: actor connected to replacement TCP fence')
  except socket.timeout:pass
  rows.append({'actor':kind,'pid':actor.pid,'argv':argv,'exit_code':actor.returncode,'events':events})
 daemon.terminate();code=daemon.wait(timeout=5)
 if code!=0:raise ValueError(('normal owned daemon did not gracefully stop',code))
 after,normal_after=load(a.reference,a.source,a.repo)
 if ref!=after or normal!=normal_after or any(sha(path)!=value for path,value in inputs.items()):raise ValueError('source/library/binary changed')
 if list(base.iterdir()):raise ValueError('private empty base directory changed')
 document={'status':'passed','scope':'actual public C ARM CLIENT versus Rust live ClientHost, cached original TCP across PORT replacement and later Unix sampling, original queued TEST/LIST, actual normal zero-managed-service daemon responses; no global Resolver broker claim','actors':rows,'daemon_exit':code,'daemon_pid':daemon.pid,'normal_compilation':compilation,'inputs':inputs,'inputs_unchanged':True,'old_bound_nonlistener_port':old_port,'replacement_tcp_fence_port':new_port,'replacement_tcp_accepted':0,'actual_daemon_tcp_port':0,'server_config_sha256':sha(config),'isolation':{'explicit_config':str(config),'base':str(base),'base_entries':[],'system_services':False,'user_mode_only':True,'binary_sections':[],'actual_native_list_counts':[row['events'][3]['count']for row in rows],'loader_source':'configuration.c:3288-3380 overrides DATADIR/config.d with GNUNET_BASE_CONFIG, then parses only explicit filename; service.c:2128 uses explicit -c branch','enumeration_source':'gnunet-service-arm.c:1906 skips arm and sections without BINARY; system-mode disabled at2148-2186'}};(out/'result.json').write_text(json.dumps(document,indent=2)+'\n');print(json.dumps({'status':'passed','actors':2,'result':str(out/'result.json')}))
finally:
 if actor is not None and actor.poll()is None:actor.kill();actor.communicate(timeout=2)
 if daemon is not None and daemon.poll()is None:
  daemon.terminate()
  try:daemon.wait(timeout=5)
  except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=2)
 reservation.close();fence.close();log.close();err.close()
