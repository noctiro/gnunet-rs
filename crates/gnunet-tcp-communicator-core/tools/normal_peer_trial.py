#!/usr/bin/env python3
"""Development actual normal peer trial. All daemon binaries/C sources unchanged."""
import argparse,hashlib,importlib.util,json,os,shlex,signal,subprocess,sys,time
from pathlib import Path
from session_inputs import TOOLS, Commands, Inputs, require_processes, require, same
sys.dont_write_bytecode=True
BASE=TOOLS
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser()
 for k in ['repository','source','reference','output','rust']:p.add_argument('--'+k,type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();guard=Inputs(a.repository,a.source,a.reference,out,'unmodified-official-c-tcp-peer-services-reference-build');out.mkdir(mode=0o700,exist_ok=False);normal=guard.reference.normal
 module=guard.reference.module
 fresh_artifacts={str(a.rust.resolve()):sha(a.rust)};before=guard.discover();before[str(a.rust.resolve())]=sha(a.rust);(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
 entry=next(r for r in json.loads(Path(normal['compile_commands']['path']).read_text())if r['file'].endswith('/transport_api_application.c'));original=entry.get('arguments')or shlex.split(entry['command']);flags=[];i=1
 while i<len(original):
  x=original[i]
  if x in ['-o','-MF','-MT','-MQ']:i+=2;continue
  if x in ['-c','-MD','-MMD']or x.endswith('/transport_api_application.c'):i+=1;continue
  flags.append(x);i+=1
 binary=out/'request';env=os.environ.copy();env.update(normal['runtime_environment']);prefix=Path(normal['prefix']);env['LTDL_LIBRARY_PATH']=str(prefix/'lib');base=out/'base';base.mkdir();env['GNUNET_BASE_CONFIG']=str(base);env['GNUNET_USER_CONFIG']=str(out/'unused-user.conf');home=out/'home';home.mkdir(mode=0o700);env.update(HOME=str(home),XDG_CONFIG_HOME=str(home),XDG_DATA_HOME=str(home),XDG_CACHE_HOME=str(home),XDG_RUNTIME_DIR=str(home));command=[original[0],*flags,str(TOOLS/'request_peer.c'),*shlex.split(normal['build_environment']['LDFLAGS']),'-L'+str(prefix/'lib'),'-lgnunettransportapplication','-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',str(binary)];compiler=Commands(out,Path(a.repository).resolve(),env);compiler.compile_c('compile',command,entry['directory']);fresh_artifacts[str(binary.resolve())]=sha(binary)
 roundtrip=out/'roundtrip';compile_round=[*command];compile_round=[str(TOOLS/'transport_roundtrip.c')if x==str(TOOLS/'request_peer.c')else str(roundtrip)if x==str(binary)else x for x in compile_round];compile_round[compile_round.index('-lgnunettransportapplication')]='-lgnunettransportcore';compile_round.insert(compile_round.index('-lgnunetutil'),'-lgnunetpeerstore');compiler.compile_c('roundtrip-compile',compile_round,entry['directory']);fresh_artifacts[str(roundtrip.resolve())]=sha(roundtrip)
 policy=out/'local.sb';policy.write_text('(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n(allow network-outbound (remote ip "localhost:*"))\n')
 # sandbox-exec is SIP protected; restore exact declared runtime env after it.
 prefix_cmd=['/usr/bin/sandbox-exec','-f',str(policy),'/usr/bin/env',*[k+'='+v for k,v in env.items()if k in normal['runtime_environment']or k=='LTDL_LIBRARY_PATH']]
 processes=[];logs=[];observations={'normal_reference':{'path':str(a.reference.resolve()),'sha256':sha(a.reference)},'compile_commands':[command,compile_round],'candidate_clock_profile':'ordinary SystemTime scheduling with process-local strictly increasing fixture stamps; configured persisted monotime remains pending','full_communicator_or_core_verified':False};stopped_databases=set();executables={}
 def launch(label,argv,localenv):
  guard.reference.check();original=Path(argv[0]).resolve();require(str(original)not in fresh_artifacts or sha(original)==fresh_artifacts[str(original)],'fresh compiler artifact changed before process');executables[label]={'path':str(original),'binary_sha256':sha(original),'argv':list(map(str,argv))};stdout=(out/(label+'.stdout')).open('wb');stderr=(out/(label+'.stderr')).open('wb');logs.extend([stdout,stderr]);p=subprocess.Popen(prefix_cmd+list(map(str,argv)),env=localenv,stdout=stdout,stderr=stderr);processes.append((label,p));return p
 def wait_file(path,proc=None):
  end=time.monotonic()+8
  while time.monotonic()<end:
   if path.exists():return
   if proc is not None and proc.poll()is not None:raise RuntimeError('process exited before '+str(path))
   time.sleep(.02)
  raise RuntimeError('timeout '+str(path))
 def stop_databases():
  for label,proc in processes:
   if not label.endswith('-peerstore')or proc.poll()is not None or label in stopped_databases:continue
   db=out/label[0]/'peerstore.db'
   check=['/usr/sbin/lsof','-a','-p',str(proc.pid),'--',str(db)]
   before=subprocess.run(check,capture_output=True);observations[label+'-database-open-before-stop']=before.returncode==0
   proc.send_signal(signal.SIGTERM)
   # Source shutdown_task clears every monitor BEFORE unloading/closing SQLite.
   # Observe that real owned DB descriptor close; no client is stopped before it.
   end=time.monotonic()+4;closed=False
   while time.monotonic()<end:
    if proc.poll()is not None:closed=proc.returncode==0;break
    after=subprocess.run(check,capture_output=True)
    if before.returncode==0 and after.returncode==1:closed=True;break
    time.sleep(.03)
   observations[label+'-database-closed-before-client-stop']=closed
   if closed:stopped_databases.add(label)
   if not closed:
    proc.kill();proc.wait();observations[label+'-forced-safe-cleanup']=True
    raise RuntimeError('cannot observe source monitor-clear boundary')
 try:
  cfgs={}
  for peer in ['a','b']:
   d=out/peer;d.mkdir(mode=0o700);(d/'home').mkdir();(d/'seed').write_bytes(bytes([11 if peer=='a'else 22])*32);os.chmod(d/'seed',0o600)
   lines=['[PATHS]',f'GNUNET_HOME = {d}',f'GNUNET_DATA_HOME = {d}',f'GNUNET_RUNTIME_DIR = {d}', '[PEER]',f'PRIVATE_KEY = {d}/seed','[util]',f'MONOTONIC_TIME_FILENAME = {d}/mono','[peerstore-sqlite]',f'FILENAME = {d}/peerstore.db']
   for service in ['statistics','pils','peerstore','nat','transport','core']:
    lines += ['['+service+']','HOSTNAME = localhost','PORT = 0','UNIXPATH = '+str(d/(service+'.sock')),'UNIX_MATCH_UID = NO','UNIX_MATCH_GID = NO']
    if service=='peerstore':lines += ['DATABASE = sqlite','USE_INCLUDED_HELLOS = NO']
    if service=='nat':lines += ['ENABLE_UPNP = NO','ENABLE_IPSCAN = NO','USE_STUN = NO','RETURN_LOCAL_ADDRESSES = YES','DISABLEV6 = YES']
    if service=='statistics':lines += ['DATABASE = '+str(d/'statistics.data')]
    if service=='transport':lines += ['USE_BURST_NAT = NO']
   lines += ['[communicator-tcp]','BINDTO = 127.0.0.1:0','DISABLE_V6 = YES','MAX_QUEUE_LENGTH = 8','REKEY_INTERVAL = 500 ms']
   cfg=d/'peer.conf';cfg.write_text('\n'.join(lines)+'\n');cfgs[peer]=cfg
   e=env.copy();e.update(HOME=str(d/'home'),XDG_CONFIG_HOME=str(d/'home'),XDG_DATA_HOME=str(d/'home'),XDG_CACHE_HOME=str(d/'home'),XDG_RUNTIME_DIR=str(d/'home'))
   for service in ['statistics','pils','peerstore','nat','transport']:
    child=launch(peer+'-'+service,[normal['artifacts'][service]['path'],'-c',cfg,'-L','DEBUG'],e);wait_file(d/(service+'.sock'),child)
  ready=out/'ready';rust=launch('rust-peer',[a.rust,out/'b/pils.sock',out/'b/peerstore.sock',out/'b/transport.sock',out/'b/seed',ready],env);wait_file(ready,rust);port,target=ready.read_text().splitlines();observations.update(rust_port=int(port),rust_identity=target)
  communicator=launch('a-communicator',[normal['artifacts']['communicator']['path'],'-c',cfgs['a'],'-L','DEBUG'],env)
  # Actual normal C PILS service and communicator must process their first update.
  time.sleep(.8)
  import socket,struct
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)as observer:
   observer.settimeout(3);observer.connect(str(out/'a/pils.sock'))
   def exact(n):
    b=b''
    while len(b)<n:
     part=observer.recv(n-len(b))
     if not part:raise RuntimeError('PILS EOF')
     b+=part
    return b
   header=exact(4);size,kind=struct.unpack('!HH',header);require(kind==1831 and size>=176,'actual PILS update layout');hello=header+exact(size-4);own_a=hello[72:104].hex()
  round_ready=out/'roundtrip-ready';round_caller=launch('public-roundtrip',[roundtrip,cfgs['a'],cfgs['b'],own_a,target,round_ready],env);wait_file(round_ready,round_caller)
  caller=launch('public-request',[binary,cfgs['a'],target,'tcp-127.0.0.1:'+port],env)
  caller.wait(timeout=12);observations['public_request_exit']=caller.returncode
  round_caller.wait(timeout=3);observations['roundtrip_exit']=round_caller.returncode
  rows=(out/'public-roundtrip.stdout').read_text().splitlines();payload=json.loads(next(x for x in rows if x.startswith('{')));require(payload['sent']==40 and payload['received_a']==payload['received_b']==payload['sent'] and payload['stored']==3 and payload['bad']==0,'actual TRANSPORT40/40/3/bad0 required');observations['actual_public_transport_roundtrip']=payload
  observations['profile']='Raw official TRANSPORT CoreHandle clients; no CORE daemons subscribe to the TEST-only fixture payload. Separate trial5 covers normal CORE-daemon incoming-neighbour notification, not CORE app encryption.'
  stop_databases()
  communicator.send_signal(signal.SIGTERM);communicator.wait(timeout=3)
  rust.wait(timeout=5);observations['rust_exit']=rust.returncode
  if rust.returncode!=0 or caller.returncode!=0:raise RuntimeError('actual normal peer trial failed')
 finally:
  # Cleanup must also avoid the now-known source monitor-disconnect NULL loop.
  if any(label.endswith('-peerstore')and proc.poll()is None for label,proc in processes):
   try:stop_databases()
   except BaseException as cleanup:observations['safe-cleanup-error']=str(cleanup)
  for label,proc in reversed(processes):
   if proc.poll()is None:proc.send_signal(signal.SIGTERM)
  for label,proc in reversed(processes):
   try:proc.wait(timeout=2)
   except subprocess.TimeoutExpired:proc.kill();proc.wait();observations[label+'-forced-cleanup']=True
  for f in logs:f.close()
  observations['processes']=[{'label':label,'pid':proc.pid,'exit':proc.returncode,**executables[label],'after_sha256':sha(executables[label]['path'])}for label,proc in processes]
  after=guard.discover();after[str(a.rust.resolve())]=sha(a.rust);(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n');observations['inputs_unchanged']=before==after and module.source_state(a.source)==normal['upstream'];(out/'observation.json').write_text(json.dumps(observations,indent=2)+'\n')
 require_processes(observations['processes']);compiler.check_artifacts();observations['actual_c_header_inputs']=compiler.headers;observations['actual_compiler_commands']=compiler.rows;require(all(sha(p)==h for p,h in fresh_artifacts.items()),'fresh compiler artifacts changed');observations['fresh_compiler_artifacts']=fresh_artifacts
 if not observations['inputs_unchanged']:raise RuntimeError('input identity changed')
 import sqlite3
 with sqlite3.connect('file:'+str(out/'b/peerstore.db')+'?mode=ro',uri=True)as db:
  rows=db.execute("SELECT key,value FROM peerstoredata WHERE sub_system='transport_tcp_communicator' AND peer_id=?",(bytes.fromhex(own_a),)).fetchall()
  observations['actual_rust_side_timestamp_store_rows']={key:bytes(value).hex()for key,value in rows}
 expected={'transport-tcp-communicator-handshake','transport-tcp-communicator-handshake-ack','transport-tcp-communicator-rekey'}
 if set(observations['actual_rust_side_timestamp_store_rows'])!=expected or any(len(v)!=16 or int(v,16)==0 for v in observations['actual_rust_side_timestamp_store_rows'].values()):raise RuntimeError('actual normal PEERSTORE replacement rows missing')
 log=(out/'a-communicator.stderr').read_text();observations['actual_normal_rekeys']={name:log.count(name)for name in ['inject_rekey','do_rekey']}
 if not all(observations['actual_normal_rekeys'].values()):raise RuntimeError('actual normal communicator rekey missing')
 rust_log=(out/'rust-peer.stdout').read_text()
 if 'observation established=true quiescent=true phase=Closed'not in rust_log:raise RuntimeError('original Rust session/callbacks not closed/quiescent')
 observations['status']='passed-normal-transport-peer-profile';observations['scope']='Actual unchanged normal C communicator to Rust inbound TCP session, normal PILS/PEERSTORE/NAT/STATISTICS/TRANSPORT, public TRANSPORT40 echo each direction and actual rekey. No CORE application encryption claim; separate historical CORE neighbour scope. Known upstream Peerstore disconnect crash remains unresolved; source-defined DB-close-before-client cleanup profile only.'
 (out/'observation.json').write_text(json.dumps(observations,indent=2)+'\n');print(json.dumps({'status':observations['status'],'receipt':str(out/'observation.json'),'sent':40}))
if __name__=='__main__':main()
