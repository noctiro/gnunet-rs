#!/usr/bin/env python3
"""Owned normal GNUnet STATISTICS daemon EMFILE suspension observations."""
import argparse,hashlib,json,os,pathlib,resource,shutil,signal,socket,subprocess,sys,tempfile,time
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
GET=bytes.fromhex('000800a973006e00');END=bytes.fromhex('000400ab')
def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def read_exact(sock,n):
 out=b''
 while len(out)<n:
  chunk=sock.recv(n-len(out))
  if not chunk:return out
  out+=chunk
 return out

def connect(kind,path,port):
 peer=socket.socket(socket.AF_UNIX if kind=='unix'else socket.AF_INET,socket.SOCK_STREAM);peer.settimeout(2)
 try:peer.connect(str(path)if kind=='unix'else('127.0.0.1',port));return peer
 except BaseException:peer.close();raise

def get(peer):peer.sendall(GET);return read_exact(peer,4)

def profile(binary,env,output,fill_kind,language="c"):
 directory=pathlib.Path(tempfile.mkdtemp(prefix='gemfile-'));directory.chmod(0o700)
 for name in ['base','home','config','data','cache','runtime']:(directory/name).mkdir(mode=0o700)
 local=directory/'s';conf=directory/'c';reserve=socket.socket();reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1];reserve.close()
 conf.write_text('[statistics]\nUNIXPATH = '+str(local)+'\nHOSTNAME = 127.0.0.1\nBINDTO = 127.0.0.1\nPORT = '+str(port)+'\nDISABLEV6 = YES\n')
 child_env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};child_env.update(env,LC_ALL='C',GNUNET_BASE_CONFIG=str(directory/'base'),HOME=str(directory/'home'),XDG_CONFIG_HOME=str(directory/'config'),XDG_DATA_HOME=str(directory/'data'),XDG_CACHE_HOME=str(directory/'cache'),XDG_RUNTIME_DIR=str(directory/'runtime'))
 label='fill-'+fill_kind;logs=[(output/(label+'.stdout')).open('wb'),(output/(label+'.stderr')).open('wb')];owned=[];queued=None;trigger=None;process=None;events=[];row={'profile':label,'language':language,'events':events,'scope':'Unmodified normal C daemon process'if language=='c'else'Actual Rust high-capacity STATISTICS component using the public shared host, not the production app configuration/default capacity.'}
 began=time.monotonic()
 def event(kind,**kw):events.append({'kind':kind,'elapsed':round(time.monotonic()-began,6),**kw})
 try:
  argv=[str(binary),'-c',str(conf),'-L','DEBUG'];process=subprocess.Popen(argv,env=child_env,stdin=subprocess.PIPE if language=="rust"else subprocess.DEVNULL,stdout=logs[0],stderr=logs[1]);row.update(argv=argv,pid=process.pid,configuration=conf.read_text(),environment={k:child_env[k]for k in ['GNUNET_BASE_CONFIG','HOME','XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_CACHE_HOME','XDG_RUNTIME_DIR']})
  until=time.monotonic()+5
  while not local.exists():
   assert process.poll()is None,'daemon exited before Unix path';assert time.monotonic()<until,'daemon readiness';time.sleep(.01)
  event('path-created')
  for i in range(1100):
   assert time.monotonic()-began<15,'bounded fill deadline'
   peer=connect(fill_kind,local,port);owned.append(peer)
   try:reply=get(peer)
   except (ConnectionResetError,BrokenPipeError)as e:reply=b'';event('trigger-reset',errno=e.errno)
   if reply!=END:
    assert reply==b'',('unexpected official reply',reply.hex());trigger=owned.pop();event('unadmitted-trigger-eof',admitted=len(owned));break
  else:raise AssertionError('native fixed FD cap not reached within 1100 owned sockets')
  assert 980<len(owned)<1024,len(owned)
  snap=subprocess.run(['/usr/sbin/lsof','-nP','-a','-p',str(process.pid),'-Ff'],capture_output=True,timeout=3);(output/(label+'.lsof')).write_bytes(snap.stdout);assert snap.returncode==0,snap.stderr
  fds=[int(line[1:])for line in snap.stdout.decode().splitlines()if line.startswith('f')and line[1:].isdigit()];assert max(fds)==1023,(len(fds),max(fds));event('native-cap-snapshot',numeric_fd_count=len(fds),max_numeric_fd=max(fds))
  opposite='tcp'if fill_kind=='unix'else'unix';queued=connect(opposite,local,port);queued.sendall(GET);queued.settimeout(.35)
  try:reply=queued.recv(4)
  except socket.timeout:reply=None
  assert reply is None,('other listener was not suspended',reply)
  event('other-listener-pending',listener=opposite)
  assert get(owned[0])==END;event('original-admitted-client-still-served')
  trigger.close();trigger=None;queued.settimeout(.65)
  try:reply=queued.recv(4)
  except socket.timeout:reply=None
  assert reply is None,('timer/unadmitted-close resumed listener',reply)
  event('still-pending-after-unadmitted-close-and-one-second-total')
  peer=owned.pop()
  try:peer.shutdown(socket.SHUT_RDWR)
  finally:peer.close()
  event('original-admitted-client-physically-closed')
  queued.settimeout(2);assert read_exact(queued,4)==END;event('opposite-listener-resumed-with-official-end',listener=opposite)
  assert get(owned[0])==END;event('original-client-remains-valid-after-resume')
  queued.close();queued=None
  while owned:owned.pop().close()
  if language=='rust':process.stdin.write(b'x');process.stdin.close()
  else:process.send_signal(signal.SIGTERM)
  process.wait(timeout=5);assert process.returncode==0,process.returncode;event('daemon-exited',exit_code=process.returncode)
  row.update(status='passed',admitted_count=next(e['admitted']for e in events if e['kind']=='unadmitted-trigger-eof'),fixed_fd_cap=1024,exit_code=process.returncode)
  return row
 finally:
  if trigger is not None:trigger.close()
  if queued is not None:queued.close()
  while owned:owned.pop().close()
  if process is not None and process.poll()is None:
   try:process.send_signal(signal.SIGCONT)
   except ProcessLookupError:pass
   try:process.terminate()
   except ProcessLookupError:pass
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:process.kill();process.wait();row['forced_kill_cleanup']=True
  for log in logs:log.close()
  shutil.rmtree(directory);row['runtime_removed']=not directory.exists();(output/(label+'.json')).write_text(json.dumps(row,indent=2)+'\n')

def main():
 p=argparse.ArgumentParser();p.add_argument('--receipt',type=pathlib.Path,required=True);p.add_argument('--reference-helper',type=pathlib.Path,required=True);p.add_argument('--repo',type=pathlib.Path,required=True);p.add_argument('--rust-binary',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.output=a.output.resolve()
 for protected in [a.repo,a.receipt.parent,a.reference_helper.parent,a.rust_binary.parent]:
  protected=protected.resolve();assert not a.output.is_relative_to(protected)and not protected.is_relative_to(a.output),'output overlaps input'
 a.output.mkdir(exist_ok=False,parents=True);sys.dont_write_bytecode=True;sys.path.insert(0,str(a.reference_helper.resolve().parent));from build_reference import source_state
 receipt=json.loads(a.receipt.read_text());source=pathlib.Path(receipt['source']);assert receipt['status']=='passed'and receipt['source_unchanged']and receipt['upstream']['revision']==PIN;before=source_state(source);assert before==receipt['upstream'];inputs={}
 for row in [*receipt['artifacts'].values(),*receipt['libraries'],*receipt['default_configurations'],receipt['generated_config']]:assert sha(row['path'])==row['sha256'],row['path'];inputs[row['path']]=row['sha256']
 for path in [a.receipt,a.reference_helper,a.rust_binary,pathlib.Path(__file__).resolve(),source/'src/lib/util/service.c',source/'src/lib/util/network.c',source/'src/service/statistics/gnunet-service-statistics.c']:inputs[str(path.resolve())]=sha(path)
 # Include every local workspace source/test/fixture/tool and manifest in the
 # candidate closure; do not depend on a live Root path while actors execute.
 def discover():
  files={}
  for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','rustfmt.toml','.cargo/config.toml']:
   path=a.repo/name
   if path.is_file():files[str(path.resolve())]=sha(path)
  for directory in ['crates','adapters','apps']:
   for path in(a.repo/directory).rglob('*'):
    if path.is_file()and '__pycache__'not in path.parts and 'target'not in path.parts:files[str(path.resolve())]=sha(path)
  return files
 local_before=discover();assert local_before;inputs.update(local_before)
 binary=pathlib.Path(receipt['artifacts']['service']['path']);limits=resource.getrlimit(resource.RLIMIT_NOFILE);assert limits[0]>8192,limits
 result={'status':'failed','scope':'Paired real unmodified normal C STATISTICS daemon and actual Rust high-capacity public STATISTICS host component, not production Rust app or whole service/owner acceptance.','inputs':inputs,'parent_inherited_rlimit_nofile':list(limits),'upstream':before,'profiles':[]}
 try:
  for language,actor in [('c',binary),('rust',a.rust_binary)]:
   output=a.output/language;output.mkdir()
   for kind in ['unix','tcp']:result['profiles'].append(profile(actor,receipt['runtime_environment'],output,kind,language))
  expected=['path-created','unadmitted-trigger-eof','native-cap-snapshot','other-listener-pending','original-admitted-client-still-served','still-pending-after-unadmitted-close-and-one-second-total','original-admitted-client-physically-closed','opposite-listener-resumed-with-official-end','original-client-remains-valid-after-resume','daemon-exited']
  result['comparisons']=[]
  for kind in ['unix','tcp']:
   pair=[row for row in result['profiles']if row['profile']=='fill-'+kind];assert len(pair)==2
   for row in pair:
    kinds=[event['kind']for event in row['events']if event['kind']!='trigger-reset'];assert kinds==expected,kinds;assert row['status']=='passed'and row['exit_code']==0 and row['runtime_removed']
   rust=next(row for row in pair if row['language']=='rust');stdout=(a.output/'rust'/('fill-'+kind+'.stdout')).read_text().splitlines();failures=[line for line in stdout if line.startswith('SOCKET_FAILED|')];assert len(failures)==1 and failures[0].startswith('SOCKET_FAILED|24|'),failures
   reports=[line for line in stdout if line.startswith('REPORT|')];assert len(reports)==1;values=list(map(int,reports[0].split('|')[1:]));count=rust['admitted_count'];assert values==[count+2,count+1,1,count+1],values
   result['comparisons'].append({'profile':kind,'status':'matched source EMFILE suspend/resume event graph','C_admitted_before_cap':pair[0]['admitted_count'],'Rust_admitted_before_cap':rust['admitted_count'],'Rust_actual_socket_failures':failures,'Rust_actual_final_report':values,'fd_count_note':'Different runtime baseline descriptors make admitted counts representation-dependent. Both actual original processes reached 1024 numeric descriptors/max1023; no equal-admitted-count claim.'})
  result['inputs_unchanged']=all(sha(path)==digest for path,digest in inputs.items());result['local_file_set_unchanged']=discover()==local_before;result['source_unchanged']=source_state(source)==before;assert result['inputs_unchanged']and result['local_file_set_unchanged']and result['source_unchanged'];assert len(result['profiles'])==4;result['status']='passed'
 except Exception as error:result['failure']=type(error).__name__+': '+str(error);raise
 finally:(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'result':str(a.output/'result.json')}))
if __name__=='__main__':main()
