#!/usr/bin/env python3
"""Normal unchanged CLI versus real Rust CLI, owned literal Unix peer only.
No source shim, public network, account change, or user-directory deletion.
"""
import argparse,hashlib,json,os,selectors,socket,struct,subprocess,tempfile,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def result(request,value):return struct.pack('>HHIQI',24,10,0,request,value)+bytes(4)
def status(value,name):return struct.pack('>HHI',9+len(name),11,value)+name+b'\0'
def listing(request,rows):
 pool=bytearray();entries=bytearray()
 for name,binary,state,exit,restart in rows:
  a=len(pool);pool.extend(name+b'\0');b=len(pool);pool.extend(binary+b'\0');entries.extend(struct.pack('>HHHHIQQ',a,b,exit,0,state,restart,0))
 return struct.pack('>HHIQH',24+len(entries)+len(pool),13,0,request,len(rows))+bytes(6)+entries+pool
ROWS=[(b'stop',b'bn',0,0,0),(b'run',b'bn',1,0,0),(b'bad',b'bn',2,65535,0),(b'done',b'bn',3,0,0),(b'going',b'bn',4,0,0),(b'future\xff',b'bn',99,0,0),(b'forever',b'bn',2,9,2**64-1)]
def execute(binary,profile,environment,destination):
 destination.mkdir();config=destination/'arm.conf';wire=[];peers=[];selector=selectors.DefaultSelector();proc=None;listener=None
 with tempfile.TemporaryDirectory(prefix='gacli-')as owned:
  owned=Path(owned);endpoint=owned/'s';home=owned/'home';home.mkdir();marker=home/'marker';marker.write_bytes(b'owned test only')
  config.write_bytes(b'[PATHS]\nGNUNET_HOME = '+os.fsencode(home)+b'\n[arm]\nUNIXPATH = '+os.fsencode(endpoint)+b'\n[TESTING]\nWEAKRANDOM = YES\n')
  if not profile.get('absent'):
   listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(endpoint));listener.listen(16);listener.setblocking(False);selector.register(listener,selectors.EVENT_READ,None)
  env=environment.copy();env['HOME']=str(owned/'isolated-user-home');env['XDG_CONFIG_HOME']=str(owned/'isolated-xdg');env['GNUNET_ARGS']=profile.get('environment_args','')
  args=[b'gnunet-arm',b'-c',os.fsencode(config),b'-L',b'ERROR']+[os.fsencode(arg)for arg in profile['args']]
  try:
   proc=subprocess.Popen(args,executable=os.fsencode(binary),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=owned)
   deadline=time.monotonic()+4
   while proc.poll()is None:
    if time.monotonic()>deadline:raise RuntimeError('CLI watchdog expired '+profile['name'])
    for key,_ in selector.select(0.005):
     if key.fileobj is listener:
      conn,_=listener.accept();conn.setblocking(False);peer={'socket':conn,'rx':bytearray(),'index':len(peers)};peers.append(peer);selector.register(conn,selectors.EVENT_READ,peer);continue
     peer=key.data;conn=peer['socket']
     try:data=conn.recv(65535)
     except BlockingIOError:continue
     if not data:selector.unregister(conn);conn.close();continue
     peer['rx'].extend(data)
     while len(peer['rx'])>=4:
      n,kind=struct.unpack('>HH',peer['rx'][:4])
      if n<4:raise ValueError('invalid actor framing')
      if len(peer['rx'])<n:break
      frame=bytes(peer['rx'][:n]);del peer['rx'][:n];entry={'peer':peer['index'],'type':kind,'hex':frame.hex()};wire.append(entry)
      if kind==15:conn.sendall(frame)
      elif kind==14:conn.sendall(status(0,b'arm')+status(2,b'svc')+status(1,b'svc')+status(0x10111213,b'future'))
      elif kind in (8,9):
       request=struct.unpack('>Q',frame[8:16])[0];name=frame[16:].split(b'\0',1)[0];entry.update(id=request,name_hex=name.hex())
       if profile.get('blackhole'):continue
       if profile.get('disconnect'):conn.shutdown(socket.SHUT_WR);continue
       value=profile.get('start_result',2)if kind==8 else profile.get('stop_result',0)
       conn.sendall(result(request,value))
       if kind==9 and name==b'arm' and value==1:conn.shutdown(socket.SHUT_WR)
      elif kind==12:
       if profile.get('disconnect'):conn.shutdown(socket.SHUT_WR)
       else:conn.sendall(listing(struct.unpack('>Q',frame[8:16])[0],[]if profile.get('empty')else ROWS))
      else:raise ValueError('unexpected message type '+str(kind))
   stdout,stderr=proc.communicate(timeout=1)
   observation={'exit':proc.returncode,'stdout_hex':stdout.hex(),'stderr_hex':stderr.hex(),'logical_actions':[{'type':row['type'],'name_hex':row.get('name_hex')}for row in wire if row['type']in(8,9,12)],'action_frames_hex':[row['hex']for row in wire if row['type']in(8,9,12)],'config_exists':config.exists(),'home_exists':home.exists(),'marker_exists':marker.exists()}
   (destination/'stdout').write_bytes(stdout);(destination/'stderr').write_bytes(stderr);save(destination/'wire.json',wire);save(destination/'observation.json',observation)
   return observation
  finally:
   if proc is not None and proc.poll()is None:proc.kill();proc.communicate(timeout=2)
   for peer in peers:peer['socket'].close()
   if listener is not None:listener.close()
   selector.close()
def profiles():
 rows=[]
 def add(name,args,**rest):rows.append(dict(name=name,args=args,**rest))
 for value in (*range(10),123):add('start-result-'+str(value),['-i','svc'],start_result=value)
 add('start-disconnected',['-i','svc'],disconnect=True)
 for value in (*range(10),123):add('kill-result-'+str(value),['-k','svc'],stop_result=value)
 add('kill-disconnected',['-k','svc'],disconnect=True)
 for value in (*range(10),123):add('end-result-'+str(value),['-e'],stop_result=value)
 add('end-disconnected',['-e'],disconnect=True)
 for flags,name in [(['-I'],'list'),(['-aI'],'list-all'),(['-qI'],'list-quiet'),(['-qaI'],'list-all-quiet')]:add(name,flags)
 add('empty-list',['-I'],empty=True);add('list-disconnected',['-I'],disconnect=True)
 for flags,name in [(['-i','svc'],'absent-init'),(['-k','svc'],'absent-kill'),(['-I'],'absent-list'),(['-e'],'absent-end'),(['-s'],'absent-start-unknown'),(['-r'],'absent-restart-unknown')]:add(name,flags,absent=True)
 add('timeout',['-i','svc','-T','30ms'],blackhole=True)
 add('monitor',['-m','-T','60ms']);add('monitor-quiet',['-qm','-T','60ms'])
 add('kill-init-list-monitor',['-k','old','-i','new','-I','-m','-T','80ms'])
 add('end-delete-success-cleared',['-ed'],stop_result=6)
 add('end-delete-absent-removes-owned',['-ed'],absent=True)
 add('non-utf8-service',['-i',b'svc\xff'])
 add('appended-args-last-value',['-i','old'],environment_args='-i svc -I')
 return rows

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--reference',type=Path,required=True);ap.add_argument('--rust',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args();out=args.output.resolve();out.mkdir(exist_ok=False,parents=True)
 receipt=json.loads(args.reference.read_text());normal=Path(receipt['artifacts']['client']['path']);assert sha(normal)==receipt['artifacts']['client']['sha256'];environment={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};environment.update(receipt['runtime_environment']);environment['LC_ALL']='C';defaults=out/'empty-defaults';defaults.mkdir();environment['GNUNET_BASE_CONFIG']=str(defaults)
 rows=[]
 try:
  for profile in profiles():
   directory=out/profile['name'];directory.mkdir();c=execute(normal,profile,environment,directory/'c');rust=execute(args.rust,profile,environment,directory/'rust');same=c==rust
   rows.append({'profile':{**profile,'args':[os.fsencode(a).hex()for a in profile['args']]},'matched':same,'c':c,'rust':rust})
   save(out/'progress.json',rows)
   if not same:raise ValueError('actual CLI mismatch '+profile['name'])
  result={'status':'passed','scope':'actual normal unmodified CLI and actual Rust CLI with owned literal Unix peer; not real daemon/completePROGRAM proof','profiles':len(rows),'actual_processes':2*len(rows),'rows':rows,'normal_cli_sha256':sha(normal),'rust_cli_sha256':sha(args.rust),'only_owned_tmp_deletion':True}
 except Exception as error:result={'status':'failed','error':str(error),'rows':rows};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'profiles':len(rows),'result':str(out/'result.json')}))
if __name__=='__main__':main()
