#!/usr/bin/env python3
"""Owned short Unix peer with literal valid official ABI8 messages only."""
import argparse,hashlib,json,os,selectors,socket,struct,subprocess,tempfile,time,shlex
from pathlib import Path
HERE=Path(__file__).resolve().parent
from reference import load
REPOSITORY=None
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--repo',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--reference',type=Path,required=True);ap.add_argument('--observer',type=Path,required=True);ap.add_argument('--actor',choices=['c','rust'],default='c');ap.add_argument('--nonzero-padding',action='store_true');ap.add_argument('--unknown-types',action='store_true');args=ap.parse_args();out=args.output.resolve();REPOSITORY=args.repo.resolve();REFERENCE=args.reference.resolve();observer=args.observer.resolve();assert not out.is_relative_to(REPOSITORY) and not REPOSITORY.is_relative_to(out),'output and source must be disjoint';out.mkdir(parents=True,exist_ok=False);ref,normal_inputs=load(REFERENCE,args.source,args.repo)
 inputs={**normal_inputs,str(HERE/'reference.py'):sha(HERE/'reference.py'),str(REFERENCE):sha(REFERENCE),str(HERE/'normal_owner.c'):sha(HERE/'normal_owner.c'),str(Path(__file__)):sha(Path(__file__)),str(observer):sha(observer)}
 for lib in ref['libraries']:inputs[lib['path']]=sha(Path(lib['path']));assert inputs[lib['path']]==lib['sha256']
 prefix=Path(ref['prefix']);db=json.loads(Path(ref['compile_commands']['path']).read_text());entry=next(e for e in db if e['file'].endswith('/arm_api.c'));original=entry.get('arguments')or shlex.split(entry['command']);compiler=[];skip=False
 for a in original:
  if skip:skip=False;continue
  if a in ['-MQ','-MF','-o']:skip=True;continue
  if a in ['-MD','-c']or a.endswith('/arm_api.c'):continue
  compiler.append(a)
 compiler +=[str(HERE/'normal_owner.c'),'-L'+str(prefix/'lib'),'-lgnunetarm','-lgnunetutil','-Wl,-rpath,'+str(prefix/'lib'),'-o',str(out/'normal-owner')]
 comp=subprocess.run(compiler,cwd=entry['directory'],stdout=subprocess.PIPE,stderr=subprocess.PIPE);(out/'compile.stdout').write_bytes(comp.stdout);(out/'compile.stderr').write_bytes(comp.stderr);assert comp.returncode==0,comp.stderr.decode()
 env=os.environ.copy();env.update(ref['runtime_environment']);wire=[];sent=[];peers=[];sel=selectors.DefaultSelector();child=None;stop_seen=False
 def result(id,r):return struct.pack('>HHIQI',24,10,0,id,r)+(b'\xa5'if args.nonzero_padding else b'\0')*4
 def status(s,name):return struct.pack('>HHI',9+len(name),11,s)+name+b'\0'
 def listing(id):
  info=struct.pack('>HHhHIQQ',0,4,-1,0xa5a5 if args.nonzero_padding else 0,2,9,10);pool=b'svc\0bn\0';return struct.pack('>HHIQH',24+len(info)+len(pool),13,0,id,1)+(b'\xa5'if args.nonzero_padding else b'\0')*6+info+pool
 def send(state,data):
  remaining=data
  while remaining:
   n,t=struct.unpack('>HH',remaining[:4]);assert 4<=n<=len(remaining);sent.append({'peer':state['index'],'type':t,'hex':remaining[:n].hex()});remaining=remaining[n:]
  state['socket'].sendall(data)
 actor_path=out/'normal-owner'
 if args.actor=='rust':actor_path=observer
 actor_digest=sha(actor_path)
 with tempfile.TemporaryDirectory(prefix='garm-')as temporary:
  endpoint=str(Path(temporary)/'p.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(endpoint);listener.listen(8);listener.setblocking(False);sel.register(listener,selectors.EVENT_READ,None)
  try:
   child=subprocess.Popen([str(actor_path),endpoint],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=temporary);deadline=time.monotonic()+8
   while child.poll()is None:
    if time.monotonic()>deadline:raise RuntimeError('public owner probe timed out')
    for key,_ in sel.select(0.05):
     if key.fileobj is listener:
      conn,_=listener.accept();conn.setblocking(False);state={'socket':conn,'rx':bytearray(),'index':len(peers)};peers.append(state);sel.register(conn,selectors.EVENT_READ,state);continue
     state=key.data;conn=state['socket']
     try:data=conn.recv(65535)
     except BlockingIOError:continue
     if not data:sel.unregister(conn);conn.close();continue
     state['rx'].extend(data)
     while len(state['rx'])>=4:
      n,t=struct.unpack('>HH',state['rx'][:4]);assert 4<=n<=65535
      if len(state['rx'])<n:break
      b=bytes(state['rx'][:n]);del state['rx'][:n];entry={'peer':state['index'],'type':t,'hex':b.hex()};wire.append(entry)
      if t==15:
       assert n==4
       if not stop_seen:send(state,(struct.pack('>HH',4,65000)+struct.pack('>HH',4,11)if args.unknown_types else b'')+b)
      elif t==14:
       assert n==4;send(state,(struct.pack('>HH',4,65000)+struct.pack('>HH',4,10)if args.unknown_types else b'')+status(0,b'arm')+status(2,b'svc')+status(1,b'svc')+status(0x10111213,b'future'))
      elif t in [8,9]:
       assert n>=17 and b[-1]==0;id=struct.unpack('>Q',b[8:16])[0];name=b[16:].split(b'\0',1)[0];entry.update(id=id,name=name.decode())
       if t==8:assert name==b'svc';send(state,result(id,2))
       elif name in [b'svc',b'cancel']:send(state,result(id,0))
       elif name==b'arm':send(state,result(id,1));conn.shutdown(socket.SHUT_WR);stop_seen=True
       else:raise RuntimeError('unexpected service '+repr(name))
      elif t==12:assert n==16;send(state,listing(struct.unpack('>Q',b[8:16])[0]))
      else:raise RuntimeError('unexpected type '+str(t))
   stdout,stderr=child.communicate(timeout=1);(out/'wire.json').write_text(json.dumps(wire,indent=2)+'\n');(out/'peer_sent.json').write_text(json.dumps(sent,indent=2)+'\n');(out/'owner.stdout').write_bytes(stdout);(out/'owner.stderr').write_bytes(stderr);assert child.returncode==0,(child.returncode,stdout.decode(),stderr.decode())
  finally:
   if child is not None and child.poll()is None:child.kill();child.communicate()
   for s in peers:s['socket'].close()
   listener.close();sel.close()
 events=[json.loads(l)for l in stdout.decode().splitlines()];names=[x['event']for x in events];assert not any(n in names for n in ['watchdog','canceled_callback','monitor_unavailable']);done=next(x for x in events if x['event']=='done');assert done=={'event':'done','failed':0,'monitor_count':4,'repeat':1,'stopped':1}
 for name,r in [('start_service',2),('stop_service',0),('local_arm_already',5),('stop_arm',0)]:assert next(x for x in events if x['event']==name)=={'event':name,'rs':0,'result':r}
 assert next(x for x in events if x['event']=='list')=={'event':'list','rs':0,'count':1,'name':'svc','binary':'bn','status':2,'exit':65535,'restart':9,'last_start':10}
 assert [x['status']for x in events if x['event']=='monitor']==[0,2,1,0x10111213]
 assert [(x['type'],x.get('id'),x.get('name'))for x in wire if x['type']in [8,9,12]]==[(8,1,'svc'),(9,2,'svc'),(12,None,None),(9,4,'cancel'),(9,5,'arm')]
 assert names.index('local_arm_already')<names.index('stop_arm')<max(i for i,n in enumerate(names)if n=='connection')
 (out/'wire.json').write_text(json.dumps(wire,indent=2)+'\n');(out/'events.json').write_text(json.dumps(events,indent=2)+'\n')
 after,after_inputs=load(REFERENCE,args.source,args.repo);assert ref==after and normal_inputs==after_inputs,'normal source/build commitment changed'
 assert sha(actor_path)==actor_digest,'executed artifact changed'
 assert all(sha(Path(p))==h for p,h in inputs.items()),'normal source/library changed'
 result={'success':True,'scope':'Owned literal Unix peer against actual '+args.actor+' observer; public C API8 functions only in C actor, no daemon/native spawn claim','actor':args.actor,'nonzero_padding':args.nonzero_padding,'unknown_types':args.unknown_types,'executed_actor':str(actor_path),'executed_actor_sha256':actor_digest,'compiler_argv':compiler,'compiler_exit':comp.returncode,'owner_exit':child.returncode,'public_functions_called':(['GNUNET_ARM_connect','GNUNET_ARM_disconnect','GNUNET_ARM_operation_cancel','GNUNET_ARM_request_service_list','GNUNET_ARM_request_service_stop','GNUNET_ARM_request_service_start','GNUNET_ARM_monitor_start','GNUNET_ARM_monitor_stop']if args.actor=='c'else[]),'events':len(events),'wire_frames':len(wire),'source_unchanged':True,'input_sha256':inputs,'managed_GNUnet_process_started':False,'C_UB_paths_tested':False,'only_self_owned_Unix_endpoint':True,'all_sockets_cleaned':True,'artifacts':{p.name:sha(p)for p in sorted(out.iterdir())if p.is_file()}}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'success':True,'events':len(events),'wire_frames':len(wire),'result':str(out/'result.json')}))
if __name__=='__main__':main()
