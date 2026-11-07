#!/usr/bin/env python3
"""Actual C public ARM versus Rust ClientHost, only defined-safe private peers.

The original normal library/source tree is read-only. Each actor owns a new Unix
connection. Raw request frames, sent bytes, callback order, EOF and actual exit
are retained per connection. No daemon/managed child or readiness is fabricated.
"""
import argparse,importlib.util,json,os,pathlib,socket,struct,subprocess,sys,time
PROFILES=('wrong-list-result','wrong-result-list','malformed-short-rows','malformed-name-index','malformed-binary-index','malformed-name-nul','malformed-binary-nul','malformed-second-name-index','malformed-second-binary-index','malformed-prefix','malformed-result','malformed-size3','valid-list','unknown-id-and-type')

def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 p.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1])
 p.add_argument('--rust',type=pathlib.Path,required=True)
 a=p.parse_args();package=a.package.resolve();support=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(support));from reference import load,compile_probe,sha
 from _common import local_snapshot,require_disjoint_output,require_lint_contract
 if len(PROFILES)!=14 or len(set(PROFILES))!=14:raise ValueError('exact nonempty 14 profile inventory required')
 ref,normal=load(a.reference,a.source,a.repo);cargo=['cargo','+1.99.1'];locked=['--offline','--locked','--manifest-path',str(package/'Cargo.toml')];environment=os.environ.copy();environment['CARGO_BUILD_JOBS']='2'
 meta=subprocess.run(cargo+['metadata',*locked,'--format-version','1'],cwd=package,env=environment,capture_output=True,timeout=120)
 if meta.returncode:raise RuntimeError(meta.stderr.decode())
 metadata=json.loads(meta.stdout);protected=[package,a.repo,a.source,a.reference.resolve().parent,support,pathlib.Path(ref['build']),pathlib.Path(ref['prefix'])]+[pathlib.Path(row['manifest_path']).parent for row in metadata['packages']if row['source']is None];out=require_disjoint_output(a.output,protected);out.mkdir();(out/'metadata.stdout').write_bytes(meta.stdout);(out/'metadata.stderr').write_bytes(meta.stderr)
 selected,inputs=local_snapshot(metadata,package,support);inputs[str(pathlib.Path(__file__).resolve())]=sha(__file__)
 result={'status':'failed','scope':'actual public libgnunetarm callbacks to private literal Unix peers versus actual Rust ClientHost, defined-safe wrong-kind/malformed-list branches only; not daemon/whole-owner evidence','owner_promotion':False,'inputs':inputs,'normal_inputs':normal,'commands':[],'cases':[]};binaries={};begin=time.monotonic()
 def run(label,argv):
  child=subprocess.run(list(map(str,argv)),cwd=package,env=environment,capture_output=True,timeout=180);(out/(label+'.stdout')).write_bytes(child.stdout);(out/(label+'.stderr')).write_bytes(child.stderr);result['commands'].append({'label':label,'argv':list(map(str,argv)),'exit_code':child.returncode})
  if child.returncode:raise RuntimeError(label+': '+child.stderr.decode()[-1800:])
 def arm_result(wid,code):return struct.pack('!HHIQI4x',24,10,0,wid,code)
 def arm_list(wid,count,rows=b'',pool=b''):
  return struct.pack('!HHIQH6x',24+len(rows)+len(pool),13,0,wid,count)+rows+pool
 def malformed(profile):
  name=bytearray(28);name[:2]=b'\0\2';binary=bytearray(28);binary[2:4]=b'\0\2';binary_nul=bytearray(28);binary_nul[2:4]=b'\0\1'
  return {'malformed-short-rows':arm_list(1,1),'malformed-name-index':arm_list(1,1,name,b'x\0'),'malformed-binary-index':arm_list(1,1,binary,b'x\0'),'malformed-name-nul':arm_list(1,1,bytes(28),b'x'),'malformed-binary-nul':arm_list(1,1,binary_nul,b'\0x'),'malformed-second-name-index':arm_list(1,2,bytes(28)+name,b'x\0'),'malformed-second-binary-index':arm_list(1,2,bytes(28)+binary,b'x\0'),'malformed-prefix':struct.pack('!HHIQH',18,13,0,1,0),'malformed-result':struct.pack('!HHIQI',20,10,0,1,3),'malformed-size3':b'\0\3\0\x0d'}[profile]
 def recv_frame(connection,records):
  def exact(n):
   data=b''
   while len(data)<n:
    part=connection.recv(n-len(data))
    if not part:raise ValueError('physical EOF before complete original request frame')
    data+=part
   return data
  header=exact(4);size,kind=struct.unpack('!HH',header)
  if not 4<=size<=65535:raise ValueError('invalid actual outbound frame')
  frame=header+exact(size-4);records.append({'event':'rx-frame','type':kind,'bytes':frame.hex()});return frame
 try:
  result['root_lint_contract']=require_lint_contract(package,a.repo,metadata)
  rust=a.rust.resolve();normal_actor=out/'normal-actor';result['normal_compilation']=compile_probe(package/'tools/negative_owner.c',normal_actor,ref);binaries={str(path):sha(path)for path in [rust,normal_actor]};result['executed_binaries']=dict(binaries)
  result['rust_build_provenance']='Caller-supplied executable: the encompassing verifier must bind its fresh build to this same source/dependency closure. This standalone comparator does not certify executable derivation.'
  base=out/'empty-base';base.mkdir();home=out/'home';home.mkdir();env={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_','ARM_'))};env.update(ref['runtime_environment'],GNUNET_BASE_CONFIG=str(base),HOME=str(home),XDG_CONFIG_HOME=str(home),LC_ALL='C')
  for index,profile in enumerate(PROFILES):
   observations={}
   for actor in ['c','rust']:
    endpoint=out/(str(index)+'-'+actor+'.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(endpoint));listener.listen(4);listener.settimeout(5);process=None;connection=None;records=[];extras=[]
    try:
     argv=[str(normal_actor if actor=='c'else rust),str(endpoint),profile];process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE);connection,_=listener.accept();connection.settimeout(5)
     test=recv_frame(connection,records)
     if test!=b'\0\4\0\x0f':raise ValueError('original TEST differs')
     connection.sendall(test);records.append({'event':'tx','purpose':'confirm','bytes':test.hex()})
     bad=recv_frame(connection,records);keep=recv_frame(connection,records)
     if struct.unpack('!Q',bad[8:16])[0]!=1 or struct.unpack('!Q',keep[8:16])[0]!=2 or keep[2:4]!=b'\0\x09' or keep[16:]!=b'keep\0':raise ValueError('actual original IDs/remote request differ')
     if profile=='wrong-result-list':
      if bad[2:4]!=b'\0\x08' or bad[16:]!=b'wrong\0':raise ValueError('expected original remote START')
      payload=arm_list(1,1,bytes(28),b'x\0')
     else:
      if bad[2:4]!=b'\0\x0c' or len(bad)!=16:raise ValueError('expected original LIST')
      if profile.startswith('malformed-'):payload=malformed(profile)
      elif profile=='wrong-list-result':payload=arm_result(1,42)
      elif profile=='unknown-id-and-type':payload=arm_result(999,123)+arm_list(999,1,bytes(28),b'x\0')+b'\0\4\xfe\xfd'+test+arm_list(1,1,bytes(28),b'x\0')
      else:payload=arm_list(1,1,bytes(28),b'x\0')
     payload+=arm_result(2,42);connection.sendall(payload);records.append({'event':'tx','purpose':profile+' plus surviving keep result','bytes':payload.hex()})
     while True:
      data=connection.recv(65536)
      if not data:records.append({'event':'eof'});break
      records.append({'event':'unexpected-rx','bytes':data.hex()})
     stdout,stderr=process.communicate(timeout=5);(out/(str(index)+'-'+actor+'.stdout')).write_bytes(stdout);(out/(str(index)+'-'+actor+'.stderr')).write_bytes(stderr)
     if process.returncode:raise RuntimeError((profile,actor,process.returncode,stderr.decode()))
     listener.settimeout(.01)
     while True:
      try:extra,_=listener.accept()
      except socket.timeout:break
      extra.settimeout(.1);observed=[]
      try:
       while True:
        part=extra.recv(65536)
        if not part:observed.append({'event':'eof'});break
        observed.append({'event':'rx-bytes','bytes':part.hex()})
      except socket.timeout:observed.append({'event':'read-timeout'})
      finally:extra.close()
      extras.append({'connection':len(extras)+1,'events':observed})
     events=[json.loads(line)for line in stdout.splitlines()]
     if profile.startswith('malformed-'):expected=[{'event':'connection','status':1},{'event':'bad-list','status':2,'count':0},{'event':'keep','status':2,'result':0},{'event':'connection','status':0},{'event':'done','bad':1,'keep':1,'failed':0}]
     elif profile.startswith('wrong-'):expected=[{'event':'connection','status':1},{'event':'keep','status':0,'result':42},{'event':'done','bad':0,'keep':1,'failed':0}]
     else:expected=[{'event':'connection','status':1},{'event':'bad-list','status':0,'count':1},{'event':'keep','status':0,'result':42},{'event':'done','bad':1,'keep':1,'failed':0}]
     if events!=expected or any(row['event']=='unexpected-rx'for row in records):raise ValueError((profile,actor,'actual callback/frame sequence differs',events,records))
     observations[actor]={'pid':process.pid,'argv':argv,'exit_code':process.returncode,'callbacks':events,'connections':[{'connection':0,'events':records},*extras]}
    finally:
     if connection is not None:connection.close()
     listener.close()
     if process is not None and process.poll()is None:process.kill();process.communicate(timeout=2)
   same=observations['c']['callbacks']==observations['rust']['callbacks'] and observations['c']['connections'][0]['events']==observations['rust']['connections'][0]['events']
   if not same:raise ValueError((profile,'primary original connection/callback trace differs'))
   result['cases'].append({'profile':profile,'primary_connection_and_callbacks_matched':True,'all_physical_connections_equal':observations['c']['connections']==observations['rust']['connections'],'observations':observations})
  if len(result['cases'])!=14 or {row['profile']for row in result['cases']}!=set(PROFILES):raise ValueError('exact nonempty 14 profiles not executed')
  after,normal_after=load(a.reference,a.source,a.repo);_,current=local_snapshot(metadata,package,support);current[str(pathlib.Path(__file__).resolve())]=sha(__file__);result['inputs_unchanged']=current==inputs;result['normal_inputs_unchanged']=ref==after and normal==normal_after;result['binaries_unchanged']=all(sha(path)==value for path,value in binaries.items())
  if not all(result[key]for key in ['inputs_unchanged','normal_inputs_unchanged','binaries_unchanged']):raise ValueError('candidate/closure/normal/executed binary changed')
  result['status']='passed';result['paired_profiles']=len(PROFILES);result['actual_actors']=2*len(PROFILES)
 except Exception as error:result['failure']=type(error).__name__+': '+str(error)
 result['elapsed_seconds']=time.monotonic()-begin;(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'paired_profiles':len(result['cases']),'failure':result.get('failure'),'result':str(out/'result.json')}));return 0 if result['status']=='passed'else 1

if __name__=='__main__':raise SystemExit(main())
