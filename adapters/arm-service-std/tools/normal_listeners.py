#!/usr/bin/env python3
"""Real unchanged C ARM daemon with a fresh finite Rust inherited-listener child.
No Rust daemon/native-launcher equivalence is claimed by this component probe.
"""
import argparse, hashlib, json, os, pathlib, socket, stat, struct, subprocess, sys, time
sys.dont_write_bytecode = True
PIN = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165"
def sha(path): return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--repository',required=True);p.add_argument('--source',required=True);p.add_argument('--reference',required=True);p.add_argument('--manifest',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 repo=pathlib.Path(a.repository).resolve();source=pathlib.Path(a.source).resolve();reference=pathlib.Path(a.reference).resolve();manifest=pathlib.Path(a.manifest).resolve();out=pathlib.Path(a.output).resolve()
 for owned_source in (repo,source,manifest.parent):
  if out==owned_source or owned_source in out.parents: raise ValueError('output must be external to every source tree')
 out.mkdir(mode=0o700)
 sys.path.insert(0,str(repo/'tools/reference'));import build_reference
 receipt=json.loads(reference.read_text());assert receipt['status']=='passed' and receipt['kind']=='unmodified-official-c-arm-reference-build' and receipt['source_unchanged']
 assert receipt['upstream']['revision']==PIN
 if 'source' in receipt:assert pathlib.Path(receipt['source']).resolve()==source
 setups=[item for item in receipt['commands'] if item['name']=='meson-setup' and item['exit_code']==0]
 assert len(setups)==1 and setups[0]['argv'][1]=='setup'
 assert pathlib.Path(setups[0]['argv'][2]).resolve()==pathlib.Path(receipt['build']).resolve() and pathlib.Path(setups[0]['argv'][3]).resolve()==source
 assert build_reference.source_state(source)==receipt['upstream']
 def discover():
  inputs={reference,pathlib.Path(__file__).resolve(),repo/'tools/reference/build_reference.py',repo/'Cargo.toml',repo/'Cargo.lock'}
  for value in list(receipt['artifacts'].values())+receipt['libraries']+receipt['default_configurations']+[receipt['generated_config']]:
   path=pathlib.Path(value['path']);assert sha(path)==value['sha256'];inputs.add(path)
  # Every local package consumed by this manifest, including include_str docs,
  # plus entire C tracked/gitlink state (recomputed separately before/after).
  metadata=json.loads(subprocess.check_output(['cargo','+1.99.1','metadata','--manifest-path',str(manifest),'--offline','--format-version','1'],cwd=str(repo)))
  for package in metadata['packages']:
   if package['source'] is not None: continue
   directory=pathlib.Path(package['manifest_path']).parent
   for child in directory.rglob('*'):
    if child.is_file() and not any(part in ('target','.git','__pycache__') for part in child.relative_to(directory).parts):inputs.add(child.resolve())
  return {str(path):sha(path) for path in sorted(inputs,key=lambda path:os.fsencode(path))}
 before=discover();subprocess.run(['cargo','+1.99.1','build','--manifest-path',str(manifest),'--bin','gnunet-arm-listener-child-fixture','--locked','--offline','--jobs','2','--target-dir',str(out/'target')],cwd=str(repo),stdout=open(out/'build.stdout','wb'),stderr=open(out/'build.stderr','wb'),check=True)
 fixture=out/'target/debug/gnunet-arm-listener-child-fixture';binary_sha=sha(fixture)
 sandbox=out/'no-ip.sb';sandbox.write_text('(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n')
 cases=[]
 def frame(sock):
  def exact(n):
   result=b''
   while len(result)<n:
    part=sock.recv(n-len(result))
    if not part:raise EOFError()
    result+=part
   return result
  header=exact(4);size,kind=struct.unpack('!HH',header);assert size>=4;return kind,header+exact(size-4)
 for label,flags,mode in [('uid','UNIX_MATCH_UID = YES\nUNIX_MATCH_GID = YES\n',0o700),('gid','UNIX_MATCH_GID = YES\n',0o770),('any','',0o777)]:
  directory=out/label;directory.mkdir(mode=0o700);endpoint=directory/'arm.sock';managed=directory/'managed.sock';config=directory/'owned.conf'
  config.write_text('[paths]\nGNUNET_HOME = '+str(directory/'home')+'\nDEFAULTCONFIG = '+str(config)+'\n[arm]\nUNIXPATH = '+str(endpoint)+'\nPORT = 0\nHOSTNAME = localhost\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\nGLOBAL_PREFIX =\nGLOBAL_POSTFIX =\n[fixture]\nBINARY = '+str(fixture)+'\nTYPE = GNUNET\nRUN_PER_USER = YES\nIMMEDIATE_START = NO\nSTART_ON_DEMAND = YES\nDISABLEV6 = YES\nUNIXPATH = '+str(managed)+'\n'+flags)
  environment={key:value for key,value in os.environ.items()if not key.startswith(('GNUNET_','LISTEN_'))};environment.update(receipt['runtime_environment'],LC_ALL='C',GNUNET_ARGS='')
  for name,key in [('user','HOME'),('xdg','XDG_CONFIG_HOME'),('cache','XDG_CACHE_HOME'),('data','XDG_DATA_HOME'),('run','XDG_RUNTIME_DIR'),('base','GNUNET_BASE_CONFIG')]:
   path=directory/name;path.mkdir(mode=0o700);environment[key]=str(path)
  # macOS protected sandbox-exec clears DYLD_*; restore only receipt-bound
  # loader settings after that executable. HOME/base remain explicitly owned.
  command=['/usr/bin/sandbox-exec','-f',str(sandbox),'/usr/bin/env']+[key+'='+value for key,value in receipt['runtime_environment'].items()]+[receipt['artifacts']['service']['path'],'-c',str(config)]
  proc=None;control=None;peer=None
  with open(directory/'stdout','wb') as stdout,open(directory/'stderr','wb') as stderr:
   try:
    assert sha(fixture)==binary_sha
    proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=environment)
    for _ in range(500):
     if proc.poll() is not None:raise RuntimeError('official ARM exited '+str(proc.returncode))
     try:
      control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);control.settimeout(5);control.connect(str(endpoint));break
     except (FileNotFoundError,ConnectionRefusedError):control.close();control=None;time.sleep(.01)
    assert control is not None and managed.exists()
    control.sendall(struct.pack('!HHIQ',16,12,0,17));kind,data=frame(control)
    assert kind==13 and struct.unpack_from('!Q',data,8)[0]==17 and struct.unpack_from('!H',data,16)[0]==1
    pool=data[52:];name_at,binary_at=struct.unpack_from('!HH',data,24)
    assert pool[name_at:].split(b'\0',1)[0]==b'fixture' and pool[binary_at:].split(b'\0',1)[0]==os.fsencode(fixture)
    control.sendall(struct.pack('!HH',4,14));kind,data=frame(control);assert kind==11 and data[8:]==b'arm\0'
    actual_mode=stat.S_IMODE(managed.stat().st_mode);assert actual_mode==mode
    peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);peer.settimeout(5);peer.connect(str(managed));peer.sendall(b'queue')
    response=b''
    while len(response)<11:
     part=peer.recv(11-len(response));assert part;response+=part
    assert response==b'child:queue';assert peer.recv(1)==b''
    statuses=[]
    while (1,b'fixture') not in statuses:
     kind,data=frame(control);assert kind==11;statuses.append((struct.unpack_from('!I',data,4)[0],data[8:-1]))
    assert statuses==[(2,b'fixture'),(1,b'fixture')],statuses
    control.sendall(struct.pack('!HHIQ',20,9,0,0x1122334455667788)+b'arm\0')
    # STOP result is not required to flush before the normal service EOF.
    try:
     while True:frame(control)
    except EOFError:pass
    assert proc.wait(timeout=5)==0
    cases.append({'label':label,'mode':actual_mode,'response_hex':response.hex(),'statuses':[(status,name.decode('ascii')) for status,name in statuses],'service_exit':proc.returncode,'configuration_sha256':sha(config),'fixture_before':binary_sha,'fixture_after':sha(fixture),'actual_initial_list_only_owned_fixture':True,'isolated_empty_base':environment['GNUNET_BASE_CONFIG'],'user_only_service_selection':True})
   finally:
    if peer is not None:peer.close()
    if control is not None:control.close()
    if proc is not None and proc.poll() is None:
     proc.terminate()
     try:proc.wait(timeout=5)
     except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
    for path in (endpoint,managed):
     if path.exists():path.unlink()
 after=discover();assert before==after and build_reference.source_state(source)==receipt['upstream'] and sha(fixture)==binary_sha
 result={'status':'passed','scope':'3 normal C ARM managed-listener on-demand cases with actual finite inherited-listener Rust child; no Rust daemon/launcher proof','cases':cases,'case_count':len(cases),'inputs_unchanged':before==after,'before':before,'after':after,'source_state':receipt['upstream'],'fixture_sha256':binary_sha,'sandbox_sha256':sha(sandbox)}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','cases':len(cases),'result':str(out/'result.json')}))
if __name__=='__main__':main()
