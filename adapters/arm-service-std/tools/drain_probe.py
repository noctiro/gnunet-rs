#!/usr/bin/env python3
"""Actual unchanged normal ARM daemon late-control admission during child drain."""
import argparse,json,os,socket,struct,subprocess,sys,time
from pathlib import Path
PACKAGE=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--repository',type=Path,required=True);p.add_argument('--upstream',type=Path,required=True);p.add_argument('--reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();sys.path.insert(0,str(a.repository/'adapters/arm-std/tools'));import reference
 out=a.output.resolve();assert not out.exists() and not out.is_relative_to(PACKAGE) and not out.is_relative_to(a.repository);out.mkdir();ref,inputs=reference.load(a.reference,a.upstream,a.repository);inputs.update({str(path):reference.sha(path)for path in [Path(__file__),PACKAGE/'tools/drain_child.c',a.repository/'adapters/arm-std/tools/reference.py']});binary=Path(ref['artifacts']['service']['path']);assert reference.sha(binary)==ref['artifacts']['service']['sha256'];inputs[str(binary)]=reference.sha(binary)
 child=out/'owned-child';c=subprocess.run(['cc',str(PACKAGE/'tools/drain_child.c'),'-Wall','-Wextra','-Werror','-o',str(child)],capture_output=True);(out/'compile.stderr').write_bytes(c.stderr);assert c.returncode==0;inputs[str(child)]=reference.sha(child)
 base=out/'base';base.mkdir();trace=out/'child.trace';endpoint=out/'arm.sock';cfg=out/'owned.conf';cfg.write_text('[paths]\nGNUNET_HOME = '+str(out/'home')+'\nDEFAULTCONFIG = '+str(cfg)+'\n[arm]\nUNIXPATH = '+str(endpoint)+'\nPORT = 0\nHOSTNAME = localhost\nSTART_SYSTEM_SERVICES = NO\nSTART_USER_SERVICES = YES\n[hold]\nTYPE = SIMPLE\nBINARY = distinct-argv-zero\nPREFIX = '+str(child)+'\nRUN_PER_USER = YES\nPIPECONTROL = NO\nNOARMBIND = YES\n')
 env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(ref['runtime_environment'],GNUNET_BASE_CONFIG=str(base),GNUNET_ARM_DRAIN_TRACE=str(trace),LC_ALL='C');frames=[];checks=[];process=None;peers=[]
 def receive(peer):
  header=peer.recv(4)
  while len(header)<4:
   b=peer.recv(4-len(header))
   if not b:raise EOFError('short actual frame')
   header+=b
  n,t=struct.unpack('>HH',header);assert n>=4;b=header
  while len(b)<n:b+=peer.recv(n-len(b))
  frames.append({'type':t,'hex':b.hex()});return t,b
 def cmd(kind,id,name):return struct.pack('>HHIQ',17+len(name),kind,0,id)+name+b'\0'
 def wait(text):
  deadline=time.monotonic()+3
  while time.monotonic()<deadline:
   if trace.exists() and text in trace.read_text():return
   if process.poll()is not None:raise RuntimeError('daemon exited before child '+text)
   time.sleep(.002)
  raise TimeoutError(text)
 stdout=open(out/'daemon.stdout','wb');stderr=open(out/'daemon.stderr','wb')
 try:
  process=subprocess.Popen([str(binary),'-c',str(cfg)],env=env,stdout=stdout,stderr=stderr,stdin=subprocess.DEVNULL);deadline=time.monotonic()+4
  while True:
   try:first=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);first.settimeout(2);first.connect(str(endpoint));peers.append(first);break
   except (FileNotFoundError,ConnectionRefusedError):first.close();assert time.monotonic()<deadline;time.sleep(.005)
  first.sendall(struct.pack('>HH',4,15));assert receive(first)==(15,struct.pack('>HH',4,15));checks.append('initial-official-test')
  first.sendall(cmd(8,1,b'hold'));t,b=receive(first);assert t==10 and struct.unpack('>Q',b[8:16])[0]==1 and struct.unpack('>I',b[16:20])[0]==2;checks.append('actual-child-admitted')
  wait('READY');checks.append('real-child-TERM-handler-ready')
  first.sendall(cmd(9,2,b'arm'));wait('TERM');assert endpoint.exists();checks.append('own-ARM-path-retained-during-drain')
  late=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);late.settimeout(2);late.connect(str(endpoint));peers.append(late);late.sendall(struct.pack('>HH',4,15));assert receive(late)==(15,struct.pack('>HH',4,15));checks.append('new-control-connection-actual-test-during-drain')
  late.sendall(cmd(8,3,b'missing'));t,b=receive(late);assert t==10 and struct.unpack('>Q',b[8:16])[0]==3 and struct.unpack('>I',b[16:20])[0]==9;checks.append('new-control-START-gets-IN_SHUTDOWN')
  while first.recv(65535):pass
  assert process.wait(timeout=3)==0;checks.append('natural-daemon-exit-zero-after-real-child-wait');assert 'EXIT' in trace.read_text();checks.append('child-real-exit-marker');assert not endpoint.exists();checks.append('own-ARM-path-removed-only-final-cleanup')
 finally:
  for peer in peers:peer.close()
  if process is not None and process.poll()is None:
   process.terminate()
   try:process.wait(timeout=3)
   except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
  stdout.close();stderr.close()
 after,current=reference.load(a.reference,a.upstream,a.repository);assert ref==after and all(reference.sha(path)==value for path,value in inputs.items());result={'status':'passed','scope':'actual unchanged normal C ARM daemon; finite owned slow TERM child; no Rust equivalence claim','checks':checks,'count':len(checks),'actual_frames':frames,'inputs':inputs,'inputs_unchanged':True,'daemon_exit':process.returncode};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','checks':len(checks),'result':str(out/'result.json')}))
if __name__=='__main__':main()
