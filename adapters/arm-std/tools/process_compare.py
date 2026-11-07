#!/usr/bin/env python3
"""Fresh unchanged C util process calls versus actual shared Rust process port.
All children/endpoints are finite and owned; no public network or GNUnet C FFI backend.
"""
import argparse,json,os,pathlib,socket,subprocess,sys,tempfile,time
from reference import load,compile_probe,sha
from _common import local_snapshot,require_disjoint_output,require_lint_contract

def main():
 p=argparse.ArgumentParser()
 for name in ['repo','source','reference','output']:p.add_argument('--'+name,type=pathlib.Path,required=True)
 p.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);a=p.parse_args()
 package=a.package.resolve();repo=a.repo.resolve();reference,normal=load(a.reference,a.source,repo)
 out=require_disjoint_output(a.output,[package,repo,a.source,a.reference.resolve().parent,pathlib.Path(reference['build']),pathlib.Path(reference['prefix'])]);out.mkdir(mode=0o700)
 metadata=json.loads(subprocess.check_output(['cargo','+1.99.1','metadata','--manifest-path',str(package/'Cargo.toml'),'--offline','--locked','--format-version','1'],cwd=repo));selected,before=local_snapshot(metadata,package,package/'tools');lints=require_lint_contract(package,repo,metadata)
 commands=[]
 def run(label,argv,**kwargs):
  result=subprocess.run([str(v)for v in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs);(out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr);commands.append({'label':label,'argv':[str(v)for v in argv],'exit':result.returncode});assert result.returncode==0,(label,result.stderr.decode(errors='replace'));return result
 target=out/'cargo-target';run('build',['cargo','+1.99.1','build','--manifest-path',package/'Cargo.toml','--bins','--example','process_owner','--locked','--offline','--jobs','2','--target-dir',target],cwd=repo)
 rust=target/'debug/examples/process_owner';helper=target/'debug/gnunet-arm-spawn-helper';c=out/'normal-process-owner';child=out/'plain-child'
 compilation=compile_probe(package/'tools/process_owner.c',c,reference);run('target-build',['cc',package/'tests/support/process_fixture.c','-Wall','-Wextra','-Werror','-o',child]);run('cc-version',['cc','--version'])
 binaries={str(path):sha(path)for path in [c,child,rust,helper]};cases=[]
 labels=['simple-raw','empty-argv','directory-late-exec','not-executable','late-interpreter','control-one-byte','control-epipe','control-default-sigpipe','two-queued-listeners']
 for label in labels:
  directory=out/label;directory.mkdir();observed={}
  bad=directory/'late-script';bad.write_bytes(b'#!/owned/definitely-no-interpreter\n');bad.chmod(0o600 if label=='not-executable'else 0o700)
  for actor in ['c','rust']:
   trace=directory/(actor+'-target.txt');mode='exit';flags=0;profile='ignore';filename=child;argv=[b'arbitrary\xff argv0',b'alpha beta'];fds=[];listeners=[];peers=[];socket_directory=None
   env={k:v for k,v in os.environ.items()if not k.startswith(('GNUNET_','LISTEN_'))};env.update(reference['runtime_environment']);env['LC_ALL']='C';env['GNUNET_PROCESS_OWNER_VALUE']=os.fsdecode(b'\xfe\xfd')
   if label=='empty-argv':filename=pathlib.Path('/usr/bin/true');argv=[]
   if label in ['not-executable','late-interpreter']:filename=bad
   if label=='directory-late-exec':filename=directory
   if label in ['control-one-byte','control-epipe','control-default-sigpipe']:
    mode='control'if label=='control-one-byte'else'close-control';flags=8
    if label=='control-default-sigpipe':profile='default';env['GNUNET_PROCESS_TEST_HOLD_MS']='100'
   if label=='two-queued-listeners':
    mode='accept'
    socket_directory=tempfile.TemporaryDirectory(prefix='gnunet-proc-',dir='/private/tmp')
    u=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);u.bind(str(pathlib.Path(socket_directory.name)/(actor+'.sock')));u.listen(5);u.setblocking(False);listeners.append(u)
    v=socket.socket(socket.AF_INET,socket.SOCK_STREAM);v.bind(('127.0.0.1',0));v.listen(5);v.setblocking(False);listeners.append(v)
    for listener in listeners:
     peer=socket.socket(listener.family,socket.SOCK_STREAM);peer.settimeout(4);peer.connect(listener.getsockname());peer.sendall(b'queue');peers.append(peer)
    fds=[fd.fileno()for fd in listeners];env['GNUNET_PROCESS_OWNER_FDS']=':'.join(map(str,fds))
   command=[str(c if actor=='c'else rust),str(filename),mode,str(trace),str(flags),profile,*argv]
   proc=None
   try:
    proc=subprocess.Popen(command,env=env,cwd=directory,pass_fds=tuple(fds),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    replies=[]
    for peer in peers:
     response=b''
     while len(response)<11:
      part=peer.recv(11-len(response));assert part;response+=part
     assert response==b'child:queue';replies.append(response.hex())
    stdout,stderr=proc.communicate(timeout=8);(directory/(actor+'.stdout')).write_bytes(stdout);(directory/(actor+'.stderr')).write_bytes(stderr)
    events=[json.loads(line)for line in stdout.splitlines()if line.startswith(b'{')]
    expected=-13 if label=='control-default-sigpipe'else 0;assert proc.returncode==expected,(label,actor,proc.returncode,stderr)
    if expected==-13:
     assert events==[{'event':'admission','admitted':True,'pid_positive':True}],events
     # Both normal/private parents have actually died by SIGPIPE; the finite
     # target auto-exits after100ms. No fabricated parent-side wait is claimed.
     time.sleep(.15)
    else:
     assert events and events[0]['admitted']==(label!='not-executable')
     if label!='not-executable':assert events[-1]['event']=='wait'
    observed[actor]={'exit':proc.returncode,'events':events,'trace':trace.read_bytes().hex()if trace.exists()else None,'replies':replies}
   finally:
    if proc is not None and proc.poll()is None:proc.kill();proc.communicate(timeout=3)
    for peer in peers:peer.close()
    for listener in listeners:
     address=listener.getsockname();listener.close()
     if isinstance(address,str)and pathlib.Path(address).exists():pathlib.Path(address).unlink()
    if socket_directory is not None:socket_directory.cleanup()
  assert observed['c']==observed['rust'],(label,observed)
  cases.append({'label':label,'matched':True,'actors':observed})
 _,after=local_snapshot(metadata,package,package/'tools');after_ref,after_normal=load(a.reference,a.source,repo);assert before==after and normal==after_normal and reference==after_ref and all(sha(path)==digest for path,digest in binaries.items())
 result={'status':'passed','scope':'9 actual shared Rust process port/normal unmodified C util API cases; no full ARM daemon certification','cases':cases,'case_count':len(cases),'normal_compilation':compilation,'root_lints':lints,'binaries':binaries,'inputs':before,'normal_inputs':normal,'inputs_unchanged':True,'commands':commands,'default_sigpipe':'actual new-exec callers terminate by13 before fallback; finite children auto-exit, no fabricated wait'}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','cases':len(cases),'result':str(out/'result.json')}))
if __name__=='__main__':main()
