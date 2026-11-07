#!/usr/bin/env python3
"""Fresh locked Rust build plus actual normal-C/Rust EMFILE process observation."""
import argparse,hashlib,json,os,pathlib,subprocess,sys,time

def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def discover(repo):
 paths=[]
 for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','rustfmt.toml','.cargo/config.toml']:
  path=repo/name
  if path.is_file():paths.append(path)
 for directory in ['crates','adapters','apps']:
  paths.extend(path for path in(repo/directory).rglob('*')if path.is_file()and'__pycache__'not in path.parts and'target'not in path.parts)
 return {str(path.resolve()):sha(path)for path in sorted(set(paths))}
def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',type=pathlib.Path,required=True);p.add_argument('--receipt',type=pathlib.Path,required=True);p.add_argument('--reference-helper',type=pathlib.Path,required=True);p.add_argument('--observer',type=pathlib.Path,default=pathlib.Path(__file__).with_name('paired_observe.py'));p.add_argument('--toolchain',default='1.99.1');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.repo=a.repo.resolve();a.output=a.output.resolve()
 for source in [a.repo,a.receipt.parent,a.reference_helper.parent,pathlib.Path(__file__).parent]:
  source=source.resolve();assert not a.output.is_relative_to(source)and not source.is_relative_to(a.output),'output overlaps input'
 a.output.mkdir(exist_ok=False,parents=True);before=discover(a.repo);assert before;tools={str(path.resolve()):sha(path)for path in [pathlib.Path(__file__),a.observer,a.receipt,a.reference_helper]};commands=[];result={'status':'failed','scope':'Actual normal C STATISTICS daemon versus actual Rust public shared STATISTICS host component; four finite owned native EMFILE profiles. No production Rust app/default-capacity or whole-owner claim.','source_inputs':before,'tool_inputs':tools,'commands':commands};env=os.environ.copy();env.update(CARGO_BUILD_JOBS='2',PYTHONDONTWRITEBYTECODE='1');cargo=['cargo','+'+a.toolchain];args=['--manifest-path',str(a.repo/'Cargo.toml'),'--offline','--locked','-j2','--target-dir',str(a.output/'target')]
 def run(name,argv,seconds=180):
  start=time.monotonic();proc=subprocess.run([str(v)for v in argv],cwd=a.repo,env=env,capture_output=True,timeout=seconds);out=a.output/(name+'.stdout');err=a.output/(name+'.stderr');out.write_bytes(proc.stdout);err.write_bytes(proc.stderr);commands.append({'name':name,'argv':[str(v)for v in argv],'exit_code':proc.returncode,'elapsed':time.monotonic()-start,'stdout_sha256':sha(out),'stderr_sha256':sha(err)});assert proc.returncode==0,(name,proc.returncode,proc.stderr.decode(errors='replace')[-2500:]);return proc.stdout.decode()
 try:
  run('strict-fixture',cargo+['clippy',*args,'-p','gnunet-ipc-unix','--example','service_emfile'])
  output=run('fresh-fixture-build',cargo+['build',*args,'-p','gnunet-ipc-unix','--example','service_emfile','--message-format=json']);artifacts=[]
  for line in output.splitlines():
   event=json.loads(line)
   if event.get('reason')=='compiler-artifact'and event.get('target',{}).get('name')=='service_emfile'and event['target']['kind']==['example']:artifacts.append(event['executable'])
  assert len(artifacts)==1 and artifacts[0];binary=pathlib.Path(artifacts[0]);assert binary.is_relative_to(a.output/'target');binary_hash=sha(binary);result['rust_binary']={'path':str(binary),'sha256':binary_hash}
  run('normal-c-rust-processes',[sys.executable,'-B',a.observer,'--receipt',a.receipt,'--reference-helper',a.reference_helper,'--repo',a.repo,'--rust-binary',binary,'--output',a.output/'processes'],60)
  process_path=a.output/'processes/result.json';process=json.loads(process_path.read_text());assert process['status']=='passed'and process['inputs_unchanged']and process['local_file_set_unchanged']and process['source_unchanged'];assert len(process['profiles'])==4 and {(r['language'],r['profile'])for r in process['profiles']}=={(lang,'fill-'+kind)for lang in ['c','rust']for kind in ['unix','tcp']};assert all(r['status']=='passed'and r['exit_code']==0 and r['runtime_removed']for r in process['profiles']);assert len(process['comparisons'])==2;result['process_receipt']={'path':str(process_path),'sha256':sha(process_path)}
  result['source_inputs_unchanged']=discover(a.repo)==before;result['tool_inputs_unchanged']=all(sha(path)==digest for path,digest in tools.items());result['rust_binary_unchanged']=sha(binary)==binary_hash;assert result['source_inputs_unchanged']and result['tool_inputs_unchanged']and result['rust_binary_unchanged'];result['status']='passed'
 except Exception as error:result['failure']=type(error).__name__+': '+str(error);raise
 finally:(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'result':str(a.output/'result.json')}))
if __name__=='__main__':main()
