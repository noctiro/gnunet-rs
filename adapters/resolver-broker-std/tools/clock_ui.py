#!/usr/bin/env python3
"""Exact canonical source/waiter compile controls against Cargo's actual IPC rlib."""
import argparse,json,pathlib,subprocess
from common import sha,disjoint,rust_library

def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',type=pathlib.Path,required=True);p.add_argument('--artifacts',type=pathlib.Path,required=True);p.add_argument('--package-id',required=True);p.add_argument('--toolchain',default='1.99.1');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();a.repo=a.repo.resolve();a.output=a.output.resolve();disjoint(a.output,a.repo);a.output.mkdir(parents=True)
 artifact_sha=sha(a.artifacts);rlib=rust_library(a.artifacts.read_text(),'gnunet_ipc_unix',a.repo/'adapters/ipc-unix/Cargo.toml',a.package_id);binary_sha=sha(rlib)
 cases={
  'source_is_not_a_waiter':('E0599',"use gnunet_ipc_unix::clock::RuntimeClock;fn bad(source:&dyn RuntimeClock,cx:&mut std::task::Context<'_>){let _value=source.poll_changed(cx,0);}"),
  'arc_cannot_mutably_poll_subscription':('E0596',"use gnunet_ipc_unix::clock::ClockSubscription;fn bad(waiter:std::sync::Arc<dyn ClockSubscription>,cx:&mut std::task::Context<'_>){let _value=waiter.poll_changed(cx,0);}"),
  'subscription_cannot_be_cloned':('E0599',"use gnunet_ipc_unix::clock::ClockSubscription;fn bad(waiter:Box<dyn ClockSubscription>){let _other=waiter.clone();}"),
  'source_factory_positive':(None,"use gnunet_ipc_unix::clock::RuntimeClock;fn good(source:&dyn RuntimeClock,cx:&mut std::task::Context<'_>){if let Ok(mut a)=source.subscribe(){let _value=a.poll_changed(cx,0);}if let Ok(mut b)=source.subscribe(){let _value=b.poll_changed(cx,0);}}"),
 }
 rows=[]
 for name,(expected,body)in cases.items():
  source=a.output/(name+'.rs');source.write_text('#![deny(warnings)]\n#![allow(dead_code,reason="Finite compile-only ownership control")]\n'+body+'\n')
  argv=['rustc','+'+a.toolchain,'--edition=2024','--crate-type=lib','--error-format=json','--extern','gnunet_ipc_unix='+str(rlib),'-L','dependency='+str(rlib.parent),'-L','dependency='+str(rlib.parent/'deps'),str(source),'-o',str(a.output/(name+'.rlib'))]
  proc=subprocess.run(argv,capture_output=True,timeout=30);(a.output/(name+'.stderr')).write_bytes(proc.stderr);(a.output/(name+'.stdout')).write_bytes(proc.stdout)
  diagnostics=[json.loads(line)for line in proc.stderr.decode().splitlines()if line.startswith('{')];codes=[d['code']['code']for d in diagnostics if d.get('level')=='error'and d.get('code')]
  passed=(proc.returncode==0 and not codes)if expected is None else(proc.returncode!=0 and codes==[expected]);rows.append({'name':name,'expected':expected,'actual_codes':codes,'exit_code':proc.returncode,'passed':passed,'argv':argv,'source_sha256':sha(source)})
  if not passed:raise ValueError(rows[-1])
 if sha(rlib)!=binary_sha or sha(a.artifacts)!=artifact_sha:raise ValueError('actual UI artifact changed')
 (a.output/'result.json').write_text(json.dumps({'status':'passed','scope':'Three canonical ownership compile negatives and one positive, no runtime or C completion claim','cases':rows,'actual_count':4,'artifact_sha256':artifact_sha,'rlib':{'path':str(rlib),'sha256':binary_sha}},indent=2)+'\n')
if __name__=='__main__':main()
