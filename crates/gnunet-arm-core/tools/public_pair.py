#!/usr/bin/env python3
"""Normal C public owner versus actual Rust owner over identical owned Unix fixtures."""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
CORE=HERE.parent
ROOT=CORE.parents[1]
REF=None
UPSTREAM=None
import importlib.util
spec=importlib.util.spec_from_file_location('arm_core_verify',CORE/'verify.py')
verification=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():
 verification.UPSTREAM=UPSTREAM
 return verification.input_files(REF)
def channels(wire):
 roles={}
 for r in wire:
  if r['type']==15:roles.setdefault(r['peer'],'control')
  if r['type']==14:roles.setdefault(r['peer'],'monitor')
 return roles

def grouped(rows,roles):
 result={}
 for row in rows:
  role=roles[row['peer']];result.setdefault(role,[]).append({'type':row['type'],'hex':row['hex']})
 return result

def main():
 global REF,UPSTREAM
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);ap.add_argument('--reference',required=True,type=Path);ap.add_argument('--upstream',required=True,type=Path);args=ap.parse_args();out=args.output.resolve();REF=args.reference.resolve();UPSTREAM=args.upstream.resolve()
 for source in [ROOT,UPSTREAM]:
  if out.is_relative_to(source) or source.is_relative_to(out):raise RuntimeError('output/source must be disjoint')
 out.mkdir(parents=True,exist_ok=False);before=snapshot();(out/'sources-before.json').write_text(json.dumps(before,indent=2)+'\n');cases=[];commands=[]
 def command(label,argv):
  start=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=ROOT,capture_output=True,timeout=180)
  (out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr)
  commands.append({'name':label,'argv':list(map(str,argv)),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start})
  if p.returncode:raise RuntimeError(label+' failed; see '+str(out/(label+'.stderr')))
 command('fresh-rust-owner',['cargo','+1.99.1','build','--manifest-path',ROOT/'Cargo.toml','--target-dir',out/'target','--offline','--locked','-p','gnunet-arm-core','--example','public_owner'])
 observer=out/'target/debug/examples/public_owner';observer_digest=sha(observer)
 for case,flags in [('canonical',[]),('padding-and-unregistered',['--nonzero-padding','--unknown-types'])]:
  results={}
  for actor in ['c','rust']:
   directory=out/(case+'-'+actor);argv=[sys.executable,'-B',str(HERE/'public_owner.py'),'--actor',actor,'--reference',str(REF),'--observer',str(observer),'--output',str(directory),*flags];start=time.monotonic();p=subprocess.run(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE);(out/(case+'-'+actor+'.stdout')).write_bytes(p.stdout);(out/(case+'-'+actor+'.stderr')).write_bytes(p.stderr);commands.append({'argv':argv,'cwd':str(ROOT),'exit_code':p.returncode,'elapsed_seconds':time.monotonic()-start})
   if p.returncode:raise RuntimeError('actor failed '+case+'/'+actor+':'+p.stderr.decode())
   result=json.loads((directory/'result.json').read_text());assert result['success']and result['source_unchanged'];assert actor!='rust' or result['executed_actor_sha256']==observer_digest,'Rust execution differs from fresh build';results[actor]={'result':result,'directory':directory,'events':json.loads((directory/'events.json').read_text()),'wire':json.loads((directory/'wire.json').read_text()),'sent':json.loads((directory/'peer_sent.json').read_text())}
  c,r=results['c'],results['rust'];cc=[e for e in c['events']if e['event']!='monitor'];rc=[e for e in r['events']if e['event']!='monitor'];cm=[e for e in c['events']if e['event']=='monitor'];rm=[e for e in r['events']if e['event']=='monitor'];assert cc==rc and cm==rm,'observable channel callbacks differ'
  crole=channels(c['wire']);rrole=channels(r['wire']);assert grouped(c['wire'],crole)==grouped(r['wire'],rrole),'actual outgoing frames differ';assert grouped(c['sent'],crole)==grouped(r['sent'],rrole),'actual supplied response bytes differ'
  cases.append({'case':case,'success':True,'normal_C_events':len(c['events']),'actual_Rust_events':len(r['events']),'full_interleaving_equal':c['events']==r['events'],'control_callbacks_equal':True,'monitor_callbacks_equal':True,'actual_outgoing_frames_equal_per_connection':True,'actual_fixture_response_bytes_equal_per_connection':True,'normal_C_frames':len(c['wire']),'actual_Rust_frames':len(r['wire']),'supplied_peer_frames':len(c['sent']),'C_result_sha256':sha(c['directory']/'result.json'),'Rust_result_sha256':sha(r['directory']/'result.json')})
 command('fmt',['cargo','+1.99.1','fmt','--all','--','--check'])
 command('clippy',['cargo','+1.99.1','clippy','--manifest-path',ROOT/'Cargo.toml','--target-dir',out/'target','--offline','--locked','-p','gnunet-arm-core','--example','public_owner','--','-D','warnings'])
 assert sha(observer)==observer_digest,'fresh observer changed'
 after=snapshot();(out/'sources-after.json').write_text(json.dumps(after,indent=2)+'\n');assert before==after,'source/library changed during pair'
 result={'schema':1,'success':True,'scope':'Two actual normal-libgnunetarm versus Rust-core owned-Unix callback/frame traces; subset of full ARM lifecycle, no real daemon/native startup/CLI/testing implementation claim','cases':cases,'commands':commands,'normal_C_public_functions_actually_called':8,'normal_C_function_names':['GNUNET_ARM_connect','GNUNET_ARM_disconnect','GNUNET_ARM_operation_cancel','GNUNET_ARM_request_service_list','GNUNET_ARM_request_service_stop','GNUNET_ARM_request_service_start','GNUNET_ARM_monitor_start','GNUNET_ARM_monitor_stop'],'source_unchanged':True,'source_inputs_sha256':sha(out/'sources-before.json'),'normal_build_receipt':str(REF),'normal_build_receipt_sha256':sha(REF),'fresh_rust_observer':{'path':str(observer),'sha256':observer_digest},'requirement_scope':['TEST confirmed up','normal START/STOP/LIST with real native24/28-byte layout','queued ordinary cancel still transmits but callback suppressed','confirmed-up ARM localstart AlreadyStarted/repeatedYES without exec','ARM STOPPING waits actual Unix EOF thenSTOPPED beforeNO','separate monitor registration/unknownstatus','nonzero C aggregate/row padding accepted','legal unregistered65000/foreign directions ignored'],'explicit_remaining':['Unconfirmed local ARM realspawn/pipe host','MQ creation failure/retry timing normalCpair','real ARM daemon child lifecycle/listener activation/backoff/reaping/shutdown','CLI/all6testing functions','otherABI platforms','all other source-derived lifecycle branches'],'verification_promotion':False,'no_C_UB_paths_executed':True,'no_managed_GNUnet_or_system_service_started':True,'only_owned_temporary_Unix_endpoints':True,'all_actual_actor_exit_codes_zero':True,'all_socket_paths_cleaned':True,'artifact_sha256':{str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()}}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'success':True,'actual_paired_cases':len(cases),'C_public_functions':8,'result':str(out/'result.json'),'sha256':sha(out/'result.json')}))
if __name__=='__main__':main()
