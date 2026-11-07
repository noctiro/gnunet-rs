#!/usr/bin/env python3
"""Current-source ordinary PROGRAM acceptance; actual owned C/R participants.
No receipt/status alone grants whole PROGRAM/SCHEDULER/service completion.
All selected source inputs and executable participants are retained proof-locally.
"""
import argparse,json,os,re,shutil,subprocess,sys
from pathlib import Path
from _common import sha,require_disjoint_output,local_snapshot,require_lint_contract
from normal_reference import load
from validation import validate_inventory,cargo_artifacts,validate_configuration_locale
BASE=Path(__file__).resolve().parents[1]
BINS={'program-observer','logging-observer','getopt-observer','helpers-observer','configuration-edge','process-logging-observer','file-logging-observer','native-gettext-observer','program-nls-observer','program-broker-observer','diagnostic-helpers-observer','program-daemon-observer','program-monolith-observer','configuration-locale-observer'}
COUNTS={'program-lifecycle':('profiles',8),'logging':('profiles',19),'getopt':('cases',63),'helpers':('profiles',65),'file-logging':('profiles',21),'native-gettext':('profiles',6),'nls0-program':('profiles',20),'nls1-program':('profiles',20),'program-broker':('profiles',3),'daemon':('profiles',8),'monolith':('profiles',4),'config-diagnostics':('profiles',30),'ownership':('negative_controls',8),'configuration-locale':('profiles',134)}
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser()
 for name in ['manifest','config-manifest','repo','source','reference','target-dir','output','library','include']:p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--msgfmt',default='msgfmt');p.add_argument('--toolchain',default='1.99.1');a=p.parse_args()
 if a.manifest.resolve()!=BASE/'Cargo.toml':raise ValueError('manifest is not this maintained package')
 target=a.target_dir.resolve();config=a.config_manifest.resolve().parent
 if target==a.repo.resolve()/'target':raise ValueError('Root target is forbidden')
 env=os.environ.copy();env['CARGO_TARGET_DIR']=str(target);env['PYTHONDONTWRITEBYTECODE']='1';env['OWNED_GNUNET_SOURCE']=str(a.source.resolve())
 for key in ['RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER']:env.pop(key,None)
 cargo=['cargo','+'+a.toolchain];common=['--manifest-path',str(a.manifest),'--offline','--locked'];cfgcommon=['--manifest-path',str(a.config_manifest),'--offline','--locked']
 def metadata(manifest,features):return json.loads(subprocess.check_output(cargo+['metadata','--manifest-path',str(manifest),'--offline','--locked',*features,'--format-version','1'],env=env))
 def snapshot():
  md=metadata(a.manifest,['--all-features']);cmd=metadata(a.config_manifest,[]);selected,inputs=local_snapshot(md,BASE,BASE/'tools');_,cfg=local_snapshot(cmd,config,config/'tools');inputs.update(cfg)
  # The executable uses exactly the diagnostic clone under test, with a single
  # Configuration type identity. Stale overlay/source-only declarations fail.
  configs=[row for row in md['packages']if row['name']=='gnunet-config'and row['source']is None]
  if len(configs)!=1:raise ValueError('config dependency identity is not unique')
  source=Path(configs[0]['manifest_path']).parent/'src';left={v.relative_to(config/'src').as_posix():sha(v)for v in (config/'src').rglob('*')if v.is_file()};right={v.relative_to(source).as_posix():sha(v)for v in source.rglob('*')if v.is_file()}
  if left!=right:raise ValueError('actual PROGRAM config differs from tested CONFIG candidate')
  return md,cmd,selected,inputs
 r,normal=load(a.reference,a.source,a.repo);md,cmd,selected,inputs=snapshot();policy=require_lint_contract(BASE,a.repo,md);cfgpolicy=require_lint_contract(config,a.repo,cmd);inventory=validate_inventory(json.loads((BASE/'inventory.json').read_text()),a.source,BASE);roots=[Path(row['manifest_path']).parent for row in [*md['packages'],*cmd['packages']]if row['source']is None];out=require_disjoint_output(a.output,[BASE,config,a.repo,a.source,a.reference.resolve().parent,Path(r['build']),Path(r['prefix']),target,*roots]);out.mkdir(parents=True);save(out/'inputs-before.json',inputs);commands=[];result={'status':'not-run'};receipts={};names=[];confignames=[]
 def run(name,argv,timeout=150):
  child=subprocess.run(argv,env=env,capture_output=True,timeout=timeout);(out/(name+'.stdout')).write_bytes(child.stdout);(out/(name+'.stderr')).write_bytes(child.stderr);commands.append({'name':name,'argv':list(map(str,argv)),'exit':child.returncode,'stdout_sha256':sha(out/(name+'.stdout')),'stderr_sha256':sha(out/(name+'.stderr'))})
  if child.returncode:raise ValueError('actual command failed '+name)
  return child.stdout
 def retain(source,directory,name):
  dst=directory/name;before=sha(source);shutil.copyfile(source,dst);dst.chmod(0o700)
  if before!=sha(dst)or before!=sha(source):raise ValueError('actor changed during retention')
  return {'path':str(dst),'sha256':before}
 def component(name,tool,actor,extra=(),common_args=True):
  argv=[sys.executable,str(BASE/'tools'/tool)]
  if common_args:argv+=['--repo',str(a.repo),'--source',str(a.source),'--reference',str(a.reference)]
  argv+=['--rust',bins[actor]['path'],'--output',str(out/name),*map(str,extra)];run(name,argv);receipt=json.loads((out/name/'result.json').read_text())
  if receipt.get('status')!='passed':raise ValueError('actual component receipt failed '+name)
  if name=='configuration-locale':validate_configuration_locale(receipt)
  if name in COUNTS:
   field,count=COUNTS[name]
   if receipt.get(field)!=count:raise ValueError(('actual required component count differs',name,field,receipt.get(field),count))
  receipts[name]={'path':str(out/name/'result.json'),'sha256':sha(out/name/'result.json')}
 try:
  tests=run('rust-tests',cargo+['test',*common,'--target-dir',str(target),'--all-features']);names=re.findall(rb'^test ([^\r\n]+) \.\.\. ok$',tests,re.M)
  required={b'speedup_revises_already_pending_logical_timer_instead_of_only_changing_log_text',b'callback_can_register_next_launch_without_aliasing_the_active_callback_or_owner',b'tests::actual_driver_and_two_provider_timers_all_wake_across_both_poll_orders',b'tests::scope_delay_may_outlive_run_but_keeps_its_own_bounded_revision_waiter',b'tests::relative_zero_registration_is_ready_across_backwards_adjustment',b'tests::never_is_not_queued_ready_at_max_and_finite_max_minus_one_can_be_ready'}
  if not required.issubset(set(names)):raise ValueError('actual required lifecycle test names missing: '+repr(required-set(names)))
  run('clippy',cargo+['clippy',*common,'--target-dir',str(target),'--all-targets','--all-features','--','-D','warnings'])
  run('tool-controls',[sys.executable,str(BASE/'tools/test_tools.py')])
  build=run('build',cargo+['build',*common,'--target-dir',str(target),'--all-features','--examples','--message-format=json']);actors=out/'actors';actors.mkdir();built=cargo_artifacts(build,selected['id'],'example')
  if set(built)!=BINS:raise ValueError(('actual package example set mismatch',set(built)))
  bins={name:retain(source,actors,name)for name,source in built.items()}
  cfgtests=run('config-rust-tests',cargo+['test',*cfgcommon,'--target-dir',str(target/'config')]);confignames=re.findall(rb'^test ([^\r\n]+) \.\.\. ok$',cfgtests,re.M)
  if b'native_load_marks_attempt_and_main_before_default_discovery_failure'not in confignames or b'local_nonsend_observer_overrides_persistent_through_nested_secret_and_is_not_retained'not in confignames:raise ValueError('actual CONFIG lifecycle tests missing')
  run('config-clippy',cargo+['clippy',*cfgcommon,'--target-dir',str(target/'config'),'--all-targets','--','-D','warnings'])
  cfgbuild=run('config-build',cargo+['build',*cfgcommon,'--target-dir',str(target/'config'),'--example','diagnostic_trace','--message-format=json']);cfgpackage=next(row['id']for row in cmd['packages']if Path(row['manifest_path']).resolve()==a.config_manifest.resolve())
  # Example artifacts use executable, not an rlib; select actual Cargo JSON.
  candidates=[]
  for line in cfgbuild.splitlines():
   try:row=json.loads(line)
   except ValueError:continue
   if row.get('reason')=='compiler-artifact'and row.get('package_id')==cfgpackage and row.get('target',{}).get('name')=='diagnostic_trace'and row.get('target',{}).get('kind')==['example']and row.get('executable'):candidates.append(Path(row['executable']))
  if len(set(candidates))!=1:raise ValueError('actual CONFIG example artifact missing/ambiguous')
  cfgactor=retain(candidates[0],actors,'config-diagnostic-trace')
  for name,tool,actor in [('program-lifecycle','program_compare.py','program-observer'),('logging','logging_compare.py','logging-observer'),('getopt','getopt_compare.py','getopt-observer'),('helpers','helpers_compare.py','helpers-observer'),('missing-home','default_filename_check.py','configuration-edge'),('file-logging','file_logging_compare.py','file-logging-observer'),('diagnostic-helpers','diagnostic_helpers_compare.py','diagnostic-helpers-observer'),('daemon','program_daemon_compare.py','program-daemon-observer'),('monolith','program_monolith_compare.py','program-monolith-observer'),('program-broker','program_broker_compare.py','program-broker-observer')]:component(name,tool,actor)
  component('configuration-locale','configuration_locale_compare.py','configuration-locale-observer',['--library',a.library])
  native=['--repo',str(a.repo),'--library',str(a.library),'--include',str(a.include),'--msgfmt',a.msgfmt]
  component('native-gettext','native_gettext_compare.py','native-gettext-observer',native,False)
  for name,extra in [('nls0-program',['--nls0']),('nls1-program',[])]:component(name,'program_nls_compare.py','program-nls-observer',['--library',a.library,'--include',a.include,'--msgfmt',a.msgfmt,*extra])
  run('config-diagnostics',[sys.executable,str(config/'tools/diagnostics_compare.py'),'--repo',str(a.repo),'--source',str(a.source),'--reference',str(a.reference),'--rust',cfgactor['path'],'--output',str(out/'config-diagnostics')]);cfgreceipt=json.loads((out/'config-diagnostics/result.json').read_text())
  if cfgreceipt.get('status')!='passed'or cfgreceipt.get('profiles')!=30:raise ValueError('actual required CONFIG comparison missing')
  receipts['config-diagnostics']={'path':str(out/'config-diagnostics/result.json'),'sha256':sha(out/'config-diagnostics/result.json')}
  native_manifest=next(Path(row['manifest_path'])for row in cmd['packages']if row['name']=='gnunet-native'and row['source']is None)
  native_test_output=run('native-locale-lifecycle',cargo+['test','--offline','--locked','--manifest-path',str(native_manifest),'--target-dir',str(target/'native-lifecycle'),'--test','locale'])
  native_names=re.findall(rb'^test ([^\r\n]+) \.\.\. ok$',native_test_output,re.M)
  if len(native_names)!=5 or b'float_failure_during_late_tls_destructor_returns_boundary_error_without_fake_success'not in native_names:raise ValueError('native lifecycle controls missing')
  run('native-locale-ownership',[sys.executable,str(BASE/'tools/native_locale_ownership.py'),'--manifest',str(native_manifest),'--toolchain',a.toolchain,'--target-dir',str(target/'native-ui'),'--output',str(out/'native-locale-ownership')])
  native_ui=json.loads((out/'native-locale-ownership/result.json').read_text())
  if native_ui.get('status')!='passed'or len(native_ui.get('cases',[]))!=4:raise ValueError('actual native locale capability controls missing')
  receipts['native-locale-ownership']={'path':str(out/'native-locale-ownership/result.json'),'sha256':sha(out/'native-locale-ownership/result.json')}
  run('native-caller-controls',[sys.executable,str(BASE/'tools/native_caller_controls.py'),'--repo',str(a.repo),'--source',str(a.source),'--reference',str(a.reference),'--output',str(out/'native-caller-controls')])
  native_c=json.loads((out/'native-caller-controls/result.json').read_text())
  if native_c.get('status')!='passed'or len(native_c.get('rows',[]))!=2 or any(row.get('executed')is not False for row in native_c['rows']):raise ValueError('actual compiler-only ownership controls missing')
  receipts['native-caller-controls']={'path':str(out/'native-caller-controls/result.json'),'sha256':sha(out/'native-caller-controls/result.json')}
  run('ownership',[sys.executable,str(BASE/'tools/ownership.py'),'--manifest',str(a.manifest),'--repo',str(a.repo),'--toolchain',a.toolchain,'--target-dir',str(target),'--output',str(out/'ownership')]);ui=json.loads((out/'ownership/result.json').read_text())
  if ui.get('status')!='passed'or ui.get('negative_controls')!=8 or ui.get('positive_controls')!=1 or len(ui.get('cases',[]))!=9:raise ValueError('actual lifetime/UI witnesses missing')
  receipts['ownership']={'path':str(out/'ownership/result.json'),'sha256':sha(out/'ownership/result.json')}
  stderrrows=[]
  for closed in [False,True]:
   file=out/('closed-stderr.log'if closed else'open-stderr.log');file.write_bytes(b'PREFIX\n');child=subprocess.run([bins['process-logging-observer']['path'],str(file)]+(['closed']if closed else[]),env=env,capture_output=True,timeout=4);expected=b'PREFIX\n* logger\nDIRECT before drop\nDIRECT after drop\n';passed=child.returncode==0 and not child.stdout and not child.stderr and file.read_bytes()==expected;stderrrows.append({'initial_fd2_closed':closed,'exit':child.returncode,'stdout_hex':child.stdout.hex(),'stderr_hex':child.stderr.hex(),'actual_file_hex':file.read_bytes().hex(),'passed':passed})
   if not passed:raise ValueError('actual process stderr witness failed')
  save(out/'native-stderr.json',stderrrows)
  _,after_normal=load(a.reference,a.source,a.repo);_,_,_,after_inputs=snapshot()
  allactors=[*bins.values(),cfgactor]
  if inputs!=after_inputs or normal!=after_normal or any(sha(Path(v['path']))!=v['sha256']for v in allactors):raise ValueError('source closure, normal inputs or actor changed')
  blobs=out/'source-blobs';blobs.mkdir();retained={}
  for path,digest in inputs.items():
   data=Path(path).read_bytes()
   if sha(Path(path))!=digest:raise ValueError('input changed during retention '+path)
   dst=blobs/digest
   if not dst.exists():dst.write_bytes(data)
   if sha(dst)!=digest:raise ValueError('retained input differs '+path)
   retained[path]={'sha256':digest,'blob':str(dst)}
  _,_,_,final=snapshot()
  if inputs!=final:raise ValueError('input set changed after retention')

  result={'status':'passed','owner_complete':False,'scope':'actual current-source ordinary PROGRAM/GETOPT/logging/native-NLS/CONFIG/caller-polled clock/DAEMON/owned service composition; no all-platform/all-SCHEDULER or ARM CLI replacement promotion','actual_rust_tests':len(names),'actual_rust_test_names':[v.decode()for v in names],'actual_config_rust_tests':len(confignames),'actual_config_test_names':[v.decode()for v in confignames],'commands':commands,'actors':bins,'config_actor':cfgactor,'receipts':receipts,'inventory':inventory,'retained_inputs':retained,'inputs_unchanged':True,'normal_inputs':normal,'root_lint_policy':policy,'config_lint_policy':cfgpolicy,'pending_required':'DESIGN.md / API.md explicitly retain native non-host profiles, full SCHEDULER/service owners, undefined C classifications and downstream CLI migration'}
 except Exception as error:result={'status':'failed','owner_complete':False,'error':str(error),'commands':commands,'receipts':receipts};raise
 finally:save(out/'result.json',result)
 print(json.dumps({'status':result['status'],'owner_complete':False,'actual_rust_tests':len(names),'actual_config_rust_tests':len(confignames),'actual_component_receipts':len(receipts)}))
if __name__=='__main__':main()
