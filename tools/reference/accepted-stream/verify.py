#!/usr/bin/env python3
"""Reproduce current Root canonical accept from exact production source bodies."""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
PACKAGE=Path(__file__).resolve().parent
TOOL_TESTS={'test_audit_traversal_unknown_role_and_missing_registry_rejected','test_audited_source_content_change_is_rejected','test_canonical_option_mismatch_and_impure_wrapper_rejected','test_dependency_contract_preserves_all_semantic_fields','test_docs_require_all_four_and_three_compile_fail_controls','test_exact_observation_sets_reject_duplicate_and_empty_rows','test_file_addition_and_deletion_change_discovered_snapshot','test_missing_or_changed_full_root_lints_are_visible','test_native_dependency_role_rejects_foreign_path','test_output_overlap_blocks_source_and_ancestor','test_payload_actor_and_original_fd_evidence_are_required','test_runtime_missing_duplicate_and_required_new_case_rejected'}
NEW_TESTS={'accepted::tests::injected_fatal_initialization_closes_only_actual_accepted_owner','accepted::tests::injected_wrong_kind_actual_nonfatal_setter_error_returns_original_usable_stream','network::tests::cloexec_and_nodelay_failure_are_nonfatal_with_bounded_ordered_diagnostics','network::tests::darwin_nosigpipe_failure_is_fatal_before_nodelay','network::tests::earlier_nonfatal_diagnostic_survives_later_fatal_error','network::tests::exact_source_order_preserves_flags_and_skips_redundant_cloexec_set','network::tests::invalid_or_fdsetsize_boundary_mints_no_native_attempt','network::tests::nonblocking_failure_is_fatal_and_does_not_attempt_later_options','network::tests::real_wrong_kind_setter_failure_keeps_owned_socket_usable'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def files(root):return {p.resolve()for p in Path(root).rglob('*')if p.is_file()and not {'target','.git','__pycache__'}.intersection(p.relative_to(root).parts)}
def snapshot(paths):return {str(p):sha(p)for p in sorted(paths,key=lambda p:os.fsencode(p))}
def output_guard(out,protected):
 for path in protected:
  if out==path or out.is_relative_to(path)or path.is_relative_to(out):raise ValueError('output overlaps inputs')
def audit_inputs(audit,metadata,source,sysroot):
 paths=set()
 for row in audit['files']:
  relative=Path(row['relative'])
  if relative.is_absolute()or '..'in relative.parts:raise ValueError('invalid audited relative path')
  if row['origin']=='upstream':base=source
  elif row['origin']=='rust-std':base=sysroot/'lib/rustlib/src/rust/library/std/src'
  elif row['origin']=='registry':
   packages=[p for p in metadata['packages']if p['source']is not None and p['name']==row['package']and p['version']==row['version']]
   if len(packages)!=1:raise ValueError('ambiguous/missing audited Cargo package')
   base=Path(packages[0]['manifest_path']).parent
  else:raise ValueError('unknown source-audit role')
  p=(base/relative).resolve()
  if not p.is_relative_to(base.resolve())or sha(p)!=row['sha256']:raise ValueError('reviewed std/mio/socket2/native source changed')
  paths.add(p)
 return paths
def lint(text,prefix):
 result={}
 for kind in ['rust','clippy','rustdoc']:
  found=re.search(r'(?ms)^\['+re.escape(prefix+kind)+r'\]\s*\n(.*?)(?=^\[|\Z)',text)
  if not found:raise ValueError('missing full lint '+kind)
  result[kind]='\n'.join(line.strip()for line in found[1].splitlines()if line.strip()and not line.strip().startswith('#'))
 return result
def contract(package,root):
 fields=['name','req','source','kind','rename','optional','uses_default_features','target','path'];rows=[];root=Path(root).resolve()
 for row in package['dependencies']:
  value={k:row.get(k)for k in fields};value['features']=sorted(row['features'])
  if value['path']is not None:
   path=Path(value['path']).resolve()
   if not path.is_relative_to(root):raise ValueError('foreign local dependency path role')
   value['path']='<workspace>/'+path.relative_to(root).as_posix()
  rows.append(value)
 return {'dependencies':sorted(rows,key=lambda r:json.dumps(r,sort_keys=True)),'features':package['features'],**{k:package[k]for k in ['name','version','edition','license','rust_version']}}
def local_roles(metadata,root):
 root=Path(root).resolve();roles={};identities=set()
 for package in metadata['packages']:
  if package['source']is not None:continue
  path=Path(package['manifest_path']).resolve()
  if not path.is_relative_to(root)or package['name']in roles or package['id']in identities:raise ValueError('duplicate/foreign local package type identity')
  roles[package['name']]=path.relative_to(root).as_posix();identities.add(package['id'])
 return roles
def inventory():
 value=json.loads((PACKAGE/'test-inventory.json').read_text());groups=value.get('groups',{});required={'native':('gnunet-native',12),'ipc':('gnunet-ipc-unix',55),'runtime':('gnunet-service-runtime',1),'broker':('gnunet-resolver-broker',19)}
 if set(groups)!=set(required):raise ValueError('missing/extra reviewed test scope')
 for key,(package,count)in required.items():
  group=groups[key]
  if group.get('package')!=package or group.get('count')!=count or len(group.get('tests',[]))!=count or len(set(group['tests']))!=count:raise ValueError('reviewed exact runtime count/name scope changed')
 all_names={name for group in groups.values()for name in group['tests']}
 if not {name.split('::')[-1]for name in NEW_TESTS}<=all_names:raise ValueError('required canonical/native regression removed')
 if value.get('docs')!={'ipc':{'package':'gnunet-ipc-unix','count':4,'compile_fail':3},'broker':{'package':'gnunet-resolver-broker','count':2,'compile_fail':1}}:raise ValueError('reviewed lifetime control scope changed')
 return value
def docs(text,count=4,compile_fail=3):
 names=re.findall(r'^test (.+?) \.\.\. ok$',text,re.M);found=[n for n in names if '.rs - 'in n]
 if len(found)!=count or sum('compile fail'in n for n in found)!=compile_fail:raise ValueError('exact named lifetime document controls required')
 return found
def tests(text,expected=None):
 names=re.findall(r'^test (.+?) \.\.\. ok$',text,re.M);document=[n for n in names if '.rs - 'in n];runtime=[n for n in names if n not in document];actual=[n.split('::')[-1]for n in runtime]
 if expected is None:expected={n for group in inventory()['groups'].values()for n in group['tests']};docs(text)
 if not expected or len(actual)!=len(expected)or len(set(actual))!=len(actual)or set(actual)!=set(expected):raise ValueError('exact reviewed runtime group required; missing/duplicate/extra/filtered test')
 return runtime,document

def main():
 parser=argparse.ArgumentParser()
 for name in ['repository','source','reference','output']:parser.add_argument('--'+name,type=Path,required=True)
 a=parser.parse_args();repo,source,reference,out=[getattr(a,k).resolve()for k in ['repository','source','reference','output']];normal=json.loads(reference.read_text())
 output_guard(out,[PACKAGE,repo,source,reference.parent,Path(normal['build']),Path(normal['prefix'])]);out.mkdir(mode=0o700,exist_ok=False);commands=[];cargo=['cargo','+1.99.1'];env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(out/'target'),PYTHONDONTWRITEBYTECODE='1')
 def run(label,argv,extra=None,cwd=None):
  e=env.copy();e.update(extra or {});cwd=repo if cwd is None else cwd;start=time.monotonic();done=subprocess.run(list(map(str,argv)),cwd=cwd,env=e,capture_output=True,timeout=300)
  for stream in ['stdout','stderr']:(out/(label+'.'+stream)).write_bytes(getattr(done,stream))
  commands.append({'name':label,'argv':list(map(str,argv)),'cwd':str(cwd),'exit':done.returncode,'seconds':time.monotonic()-start,'stdout_sha256':sha(out/(label+'.stdout')),'stderr_sha256':sha(out/(label+'.stderr'))})
  if done.returncode:raise RuntimeError(label+' failed; see '+str(out/(label+'.stderr')))
  return done.stdout.decode(errors='replace')
 try:
  sys.path.insert(0,str(repo/'adapters/arm-std/tools'));import reference as ref
  verified,normal_inputs=ref.load(reference,source,repo);assert verified==normal
  metadata=json.loads(run('root-metadata',cargo+['metadata','--manifest-path',repo/'Cargo.toml','--offline','--locked','--format-version=1']));original_roles=local_roles(metadata,repo)
  sysroot=Path(run('toolchain-sysroot',['rustc','+1.99.1','--print','sysroot']).strip()).resolve();run('toolchain-version',['rustc','+1.99.1','--version','--verbose'])
  if lint((repo/'Cargo.toml').read_text(),'workspace.lints.')!=lint((PACKAGE/'lint-policy.toml').read_text(),'workspace.lints.'):raise ValueError('full root lint contract mismatch')
  def discover():
   again,current=ref.load(reference,source,repo)
   if again!=normal or current!=normal_inputs:raise ValueError('normal C commitment changed')
   paths=files(repo)|files(PACKAGE)|{Path(p)for p in normal_inputs};paths|=audit_inputs(json.loads((PACKAGE/'prewrapping-source-audit.json').read_text()),metadata,source,sysroot)
   return snapshot(paths)
  before=discover();(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
  run('tool-boundaries',[sys.executable,'-B',PACKAGE/'test_tools.py','-v']);control_output=(out/'tool-boundaries.stderr').read_text();names=re.findall(r'^(test_\S+) \(__main__\.Guards\) \.\.\. ok$',control_output,re.M)
  if len(names)!=12 or set(names)!=TOOL_TESTS or 'Ran 12 tests'not in control_output or not control_output.rstrip().endswith('OK'):raise ValueError('exact12 named tool controls required')
  generated=out/'rust';shutil.copytree(repo,generated,ignore=shutil.ignore_patterns('.git','target','__pycache__'))
  copy_snapshot=snapshot(files(generated));relative_copy={str(Path(p).relative_to(generated)):v for p,v in copy_snapshot.items()};relative_original={str(Path(p).relative_to(repo)):v for p,v in snapshot(files(repo)).items()}
  if relative_copy!=relative_original:raise ValueError('full actual workspace/settings/locks copy changed')
  root_text=(generated/'Cargo.toml').read_text();root_text=root_text.replace('"tools/xtask"]','"tools/xtask", "tools/reference/accepted-stream/probe"]',1)
  if root_text==(generated/'Cargo.toml').read_text():raise ValueError('actual workspace member declaration needs explicit review')
  (generated/'Cargo.toml').write_text(root_text);probe=generated/'tools/reference/accepted-stream/probe';(probe/'Cargo.toml').write_text((PACKAGE/'probe/Cargo.toml.in').read_text())
  run('generated-lock',cargo+['generate-lockfile','--manifest-path',generated/'Cargo.toml','--offline'],cwd=generated)
  isolated=json.loads(run('generated-metadata',cargo+['metadata','--manifest-path',generated/'Cargo.toml','--offline','--locked','--format-version=1'],cwd=generated));generated_roles=local_roles(isolated,generated)
  if set(generated_roles)!=set(original_roles)|{'canonical-accept-probe'}:raise ValueError('unexpected generated local package set')
  for old in metadata['packages']:
   if old['source']is not None:continue
   name=old['name'];new=next(p for p in isolated['packages']if p['source']is None and p['name']==name)
   if generated_roles[name]!=original_roles[name]or contract(old,repo)!=contract(new,generated):raise ValueError('actual local dependency contract/type role changed: '+name)
  registry=lambda m:{(p['name'],p['version'],p['source'])for p in m['packages']if p['source']is not None}
  if registry(isolated)!=registry(metadata):raise ValueError('new/missing unreviewed registry package')
  if lint(root_text,'workspace.lints.')!=lint((repo/'Cargo.toml').read_text(),'workspace.lints.'):raise ValueError('generated root lint policy changed')
  allowed={'Cargo.toml','Cargo.lock','tools/reference/accepted-stream/probe/Cargo.toml'};actual={str(p.relative_to(generated)):sha(p)for p in files(generated)}
  if {k:v for k,v in actual.items()if k not in allowed}!={k:v for k,v in relative_original.items()if k not in allowed}:raise ValueError('production source copied/generated differently')
  generated_before=snapshot(files(generated));fmt=['-p','gnunet-native','-p','gnunet-service-runtime','-p','gnunet-ipc-unix','-p','gnunet-resolver-broker','-p','canonical-accept-probe'];run('format',cargo+['fmt','--manifest-path',generated/'Cargo.toml',*fmt,'--check'],cwd=generated)
  reviewed=inventory();runtime_groups={};doc_groups={}
  for name,group in reviewed['groups'].items():
   expected=set(group['tests']);source_names=[]
   for file in group['files']:source_names+=re.findall(r'#\[test\]\s*fn\s+(\w+)',(generated/file).read_text())
   if len(source_names)!=group['count']or len(set(source_names))!=group['count']or set(source_names)!=expected:raise ValueError('reviewed source test group changed: '+name)
   text=run('tests-'+name,cargo+['test','--manifest-path',generated/'Cargo.toml','--offline','--locked','-p',group['package'],*group['targets'],'-j','2','--','--test-threads=2'],cwd=generated);runtime_groups[name]=tests(text,expected)[0]
  for name,group in reviewed['docs'].items():
   text=run('docs-'+name,cargo+['test','--manifest-path',generated/'Cargo.toml','--offline','--locked','-p',group['package'],'--doc','-j','2'],cwd=generated);doc_groups[name]=docs(text,group['count'],group['compile_fail'])
  run('clippy',cargo+['clippy','--manifest-path',generated/'Cargo.toml','--offline','--locked',*fmt,'--all-targets','-j','2','--','-D','warnings'],cwd=generated)
  run('rustdoc',cargo+['doc','--manifest-path',generated/'Cargo.toml','--offline','--locked',*fmt,'--no-deps','-j','2'],{'RUSTDOCFLAGS':'-D warnings'},cwd=generated)
  run('actual-native-compare',[sys.executable,'-B',PACKAGE/'observe.py','--repository',repo,'--source',source,'--reference',reference,'--workspace',generated,'--output',out/'observed'])
  observed=json.loads((out/'observed/result.json').read_text())
  if observed['status']!='passed-canonical-and-raw-observation'or observed['normal_C_count']!=24 or observed['Rust_count']!=18 or len(observed['differences'])!=8 or any(r['accept_mode']=='canonical'for r in observed['differences']):raise ValueError('actual42 observations incomplete')
  after=discover();(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n')
  if before!=after or generated_before!=snapshot(files(generated)):raise ValueError('original/full generated file added/deleted/changed')
  result={'status':'passed-component-only','runtime_count':sum(map(len,runtime_groups.values())),'runtime_groups':runtime_groups,'runtime_transition':reviewed['transition'],'doc_count':sum(map(len,doc_groups.values())),'doc_groups':doc_groups,'tool_boundary_count':12,'normal_C_count':24,'Rust_count':18,'canonical_matching_profiles':6,'raw_preserved_difference_profiles':8,'source_and_generated_unchanged':True,'full_actual_workspace_copy':True,'original_package_roles':original_roles,'generated_package_roles':generated_roles,'full_root_lints_and_all_production_dev_dependency_contracts':True,'observation_result':{'path':str(out/'observed/result.json'),'sha256':sha(out/'observed/result.json')},'source_input_manifest_sha256':sha(out/'inputs-before.json'),'generated_input_manifest':generated_before,'commands':commands,'unaccepted_full_source_obligations':['std/mio/socket2 pre-wrapping CLOEXEC fatal policy differs from official C nonfatal policy','Tokio fallible reactor registration precedes this port','unexecuted C failed-syscall cases','other Unix platform execution','Full PROGRAM logging integration and whole SERVICE ownership remain separate pending scope'],'full_network_owner_promoted':False};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'runtime':result['runtime_count'],'docs':result['doc_count'],'normal_C':24,'Rust':18,'result':str(out/'result.json')}))
 except BaseException as e:(out/'failure.json').write_text(json.dumps({'status':'failed','error':str(e),'commands':commands},indent=2)+'\n');raise
if __name__=='__main__':main()
