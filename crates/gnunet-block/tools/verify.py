#!/usr/bin/env python3
"""Fresh, parameterized BLOCK candidate validation; never upgrades owner status."""
import argparse,hashlib,json,os,pathlib,re,subprocess,sys,tarfile,time
from workspace_bridge import helper as workspace_helper, repository, member, fixture_root, examples, TOOLS
from common import reference_inputs,require
from common import normal,disjoint,sha,successful
from compare import local_inputs
RUST_NAMES={
'maximum_size_headers_are_rejected_without_portable_length_overflow',
'revocation::boundaries::never_timestamp_score_failure_and_saturated_expiration_skip_clock_reads','revocation::boundaries::exact_lifetime_boundary_and_two_original_clock_reads','revocation::boundaries::source_epoch_score_and_clock_continuation_are_not_replaced_with_ttl_field',
'borrowed_creation_retains_two_distinct_tags_and_rejects_each_early_owner_drop','custom_plugin_callbacks_preserve_inputs_first_match_and_owning_drop','owning_builtin_registry_routes_all_installed_types_without_allocator_state',
'builtin_restore_copies_raw_state_before_its_owner_is_released','absent_merge_callback_retains_second_owner_but_null_left_consumes_it','raw_prefix_length_nonce_and_serialize_failures_preserve_real_semantics','unsigned32_size_wrap_early_entry_cap_and_exact_native_mingle','null_group_is_not_duplicate_but_null_internal_filter_is_duplicate','rehash_rounds_and_merge_only_require_nonce_size_not_k_or_type','pow_uses_caller_memory_and_short_scratch_cannot_change_output',
'gns_native_assertion_size_is_safe_error_and_unknown_type_key_is_unchanged','source_assertion_or_pointer_preconditions_are_safe_errors_without_partial_group_update','hello_capacity_is_resource_failure_and_cannot_be_invalid_or_fallback','dns_exact_expiration_readpoint_and_reply_does_not_revalidate'}
TOOL_NAMES={'test_actual_normal_exit_required','test_changed_bytes_rejected','test_complete_core_corpus_cannot_be_empty_or_filtered','test_deleted_file_rejected','test_duplicate_binding_rejected','test_empty_binding_rejected','test_legal_output_then_exit7_rejected','test_output_ancestor_of_input_rejected','test_output_descendant_of_input_rejected','test_output_same_as_input_rejected','test_real_file_bound_accepted','test_sibling_output_accepted','test_optimized_missing_trace_child_rejected','test_no_verification_asserts_can_be_disabled','test_virtual_workspace_member_identity_is_required','test_actual_fixture_graph_rejects_member_union','test_workspace_file_addition_and_deletion_rejected','test_builder_input_roles_are_complete_and_unique','test_changed_actual_builder_helper_is_rejected_even_optimized'}
NEW_REGISTRY={'argon2':('0.6.0','134c52ddac6d63c576bef8168db10c83c49c26444ecbc68060fef078925a901c'),'blake2':('0.11.0','5b5d4d889834ee8ecfc0f8426ad30faf7cdcb10f741a8e6d7224d95325479f6f'),'base64ct':('1.8.3','2af50177e190e07a26ab74f8b1efbfe2ef87da2116221318cb1c2e82baf7de06')}
def noalloc(meta):
 fixture_root(meta)
 packages={p['id']:p for p in meta['packages']};nodes={n['id']:n for n in meta['resolve']['nodes']};pending=[meta['resolve']['root']];visited=set();result=[]
 while pending:
  item=pending.pop()
  if item in visited:continue
  visited.add(item);p=packages[item];n=nodes[item]
  if set(n['features'])&{'alloc','std','getrandom','password-hash'}:raise ValueError('allocation/OS feature in target graph: '+p['name'])
  if p['name']in ['libc','tokio','async-io']or'/adapters/'in p['manifest_path']or'/apps/'in p['manifest_path']:raise ValueError('OS package in target graph')
  result.append({'name':p['name'],'version':p['version'],'features':n['features']})
  for dep in n['deps']:
   if not any(k['kind']is None for k in dep['dep_kinds']):continue
   target=packages[dep['pkg']]
   if not any('proc-macro'in t['kind']for t in target['targets']):pending.append(dep['pkg'])
 if not {'gnunet-block','argon2','blake2','base64ct'}<={p['name']for p in result}:raise ValueError('incomplete noalloc graph')
 return sorted(result,key=lambda p:p['name'])
def archives(meta,cargo_home):
 result=[]
 for name,(version,checksum)in NEW_REGISTRY.items():
  p=next(x for x in meta['packages']if x['name']==name and x['version']==version);base=pathlib.Path(p['manifest_path']).parent;archive=cargo_home/'registry/cache'/base.parent.name/(name+'-'+version+'.crate')
  if sha(archive)!=checksum:raise ValueError('registry archive checksum mismatch')
  files={}
  with tarfile.open(archive)as tar:
   for member in tar.getmembers():
    if not member.isfile():continue
    parts=pathlib.PurePosixPath(member.name).parts
    if parts[0]!=name+'-'+version or'..'in parts:raise ValueError('unsafe archive member')
    rel=pathlib.Path(*parts[1:]);expected=hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    if sha(base/rel)!=expected:raise ValueError('registry extracted source mismatch: '+str(rel))
    files[str(rel)]=expected
  actual={str(x.relative_to(base))for x in base.rglob('*')if x.is_file()and x.suffix in ['.rs','.toml']}
  if not actual<=set(files):raise ValueError('extra compilable registry source')
  result.append({'name':name,'version':version,'archive':str(archive),'checksum':checksum,'license':p['license'],'source_files':len(files),'source_projection_sha256':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()})
 return result

def dependency_contract(metadata,package):
 p=member(metadata,package)
 if p['name']!='gnunet-block'or p['features']!={'default':[]}or p['edition']!='2024'or p['rust_version']!='1.99.1':raise ValueError('package/default feature contract changed')
 expected={'gnunet-types','gnunet-crypto','gnunet-hello'}
 if {d['name']for d in p['dependencies']}!=expected or len(p['dependencies'])!=3:raise ValueError('unexpected or duplicate dependency')
 for d in p['dependencies']:
  if d['uses_default_features']or d['optional']or d['kind']is not None or d['target']is not None or d['rename']is not None:raise ValueError('dependency role/default contract changed')
  wanted={'pow'}if d['name']=='gnunet-crypto'else set()
  if d['source']is not None or set(d['features'])!=wanted:raise ValueError('internal dependency source/feature contract')
 crypto=next(x for x in metadata['packages']if x['name']=='gnunet-crypto'and x['source']is None)
 if crypto['features'].get('pow')!=['dep:argon2']or crypto['features'].get('default')!=[]:raise ValueError('shared optional PoW feature contract changed')
 argon=[d for d in crypto['dependencies']if d['name']=='argon2']
 if len(argon)!=1:raise ValueError('unique shared Argon2 dependency required')
 d=argon[0]
 if d['req']!='=0.6.0'or set(d['features'])!={'zeroize'}or d['source']!='registry+https://github.com/rust-lang/crates.io-index'or d['uses_default_features']or not d['optional']or d['kind']is not None or d['target']is not None or d['rename']is not None:raise ValueError('unpinned optional shared Argon2/feature source contract')
 return {'package':p['name'],'dependencies':sorted(expected),'shared_pow':'gnunet-crypto/pow','argon2':'optional =0.6.0/no-default/zeroize'}

def lint_contract(package,metadata):
 root=pathlib.Path(next(p['manifest_path']for p in metadata['packages']if p['name']=='gnunet-crypto')).parents[2]/'Cargo.toml'
 expected=root.read_text();actual=(package/'Cargo.toml').read_text();projection={}
 inherited=re.search(r'^\[lints\]\s*\nworkspace\s*=\s*true\s*(?=\[|\Z)',actual,re.M) is not None
 for name in ['rust','clippy','rustdoc']:
  def table(text,prefix):
   match=re.search(r'^\['+re.escape(prefix+name)+r'\]\s*\n(.*?)(?=^\[|\Z)',text,re.M|re.S)
   if match is None:raise ValueError('missing actual lint table')
   return [x.strip()for x in match.group(1).splitlines()if x.strip()and not x.strip().startswith('#')]
  projected=table(expected,'workspace.lints.')
  if not inherited and table(actual,'lints.')!=projected:raise ValueError('staging lints differ from Root actual contract')
  projection[name]=projected
 return {'root_manifest':str(root),'inherited':inherited,'tables':projection}

def test_executables(data,package):
 rows=[json.loads(line)for line in data.splitlines()if line.startswith(b'{')]
 finished=[row for row in rows if row.get('reason')=='build-finished']
 require(len(finished)==1 and finished[0].get('success')is True,'actual successful Cargo build-finished required')
 return{str(pathlib.Path(row['executable']).resolve())for row in rows if row.get('reason')=='compiler-artifact'and row.get('executable')and row['profile']['test']and pathlib.Path(row['manifest_path']).resolve()==(package/'Cargo.toml').resolve()}

def reference_negative_controls(receipt,reference_helper,output):
 original=json.loads(pathlib.Path(receipt).read_text());labels=[]
 for label,change in [('wrong-builder',lambda row:row.update(builder_sha256='00'*32)),('wrong-source-state',lambda row:row['upstream'].update(revision='00'*20)),('changed-declared-library',lambda row:row['libraries'][0].update(sha256='00'*32)),('changed-declared-private-config',lambda row:row['generated_config'].update(sha256='00'*32)),('missing-builder-inputs',lambda row:row.pop('builder_inputs',None)),('changed-builder-input-hash',lambda row:row['builder_inputs'][0].update(sha256='00'*32))]:
  row=json.loads(json.dumps(original));change(row);path=output/('reference-negative-'+label+'.json');path.write_text(json.dumps(row,indent=2)+'\n')
  try:normal(path,reference_helper)
  except (ValueError,FileNotFoundError):labels.append(label)
  else:raise ValueError('real reference negative control unexpectedly accepted: '+label)
 require(len(labels)==6,'all six actual reference negative controls required');return labels

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--repository',type=pathlib.Path,required=True)
 p.add_argument('--package',type=pathlib.Path)
 p.add_argument('--workspace-helper',type=pathlib.Path)
 for name in ('normal-receipt','deterministic-receipt','reference-helper','audit-tool','audit-db'):
  p.add_argument('--'+name,type=pathlib.Path)
 p.add_argument('--audit-revision')
 p.add_argument('--cargo-home',type=pathlib.Path,default=pathlib.Path.home()/'.cargo')
 p.add_argument('--output',type=pathlib.Path,required=True)
 p.add_argument('--prepare-only',action='store_true')
 p.add_argument('--development-snapshot',action='store_true')
 a=p.parse_args();origin=a.repository.resolve();package=(a.package or origin/'crates/gnunet-block').resolve();out=a.output.resolve()
 require(repository(package)==origin,'actual full Root repository/member required')
 shared=workspace_helper(a.workspace_helper or origin/'crates/gnunet-tcp-communicator-core/tools/session_inputs.py')
 os.environ['BLOCK_WORKSPACE_HELPER']=str(pathlib.Path(shared.__file__).resolve())
 roots=[origin,TOOLS,pathlib.Path(shared.__file__).parent]
 roots += [pathlib.Path(x).resolve()for x in(a.normal_receipt,a.deterministic_receipt,a.reference_helper,a.audit_tool,a.audit_db)if x]
 shared.disjoint_output(out,roots,workspace=origin);out.mkdir(mode=0o700,parents=True,exist_ok=False)
 origin_cmd=shared.Commands(out,origin,{'BLOCK_WORKSPACE_HELPER':os.environ['BLOCK_WORKSPACE_HELPER']});cmd=None;started=time.monotonic()
 before=shared.tree(origin);tool_before=shared.tree(TOOLS);helper_before=sha(shared.__file__)
 (out/'original-workspace-before.json').write_text(json.dumps(before,indent=2)+'\n')
 try:
  origin_cmd.run('tool-controls',[sys.executable,'-B',TOOLS/'test_tools.py'])
  log=(out/'tool-controls.stderr').read_text();names=set(re.findall(r'^(test_[a-z0-9_]+) .* \.\.\. ok$',log,re.M))
  require(names==TOOL_NAMES and f'Ran {len(TOOL_NAMES)} tests'in log and log.rstrip().endswith('OK'),'exact named nonempty BLOCK tool controls required')
  profiles={'default':(),'all-features':('--all-features',),'no-default-features':('--no-default-features',)}
  original_meta={name:origin_cmd.metadata('original-metadata-'+name,flags)for name,flags in profiles.items()}
  contract=shared.workspace_contract(origin,original_meta);dependencies=dependency_contract(original_meta['default'],package);lints=lint_contract(package,original_meta['default'])
  shared.same(shared.tree(origin),before,'complete original inputs before copy')
  workspace=out/'workspace';shared.same(shared.copy_workspace(origin,workspace),before,'actual complete Root/settings/two-lock copy')
  cmd=shared.Commands(out,workspace,{'BLOCK_WORKSPACE_HELPER':os.environ['BLOCK_WORKSPACE_HELPER']});copied_package=workspace/'crates/gnunet-block'
  copied_meta={name:cmd.metadata('copied-metadata-'+name,flags)for name,flags in profiles.items()}
  shared.same(shared.workspace_contract(workspace,copied_meta),contract,'full workspace roles/dependencies/features/registry contracts')
  (out/'workspace-contract.json').write_text(json.dumps(contract,indent=2)+'\n')
  if a.prepare_only:
   shared.same(shared.tree(origin),before,'Root inputs during preparation');shared.same(shared.tree(TOOLS),tool_before,'actual maintained tool file set');require(sha(shared.__file__)==helper_before,'shared helper changed')
   result={'status':'prepared-complete-workspace-contracts-only','whole_profile_executed':False,'source_files':len(before),'tools':len(tool_before),'control_names':sorted(names),'complete_profiles':list(profiles),'settings_and_two_locks_preserved':True,'dependency_contract':dependencies,'commands':[*origin_cmd.rows,*cmd.rows]}
   (out/'preparation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'path':str(out/'preparation.json')}));return
  require(all(getattr(a,key)for key in('normal_receipt','deterministic_receipt','reference_helper','audit_tool','audit_db','audit_revision')),'full run requires both normal profiles/reference helper/fixed audit tool/database/revision')
  r,state,source_state=normal(a.normal_receipt,a.reference_helper);d,dstate,_=normal(a.deterministic_receipt,a.reference_helper)
  require(r['hello_profile']=='normal'and d['hello_profile']=='deterministic'and state==dstate,'two distinct actual normal C build profiles required')
  reference_controls=reference_negative_controls(a.normal_receipt,a.reference_helper,out)
  refs_before=[reference_inputs(row,a.reference_helper)for row in(r,d)]
  external={str(pathlib.Path(path).resolve()):sha(path)for path in(a.normal_receipt,a.deterministic_receipt,a.reference_helper,a.audit_tool)}
  audit_before=shared.tree(a.audit_db)
  revision=origin_cmd.run('audit-db-revision',['git','-C',a.audit_db,'rev-parse','HEAD']).decode().strip()
  require(revision==a.audit_revision,'wrong fixed RustSec database revision')
  require(not origin_cmd.run('audit-db-clean',['git','-C',a.audit_db,'status','--porcelain','--untracked-files=no']),'dirty fixed RustSec database')
  registry=archives(copied_meta['all-features'],a.cargo_home)
  xtask=cmd.xtask();architecture=[]
  for check in('check-deps','check-features','check-noalloc','check-lints'):
   require(cmd.run(check,[xtask,check]).decode().rstrip().endswith(check+': passed'),'actual architecture check missing');architecture.append(check)
  cargo=['cargo','+1.99.1'];common=['--manifest-path',workspace/'Cargo.toml','--offline','--locked','-j','1','-p','gnunet-block']
  cmd.run('fmt',cargo+['fmt','--manifest-path',workspace/'Cargo.toml','--package','gnunet-block','--check'])
  cmd.run('clippy',cargo+['clippy',*common,'--all-targets','--','-D','warnings'])
  built=cmd.run('rust-test-build',cargo+['test',*common,'--all-targets','--no-run','--message-format=json'])
  executables=test_executables(built,copied_package);require(len(executables)==7,'exact7 actual BLOCK unit/integration/example executable artifacts required')
  for binary in executables:cmd.bind(binary)
  tested=cmd.run('rust-tests',cargo+['test',*common,'--all-targets','--message-format=json'])
  shared.same(test_executables(tested,copied_package),executables,'actual executed Cargo test artifact set')
  rust_names=set(re.findall(r'^test ([^ ]+) \.\.\. ok$',tested.decode(),re.M));require(rust_names==RUST_NAMES,'exact18 actual BLOCK tests required: '+str(rust_names^RUST_NAMES))
  docs=cmd.run('rust-docs',cargo+['test',*common,'--doc']).decode()
  doc_names=re.findall(r'^test (?:crates/gnunet-block/)?(src/callbacks.rs - callbacks::CallbackContext \(line \d+\)(?: - compile fail)?) \.\.\. ok$',docs,re.M)
  require(len(doc_names)==2 and sum('compile fail'in x for x in doc_names)==1,'positive and compile-fail actual BLOCK docs required')
  cmd.run('rustdoc',cargo+['doc',*common,'--no-deps'])
  graphs={}
  for platform in('thumbv6m-none-eabi','thumbv7em-none-eabi'):
   fixture=workspace/'tests/embedded/noalloc/Cargo.toml'
   meta=json.loads(cmd.run(platform+'-metadata',cargo+['metadata','--manifest-path',fixture,'--offline','--locked','--format-version','1','--filter-platform',platform]))
   graphs[platform]=noalloc(meta)
   cmd.run(platform+'-check',cargo+['check','--manifest-path',fixture,'--offline','--locked','-j','1','--target',platform])
  audits={}
  for label,lock in [('root',workspace/'Cargo.lock'),('embedded',workspace/'tests/embedded/noalloc/Cargo.lock')]:
   row=json.loads(cmd.run('audit-'+label,[a.audit_tool,'audit','--file',lock,'--db',a.audit_db,'--no-fetch','--json'],cwd=out))
   require(not row['vulnerabilities']['found']and not row['vulnerabilities']['count']and not row['warnings'],'RustSec audit not clean');audits[label]=row
  artifacts=examples(cmd,workspace)
  for label,receipt in [('normal',a.normal_receipt),('deterministic',a.deterministic_receipt)]:
   cmd.run(label+'-probe-build',[sys.executable,'-B',TOOLS/'build_probe.py','--normal-receipt',receipt,'--reference-helper',a.reference_helper,'--output',out/(label+'-probe')])
   c_receipt=json.loads((out/(label+'-probe/result.json')).read_text());cmd.bind(c_receipt['binary']['path'])
   args=['--package',copied_package,'--normal-receipt',receipt,'--c-probe',out/(label+'-probe/result.json'),'--rust-probe',artifacts['probe'],'--reference-helper',a.reference_helper]
   if label=='normal':cmd.run('normal-core',[sys.executable,'-B',TOOLS/'compare.py',*args,'--output',out/'normal-core'])
   cmd.run(label+'-signed',[sys.executable,'-B',TOOLS/'signed_compare.py',*args,'--rust-vectors',artifacts['vectors'],'--output',out/(label+'-signed')])
  core=json.loads((out/'normal-core/result.json').read_text());require(core['status']=='passed'and core['cases']==867 and not core['differences'],'complete867 core observations required')
  for label in('normal','deterministic'):
   row=json.loads((out/(label+'-signed/result.json')).read_text());require(row['status']=='passed'and row['cases']==1296 and row['vectors']==44 and row['c_built']==22 and row['rust_built']==22 and not row['differences'],'complete1296 signed/two-way observations required')
  cmd.check_artifacts();shared.same(archives(copied_meta['all-features'],a.cargo_home),registry,'registry archive/extracted inputs')
  for row,expected in zip((r,d),refs_before):shared.same(reference_inputs(row,a.reference_helper),expected,'normal source/library/provider/compiler input set')
  for receipt in(a.normal_receipt,a.deterministic_receipt):normal(receipt,a.reference_helper)
  shared.same(source_state(pathlib.Path(r['source'])),state,'all fixed tracked C sources')
  shared.same(shared.tree(a.audit_db),audit_before,'fixed RustSec database complete file set')
  require(origin_cmd.run('audit-db-revision-after',['git','-C',a.audit_db,'rev-parse','HEAD']).decode().strip()==revision,'RustSec HEAD changed')
  require(not origin_cmd.run('audit-db-clean-after',['git','-C',a.audit_db,'status','--porcelain','--untracked-files=no']),'RustSec dirty after')
  require(all(sha(path)==digest for path,digest in external.items()),'external receipt/tool bytes changed')
  final_metadata={name:cmd.metadata('final-metadata-'+name,flags)for name,flags in profiles.items()}
  shared.same(shared.workspace_contract(workspace,final_metadata),contract,'final full workspace contracts')
  shared.same(shared.tree(workspace),before,'complete copied workspace before/after');shared.same(shared.tree(origin),before,'complete original Root before/after');shared.same(shared.tree(TOOLS),tool_before,'actual all maintained tools/support file set');require(sha(shared.__file__)==helper_before,'reviewed helper changed')
  result={'status':'passed-development-complete-workspace-block-profile'if a.development_snapshot else'passed-current-integrated-block-profile','inputs_unchanged':True,'current_original_root_proof':not a.development_snapshot,'scope':'Actual BLOCK package, complete Root/settings/two-lock contracts, actual noalloc fixture M0/M4, finite safe normal C library/plugin comparisons only. No BLOCK owner or subsystem promotion.','source_files':len(before),'source_before':before,'source_after':shared.tree(origin),'tool_inputs':tool_before,'shared_workspace_helper':{'path':shared.__file__,'sha256':helper_before},'dependency_contract':dependencies,'root_lint_contract':lints,'complete_contract_profiles':list(profiles),'noalloc_target_graphs':graphs,'actual_architecture_checks':architecture,'registry_note':contract['registry_note'],'new_registry_archives':registry,'rust_test_names':sorted(rust_names),'rust_doc_names':doc_names,'tool_control_names':sorted(names),'original_tool_controls_preserved':14,'actual_reference_negative_controls':reference_controls,'audit_revision':revision,'audits':audits,'normal_core_cases':867,'normal_signed_cases':1296,'deterministic_signed_cases':1296,'normal_reference_inputs':refs_before,'external_inputs':external,'cargo_json_artifacts':cmd.artifacts,'commands':[*origin_cmd.rows,*cmd.rows],'seconds':time.monotonic()-started,'whole_owners_promoted':0,'full_subsystems_promoted':0}
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'receipt':str(out/'result.json')}))
 except BaseException as error:
  (out/'failure.json').write_text(json.dumps({'error':str(error),'commands':[*origin_cmd.rows,*(cmd.rows if cmd else[])]},indent=2)+'\n');raise
if __name__=='__main__':main()
