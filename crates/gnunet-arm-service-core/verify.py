#!/usr/bin/env python3
"""Fresh portable pure ARM service proof; no native C library/process execution."""
import argparse,ast,hashlib,json,os,pathlib,re,shutil,subprocess,sys
sys.dont_write_bytecode=True
BASE=pathlib.Path(__file__).resolve().parent
TOOLCHAIN='1.99.1'
EXPECTED={'real_reap_is_not_lost_to_optional_resource_pressure', 'boundaries::native_epoch_exhaustion_rejects_admission_before_reserving_or_starting', 'boundaries::future_and_forever_duration_zero_saturating_restart_preserves_sentinel', 'real_timer_registration_firing_clock_regression_and_cancel_are_distinct', 'boundaries::listener_timer_native_and_output_max_cannot_block_actual_shutdown_cleanup', 'list_envelope_is_actual_snapshot_while_service_state_changes', 'source_self_stop_is_queued_then_generic_trigger_and_does_not_forge_eof', 'boundaries::actual_native_ack_and_final_term_ignore_output_and_attempt_counter_exhaustion', 'exact_source_backoff_origin_and_failed_scan_do_not_spin', 'shutdown_during_pending_spawn_really_requests_term_after_actual_admission', 'empty_configured_service_name_is_not_rejected_by_an_extra_private_policy', 'old_readiness_registration_cannot_launch_after_a_new_arm', 'boundaries::native_attempt_epoch_does_not_wrap_or_grant_duplicate_lease', 'boundaries::zero_client_storage_real_child_lifecycle_is_not_an_output_budget', 'startup_gate_waits_all_real_attempts_and_does_not_replay_service_snapshot', 'boundaries::exhausted_demand_records_consumed_registration_without_a_fake_starting_child', 'monitor_duplicates_deduplicate_and_queue1024_is_still_allowed', 'boundaries::child_generation_and_envelope_sequence_exhaustion_reject_before_reservation', 'native_failure_and_admission_are_distinct_from_unexecuted_effect', 'boundaries::frame65535_registry_is_allowed_65536_rejected_before_metadata_mutation', 'leased_arm_is_not_lost_when_spawn_changes_desired_readiness', 'boundaries::duplicate_monitor_needs_no_new_registration_epoch_when_counter_exhausted', 'boundaries::actual_reap_with_reserved_stop_reply_at_max_retires_child_and_client', 'self_stop_required_reservation_cannot_overwrite_another_clients_reused_slot', 'boundaries::startup_and_restart_cursor_never_skip_a_counter_exhausted_forced_service', 'old_native_attempt_cannot_ack_new_stop_of_same_child', 'every_parent_listener_close_is_acknowledged_before_any_child_term', 'wire_baseline_unknown_extension_reserved_list_and_snapshot', 'foreign_readiness_listener_timer_and_runtime_shutdown_leases_are_rejected', 'capacity_rejection_has_no_partial_start_or_native_authority', 'foreign_scopes_with_identical_slot_generations_cannot_authorize_other_owner', 'per_client_output_order_pinned_lease_and_stale_ticket', 'clean_exit_never_schedules_forced_restart_by_itself'}

EXPECTED.add('boundaries::original_service_membership_survives_retirement_without_restoring_active_authority')
EXPECTED.add('boundaries::empty_owner_identity_is_distinct_and_survives_registry_shutdown')
EXPECTED.add('boundaries::draining_keeps_new_control_test_and_in_shutdown_start_until_final_runtime_close')

def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def files(root):return [p for p in root.rglob('*') if p.is_file() and not {'target','__pycache__','.git'}&set(p.relative_to(root).parts)]
def snapshot(paths):return {str(p):digest(p) for p in sorted(set(paths),key=lambda p:os.fsencode(str(p)))}
def contract(package):
 keys=['name','req','source','kind','rename','optional','uses_default_features','target','path']
 return package['features'],sorted([{**{k:d.get(k) for k in keys},'features':sorted(d['features'])} for d in package['dependencies']],key=lambda d:json.dumps(d,sort_keys=True))
def normal_graph(meta,manifest):
 packages={p['id']:p for p in meta['packages']};nodes={n['id']:n for n in meta['resolve']['nodes']}
 selected=next(p['id'] for p in meta['packages'] if pathlib.Path(p['manifest_path']).resolve()==manifest.resolve())
 pending=[selected];seen={}
 while pending:
  ident=pending.pop()
  if ident in seen:continue
  p=packages[ident];node=nodes[ident]
  assert not node['features'],(p['name'],node['features'])
  seen[ident]={'name':p['name'],'features':node['features']}
  for dep in node['deps']:
   if any(k['kind'] is None for k in dep['dep_kinds']):pending.append(dep['pkg'])
 assert {p['name'] for p in seen.values()}=={'gnunet-arm-service-core','gnunet-arm-core','gnunet-types','gnunet-wire'}
 return seen

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repository',required=True,type=pathlib.Path);parser.add_argument('--output',required=True,type=pathlib.Path);parser.add_argument('--upstream',type=pathlib.Path);args=parser.parse_args()
 repo=args.repository.resolve();out=args.output.resolve();upstream=args.upstream.resolve() if args.upstream else None
 roots=[repo,BASE]+([upstream] if upstream else [])
 for source in roots:assert not(out==source or out.is_relative_to(source) or source.is_relative_to(out)),'output overlaps input: '+str(source)
 out.mkdir(mode=0o700);commands=[];env=os.environ.copy();env['CARGO_BUILD_JOBS']='2';env['CARGO_TARGET_DIR']=str(out/'target')
 def run(label,cmd,extra=None,success=True):
  e=env.copy();e.update(extra or {});r=subprocess.run([str(x) for x in cmd],cwd=repo,env=e,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
  commands.append({'label':label,'argv':[str(x) for x in cmd],'exit':r.returncode,'stdout_sha256':hashlib.sha256(r.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(r.stderr).hexdigest()})
  if success:assert r.returncode==0,(label,r.returncode,r.stderr.decode(errors='replace')[-6000:])
  return r
 inventory=json.loads((BASE/'source-inventory.json').read_text());assert len(inventory['requirements'])==121 and len(inventory['sources'])==22
 source_paths=[]
 if upstream:
  assert subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()==inventory['pin']['revision']
  source_paths=[upstream/p for p in inventory['sources']]
  assert all(digest(upstream/p)==v['sha256'] for p,v in inventory['sources'].items())
 def discover():
  paths=files(BASE)
  for name in ['gnunet-types','gnunet-wire','gnunet-arm-core']:paths+=files(repo/'crates'/name)
  paths += [repo/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml']]
  return paths+source_paths
 before=snapshot(discover());(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
 rust=out/'rust';rust.mkdir()
 for name in ['src','tests']:shutil.copytree(BASE/name,rust/name)
 template=(BASE/'Cargo.toml.in').read_text();rendered=template.replace('@ARM_CORE_PATH@',json.dumps(str(repo/'crates/gnunet-arm-core'))).replace('@TYPES_PATH@',json.dumps(str(repo/'crates/gnunet-types')))
 assert '@ARM_CORE_PATH@' not in rendered and '@TYPES_PATH@' not in rendered
 # Exact current root policy; actual standalone or workspace-inherited package
 # must retain the same lint obligations as the generated independent crate.
 root_text=(repo/'Cargo.toml').read_text();root_lints=root_text[root_text.index('[workspace.lints.rust]'):root_text.index('[workspace.dependencies]')].replace('[workspace.lints.','[lints.').strip()
 assert rendered[rendered.index('[lints.rust]'):].strip()==root_lints,'template root lint policy differs'
 actual_manifest=(BASE/'Cargo.toml').read_text()
 if '[lints.rust]' in actual_manifest:assert actual_manifest[actual_manifest.index('[lints.rust]'):].strip()==root_lints,'actual package lint policy differs'
 else:assert re.search(r'(?ms)^\[lints\]\s*\n\s*workspace\s*=\s*true\s*(?:\n|$)',actual_manifest),'actual package must inherit current root lints'
 (rust/'Cargo.toml').write_text(rendered);shutil.copy2(repo/'Cargo.lock',rust/'Cargo.lock')
 cargo=['cargo','+'+TOOLCHAIN]
 generated_meta=json.loads(run('generated-metadata',cargo+['metadata','--manifest-path',rust/'Cargo.toml','--offline','--format-version','1']).stdout)
 actual_meta=json.loads(run('production-metadata',cargo+['metadata','--manifest-path',BASE/'Cargo.toml','--offline','--locked','--no-deps','--format-version','1']).stdout)
 generated=next(p for p in generated_meta['packages'] if pathlib.Path(p['manifest_path']).resolve()==(rust/'Cargo.toml').resolve())
 actual=next(p for p in actual_meta['packages'] if pathlib.Path(p['manifest_path']).resolve()==(BASE/'Cargo.toml').resolve())
 assert contract(generated)==contract(actual),'generated dependencies/features differ from actual production package'
 assert all(generated[k]==actual[k] for k in ['name','version','edition','license','rust_version'])
 graph=normal_graph(generated_meta,rust/'Cargo.toml');(out/'normal-graph.json').write_text(json.dumps(graph,indent=2)+'\n')
 assert all(not p.get('source','') for p in generated_meta['packages']),'no new registry dependency is permitted'
 generated_before=snapshot(files(rust));(out/'generated-before.json').write_text(json.dumps(generated_before,indent=2)+'\n')
 shared=['--manifest-path',rust/'Cargo.toml','--offline','--locked','--target-dir',out/'target','-j','2']
 run('fmt',cargo+['fmt','--manifest-path',rust/'Cargo.toml','--check'])
 tests=run('tests',cargo+['test']+shared);text=(tests.stdout+tests.stderr).decode();names=re.findall(r'^test (.+?) \.\.\. ok$',text,re.M)
 unit=[n for n in names if not n.startswith('src/lib.rs - Frame')];docs=[n for n in names if n.startswith('src/lib.rs - Frame')]
 assert set(unit)==EXPECTED and len(unit)==36,(unit,EXPECTED)
 assert len(docs)==2 and sum('compile fail' in n for n in docs)==1
 run('clippy',cargo+['clippy','--all-targets']+shared)
 run('rustdoc',cargo+['doc','--no-deps']+shared,{'RUSTDOCFLAGS':'-D warnings'})
 for target in ['thumbv6m-none-eabi','thumbv7em-none-eabi']:run(target,cargo+['check','--target',target]+shared)
 libs=list((out/'target/debug/deps').glob('libgnunet_arm_service_core-*.rlib'));assert len(libs)==1,libs
 negative='''use gnunet_arm_service_core::Owner;\npub fn invalid(owner:&mut Owner<'_, '_, '_, '_>){if let Some(frame)=owner.frame(){owner.begin_shutdown(0);core::hint::black_box(frame.bytes);}}\n'''
 positive='''use gnunet_arm_service_core::Owner;\npub fn valid(owner:&mut Owner<'_, '_, '_, '_>){let mut copy=[0;64];if let Some(frame)=owner.frame(){let n=frame.bytes.len().min(copy.len());copy[..n].copy_from_slice(&frame.bytes[..n]);let ticket=frame.ticket;let _result=owner.release_frame(ticket);owner.begin_shutdown(0);}core::hint::black_box(copy);}\n'''
 for label,code,valid in [('borrow-negative',negative,False),('borrow-positive',positive,True)]:
  path=out/(label+'.rs');path.write_text(code)
  result=run(label,['rustc','+'+TOOLCHAIN,'--edition=2024','--crate-type=lib','--crate-name',label.replace('-','_'),'--extern','gnunet_arm_service_core='+str(libs[0]),'-L','dependency='+str(out/'target/debug/deps'),'--out-dir',out,path],success=valid)
  if not valid:assert result.returncode!=0 and re.findall(r'error\[(E\d+)\]',result.stderr.decode())==['E0499'],result.stderr.decode()
 run('scope-ui',[sys.executable,'-B',BASE/'tools/ui.py','--target',out/'target','--output',out/'scope-ui'])
 assert json.loads((out/'scope-ui/result.json').read_text())['status']=='passed'
 after=snapshot(discover());assert before==after,'input contents or file sets changed'
 generated_after=snapshot(files(rust));assert generated_before==generated_after,'generated package inputs changed'
 if upstream:assert all(digest(upstream/p)==v['sha256'] for p,v in inventory['sources'].items())
 (out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n');(out/'generated-after.json').write_text(json.dumps(generated_after,indent=2)+'\n')
 result={'schema':2,'status':'passed','scope':'source-derived pure ARM service core; no native C library/process/network/config/CLI/testing certification','inputs_unchanged':True,'generated_inputs_unchanged':True,'before':before,'after':after,'named_rust_tests':sorted(EXPECTED),'rust_test_count':36,'rustdoc_count':2,'exact_compile_fail':'E0499','positive_compile_control':True,'scope_reset_UI':{'negative':'E0499','positive':True},'production_feature_graph_empty':True,'normal_closure_package_count':4,'production_template_contract_matches':True,'root_lint_policy_matches':True,'source_design_obligations_retained':121,'upstream_hashes_checked':22 if upstream else 0,'upstream_revision':inventory['pin']['revision'] if upstream else None,'commands':commands,'pending':'README.md actual host/config/native/C-oracle/CLI/testing obligations remain unaccepted'}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','rust_tests':36,'docs':2,'upstream_hashes':22 if upstream else 0,'result':str(out/'result.json')}))
if __name__=='__main__':main()
