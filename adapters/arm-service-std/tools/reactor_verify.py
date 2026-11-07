#!/usr/bin/env python3
"""Verify actual ARM daemon reactor components with fresh bounded process/socket witnesses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import itertools

sys.dont_write_bytecode = True
PACKAGE = Path(__file__).resolve().parents[1]
REQUIRED = {'dedicated_registry_rejects_foreign_live_child_and_returns_foreign_actual_completion_without_core_reap','malformed_port_is_zero_but_range_and_boolean_are_fatal', 'zero_small_and_over_capacity_frames_retire_without_synthetic_empty_buffer_eof', 'native_numeric_input_has_exact_family_protocol_and_source_order', 'empty_registry_driver_reborrow_rejects_foreign_owner_without_touching_original_stream', 'actual_spawn_monitor_spelling_pipe_term_consuming_reap_and_original_argv0', 'expired_idle_restart_does_not_overtake_actual_fragmented_control_rx_or_nonempty_tx', 'sibling_disarm_and_every_actual_close_precede_term_admission', 'late_control_admission_survives_real_child_drain_and_persisted_requester_closes_on_owner_drop', 'actual_control_unix_test_list_fragment_cancel_unknown_and_malformed_eof', 'adopted_parent_listener_and_replaced_owned_path_are_never_unlinked', 'immediate_noarmbind_and_ondemand_branching_retains_nonlisteners', 'category_absence_yes_no_and_invalid_follow_source_selection', 'actual_nonzero_exit_restarts_at_idle_and_final_shutdown_cancels_the_original_timer', 'actual_host_child_capacity_refusal_has_no_ghost_and_does_not_block_original_term_or_reap', 'admitted_child_and_lease_survive_clock_error_and_driver_reborrow', 'no_endpoint_and_zero_port_do_not_invent_ephemeral_listener', 'partial_attachment_capacity_retains_native_owners_until_explicit_drop', 'all_services_remain_registered_and_head_insertion_order_is_preserved', 'foreign_owner_is_rejected_before_leasing_or_retiring_original_readiness', 'actual_idle_registration_survives_backward_utc_and_uses_original_absolute_target_after_forward_jump', 'every_managed_unix_path_is_closed_before_any_actual_control_term_byte', 'actual_two_listener_demand_preserves_kernel_queues_until_original_child_accepts', 'durable_fifo_and_mq_length_follow_partial_actual_write_attempts', 'fragmented_header_and_body_survive_cancel_and_do_not_advance_until_consumed', 'caller_capacity_rejects_complete_registry_and_recursive_substitutions', 'unix_only_does_not_resolve_an_irrelevant_bindto', 'queued_unix_connection_survives_readiness_cancel_disarm_and_actual_child_inheritance', 'canceled_drive_retains_real_partial_list_tx_and_blocked_peer_does_not_block_other_control', 'stale_socket_only_precheck_regular_and_live_entries_are_preserved', 'simple_filename_argv0_options_and_global_substitution_are_source_exact', 'actual_tcp_child_receives_queued_data_and_v6_is_v6only', 'registry_cross_section_binding_and_permission_precedence_follow_source'}

REQUIRED |= {'ready_clients_and_each_stream_direction_progress_before_an_earlier_backlog_drains', 'queued_managed_demand_progresses_while_control_input_remains_ready'}
REQUIRED.add('persisted_self_stop_malformed_message_keeps_actual_socket_until_external_state_drop')



def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(directory):
    return {p.resolve() for p in directory.rglob("*") if p.is_file()
            and not {"target", ".git", "__pycache__"}.intersection(p.relative_to(directory).parts)}


def snapshot(paths):
    return {str(p): sha(p) for p in sorted(paths, key=lambda p: os.fsencode(str(p)))}


def lint_sections(text, prefix):
    result = {}
    for section in ("rust", "clippy", "rustdoc"):
        found = re.search(r"(?ms)^\[" + re.escape(prefix + section)
                          + r"\]\s*\n(.*?)(?=^\[|\Z)", text)
        if not found:
            raise ValueError("missing complete lint section: " + section)
        result[section] = "\n".join(line.strip() for line in found.group(1).splitlines()
                                    if line.strip() and not line.strip().startswith("#"))
    return result


def package_contract(package):
    fields = ("name", "req", "source", "kind", "rename", "optional",
              "uses_default_features", "target", "path")
    dependencies = [{**{key: row.get(key) for key in fields},
                     "features": sorted(row["features"])} for row in package["dependencies"]]
    return {"dependencies": sorted(dependencies, key=lambda row: json.dumps(row, sort_keys=True)),
            "features": {key: sorted(value) for key, value in package["features"].items()
                         if key != "default" or value},
            **{key: package[key] for key in ("name", "version", "edition", "license", "rust_version")}}


def select(metadata, directory):
    return next(row for row in metadata["packages"]
                if Path(row["manifest_path"]).resolve() == directory / "Cargo.toml")


def test_names(text, expected, required):
    names = re.findall(r"^test (.+?) \.\.\. ok$", text, re.M)
    docs = [name for name in names if ".rs - " in name]
    runtime = [name for name in names if name not in docs]
    if len(runtime) != expected or len(runtime) != len(set(runtime)) or not required <= set(runtime):
        raise ValueError("runtime witnesses missing, duplicated or unexpected: " + repr(runtime))
    return runtime, docs


PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'

def validate_reference_details(value, source):
    source=Path(source).resolve()
    if (value.get('status')!='passed' or value.get('source_unchanged')is not True
            or value.get('kind')!='unmodified-official-c-arm-reference-build'
            or value.get('upstream',{}).get('revision')!=PIN
            or value.get('upstream',{}).get('tag')!='v0.29.1'):
        raise ValueError('normal reference status/kind/revision mismatch')
    if 'source' in value and Path(value['source']).resolve()!=source:
        raise ValueError('normal reference source path mismatch')
    setup=[row for row in value['commands']if row['name']=='meson-setup']
    if (len(setup)!=1 or setup[0]['exit_code']!=0 or setup[0]['argv'][1]!='setup'
            or Path(setup[0]['argv'][2]).resolve()!=Path(value['build']).resolve()
            or Path(setup[0]['argv'][3]).resolve()!=source):
        raise ValueError('normal reference successful source/build setup mismatch')

def require_disjoint(output, protected):
    output=Path(output).resolve()
    for value in protected:
        value=Path(value).resolve()
        if output==value or output in value.parents or value in output.parents:
            raise ValueError('output overlaps protected input')
    if output.exists():raise ValueError('output must be fresh')
    return output

def pair_cases(value):
    expected=set(itertools.product(('normal','rust'),('c','rust'),('unix','tcp4')))
    if (value.get('status')!='passed' or value.get('inputs_unchanged')is not True
            or value.get('case_count')!=8 or len(value.get('cases',[]))!=8
            or {(r.get('server'),r.get('actor'),r.get('profile'))for r in value['cases']}!=expected
            or any(r.get('actor_exit')!=0 or r.get('daemon_exit')!=0
                   or not r.get('only_owned_endpoint')or not r.get('natural_process_cleanup')
                   for r in value['cases'])):
        raise ValueError('all actual nonempty8 C/Rust/Unix/TCP cases are required')
    for row in value['cases']:
        events=row.get('events',[])
        done=[event for event in events if event.get('event')=='done']
        stopped=[event for event in events if event.get('event')=='stop-arm']
        if len(done)!=1 or len(stopped)!=1 or (stopped[0].get('status'),stopped[0].get('result'))not in [(0,0),(2,None)]:
            raise ValueError('actual nonempty terminal actor events required')
        if row['actor']=='c':
            if done[0].get('failed')!=0 or done[0].get('monitors',0)<4:
                raise ValueError('actual normal C public callbacks missing')
        elif (done[0].get('results')!=9 or done[0].get('helper_children')!=0
                or not done[0].get('canceled_callback_suppressed')or done[0].get('repeat_connections',0)<2):
            raise ValueError('actual Rust owner callback chain missing')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('repository','source','reference','output'):parser.add_argument('--'+key,type=Path,required=True)
    a=parser.parse_args();repo,source,reference=map(lambda p:p.resolve(),(a.repository,a.source,a.reference))
    # Existing normal receipt remains immutable; output is external to every
    # declared source, installed prefix, build tree and original candidate.
    normal=json.loads(reference.read_text());validate_reference_details(normal,source)
    out=require_disjoint(a.output,[PACKAGE,repo,source,reference.parent,normal['build'],normal['prefix']]);out.mkdir(mode=0o700)
    commands=[];cargo=['cargo','+1.99.1'];env=dict(os.environ,CARGO_BUILD_JOBS='1',CARGO_TARGET_DIR=str(out/'target'))
    started=time.monotonic()
    def run(label,argv,timeout=300,extra=None):
        current=env.copy();current.update(extra or {});done=subprocess.run(list(map(str,argv)),cwd=repo,env=current,capture_output=True,timeout=timeout)
        for name in ('stdout','stderr'):(out/(label+'.'+name)).write_bytes(getattr(done,name))
        commands.append({'name':label,'argv':list(map(str,argv)),'cwd':str(repo),'exit':done.returncode,'stdout_sha256':sha(out/(label+'.stdout')),'stderr_sha256':sha(out/(label+'.stderr'))})
        if done.returncode:raise RuntimeError(label+' failed; see '+str(out/(label+'.stderr')))
        return done.stdout.decode(errors='replace')
    def metadata(path,locked=True):
        return json.loads(run('metadata-'+str(len(commands)),cargo+['metadata','--manifest-path',path,'--offline','--format-version=1']+(['--locked']if locked else [])))
    try:
        sys.path.insert(0,str(repo/'adapters/arm-std/tools'));import reference as normal_reference
        _,normal_inputs=normal_reference.load(reference,source,repo)
        actual=metadata(PACKAGE/'Cargo.toml')
        repository_metadata=metadata(repo/'Cargo.toml')
        root_lints=lint_sections((repo/'Cargo.toml').read_text(),'workspace.lints.')
        text=(PACKAGE/'Cargo.toml').read_text()
        inherited=re.search(r'(?ms)^\[lints\]\s*\n\s*workspace\s*=\s*true\s*(?:\n|$)',text)
        if not inherited and lint_sections(text,'lints.')!=root_lints:raise ValueError('actual complete root lint contract mismatch')
        template=(PACKAGE/'Cargo.toml.in').read_text()
        if lint_sections(template,'lints.')!=root_lints:raise ValueError('portable complete root lint contract mismatch')
        # Discover the full local source closure before creating/building any
        # output. Every later comparison re-enumerates names, including additions.
        def discover():
            value,current=normal_reference.load(reference,source,repo);validate_reference_details(value,source)
            if value!=normal or current!=normal_inputs:raise ValueError('normal reference changed')
            paths=files(PACKAGE)|{repo/'Cargo.toml',repo/'Cargo.lock',repo/'rust-toolchain.toml',repo/'rustfmt.toml',repo/'adapters/arm-std/tools/reference.py',repo/'tools/reference/build_reference.py',repo/'crates/gnunet-arm-service-core/source-inventory.json',reference}
            for row in [*actual['packages'],*repository_metadata['packages']]:
                if row['source']is None:paths|=files(Path(row['manifest_path']).resolve().parent)
            paths|={Path(path)for path in normal_inputs}
            projection=json.loads((PACKAGE/'reactor-obligations.json').read_text())
            inventory=json.loads((repo/'crates/gnunet-arm-service-core/source-inventory.json').read_text())
            if len(projection['sources'])!=22 or len(inventory['sources'])!=22 or len(inventory['requirements'])!=121:raise ValueError('all22 source/121 obligations required')
            projected=projection.get('requirements',projection.get('obligations',[]))
            if isinstance(projected,dict):projected=list(projected.values())
            if len(projected)!=121:raise ValueError('reactor obligation projection truncated')
            if {r['id']for r in projected}!={r['id']for r in inventory['requirements']}:raise ValueError('reactor obligation identities changed')
            for name,row in projection['sources'].items():
                path=source/name
                if sha(path)!=row['sha256']:raise ValueError('official source anchor changed '+name)
                paths.add(path)
            return snapshot(paths)
        before=discover();(out/'inputs-before.json').write_text(json.dumps(before,indent=2)+'\n')
        generated=out/'rust';generated.mkdir()
        for name in ('src','tests','examples','tools'):shutil.copytree(PACKAGE/name,generated/name)
        for name in ('reactor-obligations.json','REACTOR.md','README.md','Cargo.toml.in'):
            shutil.copy2(PACKAGE/name,generated/name)
        rendered=re.sub(r'"@REPOSITORY@/([^"\n]+)"',lambda m:json.dumps(str(repo/m.group(1))),template)
        if '@REPOSITORY@'in rendered:raise ValueError('unresolved repository placeholder')
        (generated/'Cargo.toml').write_text(rendered);shutil.copy2(repo/'Cargo.lock',generated/'Cargo.lock')
        isolated=metadata(generated/'Cargo.toml',False)
        actual_contract=package_contract(select(actual,PACKAGE))
        # A development candidate can live outside a relocated repository. Its
        # declared logical path roles are fixed by the reviewed template; path
        # prefixes alone are remapped, without changing kinds/features/source.
        roles=dict(re.findall(r'(?m)^([a-zA-Z0-9_-]+)\s*=\s*\{\s*path\s*=\s*"@REPOSITORY@/([^"\n]+)"',template))
        for dependency in actual_contract['dependencies']:
            if dependency.get('path')is not None:
                suffix=roles.get(dependency['name'])
                if suffix is None or not Path(dependency['path']).as_posix().endswith('/'+suffix):raise ValueError('unreviewed local path role')
                dependency['path']=str(repo/suffix)
        actual_contract['dependencies']=sorted(actual_contract['dependencies'],key=lambda row:json.dumps(row,sort_keys=True))
        if actual_contract!=package_contract(select(isolated,generated)):
            raise ValueError('generated complete dependency/features/source contract differs')
        generated_before=snapshot(files(generated))
        run('format',cargo+['fmt','--manifest-path',generated/'Cargo.toml','--check'])
        run('sole-production-helper',cargo+['build','--manifest-path',repo/'Cargo.toml','--locked','--offline','--target-dir',out/'target','-p','gnunet-arm-host','--bin','gnunet-arm-spawn-helper','-j','1'])
        tests=run('tests',cargo+['test','--manifest-path',generated/'Cargo.toml','--locked','--offline','-j','1','--','--test-threads=1'])
        names,docs=test_names(tests,36,REQUIRED)
        if len(docs)!=2 or sum('compile fail'in name for name in docs)!=1 or any('framed::FramedConnection::poll_receive'not in name for name in docs):raise ValueError('actual borrowed RX negative/owned-copy positive docs missing')
        run('clippy',cargo+['clippy','--manifest-path',generated/'Cargo.toml','--locked','--offline','--all-targets','-j','1','--','-D','warnings'])
        run('rustdoc',cargo+['doc','--manifest-path',generated/'Cargo.toml','--locked','--offline','--no-deps','-j','1'],extra={'RUSTDOCFLAGS':'-D warnings'})
        run('tool-controls',[sys.executable,'-B',PACKAGE/'tools/test_reactor_tools.py'])
        controls=(out/'tool-controls.stderr').read_text()
        expected_controls={'test_added_deleted_changed_source_paths_are_detected','test_dependency_feature_change_is_detected','test_duplicate_runtime_witness_is_rejected','test_empty_runtime_witness_is_rejected','test_missing_runtime_witness_is_rejected','test_reference_failed_setup_is_rejected','test_reference_wrong_kind_is_rejected','test_reference_wrong_revision_is_rejected','test_reference_wrong_source_or_build_is_rejected','test_output_source_or_ancestor_is_rejected','test_pair_empty_or_duplicate_actual_cases_is_rejected'}
        actual_controls=set(re.findall(r'^(test_\w+) \(__main__\.[^)]+\) \.\.\. ok$',controls,re.M))
        if actual_controls!=expected_controls or 'Ran 11 tests'not in controls or not controls.rstrip().endswith('OK'):raise ValueError('exact nonempty11 negative controls required')
        run('actual-daemon-pair',[sys.executable,'-B',PACKAGE/'tools/reactor_pair.py','--package',generated,'--repository',repo,'--upstream',source,'--reference',reference,'--output',out/'pair'],timeout=300)
        pair=json.loads((out/'pair/result.json').read_text());pair_cases(pair)
        # The generated lock and source set were finalized before any build.
        # No target/Cargo.lock mutation in original source is accepted.
        after=discover();(out/'inputs-after.json').write_text(json.dumps(after,indent=2)+'\n')
        if before!=after or generated_before!=snapshot(files(generated)):raise ValueError('source/generated file added/deleted/changed')
        result={'status':'passed','scope':'bounded Unix/TCP ARM daemon reactor component with actual C/Rust public clients and original PID/wait/listener ownership; not full PROGRAM/CLI/testing/OS acceptance','inputs_unchanged':True,'generated_inputs_unchanged':True,'source_obligations_retained':121,'upstream_anchors':22,'runtime_count':len(names),'runtime_names':names,'rustdoc_count':len(docs),'rustdoc_names':docs,'tool_control_count':11,'tool_controls':sorted(actual_controls),'actual_pair_cases':8,'pair_result':{'path':str(out/'pair/result.json'),'sha256':sha(out/'pair/result.json')},'complete_root_lints':True,'declared_dependency_contract_matches':True,'commands':commands,'elapsed_seconds':time.monotonic()-started,'input_manifest_sha256':sha(out/'inputs-before.json'),'full_ARM_verified_promotion':False}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'passed','runtime_count':len(names),'rustdoc_count':len(docs),'pair_cases':8,'result':str(out/'result.json')}))
    except BaseException as error:
        (out/'failure.json').write_text(json.dumps({'status':'failed','error':str(error),'commands':commands},indent=2)+'\n');raise

if __name__=='__main__':main()
