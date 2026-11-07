"""Fail-closed nonempty witness validation, separate from running executables."""
import re

SHORT_RUST={
'native_spawn::tests::positive_posix_errno_is_never_success',
'process::boundaries::helper_check_observes_xok_then_uid_then_nonroot_stat_without_file_type_policy',
'process::boundaries::exhausted_admission_generation_cannot_block_original_signal_and_reap',
'process::boundaries::interrupted_and_zero_write_seams_execute_real_kill_without_false_pipe_success',
'process::boundaries::child_identity_uses_arc_address_and_token_keeps_old_identity_alive',
'registry_echild_retires_original_pid_once_without_fabricating_wait_success',
'actual_fixture_readiness_eof_is_starting_and_child_is_reaped',
'missing_binary_nonexecutable_and_late_exec_failure_are_distinct',
'cancellation_and_disconnect_close_original_signal_without_killing_child',
'dropping_host_retains_original_live_child_wait_authority_in_caller_registry',
'one_signal_credit_defers_second_start_and_callback_reentry_until_cleanup',
'child_registry_credit_does_not_block_first_signal_cleanup_and_resumes_after_consuming_wait',
'canceled_unperformed_local_setup_creates_no_child_and_missing_helper_is_real_setup_failure',
'quiet_connected_mq_and_unbounded_drive_wake_on_owned_child_exit_to_release_registry_credit',
'fragmented_unix_all_remote_requests_cancellation_and_list_borrow',
'physical_eof_distinguishes_stopping_waiter_from_pending_stop',
'bad_registered_frame_retires_one_epoch_without_replaying_operations',
'invalid_initial_configuration_reports_each_original_unavailable_once',
'unavailable_socket_retries_inside_original_mq_and_preserves_queued_list',
'canceled_drive_under_real_socket_backpressure_keeps_every_original_byte_once',
 'tcp_monitor_raw_status_reconnect_and_stop_inside_callback',
}
SHARED_PROCESS_RUST={
'native_spawn::tests::positive_posix_errno_is_never_success',
'process::boundaries::helper_check_observes_xok_then_uid_then_nonroot_stat_without_file_type_policy',
'process::boundaries::exhausted_admission_generation_cannot_block_original_signal_and_reap',
'process::boundaries::interrupted_and_zero_write_seams_execute_real_kill_without_false_pipe_success',
'process::boundaries::child_identity_uses_arc_address_and_token_keeps_old_identity_alive',
}
RUNTIME_SUPPLEMENTARY_RUST={'process::boundaries::unrelated_child_notification_cannot_suspend_the_next_owned_death'}
RUNTIME_ORIGINAL_RUST={
'activation::tests::inactive_outer_predicate_matches_c_and_avoids_overflow',
'activation::tests::official_numeric_names_are_not_systemd_names_or_sequential_guesses',
'activation::tests::no_prefix_success_duplicate_owner_or_invalid_descriptor_number',
'activation::private_backlog_tests::actual_bound_path_is_cleaned_when_first_listen_fails',
'readiness::tests::errors_hangup_invalid_and_empty_are_distinct',
}
LONG_RUST='actual_sixty_second_signal_deadline_keeps_starting_without_readiness'
STDIO_CASES={(closed,flags,0)for closed in range(8)for flags in range(8)}|{(0,flags,clo)for flags in [0,7,8,15]for clo in [1,2,4,7]}
C_NULL_READY={(closed,flags,0)for closed,flags_set in [(3,[0,1,4,5]),(5,[0,1,2,3]),(6,[0,1,2,3]),(7,[0,1,4,5])]for flags in flags_set}
C_OCCUPIED_STDERR={(7,6,0),(7,7,0)}


def require_test_output(output,expected):
    names=re.findall(r'^test ([^\n]+?) \.\.\. ok$',output,re.MULTILINE)
    if not expected or len(names)!=len(expected)or set(names)!=set(expected):
        raise ValueError('exact nonempty actual Rust test names did not execute')
    if re.search(r'test result: (?:FAILED|ok\. 0 passed)',output):
        raise ValueError('failed or empty Rust test group')
    return sorted(names)


def require_docs(output,source_prefix=''):
    names=re.findall(r'^test ('+re.escape(source_prefix)+r'src/(?:control|monitor_host)\.rs - [^\n]+?) \.\.\. ok$',output,re.MULTILINE)
    logical=[name[len(source_prefix):]for name in names]
    if len(names)!=4 or len(set(names))!=4 or sum('compile fail' in name for name in names)!=2 or sum(name.startswith('src/control.rs')for name in logical)!=2 or sum(name.startswith('src/monitor_host.rs')for name in logical)!=2:
        raise ValueError('two negative and two positive borrowed-lifetime docs did not execute')
    return names


def require_actor(observation):
    if observation.get('exit_code')!=0 or not observation.get('target')or not observation.get('caller'):
        raise ValueError('JSON alone is not a completed child observation')
    events=observation['caller']
    results=[row for row in events if row['event']=='result']
    done=[row for row in events if row['event']=='done']
    waits=[row for row in events if row['event']=='reaped']
    if len(results)!=1 or results[0]['status']!=0 or results[0]['result']!=2 or len(done)!=1 or done[0]['callbacks']!=1 or done[0]['children']!=1 or done[0]['failed']!=0 or len(waits)!=1 or waits[0]['exit']!=0 or waits[0]['signal']!=0:
        raise ValueError('startup callback or original PID wait observation missing')


def require_stdio(document):
    rows=document.get('cases',[])
    key=lambda row:(row['closed'],row['stdio'],row['cloexec'])
    if len(rows)!=80 or {key(row)for row in rows}!=STDIO_CASES:
        raise ValueError('exact nonempty 80 stdio profiles did not execute')
    different=set()
    for row in rows:
        case=key(row)
        if set(row['observations'])!={'c','rust'}:raise ValueError('both actual actors are required')
        for actor in ['c','rust']:require_actor(row['observations'][actor])
        rust=row['observations']['rust']['target'];native=row['observations']['c']['target']
        if rust['readiness_fd']<3 or rust['readiness_type']!=4096 or rust['readiness_cloexec']or not rust['readiness_nonblock']or rust['readiness_close_errno']!=0:
            raise ValueError('Rust did not retain actual owned nonblocking FIFO')
        for fd in range(3):
            should_close=(case[0]|case[2])&case[1]&(1<<fd)
            if should_close and rust['types'][fd]!=-1:raise ValueError('original inherited closed stdio reopened')
        norm=lambda target:{key:value for key,value in target.items()if key!='readiness_fd'}
        matched=norm(native)==norm(rust)
        if row['matched']!=matched:raise ValueError('falsified native match classification')
        if not matched:
            different.add(case)
            changed={name for name in native if name!='readiness_fd'and native[name]!=rust[name]}
            expected={'readiness_type','readiness_nonblock'}if case in C_NULL_READY else set()
            if case in C_OCCUPIED_STDERR or case in {(7,4,0),(7,5,0)}:expected|={'types','access','flags'}
            if changed!=expected:raise ValueError('unreviewed native field difference')
        if case in C_NULL_READY and (native['readiness_type']!=8192 or native['readiness_nonblock']):
            raise ValueError('source-defined native null-readiness defect not observed')
        if case in C_OCCUPIED_STDERR and native['types'][2]!=4096:
            raise ValueError('source-defined native occupied-stderr defect not observed')
    if different!=C_NULL_READY|C_OCCUPIED_STDERR or document.get('matched_cases')!=62 or len(document.get('differences',[]))!=18 or document.get('status')!='observed_native_differences':
        raise ValueError('18 real C differences must remain explicit, never all-matched')
    return {'observed_profiles':80,'actual_exec_parents':160,'native_matches':62,'native_known_differences':18,'rust_fifo_and_closed_stdio_checks':80,'native_equivalence':False}

PROCESS_RUST={
'directory_filename_is_admitted_before_the_actual_exec_refuses_it',
'full_pipe_kill_zero_retains_the_actual_writer_for_a_later_successful_signal',
'actual_filename_is_independent_of_raw_argv0_and_environment_cwd_are_preserved',
'original_multiple_listener_queues_survive_actual_helper_exec_and_parent_flags',
'overlapping_explicit_descriptor_targets_cannot_clobber_the_other_source',
'explicit_stdin_mapping_wins_without_mutating_the_parent_stdio',
'exact_one_control_byte_and_broken_pipe_fallback_have_real_distinct_effects',
'full_nonblocking_control_pipe_really_falls_back_to_original_pid_kill',
'capacity_completed_credit_and_foreign_or_retired_child_tokens_never_signal',
'nonexecutable_is_refused_but_late_missing_interpreter_is_real_admitted_exit_one',
}
