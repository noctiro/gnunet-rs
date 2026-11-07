"""Fail-closed exact witnesses for the additional live CLIENT candidate scope."""
import re

LIVE_TESTS={
'actual_monitor_cfg_update_then_eof_reports_one_unavailable_and_restore_does_not_retry',
'current_logical_mq_retries_new_unix_path_but_keeps_its_original_tcp_and_queued_id',
'live_configuration_update_during_partial_tx_keeps_original_stream_and_every_frame_once',
'live_update_does_not_retarget_or_wake_an_original_polled_connection_attempt',
}
LOCAL_TEST='live_configuration_is_sampled_when_local_setup_begins_and_never_replays_created_child'
LOOP_TESTS={
'fragmented_unix_all_remote_requests_cancellation_and_list_borrow',
'tcp_monitor_raw_status_reconnect_and_stop_inside_callback',
'physical_eof_distinguishes_stopping_waiter_from_pending_stop',
'bad_registered_frame_retires_one_epoch_without_replaying_operations',
'invalid_initial_configuration_reports_each_original_unavailable_once',
'unavailable_socket_retries_inside_original_mq_and_preserves_queued_list',
'canceled_drive_under_real_socket_backpressure_keeps_every_original_byte_once',
'malformed_list_rows_indices_nuls_prefix_and_result_retire_exact_original_mq',
'wrong_kind_unknown_ids_and_unregistered_frames_preserve_live_original_operation',
'maximum_name_and_capacity_rejection_are_atomic_and_stale_generation_cannot_cancel_reused_slot',
'canceled_and_disconnected_stop_waiters_reclaim_all_slots_without_callback_or_null_call',
'two_stop_waiters_keep_each_original_operation_through_replacement_and_real_eof',
'monitor_canceled_partial_rx_recovers_exact_callback_then_stop_closes_original_stream',
'foreign_owner_scope_cannot_cancel_an_original_operation_even_before_socket_io',
'valid_wire_reply_over_declared_host_rx_capacity_retires_mq_without_partial_callback',
}
COMMAND_LABELS={
'basic',*["options-"+item for item in ['words','spaces','tab','quoted-middle','quoted-empty','escaped-space','escaped-quote','backslashes','double-quoted','unicode','shell-literal']],
*["daemon-"+item for item in ['absent','yes','mixed','no','invalid','host-empty','host-present']],
*["config-"+item for item in ['relative','space','home']],*["prefix-"+item for item in ['absolute','empty','dollar']],
'binary-relative-libexec','missing-binary','nonexecutable','directory-late-exec','missing-interpreter-late-exec','actual-target-exit3','ready-byte-before-eof','path-first-nonexec','path-directory-then-executable','path-no-entry','prefix-dot-relative',
}

def tests(output, expected):
    names=re.findall(r'^test (.+?) \.\.\. ok$',output,re.MULTILINE)
    if not expected or len(names)!=len(expected) or set(names)!=set(expected) or 'test result: FAILED' in output:
        raise ValueError('exact nonempty actual named Rust witnesses required')
    return sorted(names)

def committed(document):
    if document.get('inputs_unchanged') is not True or not document.get('inputs'):
        raise ValueError('actual nonempty unchanged input commitment required')

def commands(document):
    committed(document)
    rows=document.get('cases',[])
    if document.get('status')!='passed' or document.get('paired_cases')!=36 or len(rows)!=36 or {row['label']for row in rows}!=COMMAND_LABELS:
        raise ValueError('exact 36 command profiles required')
    for row in rows:
        if row.get('matched')is not True or set(row['observations'])!={'c','rust'}:
            raise ValueError('both command actors and true match required')
        for actor in ['c','rust']:
            if row['observations'][actor]['exit_code']!=0:
                raise ValueError('late nonzero actor exit is not success')
    return sorted(COMMAND_LABELS)

def readpoint(document):
    committed(document)
    rows=document.get('actors',[])
    if document.get('status')!='passed' or len(rows)!=2 or {row['actor']for row in rows}!={'c','rust'} or document.get('daemon_exit')!=0:
        raise ValueError('both actual readpoint actors and original daemon exit required')
    if document.get('replacement_tcp_accepted')!=0 or document.get('actual_daemon_tcp_port')!=0:
        raise ValueError('new TCP fence must remain unused and actual daemon Unix-only')
    isolation=document.get('isolation',{})
    if isolation.get('system_services')is not False or isolation.get('base_entries')!=[] or isolation.get('binary_sections')!=[] or isolation.get('actual_native_list_counts')!=[0,0]:
        raise ValueError('zero-service isolation not actually established')
    for row in rows:
        if row.get('exit_code')!=0 or row['events'][-1]!={'event':'done','confirmed':1,'listed':1,'failed':0}:
            raise ValueError('actual readpoint actor did not finish')
    return 2

def daemon(document):
    committed(document)
    rows=document.get('cases',[])
    if document.get('status')!='passed' or len(rows)!=2 or {row['profile']for row in rows}!={'unix','tcp4'}:
        raise ValueError('two actual normal daemon profiles required')
    for row in rows:
        if row.get('daemon_exit')!=0 or row.get('rust_exit')!=0:
            raise ValueError('normal daemon and Rust actor must really exit zero')
        initial={event['name']for event in row['events']if event.get('event')=='row'and event.get('kind')=='Initial'}
        if initial!={'finished','empty-prefix','running'}:
            raise ValueError('actual initial inventory must be exactly owned fixtures')
    return 2

def monitor(document):
    committed(document)
    if document.get('status')!='observed-normal-C-only' or document.get('exit_code')!=0 or document.get('events')!=[{'event':'status','status':0,'service':'arm'},{'event':'configuration-removed'},{'event':'unavailable','status':1},{'event':'done','statuses':1,'unavailable':1,'failed':0}]:
        raise ValueError('actual C-only mutable monitor trace required')
    return 1
