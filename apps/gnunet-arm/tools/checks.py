"""Independent, nonempty required witness sets for finite CLI proof scope."""
import re
RUST={
 'english_help_matches_actual_unmodified_c_width_and_option_order',
 'malformed_relative_time_is_rejected_safely_without_running_undefined_c_path',
 'actual_getopt_error_and_exclusive_status_is_255',
 'native_arguments_permutation_prefixes_and_last_string_are_preserved',
 'exact_phase_order_and_stdio_bits_survive_all_flags',
 'callback_failures_retain_ret_zero_and_distinct_acceptance_sets',
 'absent_arm_prechecks_and_delete_condition_use_remaining_flags',
 'stopping_unknown_rows_print_before_heading_and_again_in_list',
 'empty_and_stopped_only_list_summary_is_not_a_running_service_count',
 'quiet_monitor_phase_suppresses_prompt_then_prints_future_notifications',
 'disconnected_list_and_timeout_keep_different_exit_codes',
 'relative_time_display_uses_original_rounding_thresholds',
 'disconnected_kill_name_percent_bytes_are_data_never_a_second_format_string'}
FUNCTIONS={'delete_files','shutdown_task','req_string','ret_string','arm_is_running','conn_status','start_callback','stop_callback','init_callback','term_callback','list_callback','action_loop','srv_status','timeout_task_cb','run','main'}
FLAGS={'e','i','k','a','s','r','d','m','q','T','I','O','E'}
LITERAL={kind+'-result-'+str(n)for kind in ['start','kill','end']for n in [*range(10),123]}|{
 'start-disconnected','kill-disconnected','end-disconnected','list','list-all','list-quiet','list-all-quiet','empty-list','list-disconnected','absent-init','absent-kill','absent-list','absent-end','absent-start-unknown','absent-restart-unknown','timeout','monitor','monitor-quiet','kill-init-list-monitor','end-delete-success-cleared','end-delete-absent-removes-owned','non-utf8-service','appended-args-last-value'}
def require_inventory(value):
    if value.get('CLI_definition_count')!=16 or len(value.get('CLI_definitions',[]))!=16 or {r['name']for r in value['CLI_definitions']}!=FUNCTIONS:raise ValueError('16 source definitions required')
    if value.get('CLI_specific_option_count')!=13 or len(value.get('CLI_specific_options',[]))!=13 or {r['short']for r in value['CLI_specific_options']}!=FLAGS:raise ValueError('13 source flags required')
    if not value.get('explicit_safe_differences')or not value.get('pending'):raise ValueError('pending/difference scope must remain explicit')
def require_rust(text):
    names=set(re.findall(r'^test ([A-Za-z_][A-Za-z0-9_]*) \.\.\. ok$',text,re.M))
    if names!=RUST or '13 passed; 0 failed; 0 ignored'not in text:raise ValueError('13 actual named Rust tests required')
    return len(names)
def require_receipt(kind,value):
    if value.get('status')!='passed':raise ValueError('actual tool run failed')
    rows=value.get('rows',[])
    if kind=='literal':
        if value.get('profiles')!=len(LITERAL) or {r['profile']['name']for r in rows}!=LITERAL or len(rows)!=len(LITERAL)or not all(r.get('matched')and r.get('c')==r.get('rust')for r in rows):raise ValueError('full literal callback/frame scope missing')
    elif kind=='argv':
        if value.get('profiles')!=32 or len(rows)!=32 or len({tuple(r['argv_hex'])for r in rows})!=32 or value.get('excluded_malformed_relative_time_profiles')!=4 or value.get('malformed_relative_time_C_executed')is not False or not all(r.get('matched')and r.get('c')==r.get('rust')for r in rows):raise ValueError('32 distinct defined-safe actual argv profiles and explicit relative-time exclusions required')
    elif kind=='signals':
        if {r['name']for r in rows}!={'SIGINT','SIGTERM','SIGQUIT','SIGHUP','SIGPIPE'}or len(rows)!=5 or not all(r.get('matched')and r.get('c')==r.get('rust')for r in rows):raise ValueError('five actual owned signal profiles required')
    elif kind=='stdio':
        if {r['name']for r in rows}!={'inherit-both','no-stdout','no-stderr','no-both'}or len(rows)!=4 or not all(r.get('matched')and r.get('c')==r.get('rust')for r in rows):raise ValueError('four actual CLI native stdio profiles required')
    elif kind=='normal-daemon':
        cases=value.get('cases',[])
        if {r['profile']for r in cases}!={'unix','tcp4'}or len(cases)!=2 or value.get('normal_daemon_processes')!=4:raise ValueError('both real normal daemon transports required')
        for row in cases:
            if not row.get('matched_cli_steps')or row['c']['steps']!=row['rust']['steps']or len(row['c']['steps'])!=8:raise ValueError('eight actual remote normal daemon actions required')
            for actor in ['c','rust']:
                if row[actor].get('normal_daemon_exit')!=0 or not row[actor].get('actual_managed_children'):raise ValueError('actual normal daemon/managed child evidence required')
    elif kind=='local-daemon':
        c,rust=value.get('c',{}),value.get('rust',{})
        if c.get('steps')!=rust.get('steps')or len(c.get('steps',[]))!=5:raise ValueError('five actual local daemon CLI actions required')
        for owner in [c,rust]:
            pids=owner.get('actual_daemon_exec_pids',[])
            if len(pids)!=2 or len(set(pids))!=2 or not owner.get('owned_endpoint_removed')or owner.get('daemon_wait_status_claimed')is not False:raise ValueError('two real execs/cleanup and honest wait scope required')
    elif kind=='logs':
        if len(rows)!=2 or {r['profile']for r in rows}!={'suppressed','warning'}or not all(r.get('matched_body_routing_append')and r.get('c')==r.get('rust')for r in rows)or value.get('full_generic_logging_complete')is not False:raise ValueError('log destination/body checks with pending generic prefix required')
    else:raise ValueError('unrecognized proof group')
