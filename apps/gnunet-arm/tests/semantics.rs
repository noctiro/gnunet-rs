//! Independent literal CLI contracts, including source quirks and native bytes.
use gnunet_arm_cli::{
    options::{self, Options},
    state::{Action, Kind, State, relative_time},
};
use gnunet_arm_core::wire::{RequestStatus, ResultCode, ServiceInfo, ServiceStatus};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
};
fn parse(args: &[&str]) -> options::Parsed {
    options::parse(args.iter().map(OsString::from), None, false, b"0.29.1")
}
#[test]
fn english_help_matches_actual_unmodified_c_width_and_option_order() {
    let p = parse(&["gnunet-arm", "--help"]);
    assert_eq!(p.exit, Some(0));
    assert_eq!(p.stdout, include_bytes!("../reference/argv-0.stdout"));
    assert!(p.stderr.is_empty());
}
#[test]
fn actual_getopt_error_and_exclusive_status_is_255() {
    for (args, message) in [
        (
            vec!["gnunet-arm", "--unknown"],
            "gnunet-arm: unrecognized option `--unknown'\nUse --help to get a list of options.\n",
        ),
        (
            vec!["gnunet-arm", "-z"],
            "gnunet-arm: invalid option -- z\nUse --help to get a list of options.\n",
        ),
        (
            vec!["gnunet-arm", "-i"],
            "gnunet-arm: option requires an argument -- i\nUse --help to get a list of options.\n",
        ),
        (
            vec!["gnunet-arm", "--init"],
            "gnunet-arm: option `--init' requires an argument\nUse --help to get a list of options.\n",
        ),
        (
            vec!["gnunet-arm", "--quiet=x"],
            "gnunet-arm: option `--quiet' does not allow an argument\nUse --help to get a list of options.\n",
        ),
        (
            vec!["gnunet-arm", "--n"],
            "gnunet-arm: option `--n' is ambiguous\nUse --help to get a list of options.\n",
        ),
    ] {
        let p = parse(&args);
        assert_eq!(p.exit, Some(255));
        assert_eq!(p.stderr, message.as_bytes());
        assert!(p.stdout.is_empty());
    }
    let p = parse(&["gnunet-arm", "--help", "-s"]);
    assert_eq!(p.exit, Some(255));
    assert_eq!(
        p.stderr,
        b"Option `help' can't be used with other options.\n"
    );
    assert_eq!(p.stdout, include_bytes!("../reference/argv-0.stdout"));
}
// The pinned C fancy_time_to_relative reads an uninitialized local after a
// failed conversion. These are Rust safety regressions, never C oracle cases.
#[test]
fn malformed_relative_time_is_rejected_safely_without_running_undefined_c_path() {
    for args in [
        vec!["gnunet-arm", "--timeout", "bad"],
        vec!["gnunet-arm", "--timeout=2.5s"],
        vec!["gnunet-arm", "--timeout", "--help"],
    ] {
        let p = parse(&args);
        assert_eq!(p.exit, Some(255));
        assert_eq!(
            p.stderr,
            b"You must pass relative time to the `timeout' option.\n"
        );
        assert!(p.stdout.is_empty());
    }
}
#[test]
fn native_arguments_permutation_prefixes_and_last_string_are_preserved() {
    let raw = OsString::from_vec(b"svc\xff".to_vec());
    let p = options::parse(
        [
            OsString::from("different-name"),
            OsString::from("positional"),
            OsString::from("-aqI"),
            OsString::from("--sta"),
            OsString::from("-ifirst"),
            OsString::from("--init"),
            raw.clone(),
        ],
        None,
        false,
        b"0.29.1",
    );
    assert_eq!(p.exit, None);
    assert!(p.options.all && p.options.quiet && p.options.list && p.options.start);
    assert_eq!(p.options.init.as_deref(), Some(raw.as_bytes()));
    assert_eq!(p.remaining, [OsString::from("positional")]);
    let p = options::parse(
        [
            OsString::from("gnunet-arm"),
            OsString::from("positional"),
            OsString::from("-s"),
        ],
        Some(OsStr::new(" -q   -T 1s ")),
        true,
        b"0.29.1",
    );
    assert!(!p.options.start && !p.options.quiet);
    assert_eq!(p.remaining.len(), 5);
    let p = options::parse(
        [OsString::from("gnunet-arm")],
        Some(OsStr::new(" -q   -T 1s ")),
        false,
        b"0.29.1",
    );
    assert!(p.options.quiet);
    assert_eq!(p.options.timeout, 1_000_000);
}
#[test]
fn exact_phase_order_and_stdio_bits_survive_all_flags() {
    let mut state = State::new(Options {
        end: true,
        restart: true,
        start: true,
        delete: true,
        term: Some(b"kill".to_vec()),
        init: Some(b"init".to_vec()),
        list: true,
        monitor: true,
        no_stdout: true,
        ..Options::default()
    });
    assert_eq!(
        state.next(|| true),
        Some(Action::Stop(b"kill".to_vec(), Kind::Term))
    );
    state.result(Kind::Term, RequestStatus::SentOk, Some(ResultCode::STOPPED));
    assert_eq!(
        state.next(|| true),
        Some(Action::Stop(b"arm".to_vec(), Kind::End))
    );
    state.result(Kind::End, RequestStatus::SentOk, Some(ResultCode::STOPPED));
    assert!(!state.should_delete());
    assert_eq!(
        state.next(|| true),
        Some(Action::Start(b"arm".to_vec(), 4, Kind::Start))
    );
    state.result(
        Kind::Start,
        RequestStatus::SentOk,
        Some(ResultCode::STARTING),
    );
    assert_eq!(
        state.next(|| true),
        Some(Action::Start(b"init".to_vec(), 0, Kind::Init))
    );
    state.result(
        Kind::Init,
        RequestStatus::SentOk,
        Some(ResultCode::STARTING),
    );
    assert_eq!(state.next(|| true), Some(Action::List));
    state.list(&[], 0);
    assert_eq!(state.next(|| true), Some(Action::MonitorOnly));
    assert_eq!(state.next(|| true), None);
    assert!(!state.done);
    assert!(state.monitoring);
}
#[test]
fn callback_failures_retain_ret_zero_and_distinct_acceptance_sets() {
    let mut state = State::new(Options {
        start: true,
        ..Options::default()
    });
    assert!(state.next(|| false).is_some());
    state.result(
        Kind::Start,
        RequestStatus::SentOk,
        Some(ResultCode::IS_STARTING_ALREADY),
    );
    assert_eq!(state.ret, 0);
    assert!(state.done);
    assert_eq!(
        state.stdout,
        b"Failed to start the ARM service: is starting already\n"
    );
    let mut state = State::new(Options {
        term: Some(b"svc\xff".to_vec()),
        ..Options::default()
    });
    assert!(state.next(|| true).is_some());
    state.result(
        Kind::Term,
        RequestStatus::SentOk,
        Some(ResultCode::STOPPING),
    );
    assert_eq!(state.ret, 0);
    assert_eq!(
        state.stdout,
        b"Failed to kill the `svc\xff' service: is stopping\n"
    );
    let mut state = State::new(Options {
        end: true,
        ..Options::default()
    });
    assert!(state.next(|| true).is_some());
    state.result(Kind::End, RequestStatus::SentOk, Some(ResultCode::STOPPING));
    assert!(!state.done && !state.options.end);
}
#[test]
fn absent_arm_prechecks_and_delete_condition_use_remaining_flags() {
    let mut absent = State::new(Options {
        end: true,
        delete: true,
        ..Options::default()
    });
    assert_eq!(absent.next(|| false), Some(Action::Finish));
    assert!(absent.should_delete());
    assert_eq!(absent.ret, 0);
    let mut stopped = State::new(Options {
        end: true,
        delete: true,
        ..Options::default()
    });
    assert!(stopped.next(|| true).is_some());
    stopped.result(
        Kind::End,
        RequestStatus::SentOk,
        Some(ResultCode::IS_STOPPED_ALREADY),
    );
    assert!(!stopped.should_delete());
    let mut named = State::new(Options {
        init: Some(b"one".to_vec()),
        ..Options::default()
    });
    assert_eq!(named.next(|| false), None);
    assert_eq!(named.ret, 4);
    assert_eq!(
        named.stderr,
        b"Cannot start the `one' service: ARM is not running.\n"
    );
    let mut restarted = State::new(Options {
        restart: true,
        ..Options::default()
    });
    assert_eq!(
        restarted.next(|| false),
        Some(Action::Start(b"arm".to_vec(), 6, Kind::Start))
    );
    assert!(!restarted.options.restart);
}
fn row(name: &[u8], status: u32) -> ServiceInfo<'_> {
    ServiceInfo {
        name,
        binary: b"bn",
        status: ServiceStatus(status),
        last_exit_status: 65535,
        restart_at: 0,
        last_started_at: 0,
    }
}
#[test]
fn stopping_unknown_rows_print_before_heading_and_again_in_list() {
    let rows = [
        row(b"stop", 0),
        row(b"run", 1),
        row(b"bad", 2),
        row(b"done", 3),
        row(b"going", 4),
        row(b"future", 99),
    ];
    let mut state = State::new(Options::default());
    state.list(&rows, 0);
    assert_eq!(state.stdout,b"going (binary='bn', status=stopping)\nfuture (binary='bn', status=unknown)\nServices (excluding stopped services):\n(started: 1 / failed: 1 / stopping: 1 / stopped: 1 / finished: 1)\nrun (binary='bn', status=started)\nbad (binary='bn', status=failed, exit_status=65535, restart_delay='0 ms')\ndone (binary='bn', status=finished)\ngoing (binary='bn', status=stopping)\nfuture (binary='bn', status=unknown)\n");
    let mut quiet = State::new(Options {
        quiet: true,
        ..Options::default()
    });
    quiet.list(&rows[4..], 0);
    assert_eq!(quiet.stdout,b"going (binary='bn', status=stopping)\nfuture (binary='bn', status=unknown)\ngoing (binary='bn', status=stopping)\nfuture (binary='bn', status=unknown)\n");
}
#[test]
fn empty_and_stopped_only_list_summary_is_not_a_running_service_count() {
    let mut state = State::new(Options::default());
    state.list(&[], 0);
    assert_eq!(
        state.stdout,
        b"Services (excluding stopped services):\n(No services configured.)\n"
    );
    state.stdout.clear();
    state.list(&[row(b"s", 0)], 0);
    assert_eq!(
        state.stdout,
        b"Services (excluding stopped services):\n(stopped: 1)\n"
    );
}
#[test]
fn quiet_monitor_phase_suppresses_prompt_then_prints_future_notifications() {
    let mut state = State::new(Options {
        monitor: true,
        quiet: true,
        ..Options::default()
    });
    state.monitor(b"one", 2);
    assert!(state.stderr.is_empty());
    assert_eq!(state.next(|| true), Some(Action::MonitorOnly));
    assert!(state.stderr.is_empty());
    state.monitor(b"one", 0);
    state.monitor(b"two\xff", 3);
    assert_eq!(state.stderr, b"Stopping two\xff...\n");
}
#[test]
fn disconnected_list_and_timeout_keep_different_exit_codes() {
    let mut state = State::new(Options::default());
    state.list_disconnected();
    assert_eq!(state.ret, 3);
    assert_eq!(
        state.stderr,
        b"Error communicating with ARM. ARM not running?\n"
    );
    assert_eq!(state.stdout,b"Failed to request a list of services: We disconnected from ARM before we could send a request\n");
    let mut state = State::new(Options::default());
    state.timeout();
    assert_eq!(state.ret, 2);
}
#[test]
fn relative_time_display_uses_original_rounding_thresholds() {
    for (value, expected) in [
        (0, "0 ms"),
        (1, "1 µs"),
        (4999, "4999 µs"),
        (5000, "5 ms"),
        (5001, "5 ms"),
        (6_000_000, "6 s"),
        (301_000_000, "5 m"),
        (18_060_000_000, "5 h"),
        (u64::MAX, "forever"),
    ] {
        assert_eq!(relative_time(value), expected);
    }
}

#[test]
fn disconnected_kill_name_percent_bytes_are_data_never_a_second_format_string() {
    let mut state = State::new(Options {
        term: Some(b"owned%n%s%%".to_vec()),
        ..Options::default()
    });
    assert!(state.next(|| true).is_some());
    state.result(Kind::Term, RequestStatus::Disconnected, None);
    assert_eq!(state.ret, 0);
    assert_eq!(state.stdout, b"Failed to send a request to kill the `owned%n%s%%' service: We disconnected from ARM before we could send a request\n");
}
