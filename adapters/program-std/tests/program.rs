//! Source-derived preparation states and exact main-call authority.
use gnunet_config::{Configuration, Installation, Limits, ProjectData};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
    logging::Logger,
    program::{
        self, Defaults, Environment, Failure, Invocation, NlsDisabled, Preparation,
        ResolverConnect, StoppedReason,
    },
    shared_clock::SharedClock,
};
use std::{
    cell::RefCell,
    ffi::OsString,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Directory(PathBuf);
impl Directory {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "program-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
fn config() -> Result<Configuration, Failure> {
    Ok(Configuration::with_installation(
        Arc::new(ProjectData::default()),
        Installation::empty(),
        Limits::default(),
    )?)
}
fn env(args: Option<&[u8]>) -> Environment {
    Environment {
        arguments: args.map(<[u8]>::to_vec),
        posixly_correct: false,
        logging: Default::default(),
    }
}
fn invocation(defaults: Option<&Path>) -> Invocation<'_> {
    Invocation {
        binary_name: b"source-tool [options]",
        help: Some(b"Owned help"),
        select_default_filename: false,
        defaults: Defaults::Explicit(defaults),
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions validate source stop semantics; fallible setup remains Result"
)]
fn exclusive_help_outputs_before_any_log_setup_or_configuration_io() -> Result<(), Failure> {
    let root = Directory::new()?;
    let log = root.0.join("never-created/log");
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = program::prepare(
        config()?,
        invocation(None),
        Options::new(),
        [
            OsString::from("argv-name"),
            OsString::from("-h"),
            OsString::from("-l"),
            log.clone().into_os_string(),
        ],
        &env(None),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?;
    let Preparation::Stopped(result) = result else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    // Help is printed, but the later logfile option makes exclusive help fail.
    assert_eq!(result.code, -1);
    assert!(matches!(result.reason, StoppedReason::Options));
    assert!(out.starts_with(b"source-tool [options]\nOwned help\n"));
    assert!(!log.exists());
    assert!(!err.is_empty());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions validate default suppression and owned callback invocation"
)]
fn caller_short_name_suppresses_default_help_without_inventing_exclusivity() -> Result<(), Failure>
{
    let selected = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::flag(
        b'h',
        b"custom-help",
        b"owned override",
        selected.clone(),
    ));
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = program::prepare(
        config()?,
        invocation(None),
        options,
        [OsString::from("argv-name"), OsString::from("-h")],
        &env(None),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?;
    assert!(matches!(result, Preparation::Ready(_)));
    assert_eq!(selected.get()?, 1);
    assert!(out.is_empty() && err.is_empty());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions preserve positive PROGRAM logging-failure return without granting main authority"
)]
fn log_setup_failure_preserves_positive_index_and_cannot_be_used_as_main_authority()
-> Result<(), Failure> {
    let root = Directory::new()?;
    let blocked = root.0.join("regular-file");
    std::fs::write(&blocked, b"owned")?;
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = program::prepare(
        config()?,
        invocation(None),
        Options::new(),
        [
            OsString::from("argv-name"),
            OsString::from("-l"),
            blocked.join("log").into_os_string(),
        ],
        &env(None),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?;
    let Preparation::Stopped(result) = result else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    assert_eq!(result.code, 3);
    assert!(matches!(result.reason, StoppedReason::Logging(_)));
    Ok(())
}
struct Record(Rc<RefCell<Vec<&'static str>>>);
impl ResolverConnect for Record {
    fn connect(&mut self, config: Configuration) -> Result<(), Failure> {
        if config.get(b"owned", b"value") != Some(b"main") {
            return Err(gnunet_types::Error::InvalidInput.into());
        }
        self.0.borrow_mut().push("connect");
        Ok(())
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions validate source load order, native bytes, GNUNET_ARGS and exact connect-before-main"
)]
fn loads_defaults_then_main_sets_arm_config_preserves_bytes_and_connects_before_main()
-> Result<(), Failure> {
    let root = Directory::new()?;
    let defaults = root.0.join("defaults");
    std::fs::create_dir(&defaults)?;
    std::fs::write(defaults.join("00.conf"), b"[owned]\nvalue=default\n")?;
    let main = root.0.join("main.conf");
    std::fs::write(
        &main,
        b"[owned]\nvalue=main\n[testing]\nskew_offset=5000000\nskew_variance=20\n",
    )?;
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = program::prepare(
        config()?,
        invocation(Some(&defaults)),
        Options::new(),
        [
            OsString::from("different-argv0"),
            OsString::from("-c"),
            main.clone().into_os_string(),
            OsString::from("owned-arg"),
        ],
        &env(Some(b"'two words' \ttab")),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?;
    let Preparation::Ready(prepared) = result else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    assert_eq!(clock.offset()?, 4_999_980);
    assert_eq!(
        prepared.main().config.get(b"arm", b"CONFIG"),
        Some(main.as_os_str().as_encoded_bytes())
    );
    assert_eq!(
        prepared.main().arguments,
        [
            b"owned-arg".to_vec(),
            b"'two".to_vec(),
            b"words'".to_vec(),
            b"\ttab".to_vec()
        ]
    );
    let events = Rc::new(RefCell::new(Vec::new()));
    let task_events = Rc::clone(&events);
    let mut resolver = Record(Rc::clone(&events));
    assert_eq!(
        prepared.run_direct(&mut resolver, move |view| {
            assert_eq!(view.filename, Some(main.as_path()));
            task_events.borrow_mut().push("main");
        })?,
        1
    );
    assert_eq!(*events.borrow(), ["connect", "main"]);
    assert!(out.is_empty() && err.is_empty());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions distinguish unreadable and malformed source exits with no main authority"
)]
fn malformed_and_missing_entrypoints_stop_and_preserve_existing_arm_value() -> Result<(), Failure> {
    let root = Directory::new()?;
    let malformed = root.0.join("bad.conf");
    std::fs::write(&malformed, b"broken outside section\n")?;
    for (path, is_malformed) in [(root.0.join("missing.conf"), false), (malformed, true)] {
        let mut logger = Logger::new(b"old", 7, true)?;
        let clock = SharedClock::native(0)?;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = program::prepare(
            config()?,
            invocation(None),
            Options::new(),
            [
                OsString::from("argv0"),
                OsString::from("-c"),
                path.into_os_string(),
            ],
            &env(None),
            &mut NlsDisabled,
            &mut logger,
            &clock,
            &mut out,
            &mut err,
        )?;
        let Preparation::Stopped(result) = result else {
            return Err(gnunet_types::Error::Conflict.into());
        };
        assert_eq!(result.code, -1);
        assert_eq!(
            matches!(result.reason, StoppedReason::Malformed(_)),
            is_malformed
        );
        assert!(err.windows(5).any(|s| s == b"ERROR"));
    }
    let mut cfg = config()?;
    cfg.set_value(b"arm", b"CONFIG", Some(b"preserve"))?;
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let Preparation::Ready(ready) = program::prepare(
        cfg,
        invocation(None),
        Options::new(),
        [OsString::from("argv0")],
        &env(None),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?
    else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    assert_eq!(
        ready.main().config.get(b"arm", b"CONFIG"),
        Some(b"preserve".as_slice())
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions preserve the distinct conf_and_options source lifecycle"
)]
fn conf_and_options_ignores_gnunet_args_keeps_provided_cfg_and_forces_debug() -> Result<(), Failure>
{
    let root = Directory::new()?;
    let mut cfg = config()?;
    cfg.set_value(b"owned", b"retained", Some(b"yes"))?;
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let arguments = [
        OsString::from("argv0"),
        OsString::from("-c"),
        root.0.join("does-not-exist").into_os_string(),
        OsString::from("-d"),
        OsString::from("-L"),
        OsString::from("NONE"),
    ];
    let result = program::conf_and_options(
        Arc::new(ProjectData::default()),
        Some(cfg),
        arguments,
        Defaults::Explicit(None),
        &env(Some(b"--help")),
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?;
    let program::ConfigurationPreparation::Ready(ready) = result else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    assert!(!ready.created);
    assert_eq!(ready.daemonize_requested, 1);
    assert_eq!(
        ready.config.get(b"owned", b"retained"),
        Some(b"yes".as_slice())
    );
    assert!(logger.enabled(
        gnunet_program_host::policy::Level::DEBUG,
        gnunet_program_host::policy::CallSite {
            component: None,
            file: b"probe",
            function: b"probe",
            line: 1
        }
    )?);
    assert!(out.is_empty() && err.is_empty());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "conf_and_options converts help/version zero to SYSERR rather than claiming task execution"
)]
fn conf_and_options_help_consumes_error_cfg_and_retains_zero_as_source_parser_observation()
-> Result<(), Failure> {
    let mut logger = Logger::new(b"old", 7, true)?;
    let clock = SharedClock::native(0)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = program::conf_and_options(
        Arc::new(ProjectData::default()),
        Some(config()?),
        [OsString::from("argv0"), OsString::from("--version")],
        Defaults::Explicit(None),
        &env(None),
        &mut logger,
        &clock,
        &mut out,
        &mut err,
    )?;
    let program::ConfigurationPreparation::Stopped(stopped) = result else {
        return Err(gnunet_types::Error::Conflict.into());
    };
    assert_eq!(stopped.code, -1);
    assert!(matches!(stopped.reason, StoppedReason::Options));
    assert_eq!(out, b"argv0 v0.29.1\n");
    assert!(err.is_empty());
    Ok(())
}
