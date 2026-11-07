//! Source DLL order and nullable configuration ownership, without process spawn.
#![cfg(feature = "runtime")]
use gnunet_config::{Configuration, ProjectData};
use gnunet_program_host::{
    daemon::{self, Registry},
    logging::Logger,
    program::{Defaults, Environment, Failure},
    runtime::Scope,
    shared_clock::SharedClock,
};
use std::{cell::RefCell, ffi::OsString, rc::Rc, sync::Arc};
fn env() -> Environment {
    Environment {
        arguments: None,
        posixly_correct: false,
        logging: Default::default(),
    }
}
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
}
fn prepare(
    config: Option<Configuration>,
    clock: &SharedClock,
) -> Result<daemon::Prepared, Failure> {
    let mut logger = Logger::new(b"owned", 7, true)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    match daemon::prepare(
        Arc::new(ProjectData::default()),
        config,
        [OsString::from("owned")],
        Defaults::Explicit(None),
        &env(),
        &mut logger,
        clock,
        &mut out,
        &mut err,
    )? {
        daemon::Preparation::Ready(ready) => Ok(*ready),
        daemon::Preparation::Stopped(_) => Err(gnunet_types::Error::Conflict.into()),
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Source newest-first order must survive repeated runs while actual closure state persists"
)]
fn newest_first_repeated_launch_and_original_nullable_configuration_are_preserved()
-> Result<(), Failure> {
    let rt = runtime()?;
    let clock = SharedClock::native(1)?;
    let observed = Rc::new(RefCell::new(Vec::new()));
    let mut registry = Registry::new(2);
    for name in ["first", "newest"] {
        let result = Rc::clone(&observed);
        registry.register(name.as_bytes(), b"unused", move |view| {
            result.borrow_mut().push((name, view.config.is_some()))
        })?;
    }
    assert_eq!(
        registry.register(b"overflow", b"", |_| {}),
        Err(gnunet_types::Error::Capacity)
    );
    let hidden = prepare(None, &clock)?;
    assert!(hidden.callback_config().is_none());
    rt.block_on(hidden.run_daemons(&mut registry, clock.clone(), 2))?;
    let visible = prepare(Some(Configuration::default()), &clock)?;
    assert!(visible.callback_config().is_some());
    rt.block_on(visible.run_daemons(&mut registry, clock, 2))?;
    assert_eq!(
        *observed.borrow(),
        [
            ("newest", false),
            ("first", false),
            ("newest", true),
            ("first", true)
        ]
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A bounded scheduler must reject the whole registry batch, never silently start a prefix"
)]
fn launch_capacity_is_atomic_and_no_daemon_callback_runs_after_failed_registration()
-> Result<(), Failure> {
    let rt = runtime()?;
    let clock = SharedClock::native(1)?;
    let observed = Rc::new(RefCell::new(Vec::new()));
    let mut registry = Registry::new(2);
    for i in 0..2 {
        let result = Rc::clone(&observed);
        registry.register(b"owned", b"", move |_| result.borrow_mut().push(i))?;
    }
    let ready = prepare(Some(Configuration::default()), &clock)?;
    assert!(matches!(
        rt.block_on(ready.run_daemons(&mut registry, clock, 1)),
        Err(Failure::State(gnunet_types::Error::Capacity))
    ));
    assert!(observed.borrow().is_empty());
    Ok(())
}
struct Service(Rc<RefCell<Vec<&'static str>>>);
impl daemon::ServiceMain for Service {
    fn register<'a>(
        &'a mut self,
        _: &'a ProjectData,
        config: Option<&'a Configuration>,
        scope: &Scope<'a>,
    ) -> Result<(), Failure> {
        if config.is_none() {
            return Err(gnunet_types::Error::InvalidInput.into());
        }
        self.0.borrow_mut().push("service-register");
        let result = Rc::clone(&self.0);
        scope.spawn(async move {
            result.borrow_mut().push("service-task");
        })?;
        Ok(())
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Monolith must call the actual supplied service port before enqueueing registered daemon tasks"
)]
fn monolith_invokes_service_registration_then_source_daemon_queue() -> Result<(), Failure> {
    let rt = runtime()?;
    let clock = SharedClock::native(1)?;
    let observed = Rc::new(RefCell::new(Vec::new()));
    let mut service = Service(Rc::clone(&observed));
    let mut registry = Registry::new(1);
    let result = Rc::clone(&observed);
    registry.register(b"daemon", b"", move |_| {
        result.borrow_mut().push("daemon-task")
    })?;
    let ready = prepare(Some(Configuration::default()), &clock)?;
    rt.block_on(ready.run_monolith(
        &ProjectData::default(),
        &mut service,
        &mut registry,
        clock,
        2,
    ))?;
    assert_eq!(
        *observed.borrow(),
        ["service-register", "service-task", "daemon-task"]
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Internal source callsites retain their first cache even when later log_setup changes threshold"
)]
fn source_helper_log_sites_cache_first_enablement_across_setup_calls() -> Result<(), Failure> {
    use daemon::{Diagnostics, LoggingDiagnostics, Notice};
    let clock = SharedClock::native(0)?;
    let mut logger = Logger::new(b"owned", 7, true)?;
    let mut output = Vec::new();
    LoggingDiagnostics {
        logger: &mut logger,
        clock: &clock,
        stderr: &mut output,
    }
    .notice(Notice::Enter)?;
    assert!(output.is_empty());
    logger.setup(
        b"owned",
        Some(b"DEBUG"),
        None,
        &Default::default(),
        &gnunet_program_host::logging::Stamp::setup_now()?,
    )?;
    LoggingDiagnostics {
        logger: &mut logger,
        clock: &clock,
        stderr: &mut output,
    }
    .notice(Notice::Enter)?;
    assert!(output.is_empty());
    LoggingDiagnostics {
        logger: &mut logger,
        clock: &clock,
        stderr: &mut output,
    }
    .notice(Notice::Launch(b"first"))?;
    logger.setup(
        b"owned",
        Some(b"NONE"),
        None,
        &Default::default(),
        &gnunet_program_host::logging::Stamp::setup_now()?,
    )?;
    LoggingDiagnostics {
        logger: &mut logger,
        clock: &clock,
        stderr: &mut output,
    }
    .notice(Notice::Launch(b"second"))?;
    assert!(
        output
            .windows(b"Launching daemon first".len())
            .any(|v| v == b"Launching daemon first")
    );
    assert!(
        output
            .windows(b"Launching daemon second".len())
            .any(|v| v == b"Launching daemon second")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Legitimate callback registration must append only to the next source launch snapshot"
)]
fn callback_can_register_next_launch_without_aliasing_the_active_callback_or_owner()
-> Result<(), Failure> {
    let rt = runtime()?;
    let clock = SharedClock::native(1)?;
    let mut registry = Registry::new(3);
    let port = registry.context();
    let output = Rc::new(RefCell::new(Vec::new()));
    let first = Rc::clone(&output);
    registry.register(b"first", b"", move |_| first.borrow_mut().push("first"))?;
    let registered = Rc::new(std::cell::Cell::new(false));
    let state = Rc::clone(&registered);
    let newest = Rc::clone(&output);
    registry.register(b"newest", b"", move |_| {
        newest.borrow_mut().push("newest");
        if !state.replace(true) {
            let late = Rc::clone(&newest);
            assert_eq!(
                port.register(b"late", b"", move |_| late.borrow_mut().push("late")),
                Ok(1)
            );
        }
    })?;
    let ready = prepare(Some(Configuration::default()), &clock)?;
    rt.block_on(ready.run_daemons(&mut registry, clock.clone(), 3))?;
    assert_eq!(*output.borrow(), ["newest", "first"]);
    rt.block_on(ready.run_daemons(&mut registry, clock, 3))?;
    assert_eq!(
        *output.borrow(),
        ["newest", "first", "late", "newest", "first"]
    );
    let closed = registry.context();
    drop(registry);
    assert_eq!(
        closed.register(b"retired", b"", |_| {}),
        Err(gnunet_types::Error::Closed)
    );
    Ok(())
}
struct ReentrantNotice<'a> {
    port: daemon::Context<'a>,
    added: bool,
    output: Rc<RefCell<Vec<&'static str>>>,
}
impl daemon::Diagnostics for ReentrantNotice<'_> {
    fn notice(&mut self, notice: daemon::Notice<'_>) -> Result<(), Failure> {
        if matches!(notice, daemon::Notice::Launch(_)) && !self.added {
            self.added = true;
            let output = Rc::clone(&self.output);
            self.port
                .register(b"late", b"", move |_| output.borrow_mut().push("late"))?;
        }
        Ok(())
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Synchronous log callbacks cannot add a new head to the source DLL iteration already in progress"
)]
fn diagnostic_registration_does_not_sneak_a_new_head_into_the_current_launch() -> Result<(), Failure>
{
    let rt = runtime()?;
    let clock = SharedClock::native(1)?;
    let mut registry = Registry::new(2);
    let output = Rc::new(RefCell::new(Vec::new()));
    let first = Rc::clone(&output);
    registry.register(b"first", b"", move |_| first.borrow_mut().push("first"))?;
    let mut diagnostics = ReentrantNotice {
        port: registry.context(),
        added: false,
        output: Rc::clone(&output),
    };
    let ready = prepare(Some(Configuration::default()), &clock)?;
    rt.block_on(ready.run_daemons_logged(&mut registry, clock.clone(), 2, &mut diagnostics))?;
    assert_eq!(*output.borrow(), ["first"]);
    rt.block_on(ready.run_daemons_logged(&mut registry, clock, 2, &mut diagnostics))?;
    assert_eq!(*output.borrow(), ["first", "late", "first"]);
    Ok(())
}
