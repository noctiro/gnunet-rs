//! Observable real registry/scheduler helper operations, no process spawn.
#[cfg(feature = "runtime")]
mod actual {
    use gnunet_config::Configuration;
    use gnunet_program_host::{
        daemon::{self, Diagnostics, LoggingDiagnostics, Registry},
        logging::{Logger, Stamp},
        program::{Defaults, Environment, Failure},
        runtime,
        shared_clock::SharedClock,
    };
    use std::{
        cell::RefCell,
        io::{self, Write},
        rc::Rc,
        sync::Arc,
    };
    fn hex(bytes: &[u8]) -> String {
        let digits = b"0123456789abcdef";
        let mut text = String::new();
        for byte in bytes {
            text.push(char::from(digits[usize::from(byte >> 4)]));
            text.push(char::from(digits[usize::from(byte & 15)]));
        }
        text
    }
    fn line(value: &str) -> io::Result<()> {
        let mut output = io::stdout().lock();
        writeln!(output, "{value}")?;
        output.flush()
    }
    #[derive(Clone)]
    struct DiagnosticPort {
        logger: Rc<RefCell<Logger<'static>>>,
        clock: SharedClock,
    }
    impl Diagnostics for DiagnosticPort {
        fn notice(&mut self, notice: daemon::Notice<'_>) -> Result<(), Failure> {
            LoggingDiagnostics {
                logger: &mut self.logger.borrow_mut(),
                clock: &self.clock,
                stderr: &mut io::stderr(),
            }
            .notice(notice)
        }
    }
    fn callback(
        name: &str,
        count: u32,
        view: daemon::Main<'_>,
        total: &Rc<RefCell<u32>>,
        failure: &Rc<RefCell<Option<io::Error>>>,
    ) {
        let value = view
            .config
            .and_then(|config| config.get(b"owned", b"value"));
        if let Err(error) = line(&format!(
            "TASK {name} {count} CFG {} VALUE {}",
            u8::from(view.config.is_some()),
            value.map_or_else(|| "-".to_string(), hex)
        )) {
            *failure.borrow_mut() = Some(error);
        }
        *total.borrow_mut() += 1;
    }
    pub fn run() -> Result<(), Failure> {
        let mode = std::env::var("OWNED_DAEMON_MODE").map_err(io::Error::other)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let clock = SharedClock::native(1)?;
        let mut logger = Logger::new(b"owned-daemon", std::process::id(), true)?;
        logger.setup_routed(
            b"owned-daemon",
            Some(if mode == "bare" { b"DEBUG" } else { b"NONE" }),
            None,
            &Environment::capture().logging,
            &Stamp::setup_now()?,
            &mut io::stderr(),
        )?;
        let callback_error = Rc::new(RefCell::new(None));
        let error_target = Rc::clone(&callback_error);
        let token = logger.logger_add(move |record| {
            if let Err(error) = line(&format!(
                "R {} {} {} {}",
                record.kind.0,
                hex(record.component),
                hex(record.date),
                hex(record.message)
            )) {
                *error_target.borrow_mut() = Some(error);
            }
        })?;
        let logger = Rc::new(RefCell::new(logger));
        let mut diagnostics = DiagnosticPort {
            logger: Rc::clone(&logger),
            clock: clock.clone(),
        };
        let mut configuration = if mode == "null" {
            None
        } else {
            let mut config = Configuration::default();
            config.set_value(b"owned", b"value", Some(b"provided%value"))?;
            Some(config)
        };
        let mut registry = Registry::new(3);
        let total = Rc::new(RefCell::new(0));
        let first_total = Rc::clone(&total);
        let first_error = Rc::clone(&callback_error);
        let mut first = 0;
        line(&format!(
            "REGISTER {}",
            registry.register_logged(
                b"first",
                b"unused",
                move |view| {
                    first += 1;
                    callback("first", first, view, &first_total, &first_error);
                },
                &mut diagnostics
            )?
        ))?;
        let port = registry.context();
        let newest_total = Rc::clone(&total);
        let newest_error = Rc::clone(&callback_error);
        let mut registration_diagnostics = diagnostics.clone();
        let repeat = mode == "repeat";
        let mut newest = 0;
        line(&format!(
            "REGISTER {}",
            registry.register_logged(
                b"newest",
                b"unused",
                move |view| {
                    newest += 1;
                    callback("newest", newest, view, &newest_total, &newest_error);
                    if repeat && newest == 1 {
                        let late_total = Rc::clone(&newest_total);
                        let late_error = Rc::clone(&newest_error);
                        let mut count = 0;
                        if let Err(error) = port.register_logged(
                            b"late",
                            b"unused",
                            move |view| {
                                count += 1;
                                callback("late", count, view, &late_total, &late_error);
                            },
                            &mut registration_diagnostics,
                        ) {
                            *newest_error.borrow_mut() = Some(io::Error::other(error));
                        }
                    }
                },
                &mut diagnostics
            )?
        ))?;
        for iteration in 0..if repeat { 2 } else { 1 } {
            if mode == "bare" {
                runtime.block_on(runtime::run_tasks_fallible(clock.clone(), 3, |scope| {
                    registry.main_without_scheduler(
                        configuration.as_ref(),
                        &scope,
                        &mut diagnostics,
                    )?;
                    Ok::<(), Failure>(())
                }))?;
            } else {
                let ready = {
                    let mut logger = logger.borrow_mut();
                    daemon::prepare(
                        Arc::new(gnunet_config::ProjectData::default()),
                        configuration.take(),
                        std::env::args_os(),
                        Defaults::Native,
                        &Environment::capture(),
                        &mut logger,
                        &clock,
                        &mut io::stdout(),
                        &mut io::stderr(),
                    )?
                };
                if let daemon::Preparation::Ready(ready) = ready {
                    let provided = ready.callback_config().is_some();
                    runtime.block_on(ready.run_daemons_logged(
                        &mut registry,
                        clock.clone(),
                        3,
                        &mut diagnostics,
                    ))?;
                    let config = ready.into_configuration();
                    configuration = provided.then_some(config);
                }
            }
            line(&format!("RUN {iteration} TASKS {}", total.borrow()))?;
        }
        logger.borrow_mut().logger_remove(token)?;
        if let Some(error) = callback_error.borrow_mut().take() {
            return Err(error.into());
        }
        Ok(())
    }
}
#[cfg(feature = "runtime")]
fn main() -> Result<(), gnunet_program_host::program::Failure> {
    actual::run()
}
#[cfg(not(feature = "runtime"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other("requires runtime"))
}
