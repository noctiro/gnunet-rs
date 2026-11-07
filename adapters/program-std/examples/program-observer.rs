//! Actual PROGRAM/Resolver-context/SPEEDUP observer, paired with unchanged C API.
#[cfg(feature = "resolver-broker")]
mod actual {
    use gnunet_program_host::{
        getopt::Options,
        logging::Logger,
        program::{
            self, Defaults, Environment, Failure, Invocation, Main, NlsDisabled, Preparation,
        },
        shared_clock::SharedClock,
    };
    use gnunet_resolver_broker::{FamilyProfile, Limits as BrokerLimits, LiveConfiguration};
    use std::{
        io::{self, Write},
        os::unix::ffi::OsStrExt,
        sync::Arc,
    };
    fn hex(out: &mut impl Write, v: Option<&[u8]>) -> io::Result<()> {
        match v {
            None => out.write_all(b"-"),
            Some(v) => {
                for b in v {
                    write!(out, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
    fn task(
        out: &mut impl Write,
        view: Main<'_>,
        clock: &SharedClock,
        calls: usize,
    ) -> Result<(), Failure> {
        write!(out, "TASK {calls} OFFSET {} FILE ", clock.offset()?)?;
        hex(out, view.filename.map(|p| p.as_os_str().as_bytes()))?;
        out.write_all(b" ARMCONFIG ")?;
        hex(out, view.config.get(b"arm", b"CONFIG"))?;
        out.write_all(b" ARGS")?;
        for arg in view.arguments {
            out.write_all(b" ")?;
            hex(out, Some(arg))?;
        }
        out.write_all(b"\n")?;
        Ok(())
    }
    pub fn run() -> Result<(), Failure> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let entered = runtime.enter();
        let clock = SharedClock::native(4)?;
        let subscription = Arc::new(clock.clone());
        let project = Arc::new(gnunet_config::ProjectData::default());
        let initial =
            gnunet_config::Configuration::create(Arc::clone(&project), Default::default())?;
        let profile = FamilyProfile::new(libc::AF_INET, libc::AF_INET6)?;
        let (mut resolver, driver) = gnunet_resolver_broker::broker::<8, 1024>(
            LiveConfiguration::new(initial),
            BrokerLimits::default(),
            profile,
            subscription,
        )
        .map_err(Failure::Broker)?;
        let repeat = if std::env::var_os("OWNED_REPEAT").is_some() {
            2
        } else {
            1
        };
        let direct = std::env::var_os("OWNED_DIRECT").is_some();
        let shutdown = std::env::var_os("OWNED_SHUTDOWN").is_some();
        let mut calls = 0;
        let mut logger = Logger::new(b"old", std::process::id(), true)?;
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        for _ in 0..repeat {
            let cfg =
                gnunet_config::Configuration::create(Arc::clone(&project), Default::default())?;
            let prepared = program::prepare(
                cfg,
                Invocation {
                    binary_name: b"owned summary",
                    help: Some(b"Owned PROGRAM oracle"),
                    select_default_filename: true,
                    defaults: Defaults::Native,
                },
                Options::new(),
                std::env::args_os(),
                &Environment::capture(),
                &mut NlsDisabled,
                &mut logger,
                &clock,
                &mut stdout,
                &mut stderr,
            )?;
            let mut task_error = None;
            let result = match prepared {
                Preparation::Stopped(stopped) => stopped.code,
                Preparation::Ready(ready) => {
                    let clock_read = clock.clone();
                    if direct {
                        ready.run_direct(&mut resolver, |view| {
                            calls += 1;
                            if let Err(e) = task(&mut stdout, view, &clock_read, calls) {
                                task_error = Some(e);
                            }
                        })?
                    } else {
                        runtime.block_on(ready.run_scheduled(
                            &mut resolver,
                            clock.clone(),
                            0,
                            |view, scope| {
                                calls += 1;
                                if let Err(e) = task(&mut stdout, view, &clock_read, calls) {
                                    task_error = Some(e);
                                }
                                if shutdown && let Err(e) = scope.shutdown() {
                                    task_error = Some(e.into());
                                }
                            },
                        ))?
                    }
                }
            };
            if let Some(error) = task_error {
                return Err(error);
            }
            writeln!(
                stdout,
                "RETURN {result} CALLS {calls} OFFSET {}",
                clock.offset()?
            )?;
            stdout.flush()?;
        }
        drop(driver);
        drop(entered);
        Ok(())
    }
}
#[cfg(feature = "resolver-broker")]
fn main() -> Result<(), gnunet_program_host::program::Failure> {
    actual::run()
}
#[cfg(not(feature = "resolver-broker"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other(
        "program observer requires resolver-broker feature",
    ))
}
