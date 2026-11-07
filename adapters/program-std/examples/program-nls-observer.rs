//! Enabled native-NLS PROGRAM path, with real shared Resolver selection.
#[cfg(feature = "resolver-broker")]
mod actual {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Target},
        locale::{AbiProfile, ProcessLocale},
        logging::{Logger, Stamp},
        policy::Level,
        program::{
            self, Defaults, Environment, Failure, Invocation, LocaleSetup, NlsDisabled, Preparation,
        },
        shared_clock::SharedClock,
    };
    use gnunet_resolver_broker::{FamilyProfile, Limits, LiveConfiguration};
    use std::{
        io::{self, Write},
        path::PathBuf,
        sync::Arc,
    };
    enum SelectedLocale {
        Disabled(NlsDisabled),
        Enabled(ProcessLocale),
    }
    impl LocaleSetup for SelectedLocale {
        fn case_context(&self) -> Option<gnunet_config::CaseContext> {
            match self {
                Self::Disabled(value) => LocaleSetup::case_context(value),
                Self::Enabled(value) => LocaleSetup::case_context(value),
            }
        }
        fn configure(&mut self, project: &gnunet_config::ProjectData) -> Result<(), Failure> {
            match self {
                Self::Disabled(value) => value.configure(project),
                Self::Enabled(value) => value.configure(project),
            }
        }
        fn translations(&self) -> std::rc::Rc<dyn gnunet_program_host::locale::Translations> {
            match self {
                Self::Disabled(value) => value.translations(),
                Self::Enabled(value) => value.translations(),
            }
        }
    }
    pub fn run() -> Result<(), Failure> {
        #[expect(
            unsafe_code,
            reason = "Dedicated fresh exec claims its own fd2 before creating writers, threads or foreign callbacks"
        )]
        // SAFETY: the runner owns this fresh process; stderr replacement has no unrelated native users.
        let process_stderr =
            unsafe { gnunet_program_host::process_stderr::ProcessStderr::claim()? };
        let library = PathBuf::from(
            std::env::var_os("OWNED_NLS_LIBRARY")
                .ok_or_else(|| io::Error::other("trusted library missing"))?,
        );
        let directory = PathBuf::from(
            std::env::var_os("OWNED_NLS_DIRECTORY")
                .ok_or_else(|| io::Error::other("owned catalog directory missing"))?,
        );
        let marker = std::env::var_os("OWNED_CONFIG_MARKER")
            .ok_or_else(|| io::Error::other("owned marker missing"))?;
        #[expect(
            unsafe_code,
            reason = "Dedicated fresh single-thread fixture: runner supplies a hashed trusted Libintl ABI and excludes unrelated native locale/environment users"
        )]
        // SAFETY: only the runner-selected standard library is loaded; no worker/native callback has been started.
        let mut locale = if std::env::var_os("OWNED_NLS_DISABLED").is_some() {
            SelectedLocale::Disabled(NlsDisabled)
        } else {
            // SAFETY: the dedicated runner supplies the same trusted ABI and exclusive
            // early-process contract documented immediately above this selection.
            SelectedLocale::Enabled(unsafe { ProcessLocale::load(library, AbiProfile::Libintl)? })
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let entered = runtime.enter();
        let clock = SharedClock::native(3)?;
        let subscription = Arc::new(clock.clone());
        use std::os::unix::ffi::OsStrExt;
        let config_file = marker.as_os_str().as_bytes().to_vec();
        let project = gnunet_config::ProjectData {
            gettext_path: Some(directory),
            config_file: config_file.clone(),
            user_config_file: config_file,
            ..gnunet_config::ProjectData::default()
        };
        let project = Arc::new(project);
        let initial =
            gnunet_config::Configuration::create(Arc::clone(&project), Default::default())?;
        let (mut resolver, driver) = gnunet_resolver_broker::broker::<8, 1024>(
            LiveConfiguration::new(initial),
            Limits::default(),
            FamilyProfile::new(libc::AF_INET, libc::AF_INET6)?,
            subscription,
        )
        .map_err(Failure::Broker)?;
        let target = Target::new(0u32);
        let mut options = Options::new();
        options.add(helpers::uint(
            b'u',
            b"unsigned",
            b"N",
            b"Owned number",
            target.clone(),
        ));
        let config = gnunet_config::Configuration::create(project, Default::default())?;
        let mut logger = Logger::new(b"old", std::process::id(), true)?;
        logger.install_process_stderr(process_stderr)?;
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        if std::env::var_os("OWNED_PRELOG").is_some() {
            logger.setup_routed(
                b"old",
                Some(b"DEBUG"),
                None,
                &Default::default(),
                &Stamp::setup_now()?,
                &mut stderr,
            )?;
        }
        let ready = program::prepare(
            config,
            Invocation {
                binary_name: b"owned summary",
                help: Some(b"Owned help"),
                select_default_filename: true,
                defaults: Defaults::Native,
            },
            options,
            std::env::args_os(),
            &Environment::capture(),
            &mut locale,
            &mut logger,
            &clock,
            &mut stdout,
            &mut stderr,
        )?;
        let mut calls = 0;
        let mut task_error = None;
        let route =
            gnunet_program_host::config_observer::Route::new(&mut logger, &clock, &mut stderr);
        let observer = |event: gnunet_config::diagnostic::Diagnostic<'_>| route.event(event);
        let scheduled = std::env::var_os("OWNED_SCHEDULED").is_some();
        let mut invoke = |main: program::Main<'_>| {
            calls += 1;
            let result = route.with_logger(|logger, clock, stderr| {
                if std::env::var_os("OWNED_TASK_CHOICE").is_some() {
                    drop(gnunet_program_host::config_observer::operation(
                        logger,
                        clock,
                        stderr,
                        |observer| {
                            main.config.get_choice_observed(
                                b"owned",
                                b"value",
                                &[b"YES", b"NO"],
                                Some(observer),
                            )
                        },
                    )?);
                }
                logger.nocheck(
                    Level::ERROR,
                    None,
                    b"owner data%name\n",
                    &Stamp::now(clock.offset().map_err(io::Error::other)?)?,
                    stderr,
                )
            });
            if let Err(error) = result {
                task_error = Some(error);
            }
        };
        let timer_error = std::rc::Rc::new(std::cell::Cell::new(false));
        let result = match ready {
            Preparation::Stopped(stopped) => stopped.code,
            Preparation::Ready(ready) if scheduled => {
                let failed = std::rc::Rc::clone(&timer_error);
                runtime.block_on(ready.run_scheduled_observed(
                    &mut resolver,
                    clock.clone(),
                    4,
                    Some(&observer),
                    |main, scope| {
                        invoke(main);
                        let waiting = scope.delay(gnunet_types::RelativeTime::from_micros(20_000));
                        let done = scope.clone();
                        let failure = std::rc::Rc::clone(&failed);
                        if let Ok(wait) = waiting {
                            if scope
                                .spawn(async move {
                                    if wait.await.is_err() || done.shutdown().is_err() {
                                        failure.set(true);
                                    }
                                })
                                .is_err()
                            {
                                failed.set(true);
                            }
                        } else {
                            failed.set(true);
                        }
                    },
                ))?
            }
            Preparation::Ready(ready) => ready.run_direct(&mut resolver, invoke)?,
        };
        route.finish()?;
        if timer_error.get() {
            return Err(io::Error::other("actual scoped timer failed").into());
        }
        if let Some(error) = task_error {
            return Err(error.into());
        }
        if scheduled {
            writeln!(stdout, "OFFSET {}", clock.offset()?)?;
        }
        writeln!(
            stdout,
            "RETURN {result} TASKS {calls} UINT {}",
            target.get()?
        )?;
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
    Err(std::io::Error::other("requires resolver-broker feature"))
}
