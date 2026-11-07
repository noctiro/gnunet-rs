//! One actual standard PROGRAM task, one Resolver and one explicit file worker.
mod control;
mod reporting;
mod settings;
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_fs_host::auto_share::{Options, Owner, Stop};
use gnunet_program_host::{
    getopt,
    helpers::{self, Target},
    logging::Logger,
    policy::Level,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation, Prepared},
    shared_clock::SharedClock,
};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use reporting::Reports;
use settings::Settings;
use std::{
    cell::RefCell,
    error::Error,
    ffi::OsStr,
    future::{Future, poll_fn},
    io,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
pub(super) type Failure = Box<dyn Error>;
#[derive(Debug, Default)]
struct Failures {
    original: Option<Failure>,
    signal: Option<io::Error>,
    resolver: Option<Failure>,
    disconnect: Option<Failure>,
    program: Option<Failure>,
    admission: Option<Failure>,
    scope: Option<Failure>,
    native: Option<Failure>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.signal.is_none()
            && self.resolver.is_none()
            && self.disconnect.is_none()
            && self.program.is_none()
            && self.admission.is_none()
            && self.scope.is_none()
            && self.native.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("automatic sharing failed")?;
        for (name, error) in [
            ("original", self.original.as_deref()),
            ("resolver", self.resolver.as_deref()),
            ("resolver-close", self.disconnect.as_deref()),
            ("program", self.program.as_deref()),
            ("task-admission", self.admission.as_deref()),
            ("scheduler-shutdown", self.scope.as_deref()),
            ("original-publication/worker", self.native.as_deref()),
        ] {
            if let Some(error) = error {
                write!(f, "; {name}: {error}")?;
            }
        }
        if let Some(error) = &self.signal {
            write!(f, "; signal: {error}")?;
        }
        Ok(())
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.native.as_deref())
            .or(self.resolver.as_deref())
            .or(self.program.as_deref())
    }
}
pub(super) fn run(parent: Option<ParentControl>) -> Result<(), Failure> {
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-auto-share", std::process::id(), false)?;
    let anonymity = Target::new(1u32);
    let priority = Target::new(365u32);
    let replication = Target::new(1u32);
    let date = Target::new(0i32);
    let extractor = Target::new(0i32);
    let extractors = Target::new(None);
    let extractor_library = Target::new(None);
    let verbose = Target::new(0u32);
    let mut options = getopt::Options::new();
    options.add(helpers::uint(
        b'a',
        b"anonymity",
        b"LEVEL",
        b"anonymity level",
        anonymity.clone(),
    ));
    options.add(helpers::uint(
        b'p',
        b"priority",
        b"PRIORITY",
        b"publication priority",
        priority.clone(),
    ));
    options.add(helpers::uint(
        b'r',
        b"replication",
        b"LEVEL",
        b"replication level",
        replication.clone(),
    ));
    options.add(helpers::flag(
        b'd',
        b"disable-creation-time",
        b"omit creation-time metadata",
        date.clone(),
    ));
    options.add(helpers::flag(
        b'D',
        b"disable-extractor",
        b"disable format extraction and extracted keywords",
        extractor.clone(),
    ));
    options.add(helpers::string(
        0,
        b"extractors",
        b"CONFIG",
        b"override FS.EXTRACTORS (exact - disables format probes, keeps filename keywords)",
        extractors.clone(),
    ));
    options.add(helpers::string(
        0,
        b"extractor-library",
        b"ABSOLUTE-LIBRARY",
        b"explicit standard libextractor library; loaded only inside the file worker",
        extractor_library.clone(),
    ));
    options.add(helpers::verbose(verbose.clone()));
    let preparation=program::prepare(config,Invocation{binary_name:b"gnunet-auto-share",help:Some(b"Share changed files and directories using the standard FS publication API. Exactly one DIRECTORY is required."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let stop = Stop::default();
    let reports = Rc::new(RefCell::new(Reports::new(
        logger,
        clock.clone(),
        verbose.get()?,
        stop.clone(),
    )));
    let result = (|| {
        let prepared = match preparation? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s)
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
            {
                return Ok(());
            }
            Preparation::Stopped(s) => {
                return Err(
                    format!("PROGRAM stopped: {:?} (source code {})", s.reason, s.code).into(),
                );
            }
        };
        let [directory] = prepared.main().arguments else {
            return Err("gnunet-auto-share requires exactly one DIRECTORY".into());
        };
        let directory = PathBuf::from(OsStr::from_bytes(directory));
        let disabled = extractor.get()? != 0;
        let settings = extractors.with(|selected| {
            extractor_library.with(|library| {
                Settings::read(
                    prepared.main().config,
                    disabled,
                    selected.as_deref(),
                    library.as_deref(),
                )
            })
        })???;
        let policy = Options {
            anonymity: anonymity.get()?,
            priority: priority.get()?,
            replication: replication.get()?,
            disable_extractor: disabled,
            disable_creation_time: date.get()? != 0,
            ..Default::default()
        };
        let user = gnunet_service_startup::configured_user(prepared.main().config, b"auto-share")?
            .map(|n| gnunet_service_startup::resolve_user(&n))
            .transpose()?;
        let applied = gnunet_service_startup::apply_privileges(
            user.as_ref(),
            gnunet_service_startup::GroupsProfile::WithInitgroups,
        )?;
        if user.is_some() {
            reports.borrow_mut().log(
                "auto-share.process-identity",
                Level::INFO,
                format_args!("{applied:?}"),
            );
        }
        if reports.borrow().failed() {
            return Ok(());
        }
        // No directory descriptor, private catalog, thread or native client exists
        // before the process identity and the shared PROGRAM have actually succeeded.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(scheduled(
                prepared,
                clock,
                Run {
                    settings,
                    directory,
                    policy,
                    parent,
                    stop,
                    reports: Rc::clone(&reports),
                },
            ))
    })();
    if let Err(error) = &result {
        reports.borrow_mut().log(
            "auto-share.program-failed",
            Level::ERROR,
            format_args!("{error}"),
        );
    }
    let diagnostic = reports.borrow_mut().take_failure();
    gnunet_program_host::service::retain_diagnostic(result, diagnostic)
}
struct NativeTask<F> {
    future: Pin<Box<F>>,
    result: Option<Result<(), Failure>>,
}
impl<F: Future<Output = Result<(), Failure>>> NativeTask<F> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.result.is_some() {
            return Poll::Ready(());
        }
        match self.future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.result = Some(result);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
struct Run {
    settings: Settings,
    directory: PathBuf,
    policy: Options,
    parent: Option<ParentControl>,
    stop: Stop,
    reports: Rc<RefCell<Reports>>,
}
async fn scheduled(prepared: Prepared, clock: SharedClock, run: Run) -> Result<(), Failure> {
    let stop = run.stop.clone();
    let config = prepared.main().config.duplicate()?;
    let actual: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        run.settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        actual,
    )?;
    let resolution = context.resolution_context();
    let native = Rc::new(RefCell::new(NativeTask {
        future: Box::pin(run_native(run, resolver, live, resolution)),
        result: None,
    }));
    let admission = Rc::new(RefCell::new(None));
    let scope_failure = Rc::new(RefCell::new(None));
    let task = Rc::clone(&native);
    let admitted = Rc::clone(&admission);
    let shutdown = Rc::clone(&scope_failure);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let finishing = scope.clone();
            let cleanup = Rc::clone(&shutdown);
            let work = async move {
                poll_fn(|cx| task.borrow_mut().poll(cx)).await;
                if let Err(error) = finishing.shutdown() {
                    *cleanup.borrow_mut() = Some(Box::new(error) as Failure);
                }
            };
            if let Err(error) = scope.spawn(work) {
                *admitted.borrow_mut() = Some(Box::new(error) as Failure);
                if let Err(error) = scope.shutdown() {
                    *shutdown.borrow_mut() = Some(Box::new(error) as Failure);
                }
            }
        })
        .await;
    // PROGRAM may fail before spawning/polling or while its wrapper is canceled.
    // Keep the same original future through native retirement and actual worker join.
    stop.request();
    poll_fn(|cx| native.borrow_mut().poll(cx)).await;
    let native = native
        .borrow_mut()
        .result
        .take()
        .unwrap_or_else(|| Err("original auto-share task lost completion".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("auto-share PROGRAM returned source code {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    Failures {
        program,
        native,
        admission: admission.borrow_mut().take(),
        scope: scope_failure.borrow_mut().take(),
        ..Default::default()
    }
    .finish()
}
async fn run_native(
    run: Run,
    mut resolver: Driver<64, 256>,
    live: LiveConfiguration,
    resolution: gnunet_client_host::resolution::SharedResolution,
) -> Result<(), Failure> {
    let result = async {
        if run.stop.requested() {
            return Ok(());
        }
        let mut signals = control::Signals::new(run.parent)?;
        let source =
            |name: &'static [u8]| EndpointSource::live(live.clone(), name, resolution.clone());
        let mut owner = Owner::open_with_metadata(
            &run.directory,
            source(b"fs"),
            source(b"datastore"),
            run.policy,
            run.settings.limits,
            run.stop.clone(),
            run.settings.metadata,
        )?;
        serve(
            &mut owner,
            &mut resolver,
            &mut signals,
            &run.stop,
            &run.reports,
        )
        .await
    }
    .await;
    let disconnect = resolver.disconnect().err().map(|e| Box::new(e) as Failure);
    Failures {
        original: result.err(),
        disconnect,
        ..Default::default()
    }
    .finish()
}
async fn serve(
    owner: &mut Owner,
    resolver: &mut Driver<64, 256>,
    signals: &mut control::Signals,
    stop: &Stop,
    reports: &Rc<RefCell<Reports>>,
) -> Result<(), Failure> {
    let mut failures = Failures::default();
    let mut resolver_failed = false;
    let mut signals_ended = false;
    let mut running = std::pin::pin!(owner.run(|event| reports.borrow_mut().event(event)));
    let answer = loop {
        let mut resolving =
            std::pin::pin!(
                resolver.drive_waiting(None, |event| reports.borrow_mut().log(
                    "auto-share.resolver",
                    Level::DEBUG,
                    format_args!("{event:?}")
                ))
            );
        let turn = poll_fn(|cx| {
            if reports.borrow().failed() {
                stop.request();
            }
            let signal = if signals_ended {
                None
            } else {
                match signals.poll(cx) {
                    Poll::Ready(v) => Some(v),
                    Poll::Pending => None,
                }
            };
            if signal.is_some() {
                stop.request();
            }
            // Original publication/native guards are driven before canonical-clock
            // Resolver waiting, and remain polled after every stop/error request.
            let native = match running.as_mut().poll(cx) {
                Poll::Ready(v) => Some(v),
                Poll::Pending => None,
            };
            let resolved = if resolver_failed {
                None
            } else {
                match resolving.as_mut().poll(cx) {
                    Poll::Ready(v) => Some(v.map(|_| ()).map_err(|e| Box::new(e) as Failure)),
                    Poll::Pending => None,
                }
            };
            if native.is_some() || signal.is_some() || resolved.is_some() {
                Poll::Ready((native, signal, resolved))
            } else {
                Poll::Pending
            }
        })
        .await;
        if let Some(signal) = turn.1 {
            signals_ended = true;
            if let Err(error) = signal {
                failures.signal = Some(error);
            }
            stop.request();
        }
        if let Some(Err(error)) = turn.2 {
            failures.resolver = Some(error);
            resolver_failed = true;
            stop.request();
        }
        if let Some(answer) = turn.0 {
            break answer;
        }
        tokio::task::yield_now().await;
    };
    match answer {
        Ok(report) => reports.borrow_mut().stopped(&report),
        Err(error) => failures.native = Some(error as Failure),
    };
    failures.finish()
}
