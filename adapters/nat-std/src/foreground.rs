//! Safe shared foreground; each binary performs once-only inherited-FD capture
//! before logging/config/runtime, then supplies that original owner here.
use crate::{
    manager::Failure,
    server::{self, Event, Mode, Progress, Server},
};
use gnunet_config::Configuration;
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_resolver_broker::{Driver as ResolverDriver, LiveConfiguration};
use gnunet_service_runtime::{
    Activation, BoundListeners,
    clock::RuntimeClock,
    credentials::UnixAccess,
    service::{Listener, ShutdownMode},
    service_options,
};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    time::Instant,
};
/// Once-adopted parent descriptors supplied by the first operation in binary main.
pub struct Inherited {
    /// Actual listener inheritance, never copied raw descriptors.
    pub activation: Activation,
    /// Original optional parent-control source.
    pub parent: Option<ParentControl>,
}
/// Effective bounded foreground policy, using each actual official service section.
pub struct Settings {
    /// Actual NAT/per-source policy and real provider budgets.
    pub discovery: crate::settings::Settings,
    /// Actual bounded business core.
    pub core: gnunet_nat::state::Limits,
    /// Actual original native source bounds.
    pub native: server::Limits,
    /// Official SERVICE listener/access/shutdown policy.
    pub options: gnunet_service_runtime::service::ServiceOptions,
    /// Actual Unix credential admission policy.
    pub unix: UnixAccess,
    /// Same process Resolver resources.
    pub resolver: gnunet_resolver_broker::Limits,
    /// Original finite process drain bound.
    pub grace: Duration,
}
fn number(c: &Configuration, section: &[u8], key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(if c.have_value(section, key) {
        usize::try_from(c.get_number(section, key)?)?
    } else {
        default
    })
}
fn duration(
    c: &Configuration,
    section: &[u8],
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let d = if c.have_value(section, key) {
        Duration::from_micros(c.get_time(section, key)?)
    } else {
        default
    };
    if d.is_zero()
        || d.as_micros() > u128::from(u64::MAX)
        || Instant::now().checked_add(d).is_none()
    {
        return Err("NAT foreground requires finite nonzero timer".into());
    }
    Ok(d)
}
impl Settings {
    /// Read actual service/NAT keys; this does not open listeners or helpers.
    pub fn read(c: &Configuration, mode: Mode) -> Result<Self, Failure> {
        let section = mode.service();
        let d = server::Limits::default();
        let native = server::Limits {
            clients: number(c, b"nat-rust", b"MAX_CLIENTS", d.clients)?,
            frame_bytes: number(c, b"nat-rust", b"FRAME_BYTES", d.frame_bytes)?,
            output_frames: number(c, b"nat-rust", b"OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: number(c, b"nat-rust", b"OUTPUT_BYTES", d.output_bytes)?,
            io_slice_bytes: number(c, b"nat-rust", b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            first_input: duration(c, b"nat-rust", b"FIRST_INPUT_TIMEOUT", d.first_input)?,
            input_lifetime: duration(c, b"nat-rust", b"INPUT_LIFETIME", d.input_lifetime)?,
            output_lifetime: duration(c, b"nat-rust", b"OUTPUT_LIFETIME", d.output_lifetime)?,
            transient_lifetime: duration(
                c,
                b"nat-rust",
                b"TRANSIENT_LIFETIME",
                d.transient_lifetime,
            )?,
        };
        let core = gnunet_nat::state::Limits {
            sources: native.clients,
            providers: number(c, b"nat-rust", b"MAX_PROVIDERS", 1024)?,
            events: number(c, b"nat-rust", b"MAX_EVENTS", 4096)?,
            ..gnunet_nat::state::Limits::default()
        };
        let flag = |key: &[u8]| -> Result<bool, Failure> {
            Ok(c.get(section, key)
                .map(|_| c.get_yesno(section, key))
                .transpose()?
                .unwrap_or(false))
        };
        Ok(Self {
            discovery: crate::settings::Settings::read(c)?,
            core,
            native,
            options: service_options(c, section, ShutdownMode::Soft)?,
            unix: UnixAccess {
                match_uid: flag(b"UNIX_MATCH_UID")?,
                match_gid: flag(b"UNIX_MATCH_GID")?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: native.io_slice_bytes,
                max_queued_frames: 64,
            },
            grace: duration(c, b"nat-rust", b"SHUTDOWN_GRACE", Duration::from_secs(10))?,
        })
    }
}
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _written = writeln!(io::stderr().lock(), "{args}");
}
fn observe(event: Event) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(e))
            if e.is_emfile() => {}
        Event::Socket(e) => diagnostic(format_args!("NAT socket: {e:?}")),
        Event::AdmissionFailed { peer, error } => {
            diagnostic(format_args!("NAT original admission {peer:?}: {error}"))
        }
        Event::Closed { source, cause } => diagnostic(format_args!(
            "NAT source={} closed: {cause:?}",
            source.serial()
        )),
        Event::Discovery(crate::manager::Event::Failed { job, source, error }) => diagnostic(
            format_args!("NAT job={job} source={source:?} failed: {error}"),
        ),
        Event::Discovery(crate::manager::Event::MappingUnknown { source, port }) => {
            diagnostic(format_args!(
                "NAT original source={} external-port={port} mapping outcome remains unknown",
                source.serial()
            ))
        }
        Event::Discovery(crate::manager::Event::Helper(e)) => {
            diagnostic(format_args!("NAT helper: {e:?}"))
        }
        _ => {}
    }
}
struct Signals {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new(parent: Option<ParentControl>) -> io::Result<Self> {
        Ok(Self {
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(s)))
                    if i32::from(s) == SignalKind::interrupt().as_raw_value()
                        || i32::from(s) == SignalKind::terminate().as_raw_value() =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        for s in [&mut self.interrupt, &mut self.terminate] {
            match s.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "NAT signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    resolver: Option<Failure>,
    report: Option<io::Error>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none()
            && self.task.is_none()
            && self.resolver.is_none()
            && self.report.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NAT foreground failures:")?;
        for (label, error) in [
            ("PROGRAM", self.program.as_deref()),
            ("task", self.task.as_deref()),
            ("Resolver cleanup", self.resolver.as_deref()),
        ] {
            if let Some(e) = error {
                write!(f, " {label}=({e})")?;
            }
        }
        if let Some(e) = &self.report {
            write!(f, " report=({e})")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.program
            .as_deref()
            .or(self.task.as_deref())
            .or(self.resolver.as_deref())
            .or(self.report.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
struct Owners {
    server: Server,
    resolver: ResolverDriver<64, 1024>,
    done: bool,
}
impl Drop for Owners {
    fn drop(&mut self) {
        if !self.done {
            self.server.abort(&mut observe);
            let resolver = self.resolver.disconnect();
            diagnostic(format_args!(
                "NAT dropped: actual original sources/helper stop requested; router cleanup/reap not fabricated, report={:?}, Resolver={resolver:?}",
                self.server.report()
            ));
        }
    }
}
/// Shared actual PROGRAM task and original Resolver/clock; no constructor claims
/// NAT connectivity. READY is only successful local listener/owner setup.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    mode: Mode,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
        live,
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                let outcome = run(config, settings, inherited, mode, resolver, runtime_clock).await;
                *destination.borrow_mut() = Some(outcome);
                if let Err(error) = stop.shutdown() {
                    let task = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task,
                            ..Failures::default()
                        }
                        .finish(),
                    );
                }
            }) {
                *receiving.borrow_mut() = Some(Err(error.into()));
                if let Err(error) = scope.shutdown() {
                    let task = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task,
                            ..Failures::default()
                        }
                        .finish(),
                    );
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without NAT task completion".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("NAT PROGRAM returned {code}").into()),
        Err(e) => Some(Box::new(e) as Failure),
    };
    Failures {
        program,
        task,
        ..Failures::default()
    }
    .finish()
}
enum Turn {
    Signal,
    Resolver,
    Server(Progress),
}
async fn turn(
    owners: &mut Owners,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    until: Option<Instant>,
    resolver_first: bool,
) -> Result<Turn, Failure> {
    let (server, resolver) = (&mut owners.server, &mut owners.resolver);
    let mut resolving = std::pin::pin!(
        resolver.drive_waiting(until, |e| diagnostic(format_args!("NAT Resolver: {e:?}")))
    );
    poll_fn(|cx| {
        if let Poll::Ready(r) = signals.poll(cx) {
            return Poll::Ready(r.map(|()| Turn::Signal).map_err(Into::into));
        }
        for n in 0..2 {
            if (n == 0) == resolver_first {
                if let Poll::Ready(r) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(r.map(|_| Turn::Resolver).map_err(Into::into));
                }
            } else if let Poll::Ready(r) = server.poll(cx, listeners, until, &mut observe) {
                return Poll::Ready(r.map(Turn::Server));
            }
        }
        Poll::Pending
    })
    .await
}
async fn run(
    config: Configuration,
    settings: Settings,
    inherited: Inherited,
    mode: Mode,
    resolver: ResolverDriver<64, 1024>,
    clock: Arc<dyn RuntimeClock>,
) -> Result<(), Failure> {
    let initialized = (|| -> Result<_, Failure> {
        let signals = Signals::new(inherited.parent)?;
        let shared = resolver.context().resolution_context();
        let server = Server::new(
            config.duplicate()?,
            settings.discovery,
            settings.core,
            settings.native,
            server::Ports {
                options: settings.options.clone(),
                unix: settings.unix,
                clock,
                resolver: shared,
            },
            mode,
        )?;
        Ok((signals, server))
    })();
    let (mut signals, server) = match initialized {
        Ok(v) => v,
        Err(task) => {
            let mut resolver = resolver;
            let cleanup = resolver.disconnect().err().map(|e| Box::new(e) as Failure);
            return Failures {
                task: Some(task),
                resolver: cleanup,
                ..Failures::default()
            }
            .finish();
        }
    };
    let mut owners = Owners {
        server,
        resolver,
        done: false,
    };
    let bound = match BoundListeners::bind(&config, mode.service(), inherited.activation).await {
        Ok(b) => b,
        Err(e) => {
            owners.server.abort(&mut observe);
            let cleanup = owners
                .resolver
                .disconnect()
                .err()
                .map(|e| Box::new(e) as Failure);
            owners.done = true;
            return Failures {
                task: Some(e),
                resolver: cleanup,
                ..Failures::default()
            }
            .finish();
        }
    };
    for error in bound.failures() {
        diagnostic(format_args!("NAT alternate listener: {error}"));
    }
    let ready = {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "READY {} wire=0.29.1 local-listeners=yes connectivity=unproven backend=rust",
            String::from_utf8_lossy(mode.service())
        )
        .and_then(|()| out.flush())
    };
    let outcome = if let Err(e) = ready {
        Err(Box::new(e) as Failure)
    } else {
        let listeners = bound.listeners();
        let mut until = None;
        let mut resolver_first = false;
        loop {
            let next = turn(&mut owners, &mut signals, &listeners, until, resolver_first).await;
            resolver_first = !resolver_first;
            match next {
                Ok(Turn::Signal)
                    if until.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
                {
                    owners.server.request_shutdown(ShutdownMode::Soft);
                    until = Some(
                        Instant::now()
                            .checked_add(settings.grace)
                            .ok_or("NAT shutdown bound overflow")?,
                    );
                }
                Ok(Turn::Signal | Turn::Server(Progress::WaitDeadline)) => {
                    owners.server.abort(&mut observe);
                    break Ok(());
                }
                Ok(Turn::Server(Progress::Stopped)) => break Ok(()),
                Ok(Turn::Resolver | Turn::Server(Progress::Activity)) => {}
                Err(e) => break Err(e),
            }
        }
    };
    let report = owners.server.report();
    let cleanup = owners.resolver.disconnect();
    owners.done = true;
    drop(owners);
    drop(bound);
    let report_io = {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "STOPPED {} actual={report:?} resolver={cleanup:?}",
            String::from_utf8_lossy(mode.service())
        )
        .and_then(|()| out.flush())
    };
    let task = outcome.err().or_else(|| {
        (report.pending != 0 || report.unresolved != 0)
            .then(|| format!("NAT original cleanup remains unestablished: {report:?}").into())
    });
    Failures {
        task,
        resolver: cleanup.err().map(|e| Box::new(e) as Failure),
        report: report_io.err(),
        ..Failures::default()
    }
    .finish()
}
