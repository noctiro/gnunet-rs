//! Native NAT command scheduling, diagnostics and resource retirement.
use crate::Failure;
use gnunet_client_host::resolution::SharedResolution;
use gnunet_config::Configuration;
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::LiveConfiguration as ResolverConfiguration;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ClientStartup, StopSignals};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
mod auto;
mod nat;
mod resolver;
use auto::auto;
use nat::nat_monitor;
use resolver::Resolver;
type Signals = StopSignals;
/// Actual selected command, with standard official option spellings supplied by
/// the binary's shared GETOPT table. No private wire or success token is added.
#[derive(Clone, Debug)]
pub enum Action {
    /// Actual address registration/reversal/STUN monitor.
    Nat(NatOptions),
    /// Actual configuration query and/or external path test.
    Auto(AutoOptions),
}
/// Official gnunet-nat inputs; every new registration is an explicit new source
/// lease of this user's ongoing monitor intent, never an old operation replay.
#[derive(Clone, Debug)]
pub struct NatOptions {
    /// Original --in literal Internet endpoint.
    pub local: SocketAddr,
    /// Original --remote reversal target, one-shot only.
    pub remote: Option<SocketAddr>,
    /// Original --section name.
    pub section: Vec<u8>,
    /// Exactly TCP6 or UDP17.
    pub protocol: u8,
    /// Selected STUN socket behavior.
    pub stun: StunMode,
    /// Actual --watch reversal callbacks.
    pub watch: bool,
}
/// How the NAT monitor uses a bound UDP socket for STUN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StunMode {
    /// No STUN socket.
    Disabled,
    /// Forward genuine incoming STUN packets, as in the official command.
    Receive,
    /// Probe configured endpoints and forward only matching responses.
    Probe,
}
/// Official gnunet-nat-auto inputs.
#[derive(Clone, Debug)]
pub struct AutoOptions {
    /// Actual --auto query.
    pub configure: bool,
    /// Actual --section reachability test, if supplied.
    pub section: Option<Vec<u8>>,
    /// Actual TCP6/UDP17 selector for tests.
    pub protocol: Option<u8>,
    /// Actual --write permission to publish only proposed NAT configuration.
    pub write: bool,
}
fn output(args: std::fmt::Arguments<'_>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{args}")?;
    out.flush()
}
fn diagnostic(reports: &Reporter, args: std::fmt::Arguments<'_>) {
    reports.warning("nat.cli.activity", args);
}
/// Run one actual shared PROGRAM task; actual query/test output controls return,
/// while service/Resolver shutdown errors remain independent real failures.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    action: Action,
    startup: ClientStartup,
    reports: Reporter,
) -> Result<(), Failure> {
    let signals = StopSignals::for_client(startup.parent)?;
    let config = prepared.main().config.duplicate()?;
    let filename = prepared.main().filename.map(PathBuf::from);
    let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = ResolverConfiguration::new(config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
        live,
        gnunet_resolver_broker::Limits {
            max_frame_bytes: 65535,
            io_chunk_bytes: 65535,
            max_queued_frames: 64,
        },
        gnunet_resolver_broker::native_profile()?,
        runtime.clone(),
    )?;
    let resolution = context.resolution_context();
    let deferred = Rc::new(RefCell::new(None));
    let resolver = Resolver::new(resolver, deferred.clone());
    let task_reports = reports.clone();
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                let completed = run(Inputs {
                    config,
                    filename,
                    action,
                    resolver,
                    resolution,
                    clock: runtime,
                    signals,
                    reports: task_reports,
                })
                .await;
                *destination.borrow_mut() = Some(completed);
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
        .unwrap_or_else(|| Err("PROGRAM ended without NAT CLI task completion".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("NAT CLI PROGRAM returned {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    let resolver = deferred
        .borrow_mut()
        .take()
        .map(|error| Box::new(error) as Failure);
    gnunet_program_host::service::retain_diagnostic(
        Failures {
            program,
            task,
            resolver,
        }
        .finish(),
        reports.take_error(),
    )
}
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    resolver: Option<Failure>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none() && self.task.is_none() && self.resolver.is_none() {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NAT CLI failures:")?;
        for (name, error) in [
            ("PROGRAM", self.program.as_deref()),
            ("action", self.task.as_deref()),
            ("Resolver cleanup", self.resolver.as_deref()),
        ] {
            if let Some(e) = error {
                write!(f, " {name}=({e})")?;
            }
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
    }
}
struct Inputs {
    config: Configuration,
    filename: Option<PathBuf>,
    action: Action,
    resolver: Resolver,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    signals: Signals,
    reports: Reporter,
}
async fn run(input: Inputs) -> Result<(), Failure> {
    let Inputs {
        config,
        filename,
        action,
        mut resolver,
        resolution,
        clock,
        mut signals,
        reports,
    } = input;
    let mut resolving = Box::pin(resolver::drive(&mut resolver.driver, &reports));
    let mut action = Box::pin(async {
        match action {
            Action::Nat(options) => {
                nat_monitor(&config, resolution, clock, options, &mut signals, &reports).await
            }
            Action::Auto(options) => {
                auto(
                    &config,
                    filename,
                    resolution,
                    clock,
                    options,
                    &mut signals,
                    &reports,
                )
                .await
            }
        }
    });
    let mut first = false;
    let result = poll_fn(|cx| {
        reports.register(cx);
        for n in 0..2 {
            if reports.failed() {
                return Poll::Ready(Err("NAT CLI selected Logger failed".into()));
            }
            if (n == 0) == first {
                if let Poll::Ready(result) = action.as_mut().poll(cx) {
                    return Poll::Ready(result);
                }
            } else if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                return Poll::Ready(
                    result.map_err(|e: gnunet_resolver_broker::BrokerError| Box::new(e) as Failure),
                );
            }
        }
        first = !first;
        Poll::Pending
    })
    .await;
    drop(action);
    drop(resolving);
    let cleanup = resolver.close();
    Failures {
        task: result.err(),
        resolver: cleanup.err().map(|e| Box::new(e) as Failure),
        ..Failures::default()
    }
    .finish()
}
fn interval(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    let n = c
        .get(b"nat-rust", key)
        .map(|_| c.get_time(b"nat-rust", key))
        .transpose()?
        .unwrap_or(default);
    let d = Duration::from_micros(n);
    if n == 0 || n == u64::MAX || Instant::now().checked_add(d).is_none() {
        return Err("NAT CLI bounds must be finite and nonzero".into());
    }
    Ok(d)
}
