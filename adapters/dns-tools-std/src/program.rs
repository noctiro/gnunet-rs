//! One explicit PROGRAM task fairly drives actual DNS MQ and process Resolver.
use crate::{Action, packet};
use gnunet_dns_client_host::{
    self as dns, Client, EndpointSource, Instance, Progress, Request, ipc,
};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
    logging::Logger,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation, Prepared},
    shared_clock::SharedClock,
};
use gnunet_resolver_broker::{Driver, LiveConfiguration};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::RefCell,
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    time::{Instant, Sleep},
};
use zeroize::Zeroizing;
type Failure = Box<dyn Error>;
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _diagnostic = writeln!(io::stderr().lock(), "{args}");
}
struct Settings {
    action: Action,
    flags: u32,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    duration: Duration,
    packets: u32,
    verbosity: u32,
    limits: dns::Limits,
    bounds: packet::Bounds,
    socket: Option<std::path::PathBuf>,
}
/// Actual utility PROGRAM invocation. It creates no TUN/helper/firewall rule and
/// uses only the admitted DNS interception service client and shared Resolver.
pub fn run(action: Action) -> Result<(), Failure> {
    let inbound = Target::new(0i32);
    let outbound = Target::new(0i32);
    let ipv4 = Target::new(None);
    let ipv6 = Target::new(None);
    let duration = Target::new(300_000u32);
    let packets = Target::new(0u32);
    let verbosity = Target::new(0u32);
    let socket = Target::new(Filename {
        path: None,
        error: None,
    });
    let entries = Target::new(16384u32);
    let slice = Target::new(65535u32);
    let mut options = Options::new();
    match action {
        Action::Monitor => {
            options.add(helpers::flag(
                b'i',
                b"inbound-only",
                b"observe only original queries",
                inbound.clone(),
            ));
            options.add(helpers::flag(
                b'o',
                b"outbound-only",
                b"observe only final responses",
                outbound.clone(),
            ));
        }
        Action::Redirect => {
            options.add(helpers::string(
                b'4',
                b"ipv4",
                b"IPV4",
                b"replace answer-section A records",
                ipv4.clone(),
            ));
            options.add(helpers::string(
                b'6',
                b"ipv6",
                b"IPV6",
                b"replace answer-section AAAA records",
                ipv6.clone(),
            ));
        }
    }
    options.add(helpers::verbose(verbosity.clone()));
    options.add(helpers::uint(
        0,
        b"duration-ms",
        b"MS",
        b"finite run window (default300000ms)",
        duration.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"max-packets",
        b"COUNT",
        b"stop after callbacks;0 runs to original duration",
        packets.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"max-entries",
        b"COUNT",
        b"bounded counted DNS entries per packet",
        entries.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"io-slice-bytes",
        b"BYTES",
        b"actual MQ syscall byte slice",
        slice.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"socket",
        b"PATH",
        b"explicit Unix DNS service endpoint",
        socket.clone(),
    ));
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let clock = SharedClock::native(16)?;
    let binary = match action {
        Action::Monitor => b"gnunet-dns-monitor".as_slice(),
        Action::Redirect => b"gnunet-dns-redirector".as_slice(),
    };
    let mut logger = Logger::new(binary, std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:binary,help:Some(b"Actual official DNS interception monitor/answer redirector. -i/-o choose monitor directions; -4/-6 replace only answer A/AAAA. Whole write is local only; no subscription ACK. Default finite5-minute window, Ctrl-C physically closes original MQ; reconnect resubscribes flags without replay."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            return if s.code == 0 {
                Ok(())
            } else {
                Err(format!("DNS utility PROGRAM stopped {:?} code={}", s.reason, s.code).into())
            };
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("DNS utility accepts no positional arguments".into());
    }
    let ms = duration.get()?;
    let count = entries.get()?;
    let slice = slice.get()?;
    if ms == 0 || ms > 86_400_000 || count == 0 || count > 16384 || slice == 0 || slice > 65535 {
        return Err("invalid finite DNS utility resource/time policy".into());
    }
    let duration = Duration::from_millis(u64::from(ms));
    if Instant::now().checked_add(duration).is_none() {
        return Err("DNS utility duration overflow".into());
    }
    let socket = socket.get()?;
    if let Some(e) = socket.error {
        return Err(format!("DNS socket expansion: {e}").into());
    }
    let ipv4 = ipv4
        .get()?
        .map(String::from_utf8)
        .transpose()?
        .map(|s| s.parse())
        .transpose()?;
    let ipv6 = ipv6
        .get()?
        .map(String::from_utf8)
        .transpose()?
        .map(|s| s.parse())
        .transpose()?;
    let flags = if action == Action::Redirect {
        ipc::POST_RESOLUTION
    } else {
        match (inbound.get()? != 0, outbound.get()? != 0) {
            (true, false) => ipc::REQUEST_MONITOR,
            (false, true) => ipc::RESPONSE_MONITOR,
            _ => ipc::REQUEST_MONITOR | ipc::RESPONSE_MONITOR,
        }
    };
    let settings = Settings {
        action,
        flags,
        ipv4,
        ipv6,
        duration,
        packets: packets.get()?,
        verbosity: verbosity.get()?,
        limits: dns::Limits {
            requests: 64,
            source_bytes: 4 * 1024 * 1024,
            io_slice_bytes: slice as usize,
            ..Default::default()
        },
        bounds: packet::Bounds {
            entries: count as usize,
            ..Default::default()
        },
        socket: socket.path,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(scheduled(prepared, clock, settings))
}
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    resolver: Option<Failure>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DNS utility failures program={:?} task={:?} resolver={:?}",
            self.program, self.task, self.resolver
        )
    }
}
impl Error for Failures {}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none() && self.task.is_none() && self.resolver.is_none() {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let native_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live.clone(),
        Default::default(),
        gnunet_resolver_broker::native_profile()?,
        native_clock.clone(),
    )?;
    let source = match settings.socket.clone() {
        Some(path) => EndpointSource::unix_with_clock(path, native_clock),
        None => EndpointSource::live(live, b"dns", context.resolution_context()),
    };
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stopping = scope.clone();
            if let Err(error) = scope.spawn(async move {
                *destination.borrow_mut() = Some(session(source, resolver, settings).await);
                if let Err(error) = stopping.shutdown() {
                    let previous = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task: previous,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error) as Failure));
                if let Err(error) = scope.shutdown() {
                    let previous = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task: previous,
                            ..Default::default()
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
        .unwrap_or_else(|| Err("DNS PROGRAM ended without utility task result".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("DNS PROGRAM returned source code{code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    Failures {
        program,
        task,
        ..Default::default()
    }
    .finish()
}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "DNS utility signal source closed",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
struct Owner<'a> {
    dns: Client<'a>,
    resolver: Driver<8, 256>,
    closed: bool,
}
impl Owner<'_> {
    fn close(&mut self) -> Option<Failure> {
        if self.closed {
            return None;
        }
        self.closed = true;
        report_loss(self.dns.close());
        self.resolver
            .disconnect()
            .err()
            .map(|e| Box::new(e) as Failure)
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if let Some(e) = self.close() {
            diagnostic(format_args!("DNS utility independent cleanup: {e}"));
        }
    }
}
fn report_loss(progress: Progress<'_>) {
    if let Progress::Lost {
        epoch,
        cause,
        requests,
    } = progress
    {
        diagnostic(format_args!(
            "DNS original source retired epoch={epoch:?} cause={cause:?} callbacks={requests}; no remote cancellation receipt"
        ));
    }
}
#[derive(Clone, Copy, Debug)]
enum Choice {
    Forward,
    Answer { records: usize },
    TimeoutDrop,
}
struct Pending<'a> {
    token: Request<'a>,
    choice: Choice,
}
enum Turn<'a> {
    Signal,
    Dns(Progress<'a>),
    Resolver,
    Deadline,
}
async fn next<'a>(
    owner: &mut Owner<'a>,
    signals: &mut Signals,
    alarm: &mut Pin<Box<Sleep>>,
    until: Instant,
    resolver_first: bool,
) -> Result<Turn<'a>, Failure> {
    let (mut_dns, resolver) = (&mut owner.dns, &mut owner.resolver);
    let mut resolving = std::pin::pin!(resolver.drive_waiting(Some(until), |event| {
        let _actual = event;
    }));
    poll_fn(|cx| {
        if let Poll::Ready(signal) = signals.poll(cx) {
            return Poll::Ready(signal.map(|()| Turn::Signal).map_err(Into::into));
        }
        if alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(Turn::Deadline));
        }
        for i in 0..2 {
            if (i == 0) == resolver_first {
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(result.map(|_| Turn::Resolver).map_err(Into::into));
                }
            } else if let Poll::Ready(result) = mut_dns.poll(cx, Some(until)) {
                return Poll::Ready(result.map(Turn::Dns).map_err(Into::into));
            }
        }
        Poll::Pending
    })
    .await
}
async fn session(
    source: EndpointSource,
    resolver: Driver<8, 256>,
    settings: Settings,
) -> Result<(), Failure> {
    let instance = Instance::new();
    let mut owner = match Client::new(&instance, source, settings.flags, settings.limits) {
        Ok(dns) => Owner {
            dns,
            resolver,
            closed: false,
        },
        Err(original) => {
            let mut resolver = resolver;
            return Failures {
                task: Some(Box::new(original)),
                resolver: resolver.disconnect().err().map(|e| Box::new(e) as Failure),
                ..Default::default()
            }
            .finish();
        }
    };
    let outcome=async{
        let mut signals=Signals::new()?;
        let mut arena=Vec::new();arena.try_reserve_exact(packet::ARENA_BYTES)?;arena.resize(packet::ARENA_BYTES,0);let mut arena=Zeroizing::new(arena);
        let mut output=Vec::new();output.try_reserve_exact(packet::MAX_PACKET)?;output.resize(packet::MAX_PACKET,0);let mut output=Zeroizing::new(output);
        let mut pending=Vec::<Pending<'_>>::new();pending.try_reserve_exact(settings.limits.requests)?;
        let until=Instant::now().checked_add(settings.duration).ok_or("DNS utility native deadline overflow")?;
        let mut alarm=Box::pin(tokio::time::sleep_until(until));let mut stop=None;let mut packets=0u64;let mut writes=0u64;let mut first=false;
        loop{
            let wait=stop.unwrap_or(until);alarm.as_mut().reset(wait);
            match next(&mut owner,&mut signals,&mut alarm,wait,first).await?{
                Turn::Signal|Turn::Deadline=>break,
                Turn::Resolver=>{},
                Turn::Dns(Progress::Request(notification))=>{
                    if stop.is_some(){drop(notification);continue;}
                    let token=notification.request();
                    if pending.len()==settings.limits.requests{return Err("DNS original callback metadata capacity".into());}
                    let choice=match settings.action{
                        Action::Monitor=>{
                            match packet::display(notification.dns(), &mut arena, settings.bounds, &mut io::stdout().lock()) {
                                Ok(()) => {},
                                Err(error) if error.is::<gnunet_dns::Error>() => diagnostic(format_args!("Malformed/bounded DNS callback forwarded unchanged: {error}")),
                                Err(error) => return Err(error),
                            }
                            owner.dns.reply(token,ipc::Decision::Forward)?;Choice::Forward
                        }
                        Action::Redirect=>match packet::redirect(notification.dns(),settings.ipv4,settings.ipv6,&mut arena,&mut output,settings.bounds){
                            Ok((bytes,changed)) if changed!=0=>{owner.dns.reply(token,ipc::Decision::Answer(bytes))?;Choice::Answer{records:changed}}
                            Ok(_)=>{owner.dns.reply(token,ipc::Decision::Forward)?;Choice::Forward}
                            Err(error)=>{diagnostic(format_args!("DNS redirect refused; original unchanged: {error}"));owner.dns.reply(token,ipc::Decision::Forward)?;Choice::Forward}
                        }
                    };
                    if settings.verbosity!=0{diagnostic(format_args!("DNS reply locally admitted token={token:?} decision={choice:?}; no processing ACK"));}
                    pending.push(Pending{token,choice});packets=packets.saturating_add(1);
                    if settings.packets!=0&&packets>=u64::from(settings.packets){stop=Some(until.min(Instant::now()+Duration::from_secs(5)));}
                }
                Turn::Dns(Progress::Written(token))=>{
                    let row=pending.iter().position(|p|p.token==token).map(|i|pending.swap_remove(i));writes=writes.saturating_add(1);
                    if let Some(row)=row{match row.choice{Choice::Forward=>{if settings.verbosity>0{diagnostic(format_args!("DNS original Forward whole local write: {token:?}"));}},Choice::Answer{records}=>{if settings.verbosity>0{diagnostic(format_args!("DNS original Answer whole local write: {token:?}, records={records}; remote delivery unclaimed"));}},Choice::TimeoutDrop=>diagnostic(format_args!("DNS timeout Drop whole local write: {token:?}"))}}
                    if stop.is_some()&&pending.is_empty(){break;}
                }
                Turn::Dns(Progress::Dropping(token))=>{if let Some(p)=pending.iter_mut().find(|p|p.token==token){p.choice=Choice::TimeoutDrop;}diagnostic(format_args!("DNS original callback expired; actual Drop locally admitted {token:?}"));}
                Turn::Dns(Progress::Lost{epoch,cause,requests})=>{
                    diagnostic(format_args!("DNS actual source loss epoch={epoch:?} cause={cause:?} original-callbacks={requests}; replies are not replayed"));pending.clear();
                    if stop.is_some(){break;}owner.dns.reconnect()?;
                }
                Turn::Dns(Progress::Connected(epoch))=>{if settings.verbosity>0{diagnostic(format_args!("DNS actual MQ attached {epoch:?}"));}}
                Turn::Dns(Progress::InitWritten(epoch))=>diagnostic(format_args!("DNS INIT whole local write {epoch:?}; subscription ACK unavailable")),
                Turn::Dns(Progress::Retry{error,delay})=>diagnostic(format_args!("DNS actual connect retry after {delay:?}: {error}")),
                Turn::Dns(Progress::Unavailable(error))=>diagnostic(format_args!("DNS actual source unavailable: {error}")),
                Turn::Dns(Progress::Activity{epoch,read,written})=>{let _actual=(epoch,read,written);},
                Turn::Dns(Progress::Wait)=>{},Turn::Dns(Progress::Closed)=>break,
            }
            first= !first;
        }
        diagnostic(format_args!("DNS utility stopped callbacks={packets} whole-local-replies={writes} pending={} (source will actually close)",pending.len()));
        Ok::<(),Failure>(())
    }.await;
    let resolver = owner.close();
    Failures {
        task: outcome.err(),
        resolver,
        ..Default::default()
    }
    .finish()
}
