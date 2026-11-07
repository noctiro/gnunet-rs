//! Actual gnunet-nat / gnunet-nat-auto PROGRAM actions using existing native
//! clients, one process Resolver/clock and real bounded socket/provider owners.
use crate::{Failure, Limits as TestLimits, Outcome, Progress as TestProgress, Test};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_config::Configuration;
use gnunet_nat_client_host::{
    self as client, AutoProgress, AutoQuery, Command, Deadlines, Instance, Profiles,
    Progress as NatProgress, Registration, RegistrationRequest,
};
use gnunet_nat_host::{
    deadline::{Bounds, Gate},
    interfaces::portable,
    stun::{Event as StunEvent, Request as StunRequest, parse_server},
};
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_resolver_broker::{Driver, LiveConfiguration as ResolverConfiguration};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_wire::official::nat::{self, AddressWriter, RawAddress};
use std::pin::Pin;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    signal::unix::{Signal, SignalKind},
    time::{Instant, Sleep},
};
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
    /// Actual --stun bound socket/transactions.
    pub stun: bool,
    /// Actual --watch reversal callbacks.
    pub watch: bool,
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
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _written = writeln!(io::stderr().lock(), "{args}");
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
                        "NAT CLI signal stream ended",
                    )));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
/// Run one actual shared PROGRAM task; actual query/test output controls return,
/// while service/Resolver shutdown errors remain independent real failures.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    action: Action,
) -> Result<(), Failure> {
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
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                let completed = run(config, filename, action, resolver, resolution, runtime).await;
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
    Failures {
        program,
        task,
        ..Failures::default()
    }
    .finish()
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
async fn run(
    config: Configuration,
    filename: Option<PathBuf>,
    action: Action,
    mut resolver: Driver<64, 1024>,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
) -> Result<(), Failure> {
    let mut signals = Signals::new()?;
    let mut resolving = Box::pin(resolver_loop(&mut resolver));
    let mut action = Box::pin(async {
        match action {
            Action::Nat(options) => {
                nat_monitor(&config, resolution, clock, options, &mut signals).await
            }
            Action::Auto(options) => {
                auto(&config, filename, resolution, clock, options, &mut signals).await
            }
        }
    });
    let mut first = false;
    let result = poll_fn(|cx| {
        for n in 0..2 {
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
    let cleanup = resolver.disconnect();
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
struct StunRow<'id> {
    epoch: client::Epoch<'id>,
    request: StunRequest,
    finished: bool,
}
struct Session<'id> {
    registration: Registration<'id>,
    gate: Gate,
    stun: Vec<StunRow<'id>>,
    next_stun: Instant,
    timer: Pin<Box<Sleep>>,
    buffer: Vec<u8>,
    profile: nat::Profile,
    writes: Vec<(client::WriteId<'id>, Bounds)>,
    registration_first: bool,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Transfer the bounded original native progress and close receipts without allocating after physical retirement"
)]
enum Step<'id> {
    Nat(NatProgress<'id>),
    Stun,
    Stop,
}
struct SessionPorts<'a> {
    signals: &'a mut Signals,
    socket: Option<&'a Arc<UdpSocket>>,
    remote: Option<(SocketAddr, SocketAddr, Bounds)>,
    remote_admitted: &'a mut bool,
    resolution: &'a SharedResolution,
    servers: &'a [(Vec<u8>, u16)],
    frequency: Duration,
    request_timeout: Duration,
}
async fn resolver_loop(
    resolver: &mut Driver<64, 1024>,
) -> Result<(), gnunet_resolver_broker::BrokerError> {
    loop {
        resolver
            .drive_waiting(None, |e| {
                diagnostic(format_args!("NAT CLI Resolver: {e:?}"))
            })
            .await?;
    }
}
impl<'id> Session<'id> {
    fn expire_writes(&mut self, now: Option<u64>) -> Result<Option<Step<'id>>, Failure> {
        let mut i = 0;
        while i < self.writes.len() {
            let (write, bounds) = self.writes[i];
            if Instant::now() >= bounds.hard || now.is_some_and(|n| n >= bounds.expires) {
                self.writes.swap_remove(i);
                match self.registration.cancel_write(write)? {
                    client::Cancel::Unsent(end) => {
                        diagnostic(format_args!(
                            "NAT original queued write expired unexposed: {:?}",
                            end
                        ));
                    }
                    client::Cancel::SessionClosed(end) => {
                        return Ok(Some(Step::Nat(NatProgress::Ended(end))));
                    }
                }
            } else {
                i += 1;
            }
        }
        Ok(None)
    }
    fn poll_registration(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<'id>, Failure>> {
        let native = self.registration.poll(cx, None);
        if let Poll::Ready(Ok(progress)) = &native {
            match progress {
                NatProgress::Written(_, _, write, _, _) => self.writes.retain(|(w, _)| w != write),
                NatProgress::WriteExpired(end) => self.writes.retain(|(w, _)| *w != end.write),
                _ => {}
            }
        }
        if native.is_ready() {
            self.registration_first = false;
            return native.map(|r| r.map(Step::Nat).map_err(Into::into));
        }
        Poll::Pending
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        ports: SessionPorts<'_>,
    ) -> Poll<Result<Step<'id>, Failure>> {
        let SessionPorts {
            signals,
            socket,
            remote,
            remote_admitted,
            resolution,
            servers,
            frequency,
            request_timeout,
        } = ports;
        if let Poll::Ready(result) = signals.poll(cx) {
            result?;
            return Poll::Ready(Ok(Step::Stop));
        }
        if let Some(step) = self.expire_writes(None)? {
            return Poll::Ready(Ok(step));
        }
        let native = Instant::now();
        for row in &mut self.stun {
            if native >= row.request.bounds().hard {
                row.request.cancel();
            }
        }
        self.stun.retain(|r| native < r.request.bounds().hard);
        let due = self
            .stun
            .iter()
            .map(|r| r.request.bounds().hard)
            .chain(self.writes.iter().map(|(_, b)| b.hard))
            .chain((self.next_stun > native).then_some(self.next_stun))
            .min();
        if let Some(due) = due {
            self.timer.as_mut().reset(due.min(self.gate.bounds().hard));
            let _wake = self.timer.as_mut().poll(cx);
        }
        match self.gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(now)) => {
                if let Some(step) = self.expire_writes(Some(now))? {
                    return Poll::Ready(Ok(step));
                }
            }
        }
        if let Some(epoch) = self.registration.epoch()
            && matches!(
                self.registration.registered_submission(),
                client::Submission::Written { .. }
            )
        {
            if !*remote_admitted
                && self.writes.len() < 32
                && let Some((local, remote, bounds)) = remote
            {
                match bounds.check(&**self.gate.clock()) {
                    Ok(_) => {}
                    Err(gnunet_nat_host::Error::Protocol(gnunet_types::Error::Deadline)) => {
                        *remote_admitted = true;
                        diagnostic(format_args!(
                            "original reversal intent expired before admission"
                        ));
                        self.registration_first = true;
                        return Poll::Ready(Ok(Step::Stun));
                    }
                    Err(e) => return Poll::Ready(Err(e.into())),
                }
                let mut lb = [0; 28];
                let ln = portable(local).wire().encode(self.profile, &mut lb)?;
                let mut rb = [0; 28];
                let rn = portable(remote).wire().encode(self.profile, &mut rb)?;
                let write = self.registration.reverse(
                    RawAddress::decode(&lb[..ln], self.profile)?,
                    RawAddress::decode(&rb[..rn], self.profile)?,
                    bounds.expires,
                )?;
                self.writes.push((write, bounds));
                *remote_admitted = true;
                self.registration_first = true;
                return Poll::Ready(Ok(Step::Stun));
            }
            if let Some(socket) = socket
                && native >= self.next_stun
                && self.stun.len() < 32
            {
                self.next_stun = native
                    .checked_add(frequency)
                    .ok_or(gnunet_types::Error::Overflow)?;
                for (server, port) in servers {
                    if self.stun.len() >= 32 {
                        break;
                    }
                    let remaining = self.gate.bounds();
                    let b = Bounds::after(&**self.gate.clock(), request_timeout)?;
                    let bounds = Bounds {
                        expires: b.expires.min(remaining.expires),
                        hard: b.hard.min(remaining.hard),
                    };
                    match StunRequest::start(
                        resolution.clone(),
                        self.gate.clock().clone(),
                        socket.clone(),
                        server,
                        *port,
                        bounds,
                        Default::default(),
                    ) {
                        Ok(request) => self.stun.push(StunRow {
                            epoch,
                            request,
                            finished: false,
                        }),
                        Err(e) => diagnostic(format_args!("STUN original request refused: {e}")),
                    }
                }
                self.registration_first = true;
                return Poll::Ready(Ok(Step::Stun));
            }
        }
        if self.registration_first
            && let Poll::Ready(r) = self.poll_registration(cx)
        {
            return Poll::Ready(r);
        }
        for row in &mut self.stun {
            if row.finished {
                continue;
            }
            match row.request.poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(StunEvent::Finished { written, failed })) => {
                    row.finished = true;
                    output(format_args!(
                        "STUN local-send complete written={written} failed={failed}; mapped address unproven"
                    ))?;
                    self.registration_first = true;
                    return Poll::Ready(Ok(Step::Stun));
                }
                Poll::Ready(Ok(_)) => return Poll::Ready(Ok(Step::Stun)),
                Poll::Ready(Err(error)) => {
                    row.finished = true;
                    row.request.cancel();
                    diagnostic(format_args!("STUN original request ended: {error}"));
                    self.registration_first = true;
                    return Poll::Ready(Ok(Step::Stun));
                }
            }
        }
        if let Some(socket) = socket {
            if self.writes.len() >= 32 || self.registration.pending_writes() >= 32 {
                return Poll::Pending;
            }
            let mut read = ReadBuf::new(&mut self.buffer);
            match socket.poll_recv_from(cx, &mut read) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(sender)) => {
                    let packet = read.filled();
                    for row in &mut self.stun {
                        if !self.registration.is_current(row.epoch) {
                            continue;
                        }
                        let matched = match row.request.on_datagram(socket, sender, packet) {
                            Ok(Some(_)) => true,
                            Ok(None) => false,
                            Err(gnunet_nat_host::Error::Clock(e)) => {
                                return Poll::Ready(Err(gnunet_nat_host::Error::Clock(e).into()));
                            }
                            Err(e) => {
                                diagnostic(format_args!("original STUN packet refused: {e}"));
                                false
                            }
                        };
                        if matched {
                            let mut raw = [0; 28];
                            let n = portable(sender).wire().encode(self.profile, &mut raw)?;
                            let write = self.registration.stun(
                                RawAddress::decode(&raw[..n], self.profile)?,
                                packet,
                                row.request.bounds().expires,
                            )?;
                            self.writes.push((write, row.request.bounds()));
                            self.registration_first = true;
                            return Poll::Ready(Ok(Step::Stun));
                        }
                    }
                    self.registration_first = true;
                    return Poll::Ready(Ok(Step::Stun));
                }
            }
        }
        if !self.registration_first
            && let Poll::Ready(r) = self.poll_registration(cx)
        {
            return Poll::Ready(r);
        }
        Poll::Pending
    }
}
fn port_failure(error: &client::Error) -> bool {
    match error {
        client::Error::Clock(_) => true,
        client::Error::Ports(gnunet_client_host::ConnectError::Io(e)) => {
            gnunet_client_host::resolution::PortError::from_io(e).is_some()
        }
        client::Error::Ports(gnunet_client_host::ConnectError::Configuration(_)) => true,
        _ => false,
    }
}
async fn nat_monitor(
    config: &Configuration,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    mut options: NatOptions,
    signals: &mut Signals,
) -> Result<(), Failure> {
    if !matches!(options.protocol, 6 | 17)
        || options.section.contains(&0)
        || options.stun && options.protocol != 17
    {
        return Err("NAT requires one TCP/UDP selector; STUN requires UDP".into());
    }
    if options
        .remote
        .is_some_and(|r| !r.is_ipv4() || !options.local.is_ipv4() || options.local.port() == 0)
    {
        return Err("reversal requires an actual nonzero-port localIPv4 and remoteIPv4".into());
    }
    let socket = if options.stun {
        let setup = Bounds::after(&*clock, Duration::from_secs(30))?;
        let mut gate = Gate::new(clock.clone(), setup)?;
        let socket = Arc::new(gate.run(UdpSocket::bind(options.local)).await?);
        options.local = socket.local_addr()?;
        Some(socket)
    } else {
        None
    };
    let lifetime = interval(config, b"SESSION_LIFETIME", 3_600_000_000)?;
    let send_timeout = interval(config, b"SEND_TIMEOUT", 30_000_000)?;
    let request_timeout = interval(config, b"STUN_REQUEST_TIMEOUT", 30_000_000)?;
    let frequency = Duration::from_micros(
        config
            .get(b"nat", b"STUN_FREQUENCY")
            .map(|_| config.get_time(b"nat", b"STUN_FREQUENCY"))
            .transpose()?
            .unwrap_or(300_000_000),
    );
    if frequency.is_zero() {
        return Err("STUN frequency must be nonzero".into());
    }
    let mut servers = Vec::new();
    if options.stun {
        let raw = core::str::from_utf8(
            config
                .get(b"nat", b"STUN_SERVERS")
                .unwrap_or(b"stun.gnunet.org"),
        )?;
        for token in raw.split_ascii_whitespace() {
            if servers.len() >= 32 {
                return Err("too many STUN servers".into());
            }
            let (host, port) = parse_server(token)?;
            servers.push((host.as_bytes().to_vec(), port));
        }
    }
    let live = LiveConfiguration::new(config.duplicate()?);
    let instance = Instance::new();
    let profile = client::native_profile()?;
    let remote_bound = options
        .remote
        .map(|_| Bounds::after(&*clock, request_timeout))
        .transpose()?;
    let mut remote_admitted = false;
    loop {
        let bounds = Bounds::after(&*clock, lifetime)?;
        let send = Bounds::after(&*clock, send_timeout)?;
        let mut store = [0; 28];
        let mut addresses = AddressWriter::new(&mut store, profile);
        addresses.push(portable(options.local).wire())?;
        let source = EndpointSource::live(live.clone(), b"nat", resolution.clone()).snapshot()?;
        let registration = Registration::new(
            &instance,
            source,
            RegistrationRequest {
                flags: nat::ADDRESSES | if options.watch { nat::REVERSAL } else { 0 },
                protocol: options.protocol,
                addresses: addresses.addresses(),
                section: &options.section,
            },
            Profiles::same(profile),
            Deadlines {
                send_until: send.expires.min(bounds.expires),
                first_input_until: None,
                until: bounds.expires,
            },
            Default::default(),
        )?;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(65536)?;
        buffer.resize(65536, 0);
        let mut session = Session {
            registration,
            gate: Gate::new(clock.clone(), bounds)?,
            stun: Vec::new(),
            next_stun: Instant::now(),
            timer: Box::pin(tokio::time::sleep_until(bounds.hard)),
            buffer,
            profile,
            writes: Vec::new(),
            registration_first: false,
        };
        session.stun.try_reserve_exact(32)?;
        session.writes.try_reserve_exact(32)?;
        let restart = loop {
            match poll_fn(|cx| {
                session.poll(
                    cx,
                    SessionPorts {
                        signals,
                        socket: socket.as_ref(),
                        remote: options
                            .remote
                            .zip(remote_bound)
                            .map(|(r, b)| (options.local, r, b)),
                        remote_admitted: &mut remote_admitted,
                        resolution: &resolution,
                        servers: &servers,
                        frequency,
                        request_timeout,
                    },
                )
            })
            .await
            {
                Err(error) => {
                    let _end = session.registration.close();
                    if error
                        .downcast_ref::<gnunet_nat_host::Error>()
                        .is_some_and(|e| {
                            matches!(
                                e,
                                gnunet_nat_host::Error::Protocol(gnunet_types::Error::Deadline)
                            )
                        })
                    {
                        output(format_args!(
                            "NAT original finite monitor lease expired; creating a fresh source without replay"
                        ))?;
                        break true;
                    }
                    return Err(error);
                }
                Ok(Step::Stop) => {
                    let end = session.registration.close();
                    output(format_args!(
                        "NAT monitor cancelled locally; original={:?}",
                        end.as_ref().map(|e| &e.source)
                    ))?;
                    return Ok(());
                }
                Ok(Step::Stun) => {}
                Ok(Step::Nat(NatProgress::Notification { .. })) => {
                    let notice = session
                        .registration
                        .notification()?
                        .ok_or("missing original NAT callback")?;
                    match notice.response {
                        nat::Response::AddressChange {
                            add_remove,
                            class,
                            address,
                        } => {
                            let address = gnunet_nat_host::interfaces::native(
                                gnunet_nat::address::SocketAddress::from_wire(address.address())?,
                            );
                            output(format_args!(
                                "address {} class={} candidate={address}; reachability unproven",
                                if add_remove == 1 { "add" } else { "remove" },
                                class.0
                            ))?;
                        }
                        nat::Response::Reverse { remote } => output(format_args!(
                            "reverse requested from {:?}; observation unauthenticated",
                            remote.address()
                        ))?,
                    }
                    session.registration.release_notification()?;
                }
                Ok(Step::Nat(NatProgress::Written(_, _, _, Command::Reverse, _))) => output(
                    format_args!("reversal request locally written; remote result unproven"),
                )?,
                Ok(Step::Nat(NatProgress::Ended(end))) => {
                    if let client::Cause::Error(error) = end.source.cause {
                        if port_failure(&error) {
                            return Err(Box::new(error));
                        }
                        output(format_args!(
                            "NAT original source ended with actual error: {error}; old requests are not replayed"
                        ))?;
                    } else {
                        output(format_args!(
                            "NAT original source ended: {:?}; old requests are not replayed",
                            end.source.cause
                        ))?;
                    }
                    break true;
                }
                Ok(Step::Nat(NatProgress::Closed)) => break true,
                Ok(Step::Nat(_)) => {}
            }
        };
        for row in &mut session.stun {
            row.request.cancel();
        }
        drop(session);
        if restart {
            let mut backoff = std::pin::pin!(tokio::time::sleep(Duration::from_secs(1)));
            if !poll_fn(|cx| {
                if let Poll::Ready(result) = signals.poll(cx) {
                    return Poll::Ready(result.map(|()| false));
                }
                backoff.as_mut().poll(cx).map(|()| Ok(true))
            })
            .await?
            {
                return Ok(());
            }
        }
    }
}
async fn auto(
    config: &Configuration,
    filename: Option<PathBuf>,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    options: AutoOptions,
    signals: &mut Signals,
) -> Result<(), Failure> {
    if !options.configure && options.section.is_none() {
        return Err("select --auto and/or --section".into());
    }
    if options.write && !options.configure {
        return Err("--write requires --auto".into());
    }
    if options.section.is_some() && !matches!(options.protocol, Some(6 | 17)) {
        return Err("--section test requires exactly --tcp or --udp".into());
    }
    let instance = Instance::new();
    let timeout = interval(config, b"TEST_TIMEOUT", 30_000_000)?;
    let until = Bounds::after(&*clock, timeout)?;
    let mut query = if options.configure {
        let source = EndpointSource::live(
            LiveConfiguration::new(config.duplicate()?),
            b"nat-auto",
            resolution.clone(),
        );
        Some(AutoQuery::from_configuration(
            &instance,
            source,
            config,
            Deadlines {
                send_until: until.expires,
                first_input_until: None,
                until: until.expires,
            },
            Default::default(),
        )?)
    } else {
        None
    };
    let mut test = if let Some(section) = &options.section {
        Some(
            Test::from_configuration(
                &instance,
                config,
                resolution,
                section,
                options.protocol.ok_or("missing protocol")?,
                timeout,
                TestLimits::default(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut failures = Vec::new();
    let mut query_done = query.is_none();
    let mut test_done = test.is_none();
    while !query_done || !test_done {
        #[expect(
            clippy::large_enum_variant,
            reason = "Carry already-owned query/test terminal receipts without a new allocation after source close"
        )]
        enum Step<'id> {
            Stop,
            Query(AutoProgress<'id>),
            Test(TestProgress<'id>),
        }
        let step = poll_fn(|cx| {
            if let Poll::Ready(result) = signals.poll(cx) {
                result?;
                return Poll::Ready(Ok::<_, Failure>(Step::Stop));
            }
            if !query_done
                && let Some(query) = &mut query
                && let Poll::Ready(result) = query.poll(cx, None)
            {
                return Poll::Ready(result.map(Step::Query).map_err(Into::into));
            }
            if !test_done
                && let Some(test) = &mut test
                && let Poll::Ready(result) = test.poll(cx, None)
            {
                return Poll::Ready(result.map(Step::Test));
            }
            Poll::Pending
        })
        .await?;
        match step {
            Step::Stop => {
                if let Some(query) = &mut query {
                    let _end = query.cancel();
                }
                if let Some(test) = &mut test {
                    let _end = test.cancel();
                }
                return Ok(());
            }
            Step::Query(AutoProgress::ResultReady(..)) => {
                let result = query
                    .as_mut()
                    .and_then(AutoQuery::take_result)
                    .ok_or("missing actual original NATauto result")?;
                let response = result.response()?;
                output(format_args!(
                    "NAT auto actual status={} type={}; proposal does not prove connectivity",
                    response.status.0, response.nat_type.0
                ))?;
                if response.status != client::auto_ipc::Status::SUCCESS {
                    failures.push(format!("NATauto actual status{}", response.status.0));
                } else {
                    let mut diff = Configuration::create(
                        Arc::new(config.project_data().clone()),
                        Default::default(),
                    )?;
                    diff.deserialize(response.configuration_diff, None)?;
                    let mut updated = config.duplicate()?;
                    let mut changed = false;
                    for (section, key, value) in diff.entries() {
                        if section.eq_ignore_ascii_case(b"nat") {
                            updated.set_value(section, key, Some(value))?;
                            changed = true;
                            output(format_args!(
                                "suggested NAT {}={}",
                                String::from_utf8_lossy(key),
                                String::from_utf8_lossy(value)
                            ))?;
                        }
                    }
                    if options.write && changed {
                        let path = filename
                            .as_ref()
                            .ok_or("no selected configuration filename for --write")?;
                        updated.set_value(b"ARM", b"CONFIG", None)?;
                        let mut defaults = Configuration::create(
                            Arc::new(config.project_data().clone()),
                            Default::default(),
                        )?;
                        defaults.load(None)?;
                        defaults.write_diffs(&updated, path)?;
                        output(format_args!(
                            "configuration changes actually written to {}",
                            path.display()
                        ))?;
                    }
                }
                query_done = true;
            }
            Step::Query(AutoProgress::Ended(end)) => {
                failures.push(format!("NATauto original source ended: {:?}", end.cause));
                query_done = true;
            }
            Step::Query(AutoProgress::Closed) => {
                failures.push("NATauto closed without an actual result".into());
                query_done = true;
            }
            Step::Test(TestProgress::Ended(end)) => {
                if let Some(original) = &end.registration {
                    diagnostic(format_args!(
                        "NAT test original registration end: {:?}",
                        original.source
                    ));
                }
                match end.outcome {
                    Outcome::Received(o) => output(format_args!(
                        "NAT test received original challenge: target={} transport={:?} address={:?}; unauthenticated network-path observation",
                        o.target(),
                        o.transport(),
                        o.address()
                    ))?,
                    Outcome::Timeout => failures.push("NAT test original deadline elapsed".into()),
                    Outcome::Cancelled => failures.push("NAT test cancelled".into()),
                    Outcome::Failed(e) => failures.push(format!("NAT test failed: {e}")),
                }
                test_done = true;
            }
            Step::Test(TestProgress::Closed) => {
                failures.push("NAT test closed without an original terminal result".into());
                test_done = true;
            }
            _ => {}
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}
