//! Registration leases, STUN transactions and reversal monitoring.
use super::{Failure, NatOptions, Signals, StunMode, diagnostic, interval, output};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_config::Configuration;
use gnunet_nat_client_host::{
    self as client, Command, Deadlines, Instance, Profiles, Progress as NatProgress, Registration,
    RegistrationRequest,
};
use gnunet_nat_host::{
    deadline::{Bounds, BoundsError, Gate},
    interfaces::portable,
    stun::{DEFAULT_FREQUENCY_MICROS, Event as StunEvent, Request as StunRequest, Servers},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_wire::official::nat::{self, AddressWriter, RawAddress};
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    time::{Instant, Sleep},
};
struct StunRow<'id> {
    epoch: client::Epoch<'id>,
    request: StunRequest,
    finished: bool,
}
struct Session<'id> {
    registration: Registration<'id>,
    reports: Reporter,
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
struct Probe {
    servers: Servers,
    frequency: Duration,
    timeout: Duration,
}
struct SessionPorts<'a> {
    signals: &'a mut Signals,
    socket: Option<&'a Arc<UdpSocket>>,
    remote: Option<(SocketAddr, SocketAddr, Bounds)>,
    remote_admitted: &'a mut bool,
    resolution: &'a SharedResolution,
    probe: Option<&'a Probe>,
    send_timeout: Duration,
}
impl<'id> Session<'id> {
    fn expire_writes(&mut self, now: Option<u64>) -> Result<Option<Step<'id>>, Failure> {
        let mut i = 0;
        while i < self.writes.len() {
            let (write, bounds) = self.writes[i];
            if Instant::now() >= bounds.hard() || now.is_some_and(|n| n >= bounds.expires()) {
                self.writes.swap_remove(i);
                match self.registration.cancel_write(write)? {
                    client::Cancel::Unsent(end) => {
                        diagnostic(
                            &self.reports,
                            format_args!("NAT original queued write expired unexposed: {:?}", end),
                        );
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
            probe,
            send_timeout,
        } = ports;
        self.reports.register(cx);
        if self.reports.failed() {
            return Poll::Ready(Err("NAT CLI selected Logger failed".into()));
        }
        if let Poll::Ready(result) = signals.poll_stop(cx) {
            result?;
            return Poll::Ready(Ok(Step::Stop));
        }
        if let Some(step) = self.expire_writes(None)? {
            return Poll::Ready(Ok(step));
        }
        if self.reports.failed() {
            return Poll::Ready(Err("NAT CLI selected Logger failed".into()));
        }
        let native = Instant::now();
        for row in &mut self.stun {
            if native >= row.request.bounds().hard() {
                row.request.cancel();
            }
        }
        self.stun.retain(|r| native < r.request.bounds().hard());
        let due = self
            .stun
            .iter()
            .map(|r| r.request.bounds().hard())
            .chain(self.writes.iter().map(|(_, b)| b.hard()))
            .chain((probe.is_some() && self.next_stun > native).then_some(self.next_stun))
            .min();
        if let Some(due) = due {
            self.timer
                .as_mut()
                .reset(due.min(self.gate.bounds().hard()));
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
        if self.reports.failed() {
            return Poll::Ready(Err("NAT CLI selected Logger failed".into()));
        }
        let registered = self.registration.epoch().filter(|&epoch| {
            self.registration.is_current(epoch)
                && matches!(
                    self.registration.registered_submission(),
                    client::Submission::Written { .. }
                )
        });
        if let Some(epoch) = registered {
            if !*remote_admitted
                && self.writes.len() < 32
                && let Some((local, remote, bounds)) = remote
            {
                match bounds.check(&**self.gate.clock()) {
                    Ok(_) => {}
                    Err(BoundsError::Deadline) => {
                        *remote_admitted = true;
                        diagnostic(
                            &self.reports,
                            format_args!("original reversal intent expired before admission"),
                        );
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
                    bounds.expires(),
                )?;
                self.writes.push((write, bounds));
                *remote_admitted = true;
                self.registration_first = true;
                return Poll::Ready(Ok(Step::Stun));
            }
            if let Some(socket) = socket
                && let Some(probe) = probe
                && native >= self.next_stun
                && self.stun.len() < 32
            {
                self.next_stun = native
                    .checked_add(probe.frequency)
                    .ok_or(gnunet_types::Error::Overflow)?;
                for (server, port) in probe.servers.iter() {
                    if self.reports.failed() {
                        return Poll::Ready(Err("NAT CLI selected Logger failed".into()));
                    }
                    if self.stun.len() >= 32 {
                        break;
                    }
                    let remaining = self.gate.bounds();
                    let b = Bounds::after(&**self.gate.clock(), probe.timeout)?;
                    let bounds = b.capped_by(remaining);
                    match StunRequest::start(
                        resolution.clone(),
                        self.gate.clock().clone(),
                        socket.clone(),
                        server,
                        port,
                        bounds,
                        Default::default(),
                    ) {
                        Ok(request) => self.stun.push(StunRow {
                            epoch,
                            request,
                            finished: false,
                        }),
                        Err(e) => diagnostic(
                            &self.reports,
                            format_args!("STUN original request refused: {e}"),
                        ),
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
                    diagnostic(
                        &self.reports,
                        format_args!("STUN original request ended: {error}"),
                    );
                    self.registration_first = true;
                    return Poll::Ready(Ok(Step::Stun));
                }
            }
        }
        if let Some(socket) = socket
            && registered.is_some()
            && self.writes.len() < 32
            && self.registration.pending_writes() < 32
        {
            let mut read = ReadBuf::new(&mut self.buffer);
            match socket.poll_recv_from(cx, &mut read) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(sender)) => {
                    let packet = read.filled();
                    let mut raw = [0; 28];
                    let n = portable(sender).wire().encode(self.profile, &mut raw)?;
                    let sender_address = RawAddress::decode(&raw[..n], self.profile)?;
                    let forward_by = if probe.is_some() {
                        let mut matched = None;
                        for row in &mut self.stun {
                            if self.reports.failed() {
                                return Poll::Ready(Err("NAT CLI selected Logger failed".into()));
                            }
                            if !self.registration.is_current(row.epoch) {
                                continue;
                            }
                            match row.request.on_datagram(socket, sender, packet) {
                                Ok(Some(_)) => {
                                    matched = Some(row.request.bounds());
                                    break;
                                }
                                Ok(None) => {}
                                Err(gnunet_nat_host::Error::Clock(e)) => {
                                    return Poll::Ready(Err(
                                        gnunet_nat_host::Error::Clock(e).into()
                                    ));
                                }
                                Err(e) => diagnostic(
                                    &self.reports,
                                    format_args!("original STUN packet refused: {e}"),
                                ),
                            }
                        }
                        matched
                    } else if gnunet_nat::stun::Message::decode(packet).is_ok()
                        && (nat::Request::Stun {
                            sender: sender_address,
                            payload: packet,
                        })
                        .encoded_len(self.profile)
                        .is_ok()
                    {
                        Some(
                            Bounds::after(&**self.gate.clock(), send_timeout)?
                                .capped_by(self.gate.bounds()),
                        )
                    } else {
                        None
                    };
                    if let Some(bounds) = forward_by {
                        match self
                            .registration
                            .stun(sender_address, packet, bounds.expires())
                        {
                            Ok(write) => self.writes.push((write, bounds)),
                            // UDP observations cannot overrun the bounded IPC queue.
                            Err(client::Error::Protocol(gnunet_types::Error::Capacity)) => (),
                            Err(error) => return Poll::Ready(Err(error.into())),
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
pub(super) async fn nat_monitor(
    config: &Configuration,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    mut options: NatOptions,
    signals: &mut Signals,
    reports: &Reporter,
) -> Result<(), Failure> {
    if !matches!(options.protocol, 6 | 17)
        || options.section.contains(&0)
        || options.stun != StunMode::Disabled && options.protocol != 17
    {
        return Err("NAT requires one TCP/UDP selector; STUN requires UDP".into());
    }
    if options
        .remote
        .is_some_and(|r| !r.is_ipv4() || !options.local.is_ipv4() || options.local.port() == 0)
    {
        return Err("reversal requires an actual nonzero-port localIPv4 and remoteIPv4".into());
    }
    let lifetime = interval(config, b"SESSION_LIFETIME", 3_600_000_000)?;
    let send_timeout = interval(config, b"SEND_TIMEOUT", 30_000_000)?;
    let probe = if options.stun == StunMode::Probe {
        let servers = Servers::read(config)?.ok_or("--probe-stun requires [nat] STUN_SERVERS")?;
        let micros = config
            .get(b"nat", b"STUN_FREQUENCY")
            .map(|_| config.get_time(b"nat", b"STUN_FREQUENCY"))
            .transpose()?
            .unwrap_or(DEFAULT_FREQUENCY_MICROS);
        let frequency = Duration::from_micros(micros);
        if micros == 0 || micros == u64::MAX || Instant::now().checked_add(frequency).is_none() {
            return Err("STUN frequency must be finite and nonzero".into());
        }
        Some(Probe {
            servers,
            frequency,
            timeout: interval(config, b"STUN_REQUEST_TIMEOUT", 30_000_000)?,
        })
    } else {
        None
    };
    let socket = if options.stun != StunMode::Disabled {
        let setup = Bounds::after(&*clock, send_timeout)?;
        let mut gate = Gate::new(clock.clone(), setup)?;
        let socket = Arc::new(
            gate.run(async { crate::sockets::udp(options.local) })
                .await?,
        );
        options.local = socket.local_addr()?;
        Some(socket)
    } else {
        None
    };
    let live = LiveConfiguration::new(config.duplicate()?);
    let instance = Instance::new();
    let profile = client::native_profile()?;
    let remote_bound = options
        .remote
        .map(|_| Bounds::after(&*clock, send_timeout))
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
                send_until: send.expires().min(bounds.expires()),
                first_input_until: None,
                until: bounds.expires(),
            },
            Default::default(),
        )?;
        let mut buffer = Vec::new();
        if socket.is_some() {
            buffer.try_reserve_exact(65536)?;
            buffer.resize(65536, 0);
        }
        let mut session = Session {
            reports: reports.clone(),
            registration,
            gate: Gate::new(clock.clone(), bounds)?,
            stun: Vec::new(),
            next_stun: Instant::now(),
            timer: Box::pin(tokio::time::sleep_until(bounds.hard())),
            buffer,
            profile,
            writes: Vec::new(),
            registration_first: false,
        };
        if probe.is_some() {
            session.stun.try_reserve_exact(32)?;
        }
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
                        probe: probe.as_ref(),
                        send_timeout,
                    },
                )
            })
            .await
            {
                Err(error) => {
                    let _end = session.registration.close();
                    if gnunet_nat_host::deadline::is_expired(error.as_ref()) {
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
                if let Poll::Ready(result) = signals.poll_stop(cx) {
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
