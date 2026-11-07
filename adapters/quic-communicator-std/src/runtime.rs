//! Concrete one-source raw QUIC communicator owner. Drivers are polled here;
//! neither Quinn nor the application is permitted a detached task or DNS pool.
use crate::{
    application::{self, Application},
    credentials::Tls,
    drivers::Id,
    endpoint::{self, Endpoint},
    ipc::{self, Ipc},
    raw,
    types::*,
};
use gnunet_client_host::EndpointSource;
use gnunet_nat_client_host as nat;
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_transport_quic::{
    Role,
    address::{Address, Profile as AddressProfile},
};
use gnunet_types::{Error as Protocol, MonoInstant};
use gnunet_wire::official::{
    communicator::{Characteristics, Queue, Request, Response},
    nat as natwire,
};
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

mod identity;
mod recovery;

impl From<endpoint::Failure> for Fault {
    fn from(e: endpoint::Failure) -> Self {
        match e {
            endpoint::Failure::Protocol(e) => Self::Protocol(e),
            endpoint::Failure::Io(e) => Self::Io(e),
            endpoint::Failure::Connect(e) => Self::Connect(e),
            endpoint::Failure::Accept(e) => Self::Connection(e),
            endpoint::Failure::BackendInvariant => Self::BackendInvariant,
        }
    }
}
impl From<raw::Failure> for Fault {
    fn from(e: raw::Failure) -> Self {
        match e {
            raw::Failure::Protocol(e) => Self::Protocol(e),
            raw::Failure::Connection(e) => Self::Connection(e),
            raw::Failure::Read(e) => Self::Read(e),
            raw::Failure::Write(e) => Self::Write(e),
        }
    }
}
impl From<ipc::Failure> for Fault {
    fn from(e: ipc::Failure) -> Self {
        match e {
            ipc::Failure::Protocol(e) => Self::Protocol(e),
            ipc::Failure::Client(e) => Self::Client(e),
            ipc::Failure::Io(e) => Self::Io(e),
            ipc::Failure::Lost => Self::TransportLost,
        }
    }
}
struct Sending {
    queue: u32,
    orphaned: bool,
    id: raw::SendId,
    mid: [u8; 8],
    accepted: usize,
    total: usize,
    result_queued: bool,
    result_written: bool,
    result_bytes: usize,
    unknown: bool,
    credit_queued: bool,
    status: i32,
    retiring: bool,
    hard: Instant,
}
struct Incoming<'id> {
    id: [u8; 8],
    frame: application::FrameId<'id>,
    peer: [u8; 32],
    written: bool,
    hard: Instant,
}
struct Row<'id, 'slots, 'buf> {
    id: u32,
    mtu: u32,
    network: u32,
    driver: Id,
    connecting: Option<quinn::Connecting>,
    link: Option<Application<'id, 'slots, 'buf>>,
    remote: SocketAddr,
    role: Role,
    local: [u8; 32],
    peer: Option<[u8; 32]>,
    advertised: bool,
    queue_written: bool,
    capacity_needed: bool,
    down: bool,
    down_written: bool,
    closing: bool,
    retire_hard: Option<Instant>,
    hard: Instant,
    idle: Instant,
    input: Option<Instant>,
    send: Option<Sending>,
    incoming: Option<Incoming<'id>>,
}
struct Advert<'id> {
    id: nat::AddressId<'id>,
    wire: u32,
    written: bool,
}
/// One caller-driven native source. External frame loans cannot be reused until
/// their original driver, stream handles and FC/output debts have been retired.
/// No method returns a Quinn Endpoint/Runtime clone to an unbounded caller.
pub struct Runtime<'id, 'pils, 'pool, 'slots, 'buf> {
    epoch: Epoch<'id>,
    pils: gnunet_pils_host::client::Client<'pils, 1>,
    ipc: Ipc,
    endpoint: Option<Endpoint>,
    scanner: crate::network::Scanner,
    nat: Option<nat::Registration<'id>>,
    advertisements: Vec<Advert<'id>>,
    advert_cap: usize,
    advert_cursor: usize,
    rows: Vec<Option<Row<'id, 'slots, 'buf>>>,
    loans: Buffers<'pool, 'id, 'slots, 'buf>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    native_epoch: Instant,
    hard: Instant,
    until: u64,
    startup: Instant,
    limits: Limits,
    identity: identity::Owner<'pils>,
    identity_updates: u64,
    identity_recoveries: u64,
    identity_forced_drivers: usize,
    pils_input: Option<Instant>,
    attached: bool,
    register_queued: bool,
    register_written: bool,
    ready: bool,
    ever_ready: bool,
    restored: bool,
    profile: AddressProfile,
    local_advertised: bool,
    local_address_wire: u32,
    local_address_written: bool,
    bound_event: bool,
    next_queue: u32,
    next_flow: u64,
    next_send: u64,
    next_address: u32,
    round: usize,
    alarm: Option<Pin<Box<Sleep>>>,
    retry: Option<Instant>,
    closing: bool,
    closing_hard: Option<Instant>,
    closed: bool,
    backend_closed: Option<endpoint::Closed>,
    cleanup_error: Option<Fault>,
    incoming_lost: usize,
    sends_retired: usize,
}
impl<'id, 'pils, 'pool, 'slots, 'buf> Runtime<'id, 'pils, 'pool, 'slots, 'buf> {
    /// Reserve metadata and fixed selector snapshots before actual bind. Frame loans
    /// remain in their caller slots on every failed application-profile admission.
    /// TLS and the caller pool must select the same actual application profile.
    pub fn new(
        instance: &'id Instance,
        pils_instance: &'pils mut gnunet_pils::client::Instance,
        sources: Sources,
        bind: SocketAddr,
        tls: Tls,
        loans: Buffers<'pool, 'id, 'slots, 'buf>,
        limits: Limits,
    ) -> Result<Self, Fault> {
        let native_epoch = Instant::now();
        tokio::runtime::Handle::try_current().map_err(|_| Protocol::NotReady)?;
        limits.validate()?;
        if loans.len() != limits.backend.connections {
            return Err(Protocol::InvalidInput.into());
        }
        let profile = match (&loans, tls.profile()) {
            (Buffers::Raw(loans), crate::tls::Profile::Raw) => {
                if loans
                    .iter()
                    .any(|l| l.as_ref().is_none_or(|b| b.len() < limits.raw_body))
                {
                    return Err(Protocol::InvalidInput.into());
                }
                AddressProfile::Raw
            }
            #[cfg(feature = "h3-profile")]
            (Buffers::Http3(loans), crate::tls::Profile::Http3) => {
                if limits.backend.bidi < (limits.h3_polls + 2) as u32 {
                    return Err(Protocol::InvalidInput.into());
                }
                if loans
                    .iter()
                    .any(|l| l.as_ref().is_none_or(|s| s.len() < limits.h3_polls + 2))
                {
                    return Err(Protocol::InvalidInput.into());
                }
                AddressProfile::Http3
            }
            #[cfg(not(feature = "h3-profile"))]
            (Buffers::Http3(_), crate::tls::Profile::Http3) => {
                return Err(Protocol::Unsupported.into());
            }
            _ => return Err(Protocol::InvalidInput.into()),
        };
        let hard = native_epoch
            .checked_add(limits.lifetime)
            .ok_or(Protocol::Overflow)?;
        let startup = native_epoch
            .checked_add(limits.startup)
            .ok_or(Protocol::Overflow)?
            .min(hard);
        let clock = sources.transport.clock();
        if !Arc::ptr_eq(&clock, &sources.pils.clock())
            || sources
                .nat
                .as_ref()
                .is_some_and(|n| !Arc::ptr_eq(&clock, &n.source.clock()))
        {
            return Err(Protocol::InvalidInput.into());
        }
        let subscription = clock.subscribe()?;
        let sample = clock.sample()?;
        let until = sample
            .now
            .as_micros()
            .checked_add(micros(limits.lifetime)?)
            .ok_or(Protocol::Overflow)?;
        let (transport, pils, nat_source) = if let Some(n) = sources.nat.as_ref() {
            let [t, p, n] =
                EndpointSource::snapshot_all([&sources.transport, &sources.pils, &n.source])?;
            (t, p, Some(n))
        } else {
            let [t, p] = EndpointSource::snapshot_all([&sources.transport, &sources.pils])?;
            (t, p, None)
        };
        let allocation = instance
            .next
            .get()
            .checked_add(1)
            .ok_or(Protocol::Overflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.backend.connections)
            .map_err(|_| Protocol::Capacity)?;
        rows.resize_with(limits.backend.connections, || None);
        let advert_cap = sources.nat.as_ref().map_or(0, |n| n.addresses);
        if advert_cap > 65535 {
            return Err(Protocol::Capacity.into());
        }
        let mut advertisements = Vec::new();
        advertisements
            .try_reserve_exact(advert_cap)
            .map_err(|_| Protocol::Capacity)?;
        let scanner = crate::network::Scanner::new(limits.interfaces, limits.interface_refresh)?;
        let ipc = Ipc::new(
            transport,
            limits.output_frames,
            limits.output_bytes,
            limits.io_slice,
            hard,
            limits.operation,
        )?;
        let pils = gnunet_pils_host::client::Client::new(
            pils_instance,
            pils,
            limits.identity_profile,
            gnunet_pils_host::client::Limits {
                pending_operations: 1,
                frame_bytes: 65535,
                io_slice_bytes: limits.io_slice,
            },
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 256,
            },
        )?;
        // All fallible heap reservations precede the first actual socket bind.
        let endpoint = Endpoint::bind(bind, tls, limits.backend, hard)?;
        let local = endpoint.local_addr();
        let nat = match (sources.nat, nat_source) {
            (Some(n), Some(source)) => {
                let mut address = [0u8; 28];
                let mut writer = natwire::AddressWriter::new(&mut address, n.profiles.request);
                writer.push(native_address(local))?;
                let result = nat::Registration::new(
                    &instance.nat,
                    source,
                    nat::RegistrationRequest {
                        flags: natwire::ADDRESSES | natwire::REVERSAL,
                        protocol: 17,
                        addresses: writer.addresses(),
                        section: &n.section,
                    },
                    n.profiles,
                    nat::Deadlines {
                        send_until: sample
                            .now
                            .as_micros()
                            .checked_add(micros(limits.startup)?)
                            .ok_or(Protocol::Overflow)?
                            .min(until),
                        first_input_until: None,
                        until,
                    },
                    nat::Limits {
                        addresses: n.addresses,
                        io_slice_bytes: limits.io_slice,
                        ..nat::Limits::default()
                    },
                );
                match result {
                    Ok(r) => Some(r),
                    Err(e) => {
                        let _actual = endpoint.close();
                        return Err(e.into());
                    }
                }
            }
            (None, None) => None,
            _ => {
                let _actual = endpoint.close();
                return Err(Protocol::InvalidInput.into());
            }
        };
        if Instant::now() >= hard {
            let _actual = endpoint.close();
            return Err(Protocol::Deadline.into());
        }
        instance.next.set(allocation);
        Ok(Self {
            epoch: Epoch {
                owner: instance,
                allocation,
            },
            pils,
            ipc,
            endpoint: Some(endpoint),
            scanner,
            nat,
            advertisements,
            advert_cap,
            advert_cursor: 0,
            rows,
            loans,
            clock,
            subscription: Some(subscription),
            revision: sample.revision,
            native_epoch,
            hard,
            until,
            startup,
            limits,
            identity: identity::Owner::new(),
            identity_updates: 0,
            identity_recoveries: 0,
            identity_forced_drivers: 0,
            pils_input: None,
            attached: false,
            register_queued: false,
            register_written: false,
            ready: false,
            ever_ready: false,
            restored: false,
            profile,
            local_advertised: false,
            local_address_wire: 0,
            local_address_written: false,
            bound_event: false,
            next_queue: 0,
            next_flow: 0,
            next_send: 0,
            next_address: 0,
            round: 0,
            alarm: None,
            retry: None,
            closing: false,
            closing_hard: None,
            closed: false,
            backend_closed: None,
            cleanup_error: None,
            incoming_lost: 0,
            sends_retired: 0,
        })
    }
    /// Original allocation identity; not a reconstructed native connection epoch.
    pub fn epoch(&self) -> Epoch<'id> {
        self.epoch
    }
    /// Actual bound socket address, including a kernel-assigned ephemeral port.
    pub fn local_addr(&self) -> Result<SocketAddr, Fault> {
        self.endpoint
            .as_ref()
            .map(Endpoint::local_addr)
            .ok_or_else(|| Protocol::Closed.into())
    }
    /// True only after actual public identity and whole original registration write.
    pub fn is_ready(&self) -> bool {
        self.ready && !self.closing
    }
    /// Public local identity observed on this original PILS MQ.
    pub fn peer(&self) -> Option<[u8; 32]> {
        if self.closing {
            None
        } else {
            self.identity.selected()
        }
    }
    /// Current actual owned row inventory, including rows whose original
    /// connection/FC/driver retirement is still pending. No authentication claim.
    #[must_use]
    pub fn metrics(&self) -> crate::metrics::Metrics {
        crate::metrics::Metrics::owned(self.rows.iter().flatten().count())
    }
    /// Actual aggregate native socket byte observations, never per-message delivery.
    pub fn statistics(&self) -> crate::socket::Statistics {
        self.endpoint
            .as_ref()
            .map_or_else(Default::default, Endpoint::statistics)
    }
    fn mono(&self) -> Result<MonoInstant, Fault> {
        let elapsed = Instant::now().saturating_duration_since(self.native_epoch);
        Ok(MonoInstant(micros(elapsed)?))
    }
    fn deadline(&self, d: Duration) -> Result<Instant, Fault> {
        Instant::now()
            .checked_add(d)
            .map(|i| i.min(self.hard))
            .ok_or_else(|| Protocol::Overflow.into())
    }
    fn index(&self, q: u32) -> Option<usize> {
        self.rows
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.id == q))
    }
    fn earliest(&self) -> Instant {
        let mut hard = if self.ever_ready {
            self.hard
        } else {
            self.startup.min(self.hard)
        };
        hard = hard.min(self.ipc.earliest()).min(self.scanner.next());
        if let Some(t) = self.identity.bound() {
            hard = hard.min(t);
        }
        if let Some(t) = self.pils_input {
            hard = hard.min(t)
        }
        if let Some(t) = self.retry {
            hard = hard.min(t)
        }
        for r in self.rows.iter().flatten() {
            if !r.closing {
                hard = hard.min(r.hard).min(r.idle);
                if let Some(t) = r.input {
                    hard = hard.min(t)
                }
            }
            if let Some(t) = r.retire_hard {
                hard = hard.min(t)
            }
            if let Some(s) = &r.send {
                hard = hard.min(s.hard);
            }
            if let Some(i) = &r.incoming {
                hard = hard.min(i.hard);
            }
        }
        hard
    }
    fn poll_alarm(&mut self, cx: &mut Context<'_>, target: Instant) {
        if self.alarm.as_ref().is_none_or(|s| s.deadline() != target) {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(target)))
        }
        if let Some(s) = &mut self.alarm {
            let _ready = s.as_mut().poll(cx);
        }
    }
    fn sample(&mut self, cx: &mut Context<'_>) -> Result<u64, Fault> {
        match self
            .subscription
            .as_mut()
            .ok_or(Protocol::Closed)?
            .poll_changed(cx, self.revision)
        {
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        self.revision = sample.revision;
        if sample.now.as_micros() >= self.until {
            return Err(Protocol::Deadline.into());
        }
        Ok(sample.now.as_micros())
    }
    fn poll_pils(
        &mut self,
        cx: &mut Context<'_>,
        utc: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        use gnunet_pils_host::client::Progress as P;
        let result = {
            let mut f = std::pin::pin!(self.pils.drive(None));
            f.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(e)) => Err(e.into()),
            Poll::Ready(Ok(P::Inbound(gnunet_pils::client::Inbound::Identity {
                identity,
                ..
            }))) => {
                self.pils_input = None;
                let peer = *identity.peer().as_bytes();
                let change = self
                    .identity
                    .observe(identity, utc, self.hard, self.until)?;
                if let identity::Change::Begin { previous, next } = change {
                    self.retire_identity(previous, next, observe)?;
                    self.identity_updates = self.identity_updates.saturating_add(1);
                }
                observe(Event::Identity {
                    peer,
                    coverage: identity.coverage(),
                });
                Ok(true)
            }
            Poll::Ready(Ok(P::Lost {
                epoch,
                cause,
                report,
            })) => {
                observe(Event::IdentityEnded {
                    epoch: epoch.value(),
                    feeds: report.feeds().count(),
                    retained: report.retained(),
                });
                Err(Fault::IdentitySource {
                    epoch: epoch.value(),
                    cause,
                })
            }
            Poll::Ready(Ok(P::Closed)) => Err(Fault::IdentityLost),
            Poll::Ready(Ok(P::Unavailable(e))) => Err(e.into()),
            Poll::Ready(Ok(P::Activity { read_bytes, .. })) => {
                if read_bytes > 0 && self.pils_input.is_none() {
                    self.pils_input = Some(self.deadline(self.limits.operation)?)
                }
                Ok(true)
            }
            Poll::Ready(Ok(P::Inbound(_))) => {
                self.pils_input = None;
                Ok(true)
            }
            Poll::Ready(Ok(P::ConnectRetry { error, .. })) => {
                observe(Event::Rejected(Fault::Io(error)));
                Ok(true)
            }
            Poll::Ready(Ok(_)) => Ok(true),
        }
    }
    fn poll_nat(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let Some(nat) = self.nat.as_mut() else {
            return Ok(false);
        };
        let progress = match nat.poll(cx, None) {
            Poll::Pending => return Ok(false),
            Poll::Ready(r) => r?,
        };
        match progress {
            nat::Progress::Ended(end) => {
                observe(Event::NatEnded(end));
                return Err(Fault::NatLost);
            }
            nat::Progress::Closed => return Err(Fault::NatLost),
            nat::Progress::Notification { .. } => {
                let notification = nat.notification()?.ok_or(Protocol::NotReady)?;
                match notification.response {
                    natwire::Response::AddressChange {
                        add_remove,
                        class: _,
                        address,
                    } => {
                        let id = notification.address_id.ok_or(Protocol::Malformed)?;
                        if add_remove == 1 {
                            if self.advertisements.iter().any(|a| a.id == id) {
                                return Err(Protocol::Conflict.into());
                            }
                            if self.advertisements.len() == self.advert_cap {
                                return Err(Protocol::Capacity.into());
                            }
                            // The original NAT address allocation is authoritative,
                            // even while the local TRANSPORT MQ is absent. Its
                            // current bytes are read only when a fresh address
                            // announcement is actually admitted.
                            socket_address(address.address()).ok_or(Protocol::Unsupported)?;
                            self.advertisements.push(Advert {
                                id,
                                wire: 0,
                                written: false,
                            });
                        } else if add_remove == 0 {
                            let i = self
                                .advertisements
                                .iter()
                                .position(|a| a.id == id)
                                .ok_or(Protocol::Stale)?;
                            let wire = self.advertisements[i].wire;
                            if wire != 0 {
                                if !self.ipc.room(1, 8) {
                                    return Ok(false);
                                }
                                self.ipc.enqueue(
                                    Request::DeleteAddress(wire),
                                    ipc::Role::Address,
                                    self.hard,
                                )?;
                            }
                            self.advertisements.swap_remove(i);
                        } else {
                            return Err(Protocol::Malformed.into());
                        }
                    }
                    natwire::Response::Reverse { .. } => observe(Event::ReversalUnsupported),
                }
                nat.release_notification()?;
            }
            nat::Progress::Retry(error, _) => observe(Event::Rejected(Fault::Io(error))),
            _ => {}
        }
        Ok(true)
    }

    fn allocate_row(
        &mut self,
        connecting: endpoint::Connecting,
        role: Role,
        original: Option<Instant>,
    ) -> Result<usize, Fault> {
        let index = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Protocol::Capacity)?;
        let id = self.next_queue.checked_add(1).ok_or(Protocol::Overflow)?;
        let hard = self
            .deadline(self.limits.operation)?
            .min(original.unwrap_or(self.hard));
        let idle = self.deadline(self.limits.idle)?;
        self.rows[index] = Some(Row {
            id,
            mtu: match self.profile {
                AddressProfile::Raw => gnunet_transport_quic::raw::ADVERTISED_MTU as u32,
                AddressProfile::Http3 => gnunet_transport_quic::h3::ADVERTISED_MTU as u32,
            },
            network: self.scanner.classify(connecting.remote),
            driver: connecting.driver,
            connecting: Some(connecting.connecting),
            link: None,
            remote: connecting.remote,
            role,
            local: self.identity.selected().ok_or(Protocol::NotReady)?,
            peer: match role {
                Role::Initiator { expected } => Some(expected),
                Role::Acceptor => None,
            },
            advertised: false,
            queue_written: false,
            capacity_needed: false,
            down: false,
            down_written: true,
            closing: false,
            retire_hard: None,
            hard,
            idle,
            input: None,
            send: None,
            incoming: None,
        });
        self.next_queue = id;
        Ok(index)
    }
    fn command(
        &mut self,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let Some(response) = self.ipc.frame()? else {
            return Ok(false);
        };
        let response_hard = self.ipc.input_hard().ok_or(Protocol::Conflict)?;
        match response {
            Response::Create(request, peer, uri) => {
                let address = Address::decode(uri)?;
                if address.profile() != self.profile || address.socket().port() == 0 {
                    return Err(Protocol::InvalidInput.into());
                }
                if !self.ipc.room(1, 8) {
                    return Ok(false);
                }
                if self.rows.iter().all(Option::is_some) {
                    self.ipc.enqueue(
                        Request::Created(request, false),
                        ipc::Role::Control,
                        response_hard,
                    )?;
                    self.ipc.release()?;
                    return Ok(true);
                }
                let connecting = match self
                    .endpoint
                    .as_mut()
                    .ok_or(Protocol::Closed)?
                    .dial(address.socket())
                {
                    Ok(c) => c,
                    Err(e) => {
                        if self.endpoint.as_ref().is_some_and(Endpoint::is_poisoned) {
                            return Err(e.into());
                        }
                        self.ipc.enqueue(
                            Request::Created(request, false),
                            ipc::Role::Control,
                            response_hard,
                        )?;
                        self.ipc.release()?;
                        observe(Event::Rejected(e.into()));
                        return Ok(true);
                    }
                };
                self.allocate_row(
                    connecting,
                    Role::Initiator { expected: peer },
                    Some(response_hard),
                )?;
                // A real original dial intent is admitted; this does NOT mean connected.
                self.ipc.enqueue(
                    Request::Created(request, true),
                    ipc::Role::Control,
                    response_hard,
                )?;
                self.ipc.release()?;
            }
            Response::Send(queue, mid, peer, bytes) => {
                let index = self
                    .rows
                    .iter()
                    .position(|r| r.as_ref().is_some_and(|r| r.id == queue));
                let valid = index.is_some_and(|i| {
                    self.rows[i]
                        .as_ref()
                        .is_some_and(|r| !r.closing && r.queue_written && r.peer == Some(peer))
                });
                if !valid {
                    let result = Request::Sent {
                        message_id: mid,
                        queue,
                        peer,
                        status: 0,
                    };
                    if !self.ipc.room_request(result)? {
                        return Ok(false);
                    }
                    self.ipc
                        .enqueue(result, ipc::Role::Control, response_hard)?;
                    self.ipc.release()?;
                    return Ok(true);
                }
                let i = index.ok_or(Protocol::Stale)?;
                let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
                if row.send.is_some() {
                    return Err(Protocol::Conflict.into());
                }
                // Keep this exact held command and its original input deadline
                // while an earlier HTTP request still owns the last send slot.
                if !row
                    .link
                    .as_ref()
                    .ok_or(Protocol::NotReady)?
                    .send_capacity(now)?
                {
                    return Ok(false);
                }
                let id = raw::SendId(self.next_send.checked_add(1).ok_or(Protocol::Overflow)?);
                let hard = self
                    .ipc
                    .input_hard()
                    .ok_or(Protocol::Conflict)?
                    .min(self.hard);
                // Original held SEND bytes are copied once by the real link before RX release.
                row.link
                    .as_mut()
                    .ok_or(Protocol::NotReady)?
                    .queue(id, bytes, hard, now)?;
                row.send = Some(Sending {
                    queue,
                    orphaned: false,
                    id,
                    mid,
                    accepted: 0,
                    total: bytes.len(),
                    result_queued: false,
                    result_written: false,
                    result_bytes: 0,
                    unknown: false,
                    credit_queued: false,
                    status: 1,
                    retiring: false,
                    hard,
                });
                self.next_send = id.0;
                self.ipc.release()?;
            }
            Response::Received(flow, peer) => {
                let i = self
                    .rows
                    .iter()
                    .position(|r| {
                        r.as_ref()
                            .is_some_and(|r| r.incoming.as_ref().is_some_and(|d| d.id == flow))
                    })
                    .ok_or(Protocol::Stale)?;
                let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
                let incoming = row.incoming.as_ref().ok_or(Protocol::Stale)?;
                if incoming.peer != peer || !incoming.written {
                    return Err(Protocol::Conflict.into());
                }
                row.link
                    .as_mut()
                    .ok_or(Protocol::Stale)?
                    .release_frame(incoming.frame)?;
                row.incoming = None;
                row.input = None;
                self.ipc.release()?;
                observe(Event::Received {
                    epoch: self.epoch,
                    flow_id: flow,
                    peer,
                });
            }
            _ => {
                self.ipc.release()?;
                observe(Event::Unsupported)
            }
        }
        Ok(true)
    }
    fn written(
        &mut self,
        role: ipc::Role,
        bytes: usize,
        complete: bool,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Fault> {
        observe(Event::Written {
            epoch: self.epoch,
            bytes,
            complete,
        });
        if let ipc::Role::Sent(q, mid) = role {
            let i = self.index(q).ok_or(Protocol::Stale)?;
            let send = self.rows[i]
                .as_mut()
                .and_then(|r| r.send.as_mut())
                .ok_or(Protocol::Stale)?;
            if send.mid != mid {
                return Err(Protocol::Stale.into());
            }
            send.result_bytes = send
                .result_bytes
                .checked_add(bytes)
                .ok_or(Protocol::Overflow)?;
            observe(Event::ResultWritten {
                epoch: self.epoch,
                queue: q,
                message_id: mid,
                bytes,
                complete,
            });
        }
        if !complete {
            return Ok(());
        }
        match role {
            ipc::Role::Register => {
                self.register_written = true;
                observe(Event::TransportRegistered {
                    generation: self.ipc.generation(),
                });
            }
            ipc::Role::Advert(wire) => {
                if wire == self.local_address_wire {
                    self.local_address_written = true;
                } else if let Some(advert) = self.advertisements.iter_mut().find(|a| a.wire == wire)
                {
                    advert.written = true;
                }
                // A normal NAT removal can retire the claim before its queued
                // ADD completes; its FIFO DELETE remains the current authority.
            }
            ipc::Role::Queue(q) => {
                let i = self.index(q).ok_or(Protocol::Stale)?;
                self.rows[i].as_mut().ok_or(Protocol::Stale)?.queue_written = true;
                observe(Event::QueueWritten {
                    epoch: self.epoch,
                    queue: q,
                });
            }
            ipc::Role::Incoming(flow) => {
                let row = self
                    .rows
                    .iter_mut()
                    .flatten()
                    .find(|r| r.incoming.as_ref().is_some_and(|d| d.id == flow))
                    .ok_or(Protocol::Stale)?;
                row.incoming.as_mut().ok_or(Protocol::Stale)?.written = true;
                observe(Event::IncomingWritten {
                    epoch: self.epoch,
                    flow_id: flow,
                });
            }
            ipc::Role::Sent(q, mid) => {
                let i = self.index(q).ok_or(Protocol::Stale)?;
                let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
                let send = row.send.as_mut().ok_or(Protocol::Stale)?;
                if send.mid != mid {
                    return Err(Protocol::Stale.into());
                }
                send.result_written = true;
                if send.status == 1 {
                    row.link
                        .as_mut()
                        .ok_or(Protocol::Stale)?
                        .take_accepted(send.id)?
                }
                if row.closing {
                    let send = row.send.take().ok_or(Protocol::Stale)?;
                    self.sends_retired += 1;
                    observe(Event::SendRetired {
                        epoch: self.epoch,
                        queue: q,
                        message_id: send.mid,
                        accepted: send.accepted,
                        total: send.total,
                        result_written: true,
                        result_bytes: send.result_bytes,
                        unknown: send.unknown,
                    })
                }
            }
            ipc::Role::Credit(q) => {
                let i = self.index(q).ok_or(Protocol::Stale)?;
                let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
                let send = row.send.as_ref().ok_or(Protocol::Stale)?;
                if !send.result_written || !send.credit_queued {
                    return Err(Protocol::Conflict.into());
                }
                row.send = None;
            }
            ipc::Role::Available(q) => {
                self.index(q).ok_or(Protocol::Stale)?;
            }
            ipc::Role::Down(q) => {
                let i = self.index(q).ok_or(Protocol::Stale)?;
                self.rows[i].as_mut().ok_or(Protocol::Stale)?.down_written = true
            }
            _ => {}
        }
        Ok(())
    }
    fn retire_row(
        &mut self,
        i: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let bound = self.deadline(self.limits.close_grace)?;
        let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
        if row.closing {
            return Ok(false);
        }
        row.closing = true;
        // Late polling cannot turn an expired original operation into a fresh
        // close allowance. Driver/socket teardown remains original-source work.
        let mut anchor = Instant::now().min(row.hard).min(row.idle);
        if let Some(t) = row.input {
            anchor = anchor.min(t)
        }
        if let Some(s) = &row.send {
            anchor = anchor.min(s.hard)
        }
        row.retire_hard = Some(
            anchor
                .checked_add(self.limits.close_grace)
                .ok_or(Protocol::Overflow)?
                .min(self.hard),
        );
        row.input = None;
        if let Some(connecting) = row.connecting.take() {
            drop(connecting)
        }
        capture_send(row)?;
        if let Some(link) = &mut row.link {
            link.close()
        }
        if row.send.as_ref().is_some_and(|send| send.orphaned) {
            row.send = None;
        }
        if let Some(send) = &mut row.send
            && !send.result_queued
        {
            send.status = -1;
            send.retiring = true;
            send.hard = send
                .hard
                .checked_add(self.limits.close_grace)
                .ok_or(Protocol::Overflow)?
                .min(bound)
                .min(self.hard)
        }
        if row
            .send
            .as_ref()
            .is_some_and(|s| s.result_written && !s.credit_queued)
        {
            let send = row.send.take().ok_or(Protocol::Stale)?;
            self.sends_retired += 1;
            observe(Event::SendRetired {
                epoch: self.epoch,
                queue: send.queue,
                message_id: send.mid,
                accepted: send.accepted,
                total: send.total,
                result_written: true,
                result_bytes: send.result_bytes,
                unknown: send.unknown,
            });
        }
        observe(Event::QueueRetired {
            epoch: self.epoch,
            queue: row.id,
        });
        Ok(true)
    }
    fn maintenance(
        &mut self,
        mono: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let mut progress = false;
        let now = Instant::now();
        for i in 0..self.rows.len() {
            let Some(row) = &self.rows[i] else { continue };
            if row.incoming.as_ref().is_some_and(|d| now >= d.hard) {
                return Err(Protocol::Deadline.into());
            }
            // Actual old completion may retire its original row even when a
            // later poll observes expiry. It grants no fresh submission.
            if row.closing
                && row.send.is_none()
                && row.incoming.is_none()
                && row.down_written
                && self
                    .endpoint
                    .as_ref()
                    .ok_or(Protocol::Closed)?
                    .driver_done(&row.driver)?
            {
                self.reap_row(i)?;
                progress = true;
                continue;
            }
            if row.closing && row.retire_hard.is_some_and(|t| now >= t) {
                return Err(Protocol::Deadline.into());
            }
            if row
                .send
                .as_ref()
                .is_some_and(|s| !s.orphaned && now >= s.hard && (s.retiring || s.result_queued))
            {
                return Err(Protocol::Deadline.into());
            }
            if !row.closing
                && (now >= row.hard
                    || now >= row.idle
                    || row.input.is_some_and(|h| now >= h)
                    || row.send.as_ref().is_some_and(|s| now >= s.hard))
            {
                progress |= self.retire_row(i, observe)?
            }
            let row = self.rows[i].as_mut().ok_or(Protocol::Stale)?;
            if row
                .send
                .as_ref()
                .is_some_and(|send| send.orphaned && send.accepted == send.total)
            {
                let send = row.send.as_ref().ok_or(Protocol::Stale)?;
                if !send.result_written {
                    row.link
                        .as_mut()
                        .ok_or(Protocol::Stale)?
                        .take_accepted(send.id)?;
                }
                row.send = None;
                progress = true;
            }
            if let Some(send) = &mut row.send {
                if send.orphaned {
                    continue;
                }
                if !send.result_queued && (send.accepted == send.total || row.closing) {
                    let result = Request::Sent {
                        message_id: send.mid,
                        queue: row.id,
                        peer: row.peer.ok_or(Protocol::Stale)?,
                        status: send.status,
                    };
                    if self.ipc.room_request(result)? {
                        self.ipc
                            .enqueue(result, ipc::Role::Sent(row.id, send.mid), send.hard)?;
                        send.result_queued = true;
                        progress = true
                    }
                }
                if send.result_written
                    && !send.credit_queued
                    && !row.closing
                    && row
                        .link
                        .as_ref()
                        .ok_or(Protocol::NotReady)?
                        .send_capacity(mono)?
                {
                    let hard = send.hard;
                    let update = Request::QueueUpdate(queue(row, 1)?);
                    if self.ipc.room_request(update)? {
                        self.ipc.enqueue(update, ipc::Role::Credit(row.id), hard)?;
                        // Borrow ends before mutating the same original send row.
                        row.send.as_mut().ok_or(Protocol::Stale)?.credit_queued = true;
                        progress = true;
                    }
                }
            }
            if !row.closing
                && row.capacity_needed
                && row.send.is_none()
                && row.queue_written
                && row
                    .link
                    .as_ref()
                    .ok_or(Protocol::NotReady)?
                    .send_capacity(mono)?
            {
                let update = Request::QueueUpdate(queue(row, 1)?);
                if self.ipc.room_request(update)? {
                    self.ipc
                        .enqueue(update, ipc::Role::Available(row.id), self.hard)?;
                    row.capacity_needed = false;
                    progress = true;
                }
            }
            if row.closing && !row.down {
                if !row.advertised {
                    row.down = true;
                    row.down_written = true
                } else {
                    let down = Request::QueueDown(row.id, row.peer.ok_or(Protocol::Stale)?);
                    if self.ipc.room_request(down)? {
                        self.ipc.enqueue(down, ipc::Role::Down(row.id), self.hard)?;
                        row.down = true;
                        row.down_written = false;
                        progress = true
                    }
                }
            }
            let removable = row.closing
                && row.send.is_none()
                && row.incoming.is_none()
                && row.down_written
                && self
                    .endpoint
                    .as_ref()
                    .ok_or(Protocol::Closed)?
                    .driver_done(&row.driver)?;
            if removable {
                self.reap_row(i)?;
                progress = true;
            }
        }
        Ok(progress)
    }
    fn reap_row(&mut self, i: usize) -> Result<(), Fault> {
        let row = self.rows[i].as_ref().ok_or(Protocol::Stale)?;
        self.endpoint
            .as_mut()
            .ok_or(Protocol::Closed)?
            .release_driver(&row.driver)?;
        let row = self.rows[i].take().ok_or(Protocol::Stale)?;
        if let Some(link) = row.link {
            link.recycle(&mut self.loans, i)?
        }
        Ok(())
    }
    fn poll_connections(
        &mut self,
        cx: &mut Context<'_>,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Fault> {
        let mut progress = false;
        for _ in 0..self.rows.len() {
            let i = self.round % self.rows.len();
            self.round = (self.round + 1) % self.rows.len();
            let Some(row) = self.rows[i].as_mut() else {
                continue;
            };
            if row.closing {
                continue;
            }
            let mut row_progress = false;
            if let Some(connecting) = &mut row.connecting {
                match Pin::new(connecting).poll(cx) {
                    Poll::Pending => continue,
                    Poll::Ready(Err(e)) => {
                        observe(Event::Rejected(Fault::Connection(e)));
                        self.retire_row(i, observe)?;
                        progress = true;
                        continue;
                    }
                    Poll::Ready(Ok(connection)) => {
                        row.connecting = None;
                        let options = application::Options {
                            local: row.local,
                            role: row.role,
                            until: MonoInstant(micros(
                                self.hard.saturating_duration_since(self.native_epoch),
                            )?),
                            hard: self.hard,
                            limits: self.limits,
                        };
                        match Application::adopt(
                            &connection,
                            &self.epoch.owner.profile,
                            now,
                            &mut self.loans,
                            i,
                            options,
                        ) {
                            Ok(link) => {
                                row.link = Some(link);
                                row_progress = true
                            }
                            Err(error) => {
                                connection.close(quinn::VarInt::from_u32(0), b"profile rejected");
                                observe(Event::Rejected(error));
                                self.retire_row(i, observe)?;
                                progress = true;
                                continue;
                            }
                        }
                    }
                }
            }
            let step = match row.link.as_mut().ok_or(Protocol::NotReady)?.poll(cx, now) {
                Ok(s) => s,
                Err(e) => {
                    #[cfg(feature = "h3-profile")]
                    if let Fault::Http3(error) = &e
                        && let Some((id, known, total)) = error.send_unknown()
                    {
                        let send = row.send.as_mut().ok_or(Protocol::Stale)?;
                        if send.id != id
                            || send.total != total
                            || known < send.accepted
                            || known > total
                        {
                            return Err(Protocol::Conflict.into());
                        }
                        send.accepted = known;
                        send.unknown = true;
                    }
                    observe(Event::Rejected(e));
                    self.retire_row(i, observe)?;
                    progress = true;
                    continue;
                }
            };
            match step {
                raw::Step::Pending => {}
                raw::Step::Frame => {
                    // First observation only: repeated held availability must not
                    // extend the original input/callback or inactivity budget.
                    if row.input.is_none() && row.incoming.is_none() {
                        row.input = Some(
                            Instant::now()
                                .checked_add(self.limits.operation)
                                .ok_or(Protocol::Overflow)?
                                .min(self.hard),
                        );
                        row_progress = true;
                    }
                }
                raw::Step::Fin => {
                    self.retire_row(i, observe)?;
                    progress = true;
                    continue;
                }
                raw::Step::Claim(peer) => {
                    row.peer = Some(peer);
                    row.input = None;
                    row_progress = true
                }
                raw::Step::ProviderAccepted {
                    id,
                    bytes,
                    complete,
                } => {
                    let send = row.send.as_mut().ok_or(Protocol::Stale)?;
                    if send.id != id {
                        return Err(Protocol::Stale.into());
                    }
                    send.accepted = send.accepted.checked_add(bytes).ok_or(Protocol::Overflow)?;
                    if send.accepted > send.total || complete != (send.accepted == send.total) {
                        return Err(Protocol::Conflict.into());
                    }
                    observe(Event::ProviderAccepted {
                        epoch: self.epoch,
                        queue: send.queue,
                        message_id: send.mid,
                        bytes,
                        complete,
                    });
                    row_progress = true;
                }
                raw::Step::Activity { read } => {
                    if read > 0 && row.input.is_none() {
                        row.input = Some(
                            Instant::now()
                                .checked_add(self.limits.operation)
                                .ok_or(Protocol::Overflow)?
                                .min(self.hard),
                        )
                    }
                    row_progress = true
                }
                raw::Step::StreamsReady => row_progress = true,
                raw::Step::IdentityAccepted(bytes) => row_progress = bytes > 0,
            }
            progress |= row_progress;
            if row_progress {
                row.idle = Instant::now()
                    .checked_add(self.limits.idle)
                    .ok_or(Protocol::Overflow)?
                    .min(self.hard)
            }
            if self.ready
                && !row.advertised
                && row.peer.is_some()
                && row.link.as_ref().ok_or(Protocol::NotReady)?.may_send(now)?
            {
                let canonical = Address::new(self.profile, row.remote)?.canonical()?;
                if self.ipc.room(1, 65 + canonical.as_bytes().len()) {
                    let capacity = row.send.is_none()
                        && row
                            .link
                            .as_ref()
                            .ok_or(Protocol::NotReady)?
                            .send_capacity(now)?;
                    self.ipc.enqueue(
                        Request::QueueSetup(queue(row, u64::from(capacity))?, canonical.as_bytes()),
                        ipc::Role::Queue(row.id),
                        row.hard,
                    )?;
                    row.advertised = true;
                    row.capacity_needed = !capacity;
                    row.hard = self.hard;
                    observe(Event::Queue {
                        epoch: self.epoch,
                        queue: row.id,
                        peer: row.peer.ok_or(Protocol::Stale)?,
                        inbound: matches!(row.role, Role::Acceptor),
                    });
                    progress = true;
                }
            }
            if self.ready
                && row.advertised
                && row.incoming.is_none()
                && let Some(frame) = row.link.as_ref().ok_or(Protocol::NotReady)?.frame(now)?
                && self.ipc.room(1, 88 + frame.bytes.len())
            {
                let next = self.next_flow.checked_add(1).ok_or(Protocol::Overflow)?;
                let flow = next.to_be_bytes();
                let peer = row.peer.ok_or(Protocol::Stale)?;
                let hard = row
                    .input
                    .unwrap_or(
                        Instant::now()
                            .checked_add(self.limits.operation)
                            .ok_or(Protocol::Overflow)?,
                    )
                    .min(self.hard);
                self.ipc.enqueue(
                    Request::Incoming {
                        flow_control: true,
                        flow_id: flow,
                        validity: micros(self.limits.idle)?,
                        peer,
                        neighbour: peer,
                        message: frame.bytes,
                    },
                    ipc::Role::Incoming(flow),
                    hard,
                )?;
                row.incoming = Some(Incoming {
                    id: flow,
                    frame: frame.id,
                    peer,
                    written: false,
                    hard,
                });
                self.next_flow = next;
                progress = true;
            }
        }
        Ok(progress)
    }

    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Fault>> {
        if self.closing || self.closed {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        // Register immutable native alarms BEFORE any canonical clock/subscription IO.
        self.identity.guard_native()?;
        let original = self.earliest();
        self.poll_alarm(cx, original);
        if Instant::now() >= self.hard
            || (!self.ever_ready && Instant::now() >= self.startup)
            || self.pils_input.is_some_and(|t| Instant::now() >= t)
        {
            return Poll::Ready(Err(Protocol::Deadline.into()));
        }
        if self.retry.is_some_and(|t| Instant::now() >= t) {
            self.retry = None
        }
        let utc = self.sample(cx)?;
        self.identity.guard(utc)?;
        let mono = self.mono()?;
        let mut progress = false;
        if !self.bound_event {
            observe(Event::Bound {
                epoch: self.epoch,
                address: self.local_addr()?,
            });
            self.bound_event = true;
            progress = true
        }
        match self.scanner.refresh() {
            Ok(changed) => progress |= changed,
            Err(error) => {
                observe(Event::Rejected(Fault::Io(error)));
                progress = true
            }
        }
        if !self.identity.retiring() {
            progress |= self.maintenance(mono, observe)?;
        }
        progress |= self
            .endpoint
            .as_mut()
            .ok_or(Protocol::Closed)?
            .poll_drivers(cx)?;
        progress |= self.poll_pils(cx, utc, observe)?;
        self.identity.guard(utc)?;
        progress |= self.poll_identity_retirement(observe)?;
        if !self.identity.retiring() {
            match self.ipc.poll_recovering(cx, |generation, role, bytes| {
                observe(Event::TransportOutputRetired {
                    generation,
                    kind: role.kind(),
                    queue: role.queue(),
                    message_id: role.message(),
                    flow_id: role.flow(),
                    bytes,
                });
            })? {
                ipc::Step::Pending => {}
                ipc::Step::Attached => {
                    self.attached = true;
                    observe(Event::Attached(self.epoch));
                    observe(Event::TransportAttached {
                        generation: self.ipc.generation(),
                    });
                    progress = true
                }
                ipc::Step::Activity => progress = true,
                ipc::Step::Lost { facts, cause } => {
                    self.transport_lost(facts, cause.into(), observe)?;
                    progress = true;
                }
                ipc::Step::Written {
                    role,
                    bytes,
                    complete,
                } => {
                    self.written(role, bytes, complete, observe)?;
                    progress = true
                }
                ipc::Step::Frame => {
                    if self.ready {
                        progress |= self.command(mono, observe)?
                    }
                }
            }
        }
        if self.attached && !self.register_queued && self.ipc.room(1, 32) {
            self.ipc.enqueue(
                Request::Register {
                    characteristics: Characteristics::Reliable,
                    can_burst: false,
                    prefix: match self.profile {
                        AddressProfile::Raw => b"quic",
                        AddressProfile::Http3 => b"http3",
                    },
                },
                ipc::Role::Register,
                if self.ever_ready {
                    self.hard
                } else {
                    self.startup
                },
            )?;
            self.register_queued = true;
            progress = true;
        }
        if !self.ready && self.register_written && self.identity.selected().is_some() {
            self.ready = true;
            self.ever_ready = true;
            observe(Event::Ready {
                epoch: self.epoch,
                peer: self.identity.selected().ok_or(Protocol::NotReady)?,
            });
            progress = true
        }
        progress |= self.poll_nat(cx, observe)?;
        progress |= self.advertise_current(utc)?;
        if self.identity.selected().is_some() {
            if self.rows.iter().any(Option::is_none) {
                match self
                    .endpoint
                    .as_mut()
                    .ok_or(Protocol::Closed)?
                    .poll_accept(cx)
                {
                    Poll::Pending => {}
                    Poll::Ready(Ok(c)) => {
                        self.allocate_row(c, Role::Acceptor, None)?;
                        progress = true
                    }
                    Poll::Ready(Err(endpoint::Failure::Protocol(Protocol::Capacity))) => {
                        progress = true
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                }
            }
            progress |= self.poll_connections(cx, mono, observe)?;
        }
        if self.ready
            && !self.restored
            && self.ipc.announcements_written()
            && self.addresses_restored()?
            && self
                .rows
                .iter()
                .flatten()
                .filter(|row| !row.closing && row.peer.is_some() && row.link.is_some())
                .all(|row| row.queue_written)
        {
            self.restored = true;
            observe(Event::TransportRestored {
                generation: self.ipc.generation(),
            });
            if self.identity.restored() {
                self.identity_recoveries = self.identity_recoveries.saturating_add(1);
                observe(Event::IdentityRestored {
                    epoch: self.epoch,
                    peer: self.identity.selected().ok_or(Protocol::NotReady)?,
                });
            }
        }
        // A new earlier first-input/send/callback target is armed in this SAME poll.
        let mut target = self.earliest();
        let remaining = Duration::from_micros(self.until.saturating_sub(utc));
        target = target.min(
            Instant::now()
                .checked_add(remaining)
                .ok_or(Protocol::Overflow)?,
        );
        if let Some(wait) = wait {
            target = target.min(wait)
        }
        // Bounded allocation retry is needed only for retained RX with no provider
        // change waiter. Real queue-capacity changes also wake via original MQ IO.
        if !progress && self.ipc.frame()?.is_some() {
            let retry = Instant::now()
                .checked_add(Duration::from_millis(100))
                .ok_or(Protocol::Overflow)?
                .min(self.hard);
            self.retry = Some(self.retry.map_or(retry, |t| t.min(retry)));
            target = target.min(retry)
        }
        self.poll_alarm(cx, target);
        if progress {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if wait.is_some_and(|w| Instant::now() >= w) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        Poll::Pending
    }
    /// One bounded fair step. Every unexpected error physically closes original
    /// MQ/PILS/NAT and QUIC sources BEFORE returning the actual first error.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Fault>> {
        let result = self.poll_inner(cx, wait, &mut observe);
        if matches!(result, Poll::Ready(Err(_))) {
            // Clock/source failure must not leave a background driver/socket
            // awaiting a future successful clock sample or caller continuation.
            self.abort(&mut observe)
        }
        result
    }
    fn abort(&mut self, observe: &mut impl FnMut(Event<'id>)) {
        self.begin_close(observe);
        if let Some(endpoint) = self.endpoint.take() {
            match endpoint.close() {
                Ok(report) => self.backend_closed = Some(report),
                Err(e) => {
                    if self.cleanup_error.is_none() {
                        self.cleanup_error = Some(e.into())
                    }
                }
            }
        }
        let mut cleanup = None;
        self.restore_loans(&mut cleanup);
        if self.cleanup_error.is_none() {
            self.cleanup_error = cleanup
        }
        self.closed = true;
    }
    /// Canceling this future preserves all original stream/MQ cursors and loans.
    pub async fn drive(
        &mut self,
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Fault> {
        poll_fn(|cx| self.poll(cx, wait, &mut observe)).await
    }
    /// Actual physical source retirement, clock-free and idempotent. Unreturned
    /// original FC debts become LOST; this never emits a service callback/ACK.
    pub fn begin_close(&mut self, mut observe: impl FnMut(Event<'id>)) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.closing_hard = Some(
            Instant::now()
                .checked_add(self.limits.close_grace)
                .unwrap_or(self.hard)
                .min(self.hard),
        );
        self.ready = false;
        self.ipc.close();
        let _old = self.pils.close();
        if let Some(nat) = &mut self.nat
            && let Some(end) = nat.close()
        {
            observe(Event::NatEnded(end))
        }
        for row in self.rows.iter_mut().flatten() {
            row.closing = true;
            drop(row.connecting.take());
            if let Err(error) = capture_send(row)
                && self.cleanup_error.is_none()
            {
                self.cleanup_error = Some(error)
            }
            if let Some(link) = &mut row.link {
                link.close()
            }
            if row.incoming.take().is_some() {
                self.incoming_lost += 1
            }
            if let Some(send) = row.send.take()
                && !send.orphaned
            {
                self.sends_retired += 1;
                observe(Event::SendRetired {
                    epoch: self.epoch,
                    queue: send.queue,
                    message_id: send.mid,
                    accepted: send.accepted,
                    total: send.total,
                    result_written: send.result_written,
                    result_bytes: send.result_bytes,
                    unknown: send.unknown,
                })
            }
        }
        if let Some(endpoint) = &mut self.endpoint {
            endpoint.begin_close()
        }
        self.subscription = None;
        self.advertisements.clear();
    }
    /// Bounded real driver drain, followed by explicit actual force-drop if needed.
    /// No new clock sample is required, even after an original clock failure.
    /// Caller cancellation of this future retains the old driver and grace cursor.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Closed {
        self.begin_close(&mut observe);
        let grace = self.closing_hard.unwrap_or(self.hard);
        poll_fn(|cx| {
            if Instant::now() >= grace {
                return Poll::Ready(());
            }
            let Some(endpoint) = &mut self.endpoint else {
                return Poll::Ready(());
            };
            match endpoint.poll_drivers(cx) {
                Ok(_) => {}
                Err(e) => {
                    if self.cleanup_error.is_none() {
                        self.cleanup_error = Some(e.into());
                    }
                    return Poll::Ready(());
                }
            }
            if endpoint.quiescent() {
                return Poll::Ready(());
            }
            self.poll_alarm(cx, grace);
            Poll::Pending
        })
        .await;
        let mut cleanup = self.cleanup_error.take();
        let backend = match self.endpoint.take().map(Endpoint::close) {
            None => self.backend_closed,
            Some(Ok(r)) => {
                self.backend_closed = Some(r);
                Some(r)
            }
            Some(Err(e)) => {
                if cleanup.is_none() {
                    cleanup = Some(e.into())
                }
                None
            }
        };
        self.restore_loans(&mut cleanup);
        self.closed = true;
        Closed {
            backend,
            cleanup,
            incoming_lost: self.incoming_lost,
            sends_retired: self.sends_retired,
            identity_updates: self.identity_updates,
            identity_recoveries: self.identity_recoveries,
            identity_forced_drivers: self.identity_forced_drivers,
        }
    }
    fn restore_loans(&mut self, cleanup: &mut Option<Fault>) {
        // Actual backend futures have completed/dropped BEFORE original application
        // handles and slabs can return to caller pools. No authenticated fact escapes.
        for i in 0..self.rows.len() {
            if let Some(row) = self.rows[i].take()
                && let Some(link) = row.link
            {
                match link.recycle(&mut self.loans, i) {
                    Ok(()) => {}
                    Err(e) => {
                        if cleanup.is_none() {
                            *cleanup = Some(e)
                        }
                    }
                }
            }
        }
    }
}
impl Drop for Runtime<'_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.begin_close(|_| {});
        let mut cleanup = None;
        if let Some(endpoint) = self.endpoint.take()
            && let Err(e) = endpoint.close()
        {
            cleanup = Some(e.into())
        }
        self.restore_loans(&mut cleanup);
    }
}
fn micros(d: Duration) -> Result<u64, Protocol> {
    u64::try_from(d.as_micros()).map_err(|_| Protocol::Overflow)
}
fn native_address(address: SocketAddr) -> natwire::Address<'static> {
    match address {
        SocketAddr::V4(a) => natwire::Address::V4 {
            ip: a.ip().octets(),
            port: a.port(),
        },
        SocketAddr::V6(a) => natwire::Address::V6 {
            ip: a.ip().octets(),
            port: a.port(),
            flow: a.flowinfo(),
            scope: a.scope_id(),
        },
    }
}
fn socket_address(address: natwire::Address<'_>) -> Option<SocketAddr> {
    match address {
        natwire::Address::V4 { ip, port } => Some(SocketAddr::from((ip, port))),
        natwire::Address::V6 {
            ip,
            port,
            flow,
            scope,
        } => Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            ip.into(),
            port,
            flow,
            scope,
        ))),
        _ => None,
    }
}
fn queue(row: &Row<'_, '_, '_>, length: u64) -> Result<Queue, Protocol> {
    Ok(Queue {
        id: row.id,
        peer: row.peer.ok_or(Protocol::NotReady)?,
        network: row.network,
        mtu: row.mtu,
        length,
        priority: 0,
        status: u32::from(matches!(row.role, Role::Acceptor)),
    })
}

// Actual leaf metadata is read before cancellation/drop. This observes old
// provider facts only: it never manufactures a callback, write or new attempt.
fn capture_send(row: &mut Row<'_, '_, '_>) -> Result<(), Fault> {
    if let Some((id, known, total)) = row.link.as_ref().and_then(Application::pending_send) {
        let send = row.send.as_mut().ok_or(Protocol::Stale)?;
        if send.id != id || send.total != total || known < send.accepted || known > total {
            return Err(Protocol::Conflict.into());
        }
        send.accepted = known;
    }
    if let Some(id) = row
        .link
        .as_ref()
        .and_then(Application::pending_send_unknown)
    {
        let send = row.send.as_mut().ok_or(Protocol::Stale)?;
        if send.id != id {
            return Err(Protocol::Stale.into());
        }
        send.unknown = true;
    }
    Ok(())
}
