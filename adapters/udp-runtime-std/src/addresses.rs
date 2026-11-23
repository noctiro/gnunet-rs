//! Actual NAT/interface references, original communicator writes and unsigned
//! PILS feeds remain three distinct local facts. No address-validation ACK.
mod interfaces;

use crate::HelloPublisher;
use gnunet_nat_client_host as nat;
use gnunet_pils::client::{Epoch, OperationId, OperationKind};
use gnunet_pils_host::client::{Client, Progress};
use gnunet_types::Error as Fault;
use gnunet_udp_communicator_host::{
    communicator::{Communicator, Publication, PublicationState},
    identity::IdentityEpoch,
};
use gnunet_wire::official::AbsoluteTime;
use std::{
    fmt::{self, Write},
    future::Future,
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
    pin::Pin,
    task::Context,
    time::{Duration, Instant},
};
use tokio::time::Sleep;
#[derive(Debug)]
pub(super) enum Failure {
    Core(Fault),
    Nat(nat::Error),
    Pils(gnunet_client_host::ConnectError),
    Network(io::Error),
}
impl From<Fault> for Failure {
    fn from(error: Fault) -> Self {
        Self::Core(error)
    }
}
impl From<nat::Error> for Failure {
    fn from(error: nat::Error) -> Self {
        Self::Nat(error)
    }
}
impl From<gnunet_client_host::ConnectError> for Failure {
    fn from(error: gnunet_client_host::ConnectError) -> Self {
        Self::Pils(error)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UDP addresses: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(e) => Some(e),
            Self::Nat(e) => Some(e),
            Self::Pils(e) => Some(e),
            Self::Network(e) => Some(e),
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Anchor {
    /// Actual shared logical absolute sample; independent of native elapsed.
    pub utc: AbsoluteTime,
    pub native: Instant,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Reverse<'nat> {
    pub session: nat::Session<'nat>,
    pub epoch: nat::Epoch<'nat>,
    pub ordinal: u64,
    pub remote: SocketAddr,
}
#[derive(Debug)]
pub(super) enum NatRefusal {
    Capacity,
    Classification(io::Error),
}
impl fmt::Display for NatRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity => f.write_str("bounded address claim capacity exhausted"),
            Self::Classification(error) => write!(f, "address classification: {error}"),
        }
    }
}
#[derive(Debug)]
pub(super) enum NatObservation<'nat> {
    None,
    Accepted,
    Rejected {
        address: SocketAddr,
        reason: NatRefusal,
    },
    Retired,
    Reverse(Reverse<'nat>),
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Event {
    AddQueued(u32),
    AddWritten(u32),
    RemoveQueued(u32),
    RemoveWritten(u32),
    PublicationUnknown(u32),
    FeedQueued,
    RemovedUnsubmitted(u32),
}
/// Diagnostic counts only. No field proves remote address/HELLO removal.
#[derive(Default, Debug)]
pub(super) struct Report {
    pub claims: usize,
    pub rows: usize,
    pub pending_publication: bool,
    pub pending_feed: bool,
    pub add_queued: u64,
    pub add_written: u64,
    pub remove_queued: u64,
    pub remove_written: u64,
    pub publication_unknown: u64,
    pub feed_queued: u64,
    pub feed_written: u64,
    pub feed_unknown: u64,
    pub feed_not_submitted: u64,
    pub feed_retired: u64,
    pub nat_losses: u64,
    pub reverse_notifications: u64,
    pub retired_rows: u64,
    pub clear_feed_written: bool,
    pub desired_feed_unsubmitted: bool,
    pub closing: bool,
    pub failed: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin<'nat> {
    Interface,
    Nat(nat::Session<'nat>, nat::Epoch<'nat>, nat::AddressId<'nat>),
}
#[derive(Clone, Copy)]
struct Claim<'nat> {
    origin: Origin<'nat>,
    address: SocketAddr,
    network: u32,
}
struct Text {
    bytes: [u8; 96],
    used: usize,
}
impl Text {
    fn new(address: SocketAddr, uri: bool) -> Result<Self, Fault> {
        let mut text = Self {
            bytes: [0; 96],
            used: 0,
        };
        if uri {
            write!(&mut text, "udp://{address}")
        } else {
            write!(&mut text, "udp-{address}")
        }
        .map_err(|_| Fault::Capacity)?;
        Ok(text)
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}
impl Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.used.checked_add(s.len()).ok_or(fmt::Error)?;
        let out = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        out.copy_from_slice(s.as_bytes());
        self.used = end;
        Ok(())
    }
}
struct Row {
    id: u32,
    address: SocketAddr,
    network: u32,
    text: Text,
    uri: Text,
    submitted: bool,
    live: bool,
    included: bool,
}
struct Deadline {
    expires: AbsoluteTime,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
impl Deadline {
    fn new(anchor: Anchor, life: Duration) -> Result<Self, Fault> {
        let hard = anchor.native.checked_add(life).ok_or(Fault::Overflow)?;
        let expires = anchor
            .utc
            .as_micros()
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|at| *at != u64::MAX)
            .ok_or(Fault::Overflow)?;
        if Instant::now() >= hard {
            return Err(Fault::Deadline);
        }
        Ok(Self {
            expires: AbsoluteTime::from_micros(expires),
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard.into())),
        })
    }
    fn native(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
}
struct Publishing {
    row: u32,
    remove: bool,
    ticket: Publication,
    deadline: Option<Deadline>,
}
struct Feeding<'pils> {
    epoch: Epoch<'pils>,
    operation: OperationId<'pils>,
    version: u64,
    empty: bool,
    deadline: Deadline,
}
struct DirectFeed<'pils> {
    bytes: Vec<u8>,
    version: u64,
    written: u64,
    pending: Option<Feeding<'pils>>,
    epoch: Option<Epoch<'pils>>,
    turn: bool,
}
pub(super) struct Addresses<'nat, 'pils> {
    maximum: usize,
    lifetime: Duration,
    claims: Vec<Claim<'nat>>,
    rows: Vec<Row>,
    next_id: u32,
    publication: Option<Publishing>,
    direct_feed: Option<DirectFeed<'pils>>,
    last_reverse: Option<(nat::Session<'nat>, nat::Epoch<'nat>, u64)>,
    report: Report,
}
fn usable(address: SocketAddr) -> bool {
    !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !matches!(address,SocketAddr::V4(a) if a.ip().is_broadcast())
        && !matches!(address,SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_some())
}
fn socket(address: nat::ipc::Address<'_>) -> Result<SocketAddr, Fault> {
    match address {
        nat::ipc::Address::V4 { ip, port } => Ok(SocketAddr::new(IpAddr::V4(ip.into()), port)),
        nat::ipc::Address::V6 {
            ip,
            port,
            flow,
            scope,
        } => Ok(SocketAddrV6::new(ip.into(), port, flow, scope).into()),
        nat::ipc::Address::Unix(_) => Err(Fault::InvalidInput),
    }
}
impl<'nat, 'pils> Addresses<'nat, 'pils> {
    pub fn new(
        maximum: usize,
        address_bytes: usize,
        lifetime: Duration,
        publisher: HelloPublisher,
    ) -> Result<Self, Failure> {
        if maximum == 0
            || maximum > 4096
            || address_bytes == 0
            || address_bytes > 65423
            || lifetime.is_zero()
            || lifetime.as_micros() >= u128::from(u64::MAX)
            || Instant::now().checked_add(lifetime).is_none()
        {
            return Err(Fault::InvalidInput.into());
        }
        let mut claims = Vec::new();
        claims
            .try_reserve_exact(maximum)
            .map_err(|_| Fault::Capacity)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(maximum)
            .map_err(|_| Fault::Capacity)?;
        let direct_feed = match publisher {
            HelloPublisher::Transport => None,
            HelloPublisher::Communicator => {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(address_bytes)
                    .map_err(|_| Fault::Capacity)?;
                bytes.resize(address_bytes, 0);
                Some(DirectFeed {
                    bytes,
                    version: 0,
                    written: 0,
                    pending: None,
                    epoch: None,
                    turn: false,
                })
            }
        };
        Ok(Self {
            maximum,
            lifetime,
            claims,
            rows,
            next_id: 1,
            publication: None,
            direct_feed,
            last_reverse: None,
            report: Report::default(),
        })
    }
    fn reconcile_feed(&mut self) -> Result<(), Fault> {
        let Some(feed) = &mut self.direct_feed else {
            return Ok(());
        };
        let changed = self.rows.iter().any(|row| {
            row.included
                != (row.live && self.claims.iter().any(|claim| claim.address == row.address))
        });
        if changed {
            feed.version = feed.version.checked_add(1).ok_or(Fault::Overflow)?;
            self.report.clear_feed_written = false;
            for row in &mut self.rows {
                row.included =
                    row.live && self.claims.iter().any(|claim| claim.address == row.address);
            }
        }
        Ok(())
    }
    fn wanted(&self, address: SocketAddr) -> bool {
        self.claims.iter().any(|claim| claim.address == address)
    }
    fn row(&mut self, address: SocketAddr, network: u32) -> Result<(), Failure> {
        if self.rows.iter().any(|row| row.address == address) {
            return Ok(());
        }
        if self.rows.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        let id = self.next_id;
        let next = id.checked_add(1).ok_or(Fault::Overflow)?;
        let text = Text::new(address, false)?;
        let uri = Text::new(address, true)?;
        self.rows.push(Row {
            id,
            address,
            network,
            text,
            uri,
            submitted: false,
            live: false,
            included: false,
        });
        self.next_id = next;
        Ok(())
    }
    /// Borrow actual progress before Root releases a held callback. Accepted
    /// means copied into bounded original app contexts, never mapping success.
    pub fn observe_nat(
        &mut self,
        registration: &nat::Registration<'nat>,
        progress: &nat::Progress<'nat>,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<NatObservation<'nat>, Failure> {
        match progress {
            nat::Progress::Ended(end) => {
                if end.source.session != registration.session() {
                    return Err(Fault::StaleGeneration.into());
                }
                self.claims.retain(|claim|!matches!(claim.origin,Origin::Nat(session,_,_) if session==end.source.session));
                self.report.nat_losses = self.report.nat_losses.saturating_add(1);
                self.reconcile_feed()?;
                Ok(NatObservation::Retired)
            }
            nat::Progress::Notification {
                session,
                epoch,
                ordinal,
            } => {
                let notification = registration.notification()?.ok_or(Fault::Stale)?;
                if notification.session != *session
                    || notification.epoch != *epoch
                    || notification.ordinal != *ordinal
                    || !registration.is_current(*epoch)
                {
                    return Err(Fault::StaleGeneration.into());
                }
                match notification.response {
                    nat::ipc::Response::Reverse { remote } => {
                        let original = (*session, *epoch, *ordinal);
                        if self.last_reverse != Some(original) {
                            self.last_reverse = Some(original);
                            self.report.reverse_notifications =
                                self.report.reverse_notifications.saturating_add(1);
                        }
                        Ok(NatObservation::Reverse(Reverse {
                            session: *session,
                            epoch: *epoch,
                            ordinal: *ordinal,
                            remote: socket(remote.address())?,
                        }))
                    }
                    nat::ipc::Response::AddressChange {
                        add_remove,
                        address,
                        ..
                    } => {
                        let Some(id) = notification.address_id else {
                            if add_remove != 1 {
                                return Ok(NatObservation::Accepted);
                            }
                            return Err(Fault::Stale.into());
                        };
                        let origin = Origin::Nat(*session, *epoch, id);
                        if add_remove == 1 && !self.report.closing {
                            let address = socket(address.address())?;
                            if usable(address)
                                && !self.claims.iter().any(|claim| claim.origin == origin)
                            {
                                if self.claims.len() == self.maximum
                                    || (!self.rows.iter().any(|row| row.address == address)
                                        && self.rows.len() == self.maximum)
                                {
                                    return Ok(NatObservation::Rejected {
                                        address,
                                        reason: NatRefusal::Capacity,
                                    });
                                }
                                let network = match classify(address) {
                                    Ok(network) => network,
                                    Err(error) => {
                                        return Ok(NatObservation::Rejected {
                                            address,
                                            reason: NatRefusal::Classification(error),
                                        });
                                    }
                                };
                                self.row(address, network)?;
                                self.claims.push(Claim {
                                    origin,
                                    address,
                                    network,
                                });
                                self.reconcile_feed()?;
                            }
                        } else if add_remove != 1 {
                            self.claims.retain(|claim| claim.origin != origin);
                            self.reconcile_feed()?;
                        }
                        Ok(NatObservation::Accepted)
                    }
                }
            }
            _ => Ok(NatObservation::None),
        }
    }
    /// Explicit unsupported/caller-handled reversal release, checked against the
    /// exact held callback. This is not reversal completion or a new private ACK.
    pub fn release_reverse(
        &mut self,
        registration: &mut nat::Registration<'nat>,
        original: Reverse<'nat>,
    ) -> Result<(), Failure> {
        let notification = registration.notification()?.ok_or(Fault::NotReady)?;
        if notification.session != original.session
            || notification.epoch != original.epoch
            || notification.ordinal != original.ordinal
            || !registration.is_current(original.epoch)
        {
            return Err(Fault::StaleGeneration.into());
        }
        let nat::ipc::Response::Reverse { remote } = notification.response else {
            return Err(Fault::Stale.into());
        };
        if socket(remote.address())? != original.remote {
            return Err(Fault::Stale.into());
        }
        registration.release_notification()?;
        Ok(())
    }
    /// Observe before logger/control gates so a real whole-write fact is never
    /// replaced by a later error. All other PILS operations stay with Root.
    pub fn observe_pils(&mut self, progress: &Progress<'pils, 32>) -> Result<(), Failure> {
        let Some(feed) = &mut self.direct_feed else {
            return Ok(());
        };
        match progress {
            Progress::Connected(epoch) => {
                if feed.epoch.is_some_and(|old| old != *epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                feed.epoch = Some(*epoch);
            }
            Progress::Written(written) => {
                if written.kind == OperationKind::Feed
                    && feed
                        .pending
                        .as_ref()
                        .is_some_and(|feed| feed.operation == written.operation)
                {
                    let original = feed.pending.take().ok_or(Fault::Stale)?;
                    feed.written = original.version;
                    self.report.feed_written = self.report.feed_written.saturating_add(1);
                    if original.empty && original.version == feed.version {
                        self.report.clear_feed_written = true;
                    }
                }
            }
            Progress::Lost { epoch, report, .. } => {
                if feed
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.epoch == *epoch)
                {
                    let original = feed.pending.take().ok_or(Fault::Stale)?;
                    match report
                        .feeds()
                        .find(|lost| lost.operation == original.operation)
                        .map(|lost| lost.disposition)
                    {
                        Some(gnunet_pils::client::FeedDisposition::NotSubmitted) => {
                            self.report.feed_not_submitted =
                                self.report.feed_not_submitted.saturating_add(1)
                        }
                        _ => self.report.feed_unknown = self.report.feed_unknown.saturating_add(1),
                    }
                }
                if feed.epoch.is_some_and(|old| old != *epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                feed.epoch = None;
                // A new source needs a fresh snapshot of current intent, not a
                // replay of the old FEED or a claim that it was never applied.
                feed.version = feed.version.checked_add(1).ok_or(Fault::Overflow)?;
                self.report.clear_feed_written = false;
            }
            _ => {}
        }
        Ok(())
    }
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        let expired = self
            .publication
            .as_mut()
            .and_then(|pending| pending.deadline.as_mut())
            .is_some_and(|deadline| deadline.native(cx))
            || self
                .direct_feed
                .as_mut()
                .and_then(|feed| feed.pending.as_mut())
                .is_some_and(|pending| pending.deadline.native(cx));
        if expired {
            self.report.failed = true;
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    pub fn check_time(&mut self, now: AbsoluteTime) -> Result<(), Failure> {
        if self
            .publication
            .as_ref()
            .and_then(|pending| pending.deadline.as_ref())
            .is_some_and(|deadline| now >= deadline.expires)
            || self
                .direct_feed
                .as_ref()
                .and_then(|feed| feed.pending.as_ref())
                .is_some_and(|pending| now >= pending.deadline.expires)
        {
            self.report.failed = true;
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn observe_publication(&mut self, comm: &Communicator<'_>) -> Result<Option<Event>, Failure> {
        let Some(pending) = self.publication.as_ref() else {
            return Ok(None);
        };
        match comm.publication(&pending.ticket)? {
            PublicationState::Pending => Ok(None),
            state => {
                let pending = self.publication.take().ok_or(Fault::Stale)?;
                let index = self
                    .rows
                    .iter()
                    .position(|row| row.id == pending.row)
                    .ok_or(Fault::Stale)?;
                if state == PublicationState::Retired {
                    self.rows[index].submitted = false;
                    // Losing an MQ does not close the original UDP socket or
                    // erase a previous whole ADD. Keep that historical HELLO
                    // membership; a first, unwritten ADD remains non-live.
                    self.report.publication_unknown =
                        self.report.publication_unknown.saturating_add(1);
                    self.reconcile_feed()?;
                    return Ok(Some(Event::PublicationUnknown(pending.row)));
                }
                if pending.remove {
                    self.rows.remove(index);
                    self.report.remove_written = self.report.remove_written.saturating_add(1);
                    Ok(Some(Event::RemoveWritten(pending.row)))
                } else {
                    self.rows[index].live = true;
                    self.report.add_written = self.report.add_written.saturating_add(1);
                    self.reconcile_feed()?;
                    Ok(Some(Event::AddWritten(pending.row)))
                }
            }
        }
    }
    fn publish(
        &mut self,
        comm: &mut Communicator<'_>,
        anchor: Option<Anchor>,
    ) -> Result<Option<Event>, Failure> {
        if self.publication.is_some() {
            return Ok(None);
        }
        if let Some(index) = self.rows.iter().position(|row| !self.wanted(row.address)) {
            if !self.rows[index].submitted {
                let row = self.rows.remove(index);
                return Ok(Some(Event::RemovedUnsubmitted(row.id)));
            }
            if !comm.transport_ready() {
                return Ok(None);
            }
            let id = self.rows[index].id;
            let deadline = anchor
                .map(|anchor| Deadline::new(anchor, self.lifetime))
                .transpose()?;
            match comm.withdraw(id) {
                Ok(ticket) => {
                    self.publication = Some(Publishing {
                        row: id,
                        remove: true,
                        ticket,
                        deadline,
                    });
                    self.report.remove_queued = self.report.remove_queued.saturating_add(1);
                    return Ok(Some(Event::RemoveQueued(id)));
                }
                Err(Fault::WouldBlock) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        if self.report.closing || self.report.failed || !comm.transport_ready() {
            return Ok(None);
        }
        let Some(anchor) = anchor else {
            return Ok(None);
        };
        if let Some(claim) = self
            .claims
            .iter()
            .find(|claim| !self.rows.iter().any(|row| row.address == claim.address))
            .copied()
        {
            if self.rows.len() == self.maximum {
                return Ok(None);
            }
            self.row(claim.address, claim.network)?;
        }
        if let Some(index) = self
            .rows
            .iter()
            .position(|row| !row.submitted && self.wanted(row.address))
        {
            let deadline = Deadline::new(anchor, self.lifetime)?;
            let row = &self.rows[index];
            match comm.advertise(row.id, row.text.bytes(), row.network, u64::MAX) {
                Ok(ticket) => {
                    self.publication = Some(Publishing {
                        row: row.id,
                        remove: false,
                        ticket,
                        deadline: Some(deadline),
                    });
                    self.rows[index].submitted = true;
                    self.report.add_queued = self.report.add_queued.saturating_add(1);
                    return Ok(Some(Event::AddQueued(self.rows[index].id)));
                }
                Err(Fault::WouldBlock) => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }
    fn feed(
        &mut self,
        pils: &mut Client<'pils, 32>,
        binding: &IdentityEpoch<'pils>,
        anchor: Option<Anchor>,
    ) -> Result<Option<Event>, Failure> {
        let Some(feed) = &mut self.direct_feed else {
            return Ok(None);
        };
        if self.report.failed && !self.report.closing {
            return Ok(None);
        }
        if feed.pending.is_some() || feed.version == feed.written {
            return Ok(None);
        }
        let Some(anchor) = anchor else {
            return Ok(None);
        };
        binding.current_native(pils, anchor.utc)?;
        let epoch = pils.epoch().ok_or(Fault::NotReady)?;
        if feed.epoch.is_some_and(|old| old != epoch) {
            return Err(Fault::StaleGeneration.into());
        }
        feed.epoch = Some(epoch);
        let deadline = Deadline::new(anchor, self.lifetime)?;
        let limits = gnunet_hello::Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: feed.bytes.len(),
            maximum_addresses: self.maximum,
        };
        let mut builder = gnunet_hello::HelloBuilder::new(&mut feed.bytes, limits);
        for row in &self.rows {
            if row.live && self.claims.iter().any(|claim| claim.address == row.address) {
                builder.add_address(row.uri.bytes())?;
            }
        }
        let empty = builder.address_count() == 0;
        let operation = match pils.feed_addresses(&builder) {
            Ok(operation) => operation,
            Err(gnunet_client_host::ConnectError::Protocol(
                Fault::Capacity | Fault::WouldBlock | Fault::NotReady,
            )) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        feed.pending = Some(Feeding {
            epoch,
            operation,
            version: feed.version,
            empty,
            deadline,
        });
        self.report.feed_queued = self.report.feed_queued.saturating_add(1);
        Ok(Some(Event::FeedQueued))
    }
    /// One retained publication/feed step. None anchor still permits actual
    /// write observations and clockfree withdrawals; never new ADD/FEED.
    pub fn advance(
        &mut self,
        comm: &mut Communicator<'_>,
        pils: &mut Client<'pils, 32>,
        binding: &IdentityEpoch<'pils>,
        anchor: Option<Anchor>,
    ) -> Result<Option<Event>, Failure> {
        if let Some(event) = self.observe_publication(comm)? {
            return Ok(Some(event));
        }
        if let Some(anchor) = anchor {
            self.check_time(anchor.utc)?;
        }
        let Some(turn) = self.direct_feed.as_ref().map(|feed| feed.turn) else {
            return self.publish(comm, anchor);
        };
        for offset in 0..2 {
            let feed = turn ^ (offset != 0);
            let event = if feed {
                self.feed(pils, binding, anchor)?
            } else {
                self.publish(comm, anchor)?
            };
            if event.is_some() {
                if let Some(direct) = &mut self.direct_feed {
                    direct.turn = !feed;
                }
                return Ok(event);
            }
        }
        Ok(None)
    }
    /// Clockfree intent only; original tickets/operations remain to be observed.
    pub fn begin_close(&mut self) {
        if self.report.closing {
            return;
        }
        self.report.closing = true;
        self.claims.clear();
        if self.reconcile_feed().is_err() {
            self.report.failed = true;
        }
    }
    /// Observe the retired physical publication before dropping its write
    /// deadline. Original NAT/interface claims and PILS FEED operations retain
    /// their own lifetimes. Re-registration only resubmits current ADDs; it
    /// neither withdraws a still-live UDP address nor replays an old FEED.
    pub fn transport_lost(&mut self, comm: &Communicator<'_>) -> Result<(), Failure> {
        if comm.transport_attached() || comm.is_closed() {
            return Err(Fault::NotReady.into());
        }
        let _ = self.observe_publication(comm)?;
        if self.publication.is_some() {
            return Err(Fault::NotReady.into());
        }
        for row in &mut self.rows {
            row.submitted = false;
        }
        Ok(())
    }
    /// Local diagnostic only: desired updates and original retained work have
    /// settled. This does not prove a remote address/HELLO was applied/removed.
    pub fn idle(&self) -> bool {
        self.publication.is_none()
            && self
                .direct_feed
                .as_ref()
                .is_none_or(|feed| feed.pending.is_none() && feed.version == feed.written)
            && self
                .rows
                .iter()
                .all(|row| self.wanted(row.address) && row.live)
            && self.claims.iter().all(|claim| {
                self.rows
                    .iter()
                    .any(|row| row.address == claim.address && row.live)
            })
    }
    /// Call only with the original communicator after its actual local physical
    /// teardown. This records source retirement, never a remote withdrawal ACK.
    pub fn retire_comm(&mut self, comm: &Communicator<'_>) -> Result<(), Failure> {
        if !comm.is_quiescent() {
            return Err(Fault::NotReady.into());
        }
        self.begin_close();
        let _ = self.observe_publication(comm)?;
        self.report.retired_rows = self
            .report
            .retired_rows
            .saturating_add(self.rows.len() as u64);
        self.rows.clear();
        Ok(())
    }
    /// Root passes the original IDs returned by its same PILS Client.close.
    /// Missing/previously-completed IDs do not fabricate a fresh write receipt.
    pub fn pils_retired(&mut self, retired: &[Option<OperationId<'pils>>]) {
        let Some(feed) = &mut self.direct_feed else {
            return;
        };
        if feed.pending.as_ref().is_some_and(|pending| {
            retired
                .iter()
                .flatten()
                .any(|operation| *operation == pending.operation)
        }) {
            feed.pending = None;
            self.report.feed_retired = self.report.feed_retired.saturating_add(1);
            self.report.feed_unknown = self.report.feed_unknown.saturating_add(1);
        }
    }
    pub fn report(&self) -> Report {
        Report {
            claims: self.claims.len(),
            rows: self.rows.len(),
            pending_publication: self.publication.is_some(),
            pending_feed: self
                .direct_feed
                .as_ref()
                .is_some_and(|feed| feed.pending.is_some()),
            desired_feed_unsubmitted: self
                .direct_feed
                .as_ref()
                .is_some_and(|feed| feed.version != feed.written),
            add_queued: self.report.add_queued,
            add_written: self.report.add_written,
            remove_queued: self.report.remove_queued,
            remove_written: self.report.remove_written,
            publication_unknown: self.report.publication_unknown,
            feed_queued: self.report.feed_queued,
            feed_written: self.report.feed_written,
            feed_unknown: self.report.feed_unknown,
            feed_not_submitted: self.report.feed_not_submitted,
            feed_retired: self.report.feed_retired,
            nat_losses: self.report.nat_losses,
            reverse_notifications: self.report.reverse_notifications,
            retired_rows: self.report.retired_rows,
            clear_feed_written: self.report.clear_feed_written,
            closing: self.report.closing,
            failed: self.report.failed,
        }
    }
}
