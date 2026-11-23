//! Native fixed-peer UDP caches under the unchanged heap DNSSTUB owner.
use super::{Event, Flow, HostError, ProviderUpstreamLimits, UpstreamRetirement};
use crate::{UPSTREAM_SOCKETS, core};
use gnunet_dnsstub::{
    Action, Admission, AttemptId, Family, HeapDnsStub, RequestId, ServerId, SocketId, Stopped,
};
use gnunet_native::dns_proxy::{Connection, provider::Session};
use gnunet_types::{Error, MonoInstant};
use std::{io, net::SocketAddr, pin::Pin};
use tokio::time::{Instant, Sleep};
mod deadline;
mod group;
mod poll;
mod retirement;
type Core = HeapDnsStub<UPSTREAM_SOCKETS, { core::MAX_DNS_BYTES }, 4>;
struct Send {
    attempt: AttemptId,
    request: RequestId,
    socket: SocketId,
    destination: SocketAddr,
    len: usize,
    until: Option<Instant>,
}
struct Peer {
    connection: Connection,
    ready: bool,
    ready_until: Option<Instant>,
    receiving: bool,
    sending: Option<Send>,
    error: Option<io::Error>,
    retiring: bool,
}
#[derive(Clone, Copy)]
struct Opening {
    socket: SocketId,
    destination: SocketAddr,
}
struct Group {
    socket: SocketId,
    opened: bool,
    retiring: bool,
    peers: [Option<Peer>; 4],
    cursor: usize,
}
pub(super) struct Provider {
    core: Core,
    session: Session,
    servers: [Option<SocketAddr>; 4],
    groups: Vec<Option<Group>>,
    retired: Vec<Option<Group>>,
    openings: Vec<Option<Opening>>,
    sends: Vec<Option<Send>>,
    maximum: usize,
    limits: ProviderUpstreamLimits,
    epoch: Instant,
    timer: Pin<Box<Sleep>>,
    cursor: usize,
    action_first: bool,
    retirement: UpstreamRetirement,
}
impl Provider {
    pub fn start(
        session: Session,
        slots: usize,
        maximum: usize,
        limits: ProviderUpstreamLimits,
    ) -> Result<Self, HostError> {
        let limits = limits.validate()?;
        if !(12..=core::MAX_DNS_BYTES).contains(&maximum) {
            return Err(Error::InvalidInput.into());
        }
        let core =
            gnunet_dnsstub::DnsStub::<UPSTREAM_SOCKETS, { core::MAX_DNS_BYTES }, 4>::start_heap(
                slots,
            )?;
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(slots * 2)
            .map_err(|_| Error::Capacity)?;
        groups.resize_with(slots * 2, || None);
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(slots * 2)
            .map_err(|_| Error::Capacity)?;
        retired.resize_with(slots * 2, || None);
        let mut openings = Vec::new();
        openings
            .try_reserve_exact(slots * 2)
            .map_err(|_| Error::Capacity)?;
        openings.resize_with(slots * 2, || None);
        let mut sends = Vec::new();
        sends
            .try_reserve_exact(slots)
            .map_err(|_| Error::Capacity)?;
        sends.resize_with(slots, || None);
        let epoch = Instant::now();
        Ok(Self {
            core,
            session,
            servers: [None; 4],
            groups,
            retired,
            openings,
            sends,
            maximum,
            limits,
            epoch,
            timer: Box::pin(tokio::time::sleep_until(epoch)),
            cursor: 0,
            action_first: true,
            retirement: UpstreamRetirement::default(),
        })
    }
    pub fn slot_count(&self) -> usize {
        self.core.slot_count()
    }
    pub fn is_stopped(&self) -> bool {
        self.core.is_stopped()
    }
    pub fn add_dns_sa(&mut self, address: SocketAddr) -> Result<ServerId, Error> {
        if self.core.is_stopped() {
            return Err(Error::Closed);
        }
        let index = self
            .servers
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let id = self.core.add_dns_sa(address)?;
        self.servers[index] = Some(address);
        Ok(id)
    }
    pub fn set_retry(&mut self, retry: gnunet_types::Duration) -> Result<(), Error> {
        self.core.set_retry(retry)
    }
    pub fn pending_requests(&self) -> usize {
        self.core.pending_requests()
    }
    pub fn resolve(&mut self, bytes: &[u8]) -> Result<Admission, HostError> {
        let now = clock(self.epoch)?;
        let mut entropy_error = None;
        let admission = self.core.resolve(bytes, now, |bound| {
            let threshold = bound.wrapping_neg() % bound;
            loop {
                let value = getrandom::u32().map_err(|error| {
                    entropy_error = Some(error);
                    Error::Io
                })?;
                if value >= threshold {
                    return Ok(value % bound);
                }
            }
        });
        if let Some(error) = entropy_error {
            return Err(HostError::Entropy(error));
        }
        let admission = admission?;
        if let Some(old) = admission.evicted {
            self.forget_send(old);
        }
        Ok(admission)
    }
    pub fn resolve_cancel(&mut self, request: RequestId) -> Result<(), Error> {
        self.core.resolve_cancel(request)?;
        self.forget_send(request);
        Ok(())
    }
    fn forget_send(&mut self, request: RequestId) {
        for send in &mut self.sends {
            if send.as_ref().is_some_and(|send| send.request == request) {
                *send = None;
            }
        }
    }
    pub fn stop(&mut self) -> Stopped {
        let result = self.core.stop();
        self.sends.iter_mut().for_each(|send| *send = None);
        self.openings.iter_mut().for_each(|opening| *opening = None);
        for group in self.groups.iter_mut().chain(&mut self.retired).flatten() {
            retire(group);
        }
        result
    }
    fn create_group(&self, opening: Opening) -> Result<(Group, Option<io::Error>), Error> {
        let socket = opening.socket;
        let mut group = Group {
            socket,
            opened: false,
            retiring: false,
            peers: std::array::from_fn(|_| None),
            cursor: 0,
        };
        let address = opening.destination;
        if family(address) != socket.family() {
            return Err(Error::Conflict);
        }
        match connect(&self.session, address, self.limits.readiness_timeout) {
            Ok(peer) => group.peers[0] = Some(peer),
            Err(error) => {
                retire(&mut group);
                return Ok((group, Some(error)));
            }
        }
        Ok((group, None))
    }
    fn install(
        &mut self,
        opening: Opening,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        let socket = opening.socket;
        let index = group_index(socket);
        if let Some(group) = &self.groups[index] {
            if !group.retiring {
                return Err(Error::Conflict.into());
            }
            if self.openings[index].is_some_and(|old| old.socket != socket) {
                return Err(Error::Conflict.into());
            }
            if !self.park(index) {
                self.openings[index] = Some(opening);
                return Ok(None);
            }
        }
        self.openings[index] = None;
        let (group, error) = self.create_group(opening)?;
        self.groups[index] = Some(group);
        if let Some(error) = error {
            self.core.socket_opened(socket, false)?;
            return Ok(Some(callback(Event::SocketOpened {
                socket,
                result: Err(error),
            })));
        }
        Ok(None)
    }
    fn next_action(
        &mut self,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        match self.core.next_action(clock(self.epoch)?)? {
            Some(Action::OpenSocket { socket }) => {
                let opening = Opening {
                    socket,
                    destination: self.core.pending_destination(socket)?,
                };
                self.install(opening, callback)
            }
            Some(Action::Send {
                attempt,
                request,
                socket,
                destination,
                len,
            }) => {
                let slot = socket.slot() as usize;
                if self.sends[slot].is_some() {
                    return Err(Error::Conflict.into());
                }
                self.sends[slot] = Some(Send {
                    attempt,
                    request,
                    socket,
                    destination,
                    len,
                    until: None,
                });
                Ok(None)
            }
            None => Ok(None),
        }
    }
}
fn family(address: SocketAddr) -> Family {
    if address.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    }
}
fn group_index(socket: SocketId) -> usize {
    socket.slot() as usize * 2 + usize::from(socket.family() == Family::V6)
}
fn retire(group: &mut Group) {
    group.retiring = true;
    for peer in group.peers.iter_mut().flatten() {
        peer.connection.request_cancel();
    }
}
fn clock(epoch: Instant) -> Result<MonoInstant, Error> {
    u64::try_from(epoch.elapsed().as_micros())
        .map(MonoInstant)
        .map_err(|_| Error::Overflow)
}

fn connect(
    session: &Session,
    address: SocketAddr,
    readiness: std::time::Duration,
) -> io::Result<Peer> {
    let until = Instant::now()
        .checked_add(readiness)
        .ok_or_else(|| io::Error::other("DNS peer readiness deadline overflow"))?;
    let lease = session.lease()?;
    Ok(Peer {
        connection: Connection::udp_in_provider(address, lease)?,
        ready: false,
        ready_until: Some(until),
        receiving: false,
        sending: None,
        error: None,
        retiring: false,
    })
}
