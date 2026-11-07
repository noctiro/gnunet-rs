//! Official application request/notification ownership, without sockets or keys.
use crate::Limits;
use gnunet_types::Error;
use gnunet_wire::official::{
    Frames,
    core::{self, ClassOrder, Direction, KxState, PeerClass, PeerId, Request, Response, Traffic},
};
use std::collections::{BTreeMap, VecDeque};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy)]
struct Reservation {
    size: u16,
    id: u16,
    solicited: bool,
}
struct Client {
    initialized: bool,
    monitor: bool,
    options: u32,
    types: Vec<u16>,
    requests: BTreeMap<PeerId, Reservation>,
    output: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl Client {
    fn new() -> Self {
        Self {
            initialized: false,
            monitor: false,
            options: 0,
            types: Vec::new(),
            requests: BTreeMap::new(),
            output: VecDeque::new(),
            bytes: 0,
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        for frame in &mut self.output {
            frame.zeroize();
        }
    }
}
/// Actual authenticated peer state, also used for a monitor's initial snapshot.
#[derive(Clone, Copy)]
pub(crate) struct PeerState {
    pub(crate) class: PeerClass,
    pub(crate) state: u32,
    pub(crate) timeout: u64,
    pub(crate) established: bool,
}
pub(crate) struct Submission {
    pub(crate) peer: PeerId,
    pub(crate) priority: u32,
    pub(crate) messages: Zeroizing<Vec<u8>>,
}
pub(crate) struct Applications {
    local: PeerId,
    class: PeerClass,
    order: ClassOrder,
    limits: Limits,
    clients: BTreeMap<u64, Client>,
    peers: BTreeMap<PeerId, PeerState>,
    submissions: VecDeque<Submission>,
    reserved: usize,
}
impl Applications {
    pub(crate) fn new(local: PeerId, class: PeerClass, order: ClassOrder, limits: Limits) -> Self {
        Self {
            local,
            class,
            order,
            limits,
            clients: BTreeMap::new(),
            peers: BTreeMap::new(),
            submissions: VecDeque::new(),
            reserved: 0,
        }
    }
    pub(crate) fn attach(&mut self, id: u64) -> Result<(), Error> {
        if self.clients.len() >= self.limits.max_clients {
            return Err(Error::Capacity);
        }
        if self.clients.contains_key(&id) {
            return Err(Error::Conflict);
        }
        self.clients.insert(id, Client::new());
        Ok(())
    }
    pub(crate) fn alive(&self, id: u64) -> bool {
        self.clients.contains_key(&id)
    }
    pub(crate) fn remove(&mut self, id: u64) {
        if let Some(c) = self.clients.remove(&id) {
            self.reserved -= c
                .requests
                .values()
                .filter(|r| r.solicited)
                .map(|r| usize::from(r.size))
                .sum::<usize>();
        }
    }
    fn emit(&mut self, id: u64, response: Response<'_>) -> Result<(), Error> {
        let size = match response {
            Response::InitReply { .. } | Response::Connected { .. } => core::PEER_CLASS_LEN,
            Response::Disconnected(_) | Response::SendReady { .. } => core::PEER_LEN,
            Response::Monitor { .. } => core::MONITOR_LEN,
            Response::Traffic { traffic, .. } => core::TRAFFIC_PREFIX
                .checked_add(match traffic {
                    Traffic::Full(v) => v.len(),
                    Traffic::Header(_) => 4,
                })
                .ok_or(Error::Overflow)?,
        };
        let c = self.clients.get_mut(&id).ok_or(Error::Stale)?;
        if c.output.len() >= self.limits.max_pending_frames
            || size > self.limits.max_pending_bytes.saturating_sub(c.bytes)
        {
            return Err(Error::WouldBlock);
        }
        let mut frame = vec![0; size];
        let n = response.encode(&mut frame, self.order)?;
        c.bytes += n;
        c.output.push_back(frame);
        Ok(())
    }
    pub(crate) fn output(&self, id: u64) -> Option<&[u8]> {
        self.clients.get(&id)?.output.front().map(Vec::as_slice)
    }
    pub(crate) fn take_output(&mut self, id: u64) -> Option<Vec<u8>> {
        let c = self.clients.get_mut(&id)?;
        let bytes = c.output.pop_front()?;
        c.bytes -= bytes.len();
        Some(bytes)
    }
    fn interested(c: &Client, kind: u16) -> bool {
        (c.types.is_empty() && c.options != 0) || c.types.contains(&kind)
    }
    pub(crate) fn request(&mut self, id: u64, bytes: &[u8]) -> Result<(), Error> {
        let request = Request::decode(bytes)?;
        let client = self.clients.get(&id).ok_or(Error::Stale)?;
        match request {
            Request::Init { options, types } => {
                if client.initialized || client.monitor {
                    return Err(Error::Malformed);
                }
                let entries = types.iter().collect();
                let c = self.clients.get_mut(&id).ok_or(Error::Stale)?;
                c.initialized = true;
                c.options = options;
                c.types = entries;
                self.emit(
                    id,
                    Response::InitReply {
                        identity: self.local,
                        class: self.class,
                    },
                )?;
                let peers: Vec<_> = self
                    .peers
                    .iter()
                    .filter(|(_, p)| p.established)
                    .map(|(p, s)| (*p, s.class))
                    .collect();
                for (peer, class) in peers {
                    self.emit(id, Response::Connected { peer, class })?;
                }
            }
            Request::Monitor => {
                if client.initialized || client.monitor {
                    return Err(Error::Malformed);
                }
                self.clients.get_mut(&id).ok_or(Error::Stale)?.monitor = true;
                let snapshot: Vec<_> = self.peers.iter().map(|(p, s)| (*p, *s)).collect();
                for (peer, s) in snapshot {
                    self.emit(
                        id,
                        Response::Monitor {
                            peer,
                            state: KxState(s.state),
                            timeout: s.timeout,
                        },
                    )?;
                }
                self.emit(
                    id,
                    Response::Monitor {
                        peer: PeerId([0; 32]),
                        state: KxState::SNAPSHOT_FINISHED,
                        timeout: u64::MAX,
                    },
                )?;
            }
            Request::SendRequest {
                peer,
                size,
                request_id,
                ..
            } => {
                if !client.initialized {
                    return Err(Error::Malformed);
                }
                if peer != self.local && !self.peers.get(&peer).is_some_and(|p| p.established) {
                    return Ok(());
                }
                if peer != self.local && usize::from(size) > core::REMOTE_REQUEST_LIMIT {
                    return Err(Error::TooLarge);
                }
                let c = self.clients.get_mut(&id).ok_or(Error::Stale)?;
                if !c.requests.contains_key(&peer) && c.requests.len() >= self.limits.max_peers {
                    return Err(Error::Capacity);
                }
                if let Some(old) = c.requests.insert(
                    peer,
                    Reservation {
                        size,
                        id: request_id,
                        solicited: false,
                    },
                ) && old.solicited
                {
                    self.reserved -= usize::from(old.size);
                }
                self.solicit()?;
            }
            Request::Send {
                peer,
                priority,
                messages,
                ..
            } => {
                if !client.initialized {
                    return Err(Error::Malformed);
                }
                let Some(reservation) = client.requests.get(&peer).copied() else {
                    return Ok(());
                }; // legal old partial SEND after disconnect
                if !reservation.solicited || messages.len() > usize::from(reservation.size) {
                    return Err(Error::Malformed);
                }
                if peer != self.local {
                    for frame in Frames::new(messages) {
                        if frame?.encoded_len() >= core::REMOTE_REQUEST_LIMIT {
                            return Err(Error::TooLarge);
                        }
                    }
                }
                if peer != self.local && self.submissions.len() >= self.limits.max_pending_frames {
                    return Err(Error::WouldBlock);
                }
                let removed = self
                    .clients
                    .get_mut(&id)
                    .ok_or(Error::Stale)?
                    .requests
                    .remove(&peer)
                    .ok_or(Error::Stale)?;
                self.reserved -= usize::from(removed.size);
                if peer == self.local {
                    for frame in Frames::new(messages) {
                        let frame = frame?;
                        let mut one = vec![0; frame.encoded_len()];
                        frame.encode(&mut one)?;
                        self.traffic(Direction::Outbound, self.local, &one)?;
                        self.traffic(Direction::Inbound, self.local, &one)?;
                        one.zeroize();
                    }
                } else {
                    self.reserved += messages.len();
                    self.submissions.push_back(Submission {
                        peer,
                        priority,
                        messages: Zeroizing::new(messages.to_vec()),
                    });
                }
                self.solicit()?;
            }
        }
        Ok(())
    }
    pub(crate) fn solicit(&mut self) -> Result<(), Error> {
        let mut work = Vec::new();
        for (id, c) in &self.clients {
            for (peer, r) in &c.requests {
                if !r.solicited {
                    work.push((*id, *peer, *r));
                }
            }
        }
        for (id, peer, r) in work {
            if usize::from(r.size) > self.limits.max_reserved_bytes.saturating_sub(self.reserved) {
                continue;
            }
            if self
                .emit(
                    id,
                    Response::SendReady {
                        peer,
                        request_id: r.id,
                        size: r.size,
                    },
                )
                .is_err()
            {
                continue;
            }
            if let Some(request) = self
                .clients
                .get_mut(&id)
                .and_then(|c| c.requests.get_mut(&peer))
            {
                request.solicited = true;
                self.reserved += usize::from(r.size);
            }
        }
        Ok(())
    }
    pub(crate) fn find_submission(
        &self,
        mut ready: impl FnMut(&Submission) -> bool,
    ) -> Option<usize> {
        let mut peers = std::collections::BTreeSet::new();
        self.submissions
            .iter()
            .enumerate()
            .find_map(|(i, s)| (peers.insert(s.peer) && ready(s)).then_some(i))
    }
    pub(crate) fn submission(&self, index: usize) -> Option<&Submission> {
        self.submissions.get(index)
    }
    pub(crate) fn take_submission(&mut self, index: usize) -> Option<Submission> {
        let v = self.submissions.remove(index)?;
        self.reserved -= v.messages.len();
        Some(v)
    }
    pub(crate) fn set_peer(&mut self, peer: PeerId, state: PeerState) {
        let old = self.peers.insert(peer, state);
        let ids: Vec<_> = self.clients.keys().copied().collect();
        for id in ids {
            let Some(c) = self.clients.get_mut(&id) else {
                continue;
            };
            if old.is_some_and(|s| s.established)
                && !state.established
                && let Some(r) = c.requests.remove(&peer)
                && r.solicited
            {
                self.reserved -= usize::from(r.size);
            }
            let initialized = c.initialized;
            let monitor = c.monitor;
            let result = if monitor {
                self.emit(
                    id,
                    Response::Monitor {
                        peer,
                        state: KxState(state.state),
                        timeout: state.timeout,
                    },
                )
            } else if initialized && !old.is_some_and(|s| s.established) && state.established {
                self.emit(
                    id,
                    Response::Connected {
                        peer,
                        class: state.class,
                    },
                )
            } else if initialized && old.is_some_and(|s| s.established) && !state.established {
                self.emit(id, Response::Disconnected(peer))
            } else {
                Ok(())
            };
            if result.is_err() {
                self.remove(id);
            }
        }
        if !state.established {
            let removed: usize = self
                .submissions
                .iter()
                .filter(|s| s.peer == peer)
                .map(|s| s.messages.len())
                .sum();
            self.submissions.retain(|s| s.peer != peer);
            self.reserved -= removed;
        }
    }
    pub(crate) fn remove_peer(&mut self, peer: PeerId) {
        if let Some(mut state) = self.peers.get(&peer).copied() {
            state.state = 10;
            state.timeout = u64::MAX;
            state.established = false;
            self.set_peer(peer, state);
            self.peers.remove(&peer);
        }
    }
    pub(crate) fn traffic(
        &mut self,
        direction: Direction,
        peer: PeerId,
        messages: &[u8],
    ) -> Result<(), Error> {
        for frame in Frames::new(messages) {
            let frame = frame?;
            let mut encoded = vec![0; frame.encoded_len()];
            frame.encode(&mut encoded)?;
            let kind = frame.header().message_type().value();
            let ids: Vec<_> = self
                .clients
                .iter()
                .filter(|(_, c)| c.initialized)
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                let c = &self.clients[&id];
                let tm = Self::interested(c, kind);
                let (full, header) = match direction {
                    Direction::Inbound => (
                        tm || c.options & core::FULL_INBOUND != 0,
                        c.options & core::HEADER_INBOUND != 0,
                    ),
                    Direction::Outbound => (
                        c.options & core::FULL_OUTBOUND != 0,
                        c.options & core::HEADER_OUTBOUND != 0,
                    ),
                };
                let traffic = if full {
                    Traffic::Full(&encoded)
                } else if header {
                    Traffic::Header(frame.header())
                } else {
                    continue;
                };
                if self
                    .emit(
                        id,
                        Response::Traffic {
                            direction,
                            peer,
                            traffic,
                        },
                    )
                    .is_err()
                {
                    self.remove(id);
                }
            }
            encoded.zeroize();
        }
        Ok(())
    }
    pub(crate) fn clear(&mut self) {
        self.clients.clear();
        self.peers.clear();
        self.submissions.clear();
        self.reserved = 0;
    }
}
