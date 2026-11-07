//! Original physical observation owners, separate from traffic/route authority.
use super::*;
use gnunet_wire::official::transport_monitor::{self as wire, Monitor, Request, Response};

/// Diagnostic absolute target. An unrepresentable timestamp is NEVER, never
/// a new routing/validation failure or a wrapped finite clock value.
pub(super) fn next_absolute(times: Times, delay: u64) -> u64 {
    times
        .absolute_after(RelativeTime::from_micros(delay))
        .map(|t| t.as_micros())
        .unwrap_or(u64::MAX)
}

/// Read-only current Actor path, supplied by the actual native DV bridge.
/// This never installs a route, confirms a peer or grants transmission authority.
#[derive(Clone, Copy, Debug)]
pub struct DvLink {
    /// Actual final Actor route target.
    pub target: PeerId,
    /// Actual direct first hop of that original current path.
    pub first_hop: PeerId,
    /// Intermediate vector count from the actual path.
    pub distance: u32,
    /// The same route generation is installed in the original Bridge.
    pub confirmed: bool,
}
/// One synchronous original-source projection. It contains no native work.
pub struct Links {
    /// Original Engine-minted Actor source; None only for a non-DV owner.
    pub source: Option<dv_bridge::Source>,
    /// Actual bounded current Actor path observations.
    pub rows: Vec<DvLink>,
}
impl Links {
    /// Empty DV projection for an actual non-DV owner.
    pub fn direct() -> Self {
        Self {
            source: None,
            rows: Vec::new(),
        }
    }
}
/// Exact original slow/failed observation owner. Retirement is not a wire gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retirement {
    /// Original physical local IPC owner, never a replacement source.
    pub client: ClientId,
    /// Original resource/source refusal that required physical retirement.
    pub reason: Error,
}

#[derive(Eq, PartialEq)]
struct QueueView {
    serial: u64,
    peer: PeerId,
    frame: Vec<u8>,
}
struct Subscriber {
    client: ClientId,
    selector: PeerId,
    continuous: bool,
    source: Option<dv_bridge::Source>,
    pending: VecDeque<Vec<u8>>,
    bytes: usize,
    failed: Option<Error>,
}
pub(super) struct Book {
    subscribers: Vec<Subscriber>,
    previous: Vec<QueueView>,
    clients: usize,
    frames: usize,
    bytes: usize,
    cursor: usize,
    dirty: bool,
}
fn encode(r: Response<'_>) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    let n = r.encoded_len()?;
    b.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    b.resize(n, 0);
    r.encode(&mut b)?;
    Ok(b)
}
fn selected(selector: PeerId, peer: PeerId) -> bool {
    selector.0 == [0; 32] || selector == peer
}
impl Book {
    pub(super) fn new(l: Limits) -> Result<Self, Error> {
        let frames = l
            .queues
            .max(l.peers)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let bytes = l
            .queues
            .max(l.peers)
            .checked_mul(wire::LINK_BYTES + 1)
            .and_then(|n| n.checked_add(l.control_bytes))
            .ok_or(Error::Overflow)?;
        let mut subscribers = Vec::new();
        subscribers
            .try_reserve_exact(l.clients)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            subscribers,
            previous: Vec::new(),
            clients: l.clients,
            frames,
            bytes,
            cursor: 0,
            dirty: false,
        })
    }
    pub(super) fn invalidate(&mut self) {
        self.dirty = true;
    }
    fn append(
        s: &mut Subscriber,
        frame: Vec<u8>,
        frames: usize,
        bytes: usize,
    ) -> Result<(), Error> {
        let next = s.bytes.checked_add(frame.len()).ok_or(Error::Overflow)?;
        if s.pending.len() >= frames || next > bytes {
            return Err(Error::Capacity);
        }
        s.pending.try_reserve(1).map_err(|_| Error::Capacity)?;
        s.pending.push_back(frame);
        s.bytes = next;
        Ok(())
    }
    fn fail(s: &mut Subscriber, reason: Error) {
        s.failed.get_or_insert(reason);
        s.pending.clear();
        s.bytes = 0;
    }
    fn broadcast(&mut self, peer: PeerId, frame: &[u8]) {
        for s in &mut self.subscribers {
            if !s.continuous || s.failed.is_some() || !selected(s.selector, peer) {
                continue;
            }
            let result = copy(frame).and_then(|b| Self::append(s, b, self.frames, self.bytes));
            if let Err(e) = result {
                Self::fail(s, e)
            }
        }
    }
    fn observe(&mut self, views: Vec<QueueView>) -> Result<(), Error> {
        for i in 0..self.previous.len() {
            if views.iter().any(|v| v.serial == self.previous[i].serial) {
                continue;
            }
            let old = &self.previous[i];
            let Response::Monitor(m) = Response::decode(&old.frame)? else {
                return Err(Error::Malformed);
            };
            let peer = old.peer;
            let down = encode(Response::Monitor(Monitor {
                status: -1,
                pending_messages: 0,
                pending_bytes: 0,
                ..m
            }))?;
            self.broadcast(peer, &down);
        }
        for view in &views {
            if self
                .previous
                .iter()
                .any(|p| p.serial == view.serial && p.frame == view.frame)
            {
                continue;
            }
            self.broadcast(view.peer, &view.frame);
        }
        self.previous = views;
        Ok(())
    }
    fn fail_all(&mut self, error: Error) {
        for s in &mut self.subscribers {
            Self::fail(s, error)
        }
    }
    fn admit(
        &mut self,
        client: ClientId,
        selector: PeerId,
        continuous: bool,
        source: Option<dv_bridge::Source>,
        frames: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let mut fresh = Subscriber {
            client: client.clone(),
            selector,
            continuous,
            source,
            pending: VecDeque::new(),
            bytes: 0,
            failed: None,
        };
        for f in frames {
            Self::append(&mut fresh, f, self.frames, self.bytes)?;
        }
        if let Some(i) = self.subscribers.iter().position(|s| s.client == client) {
            let old = &mut self.subscribers[i];
            if old.continuous || old.failed.is_some() {
                return Err(Error::Conflict);
            }
            let combined = old.bytes.checked_add(fresh.bytes).ok_or(Error::Overflow)?;
            if old
                .pending
                .len()
                .checked_add(fresh.pending.len())
                .is_none_or(|n| n > self.frames)
                || combined > self.bytes
            {
                return Err(Error::Capacity);
            }
            old.pending
                .try_reserve(fresh.pending.len())
                .map_err(|_| Error::Capacity)?;
            old.pending.append(&mut fresh.pending);
            old.bytes = combined;
            old.continuous = continuous;
            old.selector = selector;
            if old.source.is_none() {
                old.source = fresh.source;
            }
            return Ok(());
        }
        if self.subscribers.len() == self.clients {
            return Err(Error::Capacity);
        }
        self.subscribers.push(fresh);
        Ok(())
    }
    pub(super) fn output(&mut self) -> Option<Output> {
        let count = self.subscribers.len();
        for n in 0..count {
            let i = (self.cursor + n) % count;
            let s = &mut self.subscribers[i];
            if s.failed.is_some() {
                continue;
            }
            if let Some(bytes) = s.pending.pop_front() {
                s.bytes -= bytes.len();
                let client = s.client.clone();
                self.cursor = (i + 1) % count;
                return Some(Output::Frame { client, bytes });
            }
        }
        None
    }
    pub(super) fn retire_source(&mut self, source: &dv_bridge::Source) {
        for s in &mut self.subscribers {
            if s.source.as_ref() == Some(source) {
                Self::fail(s, Error::StaleGeneration)
            }
        }
    }
    pub(super) fn close(&mut self, id: &ClientId) {
        self.subscribers.retain(|s| s.client != *id);
    }
}
impl Engine {
    /// Bound for actual host projection, not a count of available routes.
    pub fn monitor_link_limit(&self) -> usize {
        self.limits.peers
    }
    fn monitor_views(&self) -> Result<Vec<QueueView>, Error> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(self.routes.len())
            .map_err(|_| Error::Capacity)?;
        let mut retained = 0usize;
        for q in &self.routes {
            let pending = self
                .attempts
                .iter()
                .filter(|a| a.route == q.serial && !a.retired)
                .try_fold((0u32, 0u32), |(n, b), a| {
                    Ok::<_, Error>((
                        n.checked_add(1).ok_or(Error::Overflow)?,
                        b.checked_add(u32::try_from(a.bytes).map_err(|_| Error::Overflow)?)
                            .ok_or(Error::Overflow)?,
                    ))
                })?;
            let frame = encode(Response::Monitor(Monitor {
                network: q.description.network,
                peer: q.description.peer.0,
                last_validation: q.monitor_last_validation,
                valid_until: q.monitor_valid_until,
                next_validation: q.monitor_next_validation,
                rtt: q.monitor_rtt.unwrap_or(u64::MAX),
                status: q.description.status as i32,
                pending_messages: pending.0,
                pending_bytes: pending.1,
                address: &q.address,
            }))?;
            retained = retained.checked_add(frame.len()).ok_or(Error::Overflow)?;
            if retained > self.monitor.bytes {
                return Err(Error::Capacity);
            }
            result.push(QueueView {
                serial: q.serial,
                peer: q.description.peer,
                frame,
            });
        }
        Ok(result)
    }
    pub(super) fn refresh_monitors(&mut self) {
        if !self.monitor.dirty {
            return;
        }
        self.monitor.dirty = false;
        if self
            .monitor
            .subscribers
            .iter()
            .all(|s| !s.continuous || s.failed.is_some())
        {
            self.monitor.previous.clear();
            return;
        }
        let result = self.monitor_views().and_then(|v| self.monitor.observe(v));
        if let Err(e) = result {
            self.monitor.fail_all(e)
        }
    }
    /// Take a real original observation refusal; the host physically closes
    /// this exact source and reports the original cause, without a private gap.
    pub fn take_monitor_retirement(&mut self) -> Option<Retirement> {
        let i = self
            .monitor
            .subscribers
            .iter()
            .position(|s| s.failed.is_some())?;
        let s = self.monitor.subscribers.remove(i);
        Some(Retirement {
            client: s.client,
            reason: s.failed?,
        })
    }
    pub(super) fn monitor_start(
        &mut self,
        id: &ClientId,
        request: Request,
    ) -> Result<ReceiveOutcome, Error> {
        let Request::Monitor { one_shot, peer } = request else {
            return Err(Error::Unsupported);
        };
        let i = self.client(id)?;
        if self.clients[i].role != Role::Unregistered {
            return Err(Error::PermissionDenied);
        }
        self.refresh_monitors();
        let views = self.monitor_views()?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(views.len() + usize::from(one_shot))
            .map_err(|_| Error::Capacity)?;
        for v in &views {
            if selected(PeerId(peer), v.peer) {
                frames.push(copy(&v.frame)?);
            }
        }
        if one_shot {
            frames.push(encode(Response::MonitorEnd)?);
        }
        self.monitor
            .admit(id.clone(), PeerId(peer), !one_shot, None, frames)?;
        self.monitor.previous = views;
        self.clients[i].role = Role::Monitor;
        Ok(ReceiveOutcome::Accepted)
    }
    /// Preflight original caller/role/clock/framing before any host observation.
    pub fn check_link_request(
        &self,
        id: &ClientId,
        input: &[u8],
        times: Times,
        signer: &impl Signer,
    ) -> Result<PeerId, Error> {
        self.validate_times(times)?;
        if signer.identity() != self.identity {
            return Err(Error::Authentication);
        }
        let i = self.client(id)?;
        if self.clients[i].role != Role::Unregistered {
            return Err(Error::PermissionDenied);
        }
        match Request::decode(input)? {
            Request::Links { peer, .. } => Ok(PeerId(peer)),
            _ => Err(Error::Unsupported),
        }
    }
    /// Enumerate a finite read-only projection from the original current Actor.
    /// Supplying these observations changes no peer/route/CORE authority.
    pub fn receive_links_at(
        &mut self,
        id: &ClientId,
        input: &[u8],
        times: Times,
        signer: &impl Signer,
        links: Links,
    ) -> Result<ReceiveOutcome, Error> {
        self.check_link_request(id, input, times, signer)?;
        let Request::Links {
            include_unconfirmed,
            peer,
        } = Request::decode(input)?
        else {
            return Err(Error::Unsupported);
        };
        if links.source.as_ref() != self.dv_current_source()
            || (!self.dv_source_accepting() && links.source.is_some())
        {
            return Err(Error::StaleGeneration);
        }
        if links.rows.len() > self.limits.peers {
            return Err(Error::Capacity);
        }
        self.time_at(times)?;
        let mut frames = Vec::new();
        let mut retained = 0usize;
        let capacity = self
            .peers
            .len()
            .checked_add(links.rows.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        frames
            .try_reserve_exact(capacity.min(self.monitor.frames))
            .map_err(|_| Error::Capacity)?;
        for p in &self.peers {
            if !selected(PeerId(peer), p.id) {
                continue;
            }
            let direct = self
                .routes
                .iter()
                .any(|q| q.description.peer == p.id && q.valid_until > self.last_monotonic);
            if !direct && links.rows.iter().any(|r| r.target == p.id) {
                continue;
            }
            if self.routes.iter().all(|q| q.description.peer != p.id) {
                continue;
            }
            if !include_unconfirmed && !direct {
                continue;
            }
            self.prepare_observation(
                &mut frames,
                &mut retained,
                self.link_frame(p.id, p.id, direct, 0, 0)?,
            )?;
        }
        for (i, r) in links.rows.iter().enumerate() {
            if !selected(PeerId(peer), r.target)
                || (!include_unconfirmed && !r.confirmed)
                || links.rows[..i].iter().any(|old| old.target == r.target)
            {
                continue;
            }
            if self
                .routes
                .iter()
                .any(|q| q.description.peer == r.target && q.valid_until > self.last_monotonic)
            {
                continue;
            }
            if self
                .routes
                .iter()
                .all(|q| q.description.peer != r.first_hop || q.valid_until <= self.last_monotonic)
            {
                continue;
            }
            self.prepare_observation(
                &mut frames,
                &mut retained,
                self.link_frame(r.target, r.first_hop, r.confirmed, 1, r.distance)?,
            )?;
        }
        // The END is constructed only after the original actual selection was
        // completely prepared. No queue admission is called a whole write.
        self.prepare_observation(&mut frames, &mut retained, encode(Response::LinksEnd)?)?;
        self.monitor
            .admit(id.clone(), PeerId(peer), false, links.source, frames)?;
        Ok(ReceiveOutcome::Accepted)
    }
    fn prepare_observation(
        &self,
        frames: &mut Vec<Vec<u8>>,
        retained: &mut usize,
        frame: Vec<u8>,
    ) -> Result<(), Error> {
        let total = retained.checked_add(frame.len()).ok_or(Error::Overflow)?;
        if frames.len() >= self.monitor.frames || total > self.monitor.bytes {
            return Err(Error::Capacity);
        }
        frames.try_reserve(1).map_err(|_| Error::Capacity)?;
        frames.push(frame);
        *retained = total;
        Ok(())
    }
    fn link_frame(
        &self,
        target: PeerId,
        hop: PeerId,
        confirmed: bool,
        route: u32,
        distance: u32,
    ) -> Result<Vec<u8>, Error> {
        let p = self.peers.iter().find(|p| p.id == target);
        let mut names = Vec::new();
        let mut prefixes: Vec<&[u8]> = Vec::new();
        let mut queues = 0u32;
        for q in self.routes.iter().filter(|q| q.description.peer == hop) {
            queues = queues.checked_add(1).ok_or(Error::Overflow)?;
            if let Some(prefix) = self
                .clients
                .iter()
                .find(|c| c.id == q.owner)
                .and_then(|c| c.prefix.as_deref())
            {
                if prefix.is_empty() || prefixes.contains(&prefix) {
                    continue;
                }
                let size = names
                    .len()
                    .checked_add(prefix.len())
                    .and_then(|n| n.checked_add(usize::from(!names.is_empty())))
                    .ok_or(Error::Overflow)?;
                if size > self.limits.control_bytes {
                    return Err(Error::Capacity);
                }
                if size > u16::MAX as usize - wire::LINK_BYTES - 1 {
                    return Err(Error::TooLarge);
                }
                names
                    .try_reserve(size - names.len())
                    .map_err(|_| Error::Capacity)?;
                prefixes.try_reserve(1).map_err(|_| Error::Capacity)?;
                if !names.is_empty() {
                    names.push(b',')
                }
                names.extend_from_slice(prefix);
                prefixes.push(prefix);
            }
        }
        let held = p.map_or(0, |p| p.inbound_used.saturating_sub(p.inbound_released));
        let loss = p.map_or(0, |p| {
            i128::from(p.loss_anchor_sent) - i128::from(p.inbound_used)
        });
        encode(Response::Link(wire::Link {
            target: target.0,
            confirmed,
            route,
            distance,
            queues,
            core_receive_window: p.map_or(Ok(0), |p| {
                i32::try_from(p.core_window).map_err(|_| Error::Overflow)
            })?,
            stalled: p.map_or(Ok(0), |p| {
                u32::try_from(
                    p.received
                        .iter()
                        .filter(|r| p.core_window <= 0 && !r.capacity_users.is_empty())
                        .count(),
                )
                .map_err(|_| Error::Overflow)
            })?,
            pending: u32::try_from(
                self.jobs
                    .iter()
                    .filter(|j| j.peer == target && !j.control)
                    .count(),
            )
            .map_err(|_| Error::Overflow)?,
            flow_retransmissions: 0,
            available_window: p.map_or(0, |_| p2p::DEFAULT_WINDOW),
            incoming_ram: held,
            incoming_window: p.map_or(0, |p| p.monitor_incoming_window),
            incoming_used: p.map_or(0, |p| p.inbound_used),
            incoming_loss: i64::try_from(loss).map_err(|_| Error::Overflow)?,
            outbound_window: p.map_or(0, |p| p.outbound_window),
            outbound_used: p.map_or(0, |p| p.outbound_used),
            flow_rtt: u64::MAX,
            other_rtt: p.map_or(u64::MAX, |p| p.remote_burst_rtt),
            last_flow_transmission: p.map_or(0, |p| p.monitor_last_flow),
            communicators: &names,
        }))
    }
}
