//! Direct, non-anonymous FS block transfer over an explicitly supplied CADET MQ.
//!
//! Each bounded route owns one original channel. Channels are not reused across
//! query generations: the official reply has no request ID with which to reject
//! an old same-key reply on a later owner. No anonymous/discovery backend, FS
//! negative/END, hidden task or application replay is synthesized here.
use super::{
    LocalDeliveryMetadata, PeerProgress, PeerRouter, PeerShutdown, ProviderFailure, RouteAdmission,
};
use gnunet_cadet_host::{Channel, Client, Error, Loss, LossCause, Received, Step, Transmit};
use gnunet_crypto::hash512;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{
    AbsoluteTime, Frames,
    fs::{BlockType, SEARCH_LOOPBACK_ONLY, Search},
    fs_cadet::{PORT_LABEL, QUERY_BYTES, Query, Reply},
};
use std::{
    future::Future,
    ops::Range,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Explicit local route bounds. CADET's own supplied native limits bound each
/// packet and all original channel slots; no whole-file buffer is allocated.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneous live or retiring original route/channel owners.
    pub routes: usize,
    /// Original source-clock and native time from admission through a matching
    /// positive block. Cancellation retains this native bound for actual IO
    /// debt; expiry is local termination, never proof of remote absence.
    pub timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            routes: 128,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Latest actual physical retirement, independent of any later retry/new route.
/// Only the latest report is retained; the counter in Report records all losses.
#[derive(Debug)]
pub struct Retirement<'id> {
    /// Original MQ epoch and actual pending-write exposure facts.
    pub report: Loss<'id>,
    /// Actual native/protocol cause, never a remote FS negative.
    pub cause: LossCause,
}
/// Bounded cumulative local observations, not peer receipt/completion evidence.
#[derive(Default)]
pub struct Report<'id> {
    /// Actual physical MQ retirement count.
    pub losses: u64,
    /// Actual endpoint connection retry count.
    pub connection_retries: u64,
    /// Actual source configuration-unavailable count.
    pub unavailable: u64,
    /// Number of local query deadlines reached.
    pub timeouts: u64,
    /// Active queries ended by their original native hard bound, independently
    /// of a stalled or regressed source clock. Included in `timeouts`.
    pub hard_timeouts: u64,
    /// Actual requested MQ retirements after original native bounds elapsed
    /// with physical channel/write/receive debt still outstanding.
    pub hard_retirements: u64,
    /// Latest actual physical retirement and its original cause.
    pub last_retirement: Option<Retirement<'id>>,
}

struct Packet<'id> {
    original: Received<'id>,
    /// One matching complete inner frame within original.messages().
    candidate: Option<Range<usize>>,
    /// False only while a matching original result awaits consumer capacity.
    processed: bool,
    /// An actual source loss retires its receipt, but not already observed data.
    needs_ack: bool,
}
struct Route<'id> {
    serial: u64,
    peer: [u8; 32],
    query: [u8; 64],
    block_type: BlockType,
    channel: Option<Channel<'id>>,
    query_write: Option<Transmit<'id>>,
    metadata: Option<LocalDeliveryMetadata>,
    packet: Option<Packet<'id>>,
    destroy: Option<Transmit<'id>>,
    deadline: Option<Deadline>,
    // Captured before the fallible source-clock deadline registration. Neither
    // logical clock changes, end nor cancellation can renew this native bound.
    hard: Instant,
    active: bool,
    end_pending: bool,
}
impl Route<'_> {
    fn positive(&self) -> bool {
        self.active
            && self
                .packet
                .as_ref()
                .is_some_and(|packet| packet.candidate.is_some())
    }
    fn native_debt(&self) -> bool {
        self.channel.is_some()
            || self.query_write.is_some()
            || self.destroy.is_some()
            || self.packet.as_ref().is_some_and(|packet| packet.needs_ack)
    }
    fn needs_hard_bound(&self) -> bool {
        if self.active {
            // Observed positives wait for consumer capacity, not a renewed
            // business deadline. Another route can still retire their source.
            !self.positive()
        } else {
            self.native_debt()
        }
    }
    fn end(&mut self, notify: bool) {
        self.active = false;
        self.end_pending = notify;
        self.deadline = None;
        if let Some(packet) = &mut self.packet {
            packet.candidate = None;
            packet.processed = true;
        }
    }
    fn channel_retired(&mut self) {
        self.channel = None;
        self.query_write = None;
        self.destroy = None;
        self.deadline = None;
        if self.active
            && let Some(packet) = &mut self.packet
            && packet.candidate.is_some()
        {
            // Preserve an actual positive observed before EOF/destruction while
            // its consumer was blocked. The old processing token is now stale.
            packet.needs_ack = false;
        } else {
            self.end(self.active || self.end_pending);
            self.packet = None;
        }
    }
}

/// Caller-driven direct CADET PeerRouter. At most Limits.routes original packet
/// buffers are retained, each bounded by the native Client's frame_bytes. A
/// matching result remains original raw application bytes until handed off.
pub struct Router<'id, 'slots> {
    client: Client<'id, 'slots>,
    clock: Arc<dyn RuntimeClock>,
    port: [u8; 64],
    limits: Limits,
    routes: Vec<Route<'id>>,
    last_route: u64,
    cursor: usize,
    native: Option<Pin<Box<Sleep>>>,
    // The sole actual native frame keeps its originating route's hard even if
    // a service ChannelDestroy has already retired that route's channel token.
    pending_write: Option<(Transmit<'id>, Instant)>,
    stopping: bool,
    closed: bool,
    report: Report<'id>,
}
impl<'id, 'slots> Router<'id, 'slots> {
    /// Retain the independently constructed native owner and its exact source
    /// clock. The native Client owns empty listening slots and enough channel
    /// slots for the configured route policy; this adapter opens no port.
    /// No native socket or application send is started by this constructor.
    pub fn new(client: Client<'id, 'slots>, limits: Limits) -> Result<Self, Error> {
        let timeout_us =
            u64::try_from(limits.timeout.as_micros()).map_err(|_| ProtocolError::InvalidInput)?;
        if limits.routes == 0
            || timeout_us == 0
            || timeout_us == u64::MAX
            || Instant::now().checked_add(limits.timeout).is_none()
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(limits.routes)
            .map_err(|_| ProtocolError::Capacity)?;
        let clock = client.clock();
        Ok(Self {
            client,
            clock,
            port: hash512(PORT_LABEL),
            limits,
            routes,
            last_route: 0,
            cursor: 0,
            native: None,
            pending_write: None,
            stopping: false,
            closed: false,
            report: Report::default(),
        })
    }
    /// Original source clock, shared without reserving another subscription.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Original matching peer replies currently held for consumer capacity.
    /// Reading this count performs no IO and grants no application credit.
    #[must_use]
    pub fn retained_results(&self) -> usize {
        self.routes
            .iter()
            .filter(|route| {
                route.active
                    && route
                        .packet
                        .as_ref()
                        .is_some_and(|packet| packet.candidate.is_some())
            })
            .count()
    }
    /// Cumulative local observations and the latest actual physical cause.
    #[must_use]
    pub const fn report(&self) -> &Report<'id> {
        &self.report
    }
    /// Access the explicit native owner for deliberate port-error recovery.
    /// Do not create/send channels outside this router's original route owners.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        self.client.recover_ports()
    }
    fn admit(&mut self, serial: u64, search: Search<'_>) -> Result<RouteAdmission, Error> {
        if self.closed || self.stopping {
            return Ok(RouteAdmission::Idle);
        }
        if search.anonymity != 0
            || search.target == [0; 32]
            || search.options & SEARCH_LOOPBACK_ONLY != 0
            || !matches!(search.block_type, BlockType::DBLOCK | BlockType::IBLOCK)
        {
            return Ok(RouteAdmission::Idle);
        }
        search.validate()?;
        if serial <= self.last_route {
            return Err(ProtocolError::StaleGeneration.into());
        }
        // A capacity refusal creates no child effect, but still consumes this
        // caller-selected serial. It must never be reused for a later intent.
        self.last_route = serial;
        if self.routes.len() == self.limits.routes {
            return Ok(RouteAdmission::Idle);
        }
        let hard = Instant::now()
            .checked_add(self.limits.timeout)
            .ok_or(ProtocolError::Overflow)?;
        // Reserve the exact source-domain deadline before publishing ownership.
        // All subsequent inputs are fixed-size copies; admission cannot become
        // partial because of a later allocation or caller-storage borrow.
        let deadline = Deadline::after(self.clock.clone(), self.limits.timeout)?;
        if Instant::now() >= hard {
            return Err(ProtocolError::Deadline.into());
        }
        self.routes.push(Route {
            serial,
            peer: search.target,
            query: search.query,
            block_type: search.block_type,
            channel: None,
            query_write: None,
            metadata: None,
            packet: None,
            destroy: None,
            deadline: Some(deadline),
            hard,
            active: true,
            end_pending: false,
        });
        Ok(RouteAdmission::Queued)
    }
    fn retire_epoch(&mut self, report: Loss<'id>, cause: LossCause) {
        // An MQ loss ends every already admitted route, including unsent ones.
        // Preserve actual positive input already retained before the loss; a
        // later retry of other routes needs a fresh route and original channel.
        for route in &mut self.routes {
            route.channel_retired();
        }
        self.pending_write = None;
        self.report.losses = self.report.losses.saturating_add(1);
        self.report.last_retirement = Some(Retirement { report, cause });
    }
    fn written(&mut self, transmit: Transmit<'id>) -> Result<(), Error> {
        if self
            .pending_write
            .is_some_and(|(original, _)| original == transmit)
        {
            self.pending_write = None;
        }
        if let Some(route) = self
            .routes
            .iter_mut()
            .find(|route| route.query_write == Some(transmit))
        {
            // Only a complete original LOCAL_DATA write counts as this local
            // query transmission. Credit/partial progress/admission do not.
            let now = self.clock.sample()?.now.as_micros();
            route.query_write = None;
            if route.active {
                route.metadata = Some(LocalDeliveryMetadata {
                    last_transmission: AbsoluteTime::from_micros(now),
                    num_transmissions: 1,
                    // This direct query protocol offers no FS respect.
                    respect_offered: 0,
                });
            }
        } else if let Some(route) = self
            .routes
            .iter_mut()
            .find(|route| route.destroy == Some(transmit))
        {
            route.destroy = None;
            route.channel = None;
            route.packet = None;
        }
        Ok(())
    }
    fn data(&mut self, original: Received<'id>, cx: &mut Context<'_>) -> Result<(), Error> {
        let channel = original.channel();
        let index = self
            .routes
            .iter()
            .position(|route| route.channel == Some(channel))
            .ok_or(ProtocolError::StaleGeneration)?;
        let info = self.client.channel_info(channel)?;
        let route = &mut self.routes[index];
        if info.peer != route.peer || info.port != self.port || route.packet.is_some() {
            return Err(ProtocolError::Conflict.into());
        }
        let mut candidate = None;
        let mut offset = 0_usize;
        let mut invalid = false;
        for frame in Frames::new(original.messages()) {
            let frame = frame?;
            let end = offset
                .checked_add(frame.encoded_len())
                .ok_or(ProtocolError::Overflow)?;
            let reply = match Reply::decode(&original.messages()[offset..end]) {
                Ok(reply) => reply,
                Err(_) => {
                    invalid = true;
                    break;
                }
            };
            if route.active
                && route.metadata.is_some()
                && reply.block_type == route.block_type
                && hash512(reply.block) == route.query
                && candidate.is_none()
            {
                candidate = Some(offset..end);
            }
            offset = end;
        }
        if invalid {
            route.end(true);
            candidate = None;
        } else if candidate.is_some() {
            // Parsing/hash and a fallible source clock may have crossed the
            // original bounds after IO began. A newly matched late input must
            // not acquire the exemption reserved for an already held positive.
            let expired = match &mut route.deadline {
                Some(deadline) => match Pin::new(deadline).poll(cx) {
                    Poll::Ready(result) => {
                        result?;
                        true
                    }
                    Poll::Pending => false,
                },
                None => false,
            };
            let hard_elapsed = Instant::now() >= route.hard;
            if expired || hard_elapsed {
                route.end(true);
                candidate = None;
                self.report.timeouts = self.report.timeouts.saturating_add(1);
                if hard_elapsed {
                    self.report.hard_timeouts = self.report.hard_timeouts.saturating_add(1);
                }
            } else {
                // Consumer backpressure cannot turn a genuinely held matching
                // positive into a later query timeout.
                route.deadline = None;
            }
        }
        route.packet = Some(Packet {
            original,
            processed: candidate.is_none(),
            candidate,
            needs_ack: true,
        });
        Ok(())
    }
    fn native_target(&self) -> Option<Instant> {
        self.routes
            .iter()
            .filter(|route| route.needs_hard_bound())
            .map(|route| route.hard)
            .chain(
                self.pending_write
                    .filter(|(transmit, _)| self.client.pending_transmit() == Some(*transmit))
                    .map(|(_, hard)| hard),
            )
            .min()
    }
    fn expire_native(&mut self) -> Result<bool, Error> {
        let now = Instant::now();
        if self.native_target().is_none_or(|hard| now < hard) {
            return Ok(false);
        }
        let mut changed = false;
        for route in &mut self.routes {
            if route.active && !route.positive() && now >= route.hard {
                route.end(true);
                self.report.timeouts = self.report.timeouts.saturating_add(1);
                self.report.hard_timeouts = self.report.hard_timeouts.saturating_add(1);
                changed = true;
            }
        }
        if self
            .routes
            .iter()
            .any(|route| !route.active && route.native_debt() && now >= route.hard)
            || self.pending_write.is_some_and(|(transmit, hard)| {
                self.client.pending_transmit() == Some(transmit) && now >= hard
            })
        {
            // Only real attached debt justifies physical retirement. Expired
            // intents with no native effect are ended above without inventing
            // an epoch, loss or failed network operation.
            if self.client.epoch().is_none() {
                return Err(ProtocolError::StaleGeneration.into());
            }
            let Step::Lost { report, cause, .. } = self.client.reconnect()? else {
                return Err(ProtocolError::StaleGeneration.into());
            };
            self.retire_epoch(report, cause);
            self.report.hard_retirements = self.report.hard_retirements.saturating_add(1);
            changed = true;
        }
        Ok(changed)
    }
    fn poll_native_timer(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let Some(target) = self.native_target() else {
            self.native = None;
            return Ok(false);
        };
        let timer = self
            .native
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        if timer.deadline() != target {
            timer.as_mut().reset(target);
        }
        if timer.as_mut().poll(cx).is_ready() {
            let changed = self.expire_native()?;
            // Source retirement removes old debt. An expired original bound
            // with no remaining debt must not keep a ready Sleep in a hot loop.
            if self.native_target().is_none() {
                self.native = None;
            }
            Ok(changed)
        } else {
            Ok(false)
        }
    }
    fn deadlines(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let mut changed = false;
        for route in &mut self.routes {
            if let Some(deadline) = &mut route.deadline
                && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
            {
                result?;
                route.end(true);
                self.report.timeouts = self.report.timeouts.saturating_add(1);
                changed = true;
            }
        }
        Ok(changed)
    }
    fn reclaim(&mut self) {
        for route in &mut self.routes {
            if route
                .packet
                .as_ref()
                .is_some_and(|packet| packet.processed && !packet.needs_ack)
            {
                // An actual source retirement already invalidated this receipt;
                // release it without waiting for another MQ attachment or ACK.
                route.packet = None;
            }
        }
        self.routes.retain(|route| {
            route.active
                || route.end_pending
                || route.channel.is_some()
                || route.query_write.is_some()
                || route.destroy.is_some()
                || route.packet.is_some()
        });
        self.cursor %= self.routes.len().max(1);
    }
    fn result(&mut self) -> Result<Option<PeerProgress>, Error> {
        for route in &mut self.routes {
            if !route.active {
                continue;
            }
            let Some(packet) = &mut route.packet else {
                continue;
            };
            let Some(range) = packet.candidate.clone() else {
                continue;
            };
            let metadata = route.metadata.ok_or(ProtocolError::NotReady)?;
            // The only payload copy is the exact inner application frame sent
            // to its one still-live local owner. The original native packet is
            // retained until its receive_done is admitted below.
            let frame = OwnedFrame::copy_from(&packet.original.messages()[range])?;
            let serial = route.serial;
            route.end(true);
            return Ok(Some(PeerProgress::CadetReply {
                route: serial,
                frame,
                metadata,
            }));
        }
        Ok(None)
    }
    /// Try one bounded local native effect, prioritizing receive cleanup over
    /// new queries. Each successful call admits one original immutable frame.
    fn advance(&mut self) -> Result<bool, Error> {
        if self.client.pending_transmit().is_some()
            || self.client.epoch().is_none()
            || self
                .native_target()
                .is_some_and(|hard| Instant::now() >= hard)
        {
            return Ok(false);
        }
        for offset in 0..self.routes.len() {
            let index = (self.cursor + offset) % self.routes.len();
            let route = &mut self.routes[index];
            if let Some(packet) = &route.packet
                && packet.processed
            {
                if packet.needs_ack {
                    let transmit = self.client.receive_done(packet.original.delivery())?;
                    self.pending_write = Some((transmit, route.hard));
                }
                route.packet = None;
                self.cursor = (index + 1) % self.routes.len();
                return Ok(true);
            }
        }
        for offset in 0..self.routes.len() {
            let index = (self.cursor + offset) % self.routes.len();
            let route = &mut self.routes[index];
            if !route.active {
                if let Some(channel) = route.channel
                    && route.destroy.is_none()
                {
                    let transmit = self.client.destroy(channel)?;
                    route.destroy = Some(transmit);
                    self.pending_write = Some((transmit, route.hard));
                    self.cursor = (index + 1) % self.routes.len();
                    return Ok(true);
                }
                continue;
            }
            if route
                .packet
                .as_ref()
                .is_some_and(|packet| packet.candidate.is_some())
            {
                continue;
            }
            if route.channel.is_none() {
                match self.client.open(route.peer, self.port) {
                    Ok(channel) => {
                        route.channel = Some(channel);
                        let transmit = self
                            .client
                            .pending_transmit()
                            .ok_or(ProtocolError::StaleGeneration)?;
                        self.pending_write = Some((transmit, route.hard));
                    }
                    Err(Error::Protocol(ProtocolError::Capacity)) => route.end(true),
                    Err(error) => return Err(error),
                }
                self.cursor = (index + 1) % self.routes.len();
                return Ok(true);
            }
            if route.query_write.is_some() || route.metadata.is_some() {
                continue;
            }
            let channel = route.channel.ok_or(ProtocolError::NotReady)?;
            let info = self.client.channel_info(channel)?;
            if info.send_credit == 0 || info.closing {
                continue;
            }
            let mut message = [0; QUERY_BYTES];
            Query {
                block_type: route.block_type,
                query: &route.query,
            }
            .encode(&mut message)?;
            // GOODPUT(128), CORK_ALLOWED(64), OUT_OF_ORDER(256), as official FS
            // application requests. These are preferences, not completion.
            let transmit = self.client.send(channel, 128 | 64 | 256, &message)?;
            route.query_write = Some(transmit);
            self.pending_write = Some((transmit, route.hard));
            self.cursor = (index + 1) % self.routes.len();
            return Ok(true);
        }
        Ok(false)
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, Error>> {
        if self.closed {
            return Poll::Pending;
        }
        let mut timed_out = self.expire_native()?;
        timed_out |= self.deadlines(cx)?;
        timed_out |= self.expire_native()?;
        timed_out |= self.poll_native_timer(cx)?;
        if deliver && let Some(result) = self.result()? {
            return Poll::Ready(Ok(result));
        }
        if let Some(route) = self.routes.iter_mut().find(|route| route.end_pending) {
            route.end_pending = false;
            return Poll::Ready(Ok(PeerProgress::Ended(route.serial)));
        }
        self.reclaim();
        if self.stopping && self.routes.is_empty() && self.client.pending_transmit().is_none() {
            // Reclaim itself can establish real quiescence without a new native
            // socket event; return progress so the Server observes that fact.
            return Poll::Ready(Ok(PeerProgress::Activity));
        }
        let admitted = self.advance()?;
        let hard = self.native_target();
        let mut hard_elapsed = false;
        let progress = self.client.poll_guarded(cx, hard, &mut || {
            if hard.is_some_and(|hard| Instant::now() >= hard) {
                hard_elapsed = true;
                Err(ProtocolError::Deadline.into())
            } else {
                Ok(())
            }
        });
        if hard_elapsed {
            // This is our own IO fence, not a provider fault to propagate to a
            // containing Pair. Actual reconnect preserves the original loss.
            self.expire_native()?;
            self.poll_native_timer(cx)?;
            return Poll::Ready(Ok(PeerProgress::Activity));
        }
        match progress {
            Poll::Pending if admitted || timed_out => Poll::Ready(Ok(PeerProgress::Activity)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(step)) => {
                match step {
                    Step::Written(written) => self.written(written.transmit)?,
                    Step::Data(original) => self.data(original, cx)?,
                    Step::Destroyed(channel) => {
                        if let Some(route) = self
                            .routes
                            .iter_mut()
                            .find(|route| route.channel == Some(channel))
                        {
                            route.channel_retired();
                        }
                    }
                    Step::Lost { report, cause, .. } => self.retire_epoch(report, cause),
                    Step::ConnectRetry { .. } => {
                        self.report.connection_retries =
                            self.report.connection_retries.saturating_add(1);
                    }
                    Step::Unavailable(error) => {
                        self.report.unavailable = self.report.unavailable.saturating_add(1);
                        return Poll::Ready(Err(error));
                    }
                    Step::Blocked { .. } => {
                        return if admitted || timed_out {
                            Poll::Ready(Ok(PeerProgress::Activity))
                        } else {
                            Poll::Pending
                        };
                    }
                    Step::Incoming { .. } => {
                        return Poll::Ready(Err(ProtocolError::Unsupported.into()));
                    }
                    Step::Closed => {
                        self.closed = true;
                        return Poll::Ready(Err(ProtocolError::Closed.into()));
                    }
                    Step::Connected(_)
                    | Step::Credit { .. }
                    | Step::RejectedIncoming { .. }
                    | Step::Ignored { .. }
                    | Step::Activity { .. } => {}
                    Step::WaitDeadline => {
                        self.expire_native()?;
                        self.poll_native_timer(cx)?;
                    }
                }
                self.expire_native()?;
                Poll::Ready(Ok(PeerProgress::Activity))
            }
        }
    }
}
impl PeerRouter for Router<'_, '_> {
    fn request_shutdown(&mut self) {
        if self.stopping || self.closed {
            return;
        }
        self.stopping = true;
        for route in &mut self.routes {
            route.end(true);
        }
    }
    fn shutdown_state(&self) -> PeerShutdown {
        if self.closed {
            PeerShutdown::Retired
        } else {
            // The original native owner has no bounded write/destroy grace
            // deadline. The containing Pair therefore physically retires it,
            // preserving Client.close's actual Loss/partial-write report. Do
            // not wait forever or label this retirement local quiescence.
            PeerShutdown::Immediate
        }
    }
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        _seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, ProviderFailure> {
        // D/I are terminal hash-identified results; UBLOCK seen filtering is not
        // reinterpreted as direct block discovery. No caller slice is retained.
        self.admit(route, search)
            .map_err(ProviderFailure::operation)
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, ProviderFailure>> {
        self.poll_inner(cx, deliver)
            .map_err(ProviderFailure::operation)
    }
    fn cancel(&mut self, serial: u64) -> Result<(), ProviderFailure> {
        if let Some(route) = self.routes.iter_mut().find(|route| route.serial == serial) {
            route.end(false);
        }
        Ok(())
    }
    fn close(&mut self) -> Result<(), ProviderFailure> {
        let retirement = self.client.close();
        self.stopping = true;
        self.closed = true;
        self.native = None;
        self.pending_write = None;
        match retirement {
            Ok(Some(report)) => self.retire_epoch(report, LossCause::Requested),
            Ok(None) => {}
            Err(error) => {
                self.routes.clear();
                return Err(ProviderFailure::operation(error));
            }
        }
        self.routes.clear();
        Ok(())
    }
}

/// Explicit foreground selection: absent backend behaves exactly as NoPeers.
impl PeerRouter for Option<Router<'_, '_>> {
    fn request_shutdown(&mut self) {
        if let Some(router) = self {
            router.request_shutdown();
        }
    }
    fn shutdown_state(&self) -> PeerShutdown {
        self.as_ref()
            .map_or(PeerShutdown::Quiesced, PeerRouter::shutdown_state)
    }
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, ProviderFailure> {
        match self {
            Some(router) => router.start(route, search, seen),
            None => Ok(RouteAdmission::Idle),
        }
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, ProviderFailure>> {
        match self {
            Some(router) => router.poll(cx, deliver),
            None => Poll::Pending,
        }
    }
    fn cancel(&mut self, route: u64) -> Result<(), ProviderFailure> {
        match self {
            Some(router) => router.cancel(route),
            None => Ok(()),
        }
    }
    fn close(&mut self) -> Result<(), ProviderFailure> {
        match self {
            Some(router) => router.close(),
            None => Ok(()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
