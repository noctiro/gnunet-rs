//! Shared core authority, coherent selection and callback return leases.
use crate::{
    BrokerError, ClockSample, Family, FamilyProfile, Limits, LiveConfiguration,
    Reply as PublicReply, RuntimeClock,
};
use gnunet_client::{
    resolver::MAX_HOSTNAME_LEN,
    resolver_handle::{
        Completion, Event as CoreEvent, Hostname, RequestId, ResolverHandle as Core,
    },
};
use gnunet_config::Configuration;
use gnunet_types::{AbsoluteTime, Duration, Error, GenerationalId};
use std::{
    collections::VecDeque,
    fmt,
    future::poll_fn,
    marker::PhantomData,
    net::IpAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context as TaskContext, Poll, Waker},
};
const ACTIVE: u8 = 0;
const DONE: u8 = 1;
const CANCELLED: u8 = 2;
const LOST: u8 = 3;
struct Identity;
/// An original-owner callback capability; never serialized in a resolver frame.
#[derive(Clone)]
pub struct Token {
    pub(crate) id: RequestId,
    identity: Arc<Identity>,
}
impl Token {
    /// Generation/index in this original broker, useful for local correlation only.
    #[must_use]
    pub fn resource_id(&self) -> GenerationalId {
        self.id.resource_id()
    }
}
impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.identity, &other.identity)
    }
}
impl Eq for Token {}
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("resource", &self.resource_id())
            .finish_non_exhaustive()
    }
}
pub(crate) struct Receipt {
    status: AtomicU8,
    waker: Mutex<Option<Waker>>,
}
impl Receipt {
    fn new() -> Self {
        Self {
            status: AtomicU8::new(ACTIVE),
            waker: Mutex::new(None),
        }
    }
    pub(crate) fn wake(&self) {
        if let Ok(mut slot) = self.waker.lock()
            && let Some(waker) = slot.take()
        {
            drop(slot);
            waker.wake();
        }
    }
}
pub(crate) struct Route {
    pub(crate) id: RequestId,
    pub(crate) receipt: Arc<Receipt>,
    pub(crate) inline: bool,
    pub(crate) auto_drain: bool,
    pub(crate) remote: bool,
}
pub(crate) enum Value {
    Address(IpAddr),
    Name(Vec<u8>),
    Numeric(IpAddr),
    Complete(Completion),
}
pub(crate) struct Envelope {
    pub(crate) bytes: Vec<u8>,
    pub(crate) len: usize,
    pub(crate) written: usize,
    pub(crate) request: RequestId,
}
pub(crate) struct Mq {
    pub(crate) free: Vec<Vec<u8>>,
    pub(crate) queue: VecDeque<Envelope>,
}
impl Mq {
    fn new(limits: Limits) -> Result<Self, Error> {
        limits
            .max_frame_bytes
            .checked_mul(limits.max_queued_frames)
            .ok_or(Error::Overflow)?;
        let mut free = Vec::new();
        free.try_reserve_exact(limits.max_queued_frames)
            .map_err(|_| Error::Capacity)?;
        for _ in 0..limits.max_queued_frames {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(limits.max_frame_bytes)
                .map_err(|_| Error::Capacity)?;
            bytes.resize(limits.max_frame_bytes, 0);
            free.push(bytes);
        }
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(limits.max_queued_frames)
            .map_err(|_| Error::Capacity)?;
        Ok(Self { free, queue })
    }
}
pub(crate) struct Pending {
    pub(crate) id: RequestId,
    pub(crate) serial: u64,
    pub(crate) value: Option<Value>,
    pub(crate) block_process: bool,
}
pub(crate) struct Credit {
    pub(crate) id: RequestId,
    pub(crate) pending_tx: bool,
}
pub(crate) struct State<const R: usize, const N: usize> {
    pub(crate) core: Core<R, N>,
    pub(crate) mq: Mq,
    pub(crate) pending_error: Option<Error>,
    pub(crate) credits: Vec<Credit>,
    pub(crate) selected: LiveConfiguration,
    pub(crate) routes: Vec<Route>,
    pub(crate) pending: Option<Pending>,
    pub(crate) scratch: Vec<u8>,
    pub(crate) driver_waker: Option<Waker>,
    pub(crate) alive: bool,
    pub(crate) serial: u64,
    pub(crate) last_now: AbsoluteTime,
}
impl<const R: usize, const N: usize> State<R, N> {
    pub(crate) fn reconcile_credits(&mut self) {
        let core = &self.core;
        self.credits
            .retain(|credit| credit.pending_tx || core.owns_request(credit.id));
    }
    pub(crate) fn clear_mq(&mut self) {
        while let Some(envelope) = self.mq.queue.pop_front() {
            self.mq.free.push(envelope.bytes);
        }
        for credit in &mut self.credits {
            credit.pending_tx = false;
        }
        self.reconcile_credits();
    }
    pub(crate) fn pump(&mut self, now: AbsoluteTime) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.block_process)
            || self.core.terminal_callbacks_pending()
        {
            return;
        }
        let Some(epoch) = self.core.connection_epoch() else {
            if let Err(error) = self.core.reconnect_inline(now) {
                self.pending_error = Some(error);
            }
            return;
        };
        let Some(mut bytes) = self.mq.free.pop() else {
            return;
        };
        match self.core.next_request_inline(epoch, &mut bytes) {
            Ok(frame) => {
                self.mq.queue.push_back(Envelope {
                    bytes,
                    len: frame.len,
                    written: 0,
                    request: frame.request,
                });
                if let Some(credit) = self
                    .credits
                    .iter_mut()
                    .find(|credit| credit.id == frame.request)
                {
                    credit.pending_tx = true;
                } else {
                    self.pending_error = Some(Error::Stale);
                }
            }
            Err(error) => {
                self.mq.free.push(bytes);
                if error != Error::WouldBlock {
                    self.pending_error = Some(error);
                }
            }
        }
    }
}

pub(crate) struct Shared<const R: usize, const N: usize> {
    pub(crate) state: Mutex<State<R, N>>,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    identity: Arc<Identity>,
    pub(crate) limits: Limits,
}
/// Cloning shares the actual process FIFO and MQ; connect never opens a socket.
pub struct Context<const R: usize, const N: usize> {
    pub(crate) shared: Arc<Shared<R, N>>,
}
impl<const R: usize, const N: usize> Clone for Context<R, N> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}
pub(crate) fn check_config(config: &Configuration) -> bool {
    crate::profile::check_config(config)
}
fn local(name: &[u8], family: Family) -> bool {
    name.eq_ignore_ascii_case(b"localhost")
        || name.eq_ignore_ascii_case(b"ip6-localnet")
        || std::str::from_utf8(name)
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .is_some_and(|a| family.accepts(a))
}
impl<const R: usize, const N: usize> Context<R, N> {
    pub(crate) fn build(
        selected: LiveConfiguration,
        limits: Limits,
        profile: FamilyProfile,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, BrokerError> {
        let configured = check_config(&selected.snapshot()?);
        let last_now = clock.sample()?.now;
        let mut routes = Vec::new();
        routes.try_reserve_exact(R).map_err(|_| Error::Capacity)?;
        let mut credits = Vec::new();
        credits
            .try_reserve_exact(limits.max_queued_frames)
            .map_err(|_| Error::Capacity)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.max_frame_bytes)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    core: Core::new(profile, configured)?,
                    mq: Mq::new(limits)?,
                    pending_error: None,
                    credits,
                    selected,
                    routes,
                    pending: None,
                    scratch,
                    driver_waker: None,
                    alive: true,
                    serial: 0,
                    last_now,
                }),
                clock,
                identity: Arc::new(Identity),
                limits,
            }),
        })
    }
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, State<R, N>>, BrokerError> {
        self.shared.state.lock().map_err(|_| BrokerError::Poisoned)
    }
    pub(crate) fn sample(&self) -> Result<ClockSample, BrokerError> {
        let sample = self.shared.clock.sample()?;
        self.lock()?.last_now = sample.now;
        Ok(sample)
    }
    fn token(&self, id: RequestId) -> Token {
        Token {
            id,
            identity: self.shared.identity.clone(),
        }
    }
    /// Select an owned configuration and reset resolver backoff to1ms. Existing
    /// MQ/attempt/Unix identity, FIFO/IDs and original deadlines remain untouched.
    /// No I/O or driver wake is performed by this PROGRAM read-point operation.
    pub fn connect(&self, configuration: Configuration) -> Result<(), BrokerError> {
        self.connect_live(LiveConfiguration::new(configuration))
    }
    /// Select a mutable caller-owned cfg identity. Existing MQs retain their old
    /// identity; mutations of either store do not implicitly wake or reconnect.
    pub fn connect_live(&self, configuration: LiveConfiguration) -> Result<(), BrokerError> {
        let configured = check_config(&configuration.snapshot()?);
        let mut state = self.lock()?;
        if !state.alive {
            return Err(BrokerError::OwnerLost);
        }
        state.selected = configuration;
        state.core.connect(configured);
        Ok(())
    }
    fn admit(
        &self,
        operation: impl FnOnce(&mut Core<R, N>, AbsoluteTime) -> Result<RequestId, Error>,
        needs_config: bool,
        remote: bool,
        inline: bool,
    ) -> Result<Query<R, N>, BrokerError> {
        let now = self.sample()?.now;
        let receipt = Arc::new(Receipt::new());
        let (id, waker) = {
            let mut state = self.lock()?;
            if !state.alive {
                return Err(BrokerError::OwnerLost);
            }
            state.reconcile_credits();
            let credit_limit = self.shared.limits.max_queued_frames - usize::from(!inline);
            if remote && state.credits.len() >= credit_limit {
                return Err(Error::Capacity.into());
            }
            let inline_live = state
                .routes
                .iter()
                .any(|route| route.inline && state.core.owns_request(route.id));
            let slot_limit = R - usize::from(!inline && !inline_live);
            if state.routes.len() >= R || state.core.pending_requests() >= slot_limit {
                return Err(Error::Capacity.into());
            }
            if needs_config {
                let configured = check_config(&state.selected.snapshot()?);
                state.core.update_configuration_admissibility(configured);
            }
            let id = operation(&mut state.core, now)?;
            if remote {
                state.credits.push(Credit {
                    id,
                    pending_tx: false,
                });
            }
            state.routes.push(Route {
                id,
                receipt: receipt.clone(),
                inline,
                auto_drain: false,
                remote,
            });
            if remote {
                state.pump(now);
            }
            (id, state.driver_waker.take())
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(Query {
            context: self.clone(),
            token: self.token(id),
            receipt,
            ended: false,
        })
    }
    /// Admit an official forward query synchronously. Timeout includes all queue,
    /// callback-return and reconnect delay. Numeric/loopback tasks bypass cfg check.
    pub fn ip_get(
        &self,
        name: &[u8],
        family: Family,
        timeout: Duration,
    ) -> Result<Query<R, N>, BrokerError> {
        if !local(name, family)
            && name.len().checked_add(17).ok_or(Error::Overflow)?
                > self.shared.limits.max_frame_bytes
        {
            return Err(Error::Capacity.into());
        }
        if name.len() > MAX_HOSTNAME_LEN {
            return Err(Error::TooLarge.into());
        }
        self.admit(
            |core, now| core.ip_get(name, family, timeout, now),
            !local(name, family),
            !local(name, family),
            false,
        )
    }
    pub(crate) fn client_query(
        &self,
        name: &[u8],
        timeout: Duration,
        inline: bool,
    ) -> Result<Query<R, N>, BrokerError> {
        self.client_query_family(name, timeout, inline, Family::Any)
    }
    pub(crate) fn client_query_family(
        &self,
        name: &[u8],
        timeout: Duration,
        inline: bool,
        family: Family,
    ) -> Result<Query<R, N>, BrokerError> {
        let local = local(name, family);
        if !local
            && name.len().checked_add(17).ok_or(Error::Overflow)?
                > self.shared.limits.max_frame_bytes
        {
            return Err(Error::Capacity.into());
        }
        self.admit(
            |core, now| core.ip_get(name, family, timeout, now),
            !local,
            !local,
            inline,
        )
    }
    /// Admit numeric or resolving reverse query. Native check_config applies even
    /// for numeric-only reverse; all names still come from official type5 replies.
    pub fn hostname_get(
        &self,
        address: IpAddr,
        resolve: bool,
        timeout: Duration,
    ) -> Result<Query<R, N>, BrokerError> {
        let size = if address.is_ipv4() { 20 } else { 32 };
        if resolve && size > self.shared.limits.max_frame_bytes {
            return Err(Error::Capacity.into());
        }
        self.admit(
            |core, now| core.hostname_get(address, resolve, timeout, now),
            true,
            resolve,
            false,
        )
    }
    /// Read only the actual native hostname and follow the ordinary shared forward
    /// path. This does not call native DNS, FQDN or change Resolver selection.
    pub fn hostname_resolve(
        &self,
        family: Family,
        timeout: Duration,
    ) -> Result<Query<R, N>, BrokerError> {
        let hostname = gnunet_native::hostname()?;
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt;
            hostname.as_bytes()
        };
        #[cfg(windows)]
        let bytes = hostname
            .to_str()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "hostname contains invalid Unicode",
                )
            })?
            .as_bytes();
        self.ip_get(bytes, family, timeout)
    }
    /// Cancel before the next callback. Sent requests retain the original drain
    /// tombstone; no cancel wire frame or terminal callback is manufactured.
    pub fn request_cancel(&self, token: &Token) -> Result<(), BrokerError> {
        self.cancel(token, false)
    }
    fn cancel(&self, token: &Token, abandon: bool) -> Result<(), BrokerError> {
        if !Arc::ptr_eq(&token.identity, &self.shared.identity) {
            return Err(Error::StaleGeneration.into());
        }
        // Explicit cleanup and Drop must not acquire a new clock capability.
        // Only ordinary request_cancel samples; cleanup uses this shared core's
        // last successful timestamp under the same lock as its state mutation.
        let ordinary_now = if abandon {
            None
        } else {
            Some(self.sample()?.now)
        };
        let (wake, receipt) = {
            let mut state = self.lock()?;
            let now = ordinary_now.unwrap_or(state.last_now);
            let route = state.routes.iter().position(|route| route.id == token.id);
            if !abandon && !state.core.callbacks_enabled(token.id) {
                return Err(Error::StaleGeneration.into());
            }
            if state.core.callbacks_enabled(token.id) {
                state.core.request_cancel(token.id, now)?;
            }
            let receipt = route.map(|index| state.routes.swap_remove(index).receipt);
            if let Some(receipt) = &receipt {
                receipt.status.store(CANCELLED, Ordering::Release);
            }
            if state
                .pending
                .as_ref()
                .is_some_and(|p| p.id == token.id && p.value.is_some())
                && let Some(pending) = state.pending.take()
                && let Some(Value::Name(mut bytes)) = pending.value
            {
                bytes.clear();
                state.scratch = bytes;
            }
            (state.driver_waker.take(), receipt)
        };
        if let Some(receipt) = receipt {
            receipt.wake();
        }
        if let Some(waker) = wake {
            waker.wake();
        }
        Ok(())
    }
    /// Count reserved core slots, including canceled transmitted drains.
    pub fn pending_requests(&self) -> Result<usize, BrokerError> {
        Ok(self.lock()?.core.pending_requests())
    }
    pub(crate) fn publish(&self, event: CoreEvent<'_>) -> Result<(), BrokerError> {
        let mut state = self.lock()?;
        state.reconcile_credits();
        if state.pending.is_some() {
            return Err(Error::WouldBlock.into());
        }
        let id = match event {
            CoreEvent::Address { request, .. }
            | CoreEvent::Hostname { request, .. }
            | CoreEvent::Complete { request, .. } => request,
        };
        let Some(route) = state.routes.iter().find(|route| route.id == id) else {
            return Ok(());
        };
        if route.auto_drain {
            if matches!(event, CoreEvent::Complete { .. }) {
                let receipt = route.receipt.clone();
                receipt.status.store(DONE, Ordering::Release);
                let remote = route.remote;
                state.routes.retain(|route| route.id != id);
                if remote {
                    let now = state.last_now;
                    state.pump(now);
                }
                drop(state);
                receipt.wake();
            }
            return Ok(());
        }
        let receipt = route.receipt.clone();
        let remote = route.remote;
        let next_serial = state.serial.wrapping_add(1);
        let value = match event {
            CoreEvent::Address { address, .. } => Value::Address(address),
            CoreEvent::Hostname {
                hostname: Hostname::Numeric(address),
                ..
            } => Value::Numeric(address),
            CoreEvent::Complete { reason, .. } => Value::Complete(reason),
            CoreEvent::Hostname {
                hostname: Hostname::Resolved(name),
                ..
            } => {
                if name.len() > state.scratch.capacity() {
                    return Err(Error::Capacity.into());
                }
                let mut bytes = std::mem::take(&mut state.scratch);
                bytes.clear();
                bytes.extend_from_slice(name);
                Value::Name(bytes)
            }
        };
        state.serial = next_serial;
        state.pending = Some(Pending {
            id,
            serial: state.serial,
            value: Some(value),
            block_process: remote && matches!(event, CoreEvent::Complete { .. }),
        });
        drop(state);
        receipt.wake();
        Ok(())
    }
    pub(crate) fn inline_pending(&self) -> Result<bool, BrokerError> {
        let state = self.lock()?;
        Ok(state.pending.as_ref().is_some_and(|pending| {
            state
                .routes
                .iter()
                .any(|route| route.id == pending.id && route.inline)
        }))
    }
    pub(crate) fn owner_lost(&self) {
        if let Ok(mut state) = self.lock() {
            state.alive = false;
            state.driver_waker = None;
            let routes = std::mem::take(&mut state.routes);
            let cleanup_now = state.last_now;
            for route in &routes {
                if state.core.callbacks_enabled(route.id) {
                    let _result = state.core.request_cancel(route.id, cleanup_now);
                }
                route.receipt.status.store(LOST, Ordering::Release);
            }
            let _result = state.core.disconnect();
            state.pending = None;
            drop(state);
            for route in routes {
                route.receipt.wake();
            }
        }
    }
}
/// One actual callback value. A complete event is distinct from canceled/closed
/// query iteration; no successful DNS END is inferred from channel closure.
#[derive(Clone, Copy, Debug)]
pub enum Reply<'a> {
    /// One native address value, without requested-family postfiltering.
    Address(IpAddr),
    /// One resolved raw C-string prefix or numeric reverse fallback.
    Hostname(Hostname<'a>),
    /// Actual core terminal callback and its local reason.
    Complete(Completion),
}
/// Unique callback subscription. Drop suppresses future callbacks and cancels
/// its original request; the one shared MQ is not replaced or privately closed.
pub struct Query<const R: usize, const N: usize> {
    context: Context<R, N>,
    token: Token,
    receipt: Arc<Receipt>,
    ended: bool,
}
impl<const R: usize, const N: usize> Query<R, N> {
    /// Clone the original owner capability for explicit callback-time cancellation.
    #[must_use]
    pub fn token(&self) -> Token {
        self.token.clone()
    }
    /// Cancel this subscription before a future callback. Completion tokens are stale.
    pub fn cancel(&mut self) -> Result<(), BrokerError> {
        self.context.request_cancel(&self.token)?;
        self.ended = true;
        Ok(())
    }
    /// Revoke only this original callback subscription without sampling time.
    /// The local receipt is permanently fenced even if shared cleanup fails;
    /// that original error is returned independently. The same foreground's
    /// Driver still owns any old wire/tombstone/partial IO debt, so this is not
    /// a remote cancellation, queue-drain or whole-source retirement receipt.
    /// An outstanding public Delivery borrows this Query and prevents this
    /// method from being called until that original lease is returned.
    pub fn cancel_clock_free(&mut self) -> Result<(), BrokerError> {
        self.receipt.status.store(CANCELLED, Ordering::Release);
        self.receipt.wake();
        self.ended = true;
        self.context.cancel(&self.token, true)
    }
    /// Await one callback return lease. Dropping only this waiting future leaves the
    /// original query and partial MQ I/O intact. Drop the returned lease before
    /// polling another callback; its borrow makes that sequencing compiler-checked.
    pub async fn next(&mut self) -> Result<Option<Delivery<'_, R, N>>, BrokerError> {
        let value = poll_fn(|cx| self.poll_value(cx)).await?;
        Ok(value.map(|(value, serial)| Delivery {
            context: self.context.clone(),
            token: self.token.clone(),
            receipt: self.receipt.clone(),
            value: Some(value),
            serial,
            _borrow: PhantomData,
        }))
    }
    pub(crate) fn poll_client_callback(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<ClientCallback<R, N>>, BrokerError>> {
        // This is only the internal CLIENT upcall. Do not dispatch unrelated
        // scheduler work, another query, or public Query/Delivery effects.
        let continuation = {
            let mut state = self.context.lock()?;
            if state.pending.is_none() && state.core.callback_continuation_is(self.token.id) {
                let now = state.last_now;
                state.core.next_event(now)
            } else {
                None
            }
        };
        if let Some(event) = continuation {
            self.context.publish(event)?;
        }
        match self.poll_value(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Ok(Some((value, serial)))) => Poll::Ready(Ok(Some(ClientCallback {
                context: self.context.clone(),
                token: self.token.clone(),
                receipt: self.receipt.clone(),
                serial,
                value: Some(value),
            }))),
        }
    }
    pub(crate) fn into_drain(mut self) -> Result<Drain<R, N>, BrokerError> {
        let mut state = self.context.lock()?;
        if !state.alive {
            return Err(BrokerError::OwnerLost);
        }
        if let Some(route) = state
            .routes
            .iter_mut()
            .find(|route| route.id == self.token.id)
        {
            route.auto_drain = true;
        }
        let mut returned_remote_terminal = false;
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == self.token.id)
            && let Some(pending) = state.pending.take()
        {
            returned_remote_terminal = pending.block_process;
            match pending.value {
                Some(Value::Name(mut bytes)) => {
                    bytes.clear();
                    state.scratch = bytes;
                }
                Some(Value::Complete(_)) => {
                    state.routes.retain(|route| route.id != self.token.id);
                    self.receipt.status.store(DONE, Ordering::Release);
                }
                _ => {}
            }
        }
        if returned_remote_terminal {
            let now = state.last_now;
            state.pump(now);
        }
        let wake = state.driver_waker.take();
        drop(state);
        if let Some(waker) = wake {
            waker.wake();
        }
        self.ended = true;
        Ok(Drain {
            context: self.context.clone(),
            token: self.token.clone(),
        })
    }
    pub(crate) fn poll_value(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<(Value, u64)>, BrokerError>> {
        if self.ended {
            return Poll::Ready(Ok(None));
        }
        let mut state = match self.context.lock() {
            Ok(s) => s,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match self.receipt.status.load(Ordering::Acquire) {
            DONE | CANCELLED => {
                self.ended = true;
                return Poll::Ready(Ok(None));
            }
            LOST => {
                self.ended = true;
                return Poll::Ready(Err(BrokerError::OwnerLost));
            }
            _ => {}
        }
        if let Some(pending) = &mut state.pending
            && pending.id == self.token.id
            && let Some(value) = pending.value.take()
        {
            return Poll::Ready(Ok(Some((value, pending.serial))));
        }
        match self.receipt.waker.lock() {
            Ok(mut waker) => {
                *waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(BrokerError::Poisoned)),
        }
    }
}
impl<const R: usize, const N: usize> Drop for Query<R, N> {
    fn drop(&mut self) {
        if !self.ended {
            let _result = self.context.cancel(&self.token, true);
        }
    }
}
/// Callback-duration return lease. It owns copied name bytes and blocks the
/// broker's next callback effect until Drop, like returning from a C callback.
/// Configuration/cancellation through another Context clone is safe during it.
///
/// The original query cannot be dropped while its callback lease is live:
/// ```compile_fail
/// use gnunet_resolver_broker::{BrokerError, Query};
/// async fn wrong(mut query: Query<2, 64>) -> Result<(), BrokerError> {
///     let lease = query.next().await?;
///     drop(query);
///     if let Some(lease) = lease { let _reply = lease.reply()?; }
///     Ok(())
/// }
/// ```
/// Return the callback lease before releasing its original query instead:
/// ```no_run
/// use gnunet_resolver_broker::{BrokerError, Query};
/// async fn correct(mut query: Query<2, 64>) -> Result<(), BrokerError> {
///     {
///         let lease = query.next().await?;
///         if let Some(lease) = lease { let _reply = lease.reply()?; drop(lease); }
///     }
///     drop(query);
///     Ok(())
/// }
/// ```
pub struct Delivery<'q, const R: usize, const N: usize> {
    context: Context<R, N>,
    token: Token,
    receipt: Arc<Receipt>,
    value: Option<Value>,
    serial: u64,
    _borrow: PhantomData<&'q mut Query<R, N>>,
}
impl<const R: usize, const N: usize> Delivery<'_, R, N> {
    /// Original callback authority; this is not the opaque wire counter.
    #[must_use]
    pub fn token(&self) -> &Token {
        &self.token
    }
    /// Borrow the current callback value until this lease returns.
    pub fn reply(&self) -> Result<PublicReply<'_>, Error> {
        Ok(match self.value.as_ref() {
            Some(Value::Address(a)) => Reply::Address(*a),
            Some(Value::Name(bytes)) => Reply::Hostname(Hostname::Resolved(bytes)),
            Some(Value::Numeric(a)) => Reply::Hostname(Hostname::Numeric(*a)),
            Some(Value::Complete(reason)) => Reply::Complete(*reason),
            None => return Err(Error::NotReady),
        })
    }
}
fn return_callback<const R: usize, const N: usize>(
    context: &Context<R, N>,
    token: &Token,
    receipt: &Arc<Receipt>,
    serial: u64,
    value: &mut Option<Value>,
) {
    let complete = matches!(&*value, Some(Value::Complete(_)));
    let sample = context.shared.clock.sample().ok();
    if let Ok(mut state) = context.lock() {
        let mut returned_remote_terminal = false;
        if let Some(Value::Name(mut bytes)) = value.take() {
            bytes.clear();
            state.scratch = bytes;
        }
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.serial == serial && pending.id == token.id)
        {
            returned_remote_terminal = state.pending.as_ref().is_some_and(|p| p.block_process);
            state.pending = None;
            if complete {
                state.routes.retain(|route| route.id != token.id);
                if receipt.status.load(Ordering::Acquire) == ACTIVE {
                    receipt.status.store(DONE, Ordering::Release);
                }
            }
        }
        if let Some(sample) = sample {
            state.last_now = sample.now;
        }
        if returned_remote_terminal {
            let now = state.last_now;
            state.pump(now);
        }
        let wake = state.driver_waker.take();
        drop(state);
        receipt.wake();
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}
impl<const R: usize, const N: usize> Drop for Delivery<'_, R, N> {
    fn drop(&mut self) {
        return_callback(
            &self.context,
            &self.token,
            &self.receipt,
            self.serial,
            &mut self.value,
        );
    }
}
/// Internal CLIENT callback hold. Unlike public Delivery it is owned by the
/// unique lookup, so a native socket effect can occur before callback return.
/// It never escapes the crate or borrows its containing Query/self.
pub(crate) struct ClientCallback<const R: usize, const N: usize> {
    context: Context<R, N>,
    token: Token,
    receipt: Arc<Receipt>,
    serial: u64,
    value: Option<Value>,
}
impl<const R: usize, const N: usize> ClientCallback<R, N> {
    pub(crate) fn address(&self) -> Result<Option<IpAddr>, Error> {
        match &self.value {
            Some(Value::Address(address)) => Ok(Some(*address)),
            Some(Value::Complete(_)) => Ok(None),
            _ => Err(Error::Malformed),
        }
    }
}
impl<const R: usize, const N: usize> Drop for ClientCallback<R, N> {
    fn drop(&mut self) {
        return_callback(
            &self.context,
            &self.token,
            &self.receipt,
            self.serial,
            &mut self.value,
        );
    }
}

/// Original DNS subscription retained after a CLIENT TCP probe succeeds.
/// Drop cancels only this original request; it never closes the service socket.
pub struct Drain<const R: usize, const N: usize> {
    context: Context<R, N>,
    token: Token,
}
impl<const R: usize, const N: usize> Drop for Drain<R, N> {
    fn drop(&mut self) {
        let _result = self.context.cancel(&self.token, true);
    }
}
impl<const R: usize, const N: usize> gnunet_service_runtime::connection::ConnectionLease
    for Drain<R, N>
{
}
