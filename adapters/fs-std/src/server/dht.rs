//! Non-anonymous FS UBLOCK lookup/publication over one actual DHT client.
//!
//! A local FS route keeps its original branded GET through MQ replacement. One
//! retained input backpressures further input while STOP/output still progress.
//! No DHT/FS negative reply, search END or network completion is fabricated.
/// Service-owned actual zero-anonymity UBLOCK advertisements.
pub mod publication;
use super::{PeerProgress, PeerRouter, PeerShutdown, ProviderFailure, RouteAdmission};
use gnunet_dht_client_host::{
    Action, Cancel, Client, EndpointSource, Epoch, Event, Get, GetId, Instance,
    Limits as NativeLimits, LossCause, Progress, Received, Snapshot,
};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{
    dht::{RouteOptions, ipc},
    fs::{BlockType, CLIENT_PUT_PREFIX, ClientPut, Response, SEARCH_LOOPBACK_ONLY, Search},
};
use publication::Publisher;
use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

type Failure = ProviderFailure;
/// Source/format/resource failure from the original owner.
#[derive(Debug)]
pub enum Error {
    /// Actual native DHT/CLIENT refusal.
    Native(gnunet_dht_client_host::Error),
    /// Original clock, format or explicit resource refusal.
    Protocol(ProtocolError),
    /// Actual publication source/operation refusal, preserving its concrete cause.
    Publication(publication::Failure),
    /// Independent original cleanup failure while retaining the principal cause.
    Retirement {
        /// Original operation or source refusal.
        cause: Box<Error>,
        /// Independent actual cleanup refusal.
        cleanup: Box<Error>,
    },
    /// Admission's original native bound elapsed before a GET could be created.
    NativeDeadline,
    /// Known-filter preparation failed and its original GET was retired locally.
    Admission {
        /// Original preparation cause.
        cause: gnunet_dht_client_host::Error,
        /// Independent actual stop failure, when any.
        cleanup: Option<gnunet_dht_client_host::Error>,
    },
}
impl From<gnunet_dht_client_host::Error> for Error {
    fn from(cause: gnunet_dht_client_host::Error) -> Self {
        Self::Native(cause)
    }
}
impl From<ProtocolError> for Error {
    fn from(cause: ProtocolError) -> Self {
        Self::Protocol(cause)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS DHT owner: {self:?}")
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Native(cause) | Self::Admission { cause, .. } => Some(cause),
            Self::Protocol(cause) => Some(cause),
            Self::Publication(cause) => Some(cause.as_ref()),
            Self::Retirement { cause, .. } => Some(cause.as_ref()),
            Self::NativeDeadline => None,
        }
    }
}
/// Bounded metadata, duplicate history and original per-GET lifetime.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Live plus physically draining GET owners.
    pub routes: usize,
    /// Maximum original known-result hashes for one GET, including reconnect history.
    pub known_hashes: usize,
    /// Largest FS payload admitted to the local response path.
    pub block_bytes: usize,
    /// Original canonical and native bound, retained across every MQ retry.
    pub timeout: Duration,
    /// Maximum original native read/write slice.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            routes: 128,
            known_hashes: 256,
            block_bytes: 65535 - CLIENT_PUT_PREFIX,
            timeout: Duration::from_secs(30),
            io_slice_bytes: 65535,
        }
    }
}
/// Actual physical source retirement and its retained logical state.
#[derive(Debug)]
pub struct Retirement<'id> {
    /// Original physical stream.
    pub epoch: Epoch<'id>,
    /// Actual original cause.
    pub cause: LossCause,
    /// Actual logical state after physical retirement.
    pub retained: Snapshot,
}
/// Bounded observations; neither local GET nor STOP writing is a remote ACK.
#[derive(Debug, Default)]
pub struct Report<'id> {
    /// Actual physical MQ retirements, including an elapsed STOP fence.
    pub losses: u64,
    /// Actual native connection retries.
    pub connection_retries: u64,
    /// Original local GET bounds reached.
    pub timeouts: u64,
    /// Complete but invalid/mismatched/duplicate results rejected.
    pub rejected: u64,
    /// Latest actual physical loss/close cause.
    pub last_retirement: Option<Retirement<'id>>,
    /// Original private client usage at explicit close entry, before cancellations.
    pub close_snapshot: Option<Snapshot>,
}
struct Route<'id> {
    serial: u64,
    get: Option<GetId<'id>>,
    key: [u8; 64],
    until: u64,
    hard: Instant,
    active: bool,
    end_pending: bool,
}
struct Held<'id> {
    route: u64,
    original: Received<'id>,
}
/// One explicit native DHT source and bounded original FS-to-GET associations.
pub struct Router<'id> {
    client: Client<'id>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    timeout_us: u64,
    routes: Vec<Route<'id>>,
    held: Option<Held<'id>>,
    publisher: Option<Publisher<'id>>,
    canonical: Option<(u64, Deadline)>,
    native: Option<Pin<Box<Sleep>>>,
    last_route: u64,
    stopping: bool,
    closed: bool,
    pending_error: Option<Error>,
    report: Report<'id>,
}
impl<'id> Router<'id> {
    /// Reserve metadata and the actual DHT client before polling any IO. The
    /// source supplies the same explicit clock/Resolver used by normal FS.
    pub fn new(
        instance: &'id mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        let timeout_us =
            u64::try_from(limits.timeout.as_micros()).map_err(|_| ProtocolError::Overflow)?;
        if limits.routes == 0
            || limits.known_hashes == 0
            || timeout_us == 0
            || timeout_us == u64::MAX
            || limits.io_slice_bytes == 0
            || limits.block_bytes > 65535 - CLIENT_PUT_PREFIX
            || Instant::now().checked_add(limits.timeout).is_none()
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let source_bytes = limits
            .known_hashes
            .checked_mul(64)
            .and_then(|n| n.checked_add(ipc::GET_FIXED_LEN))
            .and_then(|n| n.checked_mul(limits.routes))
            .and_then(|n| n.checked_add(limits.block_bytes))
            .and_then(|n| n.checked_add(ipc::PUT_FIXED_LEN))
            .ok_or(ProtocolError::Overflow)?;
        let NativeLimits {
            mut protocol,
            output,
            hello,
            ..
        } = NativeLimits::default();
        protocol.gets = limits.routes;
        protocol.monitors = 0;
        protocol.hellos = 0;
        protocol.operations = 1;
        protocol.attempts = limits.routes.min(64);
        protocol.known_per_get = limits.known_hashes;
        protocol.source_bytes = source_bytes;
        let native = NativeLimits {
            protocol,
            output,
            hello,
            io_slice_bytes: limits.io_slice_bytes,
        };
        let clock = source.clock();
        let client = Client::new(instance, source, native)?;
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(limits.routes)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            client,
            clock,
            limits,
            timeout_us,
            routes,
            held: None,
            publisher: None,
            canonical: None,
            native: None,
            last_route: 0,
            stopping: false,
            closed: false,
            pending_error: None,
            report: Report::default(),
        })
    }
    /// Install the actual independent one-slot DATASTORE publication source.
    /// It shares this same DHT client/reader; no second DHT connection is opened.
    pub fn install_publisher(
        &mut self,
        port: Box<dyn super::gap::storage::Port + 'id>,
        limits: publication::Limits,
    ) -> Result<(), Error> {
        if self.closed || self.stopping || self.publisher.is_some() {
            return Err(ProtocolError::Conflict.into());
        }
        self.publisher = Some(
            Publisher::new(port, self.clock.clone(), self.limits.block_bytes, limits)
                .map_err(Error::Publication)?,
        );
        Ok(())
    }
    /// Bounded original publication outcomes, separate from GET/native history.
    #[must_use]
    pub fn publication_report(&self) -> Option<&publication::Report<'id>> {
        self.publisher.as_ref().map(Publisher::report)
    }
    fn remember(&mut self, error: Error) {
        self.pending_error = Some(match self.pending_error.take() {
            Some(cause) => Error::Retirement {
                cause: Box::new(cause),
                cleanup: Box::new(error),
            },
            None => error,
        });
    }
    fn take_completion(&mut self) -> Result<bool, Error> {
        let Some(completion) = self.client.take_completion() else {
            return Ok(false);
        };
        self.publisher
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?
            .completed(completion)
            .map_err(Error::Publication)?;
        Ok(true)
    }
    fn publication_guard(&mut self, now: Option<u64>) -> Result<bool, Error> {
        match &mut self.publisher {
            Some(publisher) => publisher
                .guard(now, &mut self.client)
                .map_err(Error::Publication),
            None => Ok(false),
        }
    }
    fn retire_expired(&mut self) -> Result<bool, Error> {
        let now = Instant::now();
        let get = self
            .routes
            .iter()
            .any(|r| !r.active && r.get.is_some() && now >= r.hard);
        let publication = self
            .publisher
            .as_ref()
            .is_some_and(Publisher::needs_retirement);
        if !get && !publication {
            return Ok(false);
        }
        if self.client.epoch().is_none() {
            return Err(ProtocolError::Stale.into());
        }
        let retirement = self.client.reconnect()?;
        self.source_progress(retirement)?;
        Ok(true)
    }
    /// Original source clock; this creates no subscription or source.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Actual bounded observations and original physical close facts.
    #[must_use]
    pub const fn report(&self) -> &Report<'id> {
        &self.report
    }
    /// Explicit source-port recovery; this does not replace queries or their bounds.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        Ok(self.client.recover_ports()?)
    }
    fn admit(
        &mut self,
        serial: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Error> {
        if self.closed
            || self.stopping
            || search.anonymity != 0
            || search.block_type != BlockType::UBLOCK
            || search.options & SEARCH_LOOPBACK_ONLY != 0
        {
            return Ok(RouteAdmission::Idle);
        }
        search.validate()?;
        if serial <= self.last_route {
            return Err(ProtocolError::StaleGeneration.into());
        }
        if self.routes.len() == self.limits.routes {
            return Ok(RouteAdmission::Idle);
        }
        if seen.len() > self.limits.known_hashes {
            return Err(ProtocolError::Capacity.into());
        }
        let hard = Instant::now()
            .checked_add(self.limits.timeout)
            .ok_or(ProtocolError::Overflow)?;
        let until = self
            .clock
            .sample()?
            .now
            .as_micros()
            .checked_add(self.timeout_us)
            .filter(|n| *n != u64::MAX)
            .ok_or(ProtocolError::Overflow)?;
        // All fallible timer preparation precedes the new original GET.
        let canonical = if self.canonical.as_ref().is_none_or(|(old, _)| until < *old) {
            Some((
                until,
                Deadline::at(self.clock.clone(), AbsoluteTime::from_micros(until))?,
            ))
        } else {
            None
        };
        let native = self
            .native
            .is_none()
            .then(|| Box::pin(tokio::time::sleep_until(hard)));
        if Instant::now() >= hard {
            return Err(Error::NativeDeadline);
        }
        let get = self.client.get(Get {
            key: &search.query,
            block_type: BlockType::UBLOCK.value(),
            options: u32::from(RouteOptions::DEMULTIPLEX_EVERYWHERE.bits()),
            replication: 5,
            extended_query: &[],
        })?;
        if let Err(cause) = self.client.known(get, seen) {
            let cleanup = self.client.stop(get).err();
            return Err(Error::Admission { cause, cleanup });
        }
        self.routes.push(Route {
            serial,
            get: Some(get),
            key: search.query,
            until,
            hard,
            active: true,
            end_pending: false,
        });
        if let Some(canonical) = canonical {
            self.canonical = Some(canonical);
        }
        if let Some(native) = native {
            self.native = Some(native);
        }
        self.last_route = serial;
        Ok(RouteAdmission::Queued)
    }
    fn stop(&mut self, index: usize, notify: bool) -> Result<(), Error> {
        let route = &mut self.routes[index];
        if !route.active {
            return Ok(());
        }
        let get = route.get.ok_or(ProtocolError::Stale)?;
        let result = self.client.stop(get)?;
        route.active = false;
        route.end_pending = notify;
        if result == Cancel::BeforeIssue {
            route.get = None;
        }
        if self.held.as_ref().is_some_and(|h| h.route == route.serial) {
            self.held = None;
        }
        Ok(())
    }
    fn native_expiry(&mut self) -> Result<bool, Error> {
        // Actual terminal notices are clock-free and must survive a late bound.
        let mut changed = self.take_completion()?;
        let now = Instant::now();
        for i in 0..self.routes.len() {
            if self.routes[i].active && now >= self.routes[i].hard {
                self.stop(i, true)?;
                self.report.timeouts = self.report.timeouts.saturating_add(1);
                changed = true;
            }
        }
        changed |= self.publication_guard(None)?;
        changed |= self.retire_expired()?;
        Ok(changed)
    }
    fn expire(&mut self) -> Result<bool, Error> {
        let mut changed = self.native_expiry()?;
        if self.routes.iter().any(|r| r.active)
            || self
                .publisher
                .as_ref()
                .is_some_and(|p| p.native_target().is_some())
        {
            let now = self.clock.sample()?.now.as_micros();
            changed |= self.native_expiry()?;
            for i in 0..self.routes.len() {
                if self.routes[i].active && now >= self.routes[i].until {
                    self.stop(i, true)?;
                    self.report.timeouts = self.report.timeouts.saturating_add(1);
                    changed = true;
                }
            }
            changed |= self.publication_guard(Some(now))?;
            changed |= self.retire_expired()?;
        }
        Ok(changed)
    }
    fn poll_timers(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let until = self
            .routes
            .iter()
            .filter(|r| r.active)
            .map(|r| r.until)
            .chain(
                self.publisher
                    .as_ref()
                    .and_then(Publisher::canonical_target),
            )
            .min();
        if self.canonical.as_ref().map(|(t, _)| *t) != until {
            self.canonical = until
                .map(|t| {
                    Deadline::at(self.clock.clone(), AbsoluteTime::from_micros(t)).map(|d| (t, d))
                })
                .transpose()?;
        }
        if let Some((_, deadline)) = &mut self.canonical
            && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
        {
            result?;
        }
        if let Some(hard) = self
            .routes
            .iter()
            .filter(|r| r.get.is_some())
            .map(|r| r.hard)
            .chain(self.publisher.as_ref().and_then(Publisher::native_target))
            .min()
        {
            let native = self
                .native
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(hard)));
            if native.deadline() != hard {
                native.as_mut().reset(hard);
            }
            let _elapsed = native.as_mut().poll(cx).is_ready();
        } else {
            self.native = None;
        }
        Ok(())
    }
    fn release_canceled(&mut self) {
        self.routes
            .retain(|r| r.active || r.get.is_some() || r.end_pending);
    }
    fn ended(&mut self) -> Option<PeerProgress> {
        let index = self
            .routes
            .iter()
            .position(|r| !r.active && r.get.is_none() && r.end_pending)?;
        Some(PeerProgress::Ended(self.routes.swap_remove(index).serial))
    }
    fn deliver(&mut self, allowed: bool) -> Result<Option<PeerProgress>, Error> {
        if !allowed {
            return Ok(None);
        }
        let Some(held) = &self.held else {
            return Ok(None);
        };
        let Some(route) = self
            .routes
            .iter()
            .find(|r| r.serial == held.route && r.active)
        else {
            self.held = None;
            return Ok(Some(PeerProgress::Activity));
        };
        let result = held.original.result()?;
        if result.block_type != BlockType::UBLOCK.value()
            || *result.key != route.key
            || result.payload.len() > self.limits.block_bytes
        {
            self.held = None;
            self.report.rejected = self.report.rejected.saturating_add(1);
            return Ok(Some(PeerProgress::Activity));
        }
        match gnunet_fs::ublock::verify_envelope(result.payload, &route.key) {
            Ok(()) => {}
            Err(ProtocolError::Malformed | ProtocolError::Authentication) => {
                self.held = None;
                self.report.rejected = self.report.rejected.saturating_add(1);
                return Ok(Some(PeerProgress::Activity));
            }
            Err(cause) => return Err(cause.into()),
        }
        let put = Response::Put(ClientPut {
            block_type: BlockType::UBLOCK,
            expiration: result.expiration,
            last_transmission: AbsoluteTime::NEVER,
            num_transmissions: 0,
            respect_offered: 0,
            block: result.payload,
        });
        let size = put.encoded_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(size, 0);
        put.encode(&mut bytes)?;
        let serial = route.serial;
        let hard = route.hard;
        let until = route.until;
        // Authentication/allocation spent work under these same original bounds.
        // A result prepared before expiry is not permission to publish it late.
        let elapsed = if Instant::now() >= hard {
            true
        } else {
            let now = self.clock.sample()?.now.as_micros();
            Instant::now() >= hard || now >= until
        };
        if elapsed {
            let index = self
                .routes
                .iter()
                .position(|r| r.serial == serial)
                .ok_or(ProtocolError::Stale)?;
            self.stop(index, true)?;
            self.report.timeouts = self.report.timeouts.saturating_add(1);
            return Ok(Some(PeerProgress::Activity));
        }
        self.held = None;
        Ok(Some(PeerProgress::Reply {
            route: serial,
            frame: OwnedFrame::new(bytes),
        }))
    }
    fn source_progress(&mut self, progress: Progress<'id>) -> Result<(), Error> {
        match progress {
            Progress::Inbound(original) => {
                if let Event::Result { get, duplicate, .. } = original.event() {
                    if !*duplicate
                        && let Some(route) =
                            self.routes.iter().find(|r| r.active && r.get == Some(*get))
                    {
                        self.held = Some(Held {
                            route: route.serial,
                            original,
                        });
                    } else {
                        self.report.rejected = self.report.rejected.saturating_add(1);
                    }
                }
            }
            Progress::Written {
                action: Action::Stop(get),
                ..
            } => {
                if let Some(route) = self
                    .routes
                    .iter_mut()
                    .find(|r| r.get == Some(get) && !r.active)
                {
                    route.get = None;
                }
            }
            Progress::Lost {
                epoch,
                cause,
                retained,
            } => {
                for route in &mut self.routes {
                    if !route.active {
                        route.get = None;
                    }
                }
                self.report.losses = self.report.losses.saturating_add(1);
                self.report.last_retirement = Some(Retirement {
                    epoch,
                    cause,
                    retained,
                });
            }
            Progress::ConnectRetry { .. } => {
                self.report.connection_retries = self.report.connection_retries.saturating_add(1);
            }
            Progress::Completed(completion) => {
                self.publisher
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?
                    .completed(completion)
                    .map_err(Error::Publication)?;
            }
            Progress::Unavailable(cause) => return Err(cause.into()),
            Progress::Closed => return Err(ProtocolError::Closed.into()),
            _ => {}
        }
        let _notice = self.take_completion()?;
        Ok(())
    }
    fn poll_owner(
        &mut self,
        cx: &mut Context<'_>,
        allowed: bool,
    ) -> Poll<Result<PeerProgress, Error>> {
        if let Some(cause) = self.pending_error.take() {
            return Poll::Ready(Err(cause));
        }
        if self.closed {
            return Poll::Pending;
        }
        let mut changed = self.expire()?;
        self.release_canceled();
        self.poll_timers(cx)?;
        changed |= self.expire()?;
        if let Some(publisher) = &mut self.publisher {
            match publisher.poll(cx, &mut self.client) {
                Poll::Ready(Ok(())) => changed = true,
                Poll::Ready(Err(cause)) => return Poll::Ready(Err(Error::Publication(cause))),
                Poll::Pending => {}
            }
            // Source/verification work spent these same original GET/PUT bounds.
            changed |= self.expire()?;
            self.poll_timers(cx)?;
        }
        if let Some(ended) = self.ended() {
            return Poll::Ready(Ok(ended));
        }
        if let Some(output) = self.deliver(allowed)? {
            return Poll::Ready(Ok(output));
        }
        if self.routes.iter().any(|r| r.get.is_some())
            || self.publisher.as_ref().is_some_and(Publisher::needs_client)
        {
            let hard = self
                .routes
                .iter()
                .filter(|r| r.get.is_some())
                .map(|r| r.hard)
                .chain(self.publisher.as_ref().and_then(Publisher::native_target))
                .min();
            match self.client.poll_with_input(cx, hard, self.held.is_none()) {
                Poll::Pending => {}
                Poll::Ready(Err(cause)) => return Poll::Ready(Err(cause.into())),
                Poll::Ready(Ok(progress)) => {
                    self.source_progress(progress)?;
                    changed = true;
                    changed |= self.expire()?;
                    self.release_canceled();
                    if let Some(output) = self.deliver(allowed)? {
                        return Poll::Ready(Ok(output));
                    }
                    if let Some(ended) = self.ended() {
                        return Poll::Ready(Ok(ended));
                    }
                }
            }
        }
        if changed {
            Poll::Ready(Ok(PeerProgress::Activity))
        } else {
            Poll::Pending
        }
    }
}
impl PeerRouter for Router<'_> {
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Failure> {
        self.admit(route, search, seen).map_err(Failure::operation)
    }
    fn poll(&mut self, cx: &mut Context<'_>, deliver: bool) -> Poll<Result<PeerProgress, Failure>> {
        self.poll_owner(cx, deliver).map_err(Failure::operation)
    }
    fn cancel(&mut self, serial: u64) -> Result<(), Failure> {
        if let Some(index) = self.routes.iter().position(|r| r.serial == serial) {
            self.stop(index, false).map_err(Failure::operation)?;
            self.routes[index].end_pending = false;
            self.release_canceled();
        }
        Ok(())
    }
    fn request_shutdown(&mut self) {
        if self.stopping || self.closed {
            return;
        }
        self.stopping = true;
        // A callback may already be queued between polls. Preserve that actual
        // terminal before attempting to cancel only a still-live operation.
        if let Err(cause) = self.take_completion() {
            self.remember(cause);
        }
        if let Some(publisher) = &mut self.publisher
            && let Err(cause) = publisher.request_shutdown(&mut self.client)
        {
            self.remember(Error::Publication(cause));
        }
        for i in 0..self.routes.len() {
            if let Err(cause) = self.stop(i, true) {
                self.remember(cause);
            }
        }
    }
    fn shutdown_state(&self) -> PeerShutdown {
        if self.closed {
            PeerShutdown::Retired
        } else if !self.stopping {
            PeerShutdown::Immediate
        } else if self.pending_error.is_some()
            || self.held.is_some()
            || self.routes.iter().any(|r| r.get.is_some())
            || self.client.snapshot().attempts != 0
            || self.publisher.as_ref().is_some_and(|p| !p.quiesced())
        {
            PeerShutdown::Draining
        } else {
            PeerShutdown::Quiesced
        }
    }
    fn close(&mut self) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        self.report.close_snapshot = Some(self.client.snapshot());
        if let Err(cause) = self.take_completion() {
            self.remember(cause);
        }
        if let Some(publisher) = &mut self.publisher {
            let stop = publisher.request_shutdown(&mut self.client);
            let source = publisher.close_source();
            if let Err(cause) = stop {
                self.remember(Error::Publication(cause));
            }
            if let Err(cause) = source {
                self.remember(Error::Publication(cause));
            }
        }
        if let Some(Progress::Lost {
            epoch,
            cause,
            retained,
        }) = self.client.close()
        {
            self.report.last_retirement = Some(Retirement {
                epoch,
                cause,
                retained,
            });
        }
        if let Err(cause) = self.take_completion() {
            self.remember(cause);
        }
        self.closed = true;
        self.stopping = true;
        self.held = None;
        self.canonical = None;
        self.native = None;
        self.routes.clear();
        match self.pending_error.take() {
            Some(cause) => Err(Failure::operation(cause)),
            None => Ok(()),
        }
    }
}
