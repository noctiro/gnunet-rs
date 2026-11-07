//! Explicit deferred construction and bounded direct/GAP peer composition.
use super::{
    Error, FailureScope, IndexResolver, PeerProgress, PeerRouter, PeerShutdown, ProviderFailure,
    RouteAdmission, Server,
    ports::{LocationSigner, StorePort},
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::fs::{BlockType, SEARCH_LOOPBACK_ONLY, Search};
use std::{
    error::Error as StdError,
    fmt,
    sync::Arc,
    task::{Context, Poll},
};

/// Exact original provider refusal, without a substituted protocol outcome.
pub type Failure = ProviderFailure;
type SharedFailure = Arc<ProviderFailure>;

/// Actual backend responsible for an independent operation or refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    /// Original non-anonymous direct CADET owner.
    Direct,
    /// Original anonymous CORE GAP owner.
    Gap,
    /// Original non-anonymous UBLOCK DHT owner.
    Dht,
    /// The containing provider, when a generic Server boundary retires it.
    Provider,
}

/// Original refusal plus an independent physical cleanup refusal, if any.
/// Cloning shares the original concrete causes and does not replace them.
#[derive(Clone, Debug)]
pub struct PeerFailure {
    /// Actual original backend; never selected from a later route's metadata.
    pub backend: Backend,
    /// Original operation refusal, retaining its concrete type/source chain.
    pub cause: SharedFailure,
    /// Independent original cleanup failure, retaining its own classification.
    pub cleanup: Option<SharedFailure>,
}
impl PeerFailure {
    /// Preserve one original cause and its independent physical close result.
    #[must_use]
    pub fn new(backend: Backend, cause: Failure, cleanup: Option<Failure>) -> Self {
        Self {
            backend,
            cause: Arc::new(cause),
            cleanup: cleanup.map(Arc::new),
        }
    }
    /// An original permanent/Unknown source or worker failure stops all FS.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.cause.is_fatal() || self.cleanup.as_ref().is_some_and(|e| e.is_fatal())
    }
    pub(super) fn into_failure(self) -> Failure {
        let scope = if self.is_fatal() {
            FailureScope::Service
        } else {
            FailureScope::Operation
        };
        Failure::new(Box::new(self), scope)
    }
}
impl fmt::Display for PeerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS {:?} peer owner: {}", self.backend, self.cause)?;
        if let Some(cleanup) = &self.cleanup {
            write!(f, "; independent cleanup: {cleanup}")?;
        }
        Ok(())
    }
}
impl StdError for PeerFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.cause.as_ref())
    }
}
#[derive(Debug)]
struct Cleanup {
    previous: Option<SharedFailure>,
    direct: Option<SharedFailure>,
    secondary: Option<SharedFailure>,
}
impl fmt::Display for Cleanup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS peer cleanup {self:?}")
    }
}
impl StdError for Cleanup {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.previous
            .as_ref()
            .or(self.direct.as_ref())
            .or(self.secondary.as_ref())
            .map(|e| e.as_ref() as &(dyn StdError + 'static))
    }
}
impl Cleanup {
    fn into_failure(self) -> Failure {
        let scope = if [&self.previous, &self.direct, &self.secondary]
            .into_iter()
            .any(|cause| cause.as_ref().is_some_and(|cause| cause.is_fatal()))
        {
            FailureScope::Service
        } else {
            FailureScope::Operation
        };
        Failure::new(Box::new(self), scope)
    }
}

/// Empty original-owner slot used only until the Server's real worker exists.
/// It never constructs an Index, worker, resolver, socket or replacement owner.
pub struct Deferred<R: PeerRouter> {
    inner: Option<R>,
    stopping: bool,
    closed: bool,
}
impl<R: PeerRouter> Deferred<R> {
    /// Create an empty slot; callers initialize it before driving the Server.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: None,
            stopping: false,
            closed: false,
        }
    }
    /// Observe the original provider without bypassing recovery generations.
    #[must_use]
    pub const fn get(&self) -> Option<&R> {
        self.inner.as_ref()
    }
}
impl<R: PeerRouter> Default for Deferred<R> {
    fn default() -> Self {
        Self::new()
    }
}
impl<R: PeerRouter> PeerRouter for Deferred<R> {
    fn initialized(&self) -> bool {
        self.inner.as_ref().is_some_and(PeerRouter::initialized)
    }
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Failure> {
        let router = self
            .inner
            .as_mut()
            .ok_or_else(|| Failure::operation(ProtocolError::NotReady))?;
        if self.stopping || self.closed {
            return Ok(RouteAdmission::Idle);
        }
        router.start(route, search, seen)
    }
    fn poll(&mut self, cx: &mut Context<'_>, deliver: bool) -> Poll<Result<PeerProgress, Failure>> {
        match &mut self.inner {
            Some(router) if !self.closed => router.poll(cx, deliver),
            _ => Poll::Pending,
        }
    }
    fn input_needed(&self) -> Option<u64> {
        self.inner
            .as_ref()
            .filter(|_| !self.closed && !self.stopping)?
            .input_needed()
    }
    fn refresh(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<(), Failure> {
        if self.closed || self.stopping {
            return Err(Failure::operation(ProtocolError::Closed));
        }
        self.inner
            .as_mut()
            .ok_or_else(|| Failure::operation(ProtocolError::NotReady))?
            .refresh(route, search, seen)
    }
    fn cancel(&mut self, route: u64) -> Result<(), Failure> {
        match &mut self.inner {
            Some(router) if !self.closed => router.cancel(route),
            _ => Ok(()),
        }
    }
    fn request_shutdown(&mut self) {
        self.stopping = true;
        if let Some(router) = &mut self.inner {
            router.request_shutdown();
        }
    }
    fn shutdown_state(&self) -> PeerShutdown {
        match &self.inner {
            Some(_) if self.closed => PeerShutdown::Retired,
            Some(router) => router.shutdown_state(),
            None => PeerShutdown::Quiesced,
        }
    }
    fn close(&mut self) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.stopping = true;
        match &mut self.inner {
            Some(router) => router.close(),
            None => Ok(()),
        }
    }
}
impl<'id, 'slots, 'seen, S: StorePort, L: LocationSigner, R: PeerRouter>
    Server<'id, 'slots, 'seen, S, L, Deferred<R>>
{
    /// Construct peers against the weak resolver of this Server's already
    /// started sole worker and its original shared clock. On factory failure
    /// retain this Server, then call normal shutdown to drain and join it.
    pub fn initialize_peers(
        &mut self,
        factory: impl FnOnce(IndexResolver, Arc<dyn RuntimeClock>) -> Result<R, Failure>,
    ) -> Result<(), Arc<Error>> {
        if self.closing || self.router.inner.is_some() || self.router.closed {
            return Err(Arc::new(Error::Protocol(ProtocolError::Conflict)));
        }
        let result = self.worker.resolver().and_then(|resolver| {
            factory(resolver, self.clock.clone()).map_err(|e| Arc::new(Error::Route(e)))
        });
        match result {
            Ok(router) => {
                self.router.inner = Some(router);
                Ok(())
            }
            Err(error) => {
                if self.report.failure.is_none() {
                    self.report.failure = Some(error.clone());
                }
                self.report.peer_failure = Some(error.clone());
                self.request_shutdown();
                Err(error)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Route {
    serial: u64,
    backend: Backend,
    ended: bool,
    additional: Option<Backend>,
    additional_ended: bool,
}
impl Route {
    fn live(&self, backend: Backend) -> bool {
        self.backend == backend && !self.ended
            || self.additional == Some(backend) && !self.additional_ended
    }
    fn end(&mut self, backend: Backend) {
        if self.backend == backend {
            self.ended = true;
        }
        if self.additional == Some(backend) {
            self.additional_ended = true;
        }
    }
    fn complete(&self) -> bool {
        self.ended && (self.additional.is_none() || self.additional_ended)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Selection {
    Anonymity,
    NonAnonymous,
}

/// Two independently owned optional backends and a fixed-capacity route table.
/// Anonymity0 selects direct except unknown-target D/I, which use the explicit
/// GAP capability without changing their numeric level. Every positive level
/// selects GAP. An unadmitted level0 D/I/UBLOCK may fall back to GAP only after
/// the direct chain reports Idle (no peer effect), is absent or is retired.
/// Queued work and errors never switch backend. The explicit `discovery`
/// constructor plans an independent CORE child before first admission, even
/// when the optional primary refuses nonfatally; it never starts a child later
/// after a timeout or Ended.
pub struct Pair<A: PeerRouter, B: PeerRouter> {
    direct: Option<A>,
    secondary: Option<B>,
    selection: Selection,
    discovery: bool,
    direct_retired: bool,
    secondary_retired: bool,
    routes: Vec<Route>,
    capacity: usize,
    last_route: u64,
    first: Backend,
    stopping: bool,
    closed: bool,
    first_failure: Option<PeerFailure>,
    direct_failure: Option<PeerFailure>,
    secondary_failure: Option<PeerFailure>,
    shutdown_direct: Option<SharedFailure>,
    shutdown_secondary: Option<SharedFailure>,
    pending_fatal: Option<PeerFailure>,
}
impl<A: PeerRouter, B: PeerRouter> Pair<A, B> {
    /// Reserve the exact finite route table before either provider is driven.
    pub fn new(direct: Option<A>, gap: Option<B>, routes: usize) -> Result<Self, ProtocolError> {
        Self::with_selection(direct, gap, routes, Selection::Anonymity)
    }
    /// Plan configured CORE discovery alongside the optional level0 direct/DHT
    /// child before either starts. A nonfatal primary refusal retains its cause
    /// without canceling that original CORE plan. Each actual child keeps its
    /// own timers and native cleanup; no later Ended/error starts a retry.
    /// Positive anonymity and unknown-target level0 D/I still select only GAP.
    pub fn discovery(
        direct: Option<A>,
        gap: Option<B>,
        routes: usize,
    ) -> Result<Self, ProtocolError> {
        let mut pair = Self::with_selection(direct, gap, routes, Selection::Anonymity)?;
        pair.discovery = true;
        Ok(pair)
    }
    /// Compose independently owned non-anonymous CADET and DHT backends. Only
    /// actual UBLOCK queries select DHT; the original search is never rewritten.
    pub fn non_anonymous(
        cadet: Option<A>,
        dht: Option<B>,
        routes: usize,
    ) -> Result<Self, ProtocolError> {
        Self::with_selection(cadet, dht, routes, Selection::NonAnonymous)
    }
    fn with_selection(
        direct: Option<A>,
        secondary: Option<B>,
        routes: usize,
        selection: Selection,
    ) -> Result<Self, ProtocolError> {
        if routes == 0 {
            return Err(ProtocolError::InvalidInput);
        }
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(routes)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            direct,
            secondary,
            selection,
            discovery: false,
            direct_retired: false,
            secondary_retired: false,
            routes: owners,
            capacity: routes,
            last_route: 0,
            first: Backend::Direct,
            stopping: false,
            closed: false,
            first_failure: None,
            direct_failure: None,
            secondary_failure: None,
            shutdown_direct: None,
            shutdown_secondary: None,
            pending_fatal: None,
        })
    }
    fn secondary_backend(&self) -> Backend {
        match self.selection {
            Selection::Anonymity => Backend::Gap,
            Selection::NonAnonymous => Backend::Dht,
        }
    }
    /// Observe the original direct owner, including its actual retired report.
    #[must_use]
    pub const fn direct(&self) -> Option<&A> {
        self.direct.as_ref()
    }
    /// Observe the original GAP owner, including its actual retired report.
    #[must_use]
    pub fn gap(&self) -> Option<&B> {
        (self.selection == Selection::Anonymity)
            .then_some(self.secondary.as_ref())
            .flatten()
    }
    /// Observe the actual DHT owner of a non-anonymous composition.
    #[must_use]
    pub fn dht(&self) -> Option<&B> {
        (self.selection == Selection::NonAnonymous)
            .then_some(self.secondary.as_ref())
            .flatten()
    }
    /// Earliest actual backend refusal and its independent physical close cause.
    #[must_use]
    pub const fn first_failure(&self) -> Option<&PeerFailure> {
        self.first_failure.as_ref()
    }
    /// Observe each backend's first original cause even if its sibling failed
    /// earlier. Storage is bounded to one original failure per actual backend.
    #[must_use]
    pub const fn failure(&self, backend: Backend) -> Option<&PeerFailure> {
        match (backend, self.selection) {
            (Backend::Direct, _) => self.direct_failure.as_ref(),
            (Backend::Gap, Selection::Anonymity) | (Backend::Dht, Selection::NonAnonymous) => {
                self.secondary_failure.as_ref()
            }
            (Backend::Gap | Backend::Dht, _) => None,
            (Backend::Provider, _) => self.first_failure.as_ref(),
        }
    }
    fn remember(&mut self, failure: &PeerFailure) {
        if self.first_failure.is_none() {
            self.first_failure = Some(failure.clone());
        }
        let slot = match failure.backend {
            Backend::Direct => &mut self.direct_failure,
            Backend::Gap | Backend::Dht => &mut self.secondary_failure,
            Backend::Provider => return,
        };
        if slot.is_none() {
            *slot = Some(failure.clone());
        }
    }
    fn close_backend(&mut self, backend: Backend) -> Option<Failure> {
        let result = match backend {
            Backend::Direct => {
                if self.direct_retired {
                    return None;
                }
                let router = self.direct.as_mut()?;
                self.direct_retired = true;
                router.close()
            }
            Backend::Gap | Backend::Dht => {
                if self.secondary_retired {
                    return None;
                }
                let router = self.secondary.as_mut()?;
                self.secondary_retired = true;
                router.close()
            }
            Backend::Provider => return None,
        };
        for route in &mut self.routes {
            route.end(backend);
        }
        result.err()
    }
    fn failed(&mut self, backend: Backend, cause: Failure) -> PeerFailure {
        let cleanup = self.close_backend(backend);
        let failure = PeerFailure::new(backend, cause, cleanup);
        self.remember(&failure);
        failure
    }
    fn backend_state(&self, backend: Backend) -> Option<PeerShutdown> {
        match backend {
            Backend::Direct if self.direct_retired => Some(PeerShutdown::Retired),
            Backend::Gap | Backend::Dht if self.secondary_retired => Some(PeerShutdown::Retired),
            Backend::Direct => self.direct.as_ref().map(PeerRouter::shutdown_state),
            Backend::Gap | Backend::Dht => self.secondary.as_ref().map(PeerRouter::shutdown_state),
            Backend::Provider => None,
        }
    }
    fn start_backend(
        &mut self,
        backend: Backend,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Failure> {
        if self.backend_state(backend) == Some(PeerShutdown::Retired) {
            return Ok(RouteAdmission::Idle);
        }
        match backend {
            Backend::Direct => self.direct.as_mut().map(|r| r.start(route, search, seen)),
            Backend::Gap | Backend::Dht => self
                .secondary
                .as_mut()
                .map(|r| r.start(route, search, seen)),
            Backend::Provider => None,
        }
        .unwrap_or(Ok(RouteAdmission::Idle))
    }
    fn poll_backend(
        &mut self,
        backend: Backend,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, Failure>> {
        let physically_closed = match backend {
            Backend::Direct => self.direct_retired,
            Backend::Gap | Backend::Dht => self.secondary_retired,
            Backend::Provider => true,
        };
        if physically_closed {
            return Poll::Pending;
        }
        // An independently composed provider can be physically retired yet
        // retain original terminal observations. Drain those before skipping it.
        let progress = match backend {
            Backend::Direct => self.direct.as_mut().map(|r| r.poll(cx, deliver)),
            Backend::Gap | Backend::Dht => self.secondary.as_mut().map(|r| r.poll(cx, deliver)),
            Backend::Provider => None,
        };
        let Some(Poll::Ready(progress)) = progress else {
            return Poll::Pending;
        };
        let progress = match progress {
            Ok(progress) => progress,
            Err(cause) => {
                let failure = self.failed(backend, cause);
                return Poll::Ready(if failure.is_fatal() {
                    Err(failure.into_failure())
                } else {
                    Ok(PeerProgress::Activity)
                });
            }
        };
        let serial = match &progress {
            PeerProgress::Reply { route, .. }
            | PeerProgress::CadetReply { route, .. }
            | PeerProgress::GapReply { route, .. }
            | PeerProgress::Ended(route) => *route,
            PeerProgress::Activity => return Poll::Ready(Ok(progress)),
        };
        let Some(index) = self
            .routes
            .iter()
            .position(|r| r.serial == serial && r.live(backend))
        else {
            if matches!(progress, PeerProgress::Ended(_)) {
                // A successfully cancelled original consumer no longer owns a
                // Pair slot; its backend may still report actual retirement.
                return Poll::Ready(Ok(PeerProgress::Activity));
            }
            let failure = self.failed(backend, Failure::operation(ProtocolError::Authentication));
            return Poll::Ready(if failure.is_fatal() {
                Err(failure.into_failure())
            } else {
                Ok(PeerProgress::Activity)
            });
        };
        if matches!(progress, PeerProgress::Ended(_)) {
            self.routes[index].end(backend);
            if self.routes[index].complete() {
                self.routes.swap_remove(index);
            } else {
                // Ended revokes this child's delivery authority only. Its
                // provider still polls original native cleanup, while the
                // other already-admitted child can produce actual results.
                return Poll::Ready(Ok(PeerProgress::Activity));
            }
        } else if !deliver {
            let failure = self.failed(backend, Failure::operation(ProtocolError::Capacity));
            return Poll::Ready(if failure.is_fatal() {
                Err(failure.into_failure())
            } else {
                Ok(PeerProgress::Activity)
            });
        }
        Poll::Ready(Ok(progress))
    }
}
impl<A: PeerRouter, B: PeerRouter> PeerRouter for Pair<A, B> {
    fn initialized(&self) -> bool {
        self.direct.as_ref().is_none_or(PeerRouter::initialized)
            && self.secondary.as_ref().is_none_or(PeerRouter::initialized)
    }
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Failure> {
        if self.stopping || self.closed {
            return Ok(RouteAdmission::Idle);
        }
        if self.pending_fatal.is_some() {
            return Ok(RouteAdmission::Refused);
        }
        if route <= self.last_route {
            return Err(Failure::operation(ProtocolError::StaleGeneration));
        }
        if self.routes.len() == self.capacity {
            return Err(Failure::operation(ProtocolError::Capacity));
        }
        self.last_route = route;
        let mut backend = match self.selection {
            Selection::Anonymity
                if search.anonymity != 0
                    || search.target == [0; 32]
                        && matches!(
                            search.block_type,
                            gnunet_wire::official::fs::BlockType::DBLOCK
                                | gnunet_wire::official::fs::BlockType::IBLOCK
                        ) =>
            {
                Backend::Gap
            }
            Selection::Anonymity => Backend::Direct,
            Selection::NonAnonymous if search.anonymity != 0 => return Ok(RouteAdmission::Idle),
            Selection::NonAnonymous
                if search.block_type == gnunet_wire::official::fs::BlockType::UBLOCK =>
            {
                Backend::Dht
            }
            Selection::NonAnonymous => Backend::Direct,
        };
        // This original plan is fixed before the first provider can admit any
        // effect. Its independent CORE child is not inferred later from Idle,
        // Refused, a timeout or Ended.
        let planned_gap = self.discovery
            && backend == Backend::Direct
            && search.anonymity == 0
            && search.options & SEARCH_LOOPBACK_ONLY == 0
            && matches!(
                search.block_type,
                BlockType::DBLOCK | BlockType::IBLOCK | BlockType::UBLOCK
            );
        // The fixed-capacity parent slot is reserved before either child can
        // admit a native effect. No allocation or fallible parent insertion
        // remains after a child reports Queued.
        let index = self.routes.len();
        self.routes.push(Route {
            serial: route,
            backend,
            ended: false,
            additional: None,
            additional_ended: false,
        });
        let mut result = self.start_backend(backend, route, search, seen);
        if !planned_gap
            && self.selection == Selection::Anonymity
            && backend == Backend::Direct
            && search.anonymity == 0
            && matches!(
                search.block_type,
                gnunet_wire::official::fs::BlockType::DBLOCK
                    | gnunet_wire::official::fs::BlockType::IBLOCK
                    | gnunet_wire::official::fs::BlockType::UBLOCK
            )
            && matches!(&result, Ok(RouteAdmission::Idle))
        {
            // Idle is the provider's explicit no-effect contract. No original
            // child route, timer or native debt is transferred or restarted.
            backend = Backend::Gap;
            self.routes[index].backend = backend;
            result = self.start_backend(backend, route, search, seen);
        }
        if planned_gap {
            let primary_queued = matches!(&result, Ok(RouteAdmission::Queued));
            let primary_refused = match result {
                Ok(RouteAdmission::Queued | RouteAdmission::Idle) => false,
                Ok(RouteAdmission::Refused) => true,
                Err(cause) => {
                    let failure = self.failed(backend, cause);
                    if failure.is_fatal() {
                        self.routes.swap_remove(index);
                        return Err(failure.into_failure());
                    }
                    true
                }
            };
            // The CORE branch was part of the original plan even when the
            // optional primary refuses. Its cause and physical retirement stay
            // with that provider; no first-child effect is transferred/replayed.
            return match self.start_backend(Backend::Gap, route, search, seen) {
                Ok(RouteAdmission::Queued) => {
                    if primary_queued {
                        self.routes[index].additional = Some(Backend::Gap);
                    } else {
                        self.routes[index] = Route {
                            serial: route,
                            backend: Backend::Gap,
                            ended: false,
                            additional: None,
                            additional_ended: false,
                        };
                    }
                    Ok(RouteAdmission::Queued)
                }
                Ok(admission @ (RouteAdmission::Idle | RouteAdmission::Refused)) => {
                    if primary_queued {
                        Ok(RouteAdmission::Queued)
                    } else {
                        self.routes.swap_remove(index);
                        Ok(if primary_refused {
                            RouteAdmission::Refused
                        } else {
                            admission
                        })
                    }
                }
                Err(cause) => {
                    let failure = self.failed(Backend::Gap, cause);
                    if primary_queued {
                        if failure.is_fatal() && self.pending_fatal.is_none() {
                            // Keep the admitted primary for normal poll/error
                            // shutdown, never a no-route admission-error path.
                            self.pending_fatal = Some(failure);
                        }
                        Ok(RouteAdmission::Queued)
                    } else {
                        self.routes.swap_remove(index);
                        if failure.is_fatal() {
                            Err(failure.into_failure())
                        } else {
                            Ok(RouteAdmission::Refused)
                        }
                    }
                }
            };
        }
        match result {
            Ok(RouteAdmission::Queued) => Ok(RouteAdmission::Queued),
            Ok(admission @ (RouteAdmission::Idle | RouteAdmission::Refused)) => {
                self.routes.swap_remove(index);
                Ok(admission)
            }
            Err(cause) => {
                let failure = self.failed(backend, cause);
                self.routes.swap_remove(index);
                if failure.is_fatal() {
                    Err(failure.into_failure())
                } else {
                    // An outer Pair must not reinterpret a nested provider
                    // failure/physical retirement as an unadmitted Idle.
                    Ok(RouteAdmission::Refused)
                }
            }
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>, deliver: bool) -> Poll<Result<PeerProgress, Failure>> {
        if let Some(failure) = self.pending_fatal.take() {
            return Poll::Ready(Err(failure.into_failure()));
        }
        if let Some(index) = self.routes.iter().position(Route::complete) {
            return Poll::Ready(Ok(PeerProgress::Ended(
                self.routes.swap_remove(index).serial,
            )));
        }
        if self.closed {
            return Poll::Pending;
        }
        let second = if self.first == Backend::Direct {
            self.secondary_backend()
        } else {
            Backend::Direct
        };
        for backend in [self.first, second] {
            if let Poll::Ready(result) = self.poll_backend(backend, cx, deliver) {
                self.first = if backend == Backend::Direct {
                    self.secondary_backend()
                } else {
                    Backend::Direct
                };
                // Return the first ready owner immediately. A later backend
                // error cannot consume or overwrite this owner's positive.
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    }
    fn input_needed(&self) -> Option<u64> {
        if self.closed || self.stopping || self.pending_fatal.is_some() {
            return None;
        }
        // Preserve the actual child's request; an unknown serial remains an
        // ownership fault for refresh/the canonical host, never a new query.
        if !self.direct_retired
            && let Some(route) = self.direct.as_ref().and_then(PeerRouter::input_needed)
        {
            return Some(route);
        }
        if !self.secondary_retired {
            return self.secondary.as_ref().and_then(PeerRouter::input_needed);
        }
        None
    }
    fn refresh(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<(), Failure> {
        if self.closed || self.stopping || self.pending_fatal.is_some() {
            return Err(Failure::operation(ProtocolError::Closed));
        }
        let owner = self
            .routes
            .iter()
            .find(|r| r.serial == route)
            .copied()
            .ok_or_else(|| Failure::operation(ProtocolError::StaleGeneration))?;
        let backend = if owner.live(Backend::Direct)
            && !self.direct_retired
            && self.direct.as_ref().and_then(PeerRouter::input_needed) == Some(route)
        {
            Backend::Direct
        } else if owner.live(self.secondary_backend())
            && !self.secondary_retired
            && self.secondary.as_ref().and_then(PeerRouter::input_needed) == Some(route)
        {
            self.secondary_backend()
        } else {
            return Err(Failure::operation(ProtocolError::StaleGeneration));
        };
        let result = match backend {
            Backend::Direct => self
                .direct
                .as_mut()
                .ok_or_else(|| Failure::operation(ProtocolError::NotReady))?
                .refresh(route, search, seen),
            Backend::Gap | Backend::Dht => self
                .secondary
                .as_mut()
                .ok_or_else(|| Failure::operation(ProtocolError::NotReady))?
                .refresh(route, search, seen),
            Backend::Provider => return Err(Failure::operation(ProtocolError::InvalidInput)),
        };
        if let Err(cause) = result {
            let failure = self.failed(backend, cause);
            if failure.is_fatal() {
                return Err(failure.into_failure());
            }
        }
        Ok(())
    }
    fn cancel(&mut self, route: u64) -> Result<(), Failure> {
        let Some(index) = self.routes.iter().position(|r| r.serial == route) else {
            return Ok(());
        };
        let owner = self.routes[index];
        let mut fatal = None;
        for backend in [Some(owner.backend), owner.additional]
            .into_iter()
            .flatten()
        {
            if self.backend_state(backend) == Some(PeerShutdown::Retired) {
                continue;
            }
            let result = match backend {
                Backend::Direct => self.direct.as_mut().map(|r| r.cancel(route)),
                Backend::Gap | Backend::Dht => self.secondary.as_mut().map(|r| r.cancel(route)),
                Backend::Provider => None,
            }
            .unwrap_or(Ok(()));
            if let Err(cause) = result {
                let failure = self.failed(backend, cause);
                if failure.is_fatal() && fatal.is_none() {
                    fatal = Some(failure);
                }
            }
        }
        // Revoke both original callbacks even if one cancel/close failed.
        // Each backend retains its actual native drain owner after local
        // authority is removed; no Ended or remote cancel is synthesized.
        self.routes.swap_remove(index);
        match fatal {
            Some(failure) => Err(failure.into_failure()),
            None => Ok(()),
        }
    }
    fn request_shutdown(&mut self) {
        if self.stopping || self.closed {
            return;
        }
        self.stopping = true;
        if !self.direct_retired
            && let Some(router) = &mut self.direct
        {
            router.request_shutdown();
        }
        if !self.secondary_retired
            && let Some(router) = &mut self.secondary
        {
            router.request_shutdown();
        }
        for backend in [Backend::Direct, self.secondary_backend()] {
            if self.backend_state(backend) == Some(PeerShutdown::Immediate)
                && let Some(cause) = self.close_backend(backend)
            {
                let failure = PeerFailure::new(backend, cause, None);
                match backend {
                    Backend::Direct => self.shutdown_direct = Some(failure.cause.clone()),
                    Backend::Gap | Backend::Dht => {
                        self.shutdown_secondary = Some(failure.cause.clone())
                    }
                    Backend::Provider => {}
                }
                self.remember(&failure);
                if failure.is_fatal() && self.pending_fatal.is_none() {
                    self.pending_fatal = Some(failure);
                }
            }
        }
    }
    fn shutdown_state(&self) -> PeerShutdown {
        if self.closed {
            return PeerShutdown::Retired;
        }
        if self.pending_fatal.is_some() {
            return PeerShutdown::Draining;
        }
        let states = [
            self.backend_state(Backend::Direct),
            self.backend_state(self.secondary_backend()),
        ];
        if states.contains(&Some(PeerShutdown::Draining)) {
            PeerShutdown::Draining
        } else if states.contains(&Some(PeerShutdown::Immediate)) {
            PeerShutdown::Immediate
        } else if states.iter().any(Option::is_some)
            && states
                .iter()
                .all(|state| state.is_none_or(|s| s == PeerShutdown::Retired))
        {
            PeerShutdown::Retired
        } else {
            PeerShutdown::Quiesced
        }
    }
    fn close(&mut self) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        // Both closes are independent even when the first one refuses.
        let direct = self
            .close_backend(Backend::Direct)
            .map(Arc::new)
            .or_else(|| self.shutdown_direct.take());
        let secondary = self
            .close_backend(self.secondary_backend())
            .map(Arc::new)
            .or_else(|| self.shutdown_secondary.take());
        self.closed = true;
        self.stopping = true;
        self.routes.clear();
        if direct.is_none() && secondary.is_none() {
            return match self.pending_fatal.take() {
                Some(failure) => Err(failure.into_failure()),
                None => Ok(()),
            };
        }
        let failure = if let Some(original) = &self.first_failure {
            PeerFailure {
                backend: original.backend,
                cause: original.cause.clone(),
                cleanup: Some(Arc::new(
                    Cleanup {
                        previous: original.cleanup.clone(),
                        direct,
                        secondary,
                    }
                    .into_failure(),
                )),
            }
        } else {
            let (backend, cause, cleanup) = match (direct, secondary) {
                (Some(cause), cleanup) => (Backend::Direct, cause, cleanup),
                (None, Some(cause)) => (self.secondary_backend(), cause, None),
                (None, None) => return Ok(()),
            };
            PeerFailure {
                backend,
                cause,
                cleanup,
            }
        };
        self.remember(&failure);
        Err(failure.into_failure())
    }
}
