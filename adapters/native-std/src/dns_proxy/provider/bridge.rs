//! Fixed lifecycle slots and a pre-reserved incoming flow queue.
#[cfg(target_os = "macos")]
use super::class;
use super::{
    accepted::{AcceptedFlow, TcpFlowLoan, UdpFlowLoan},
    lease::{Counter, Session},
    native::{NativeIncoming, NativeProvider, StartCompletion, StopCompletion},
    requests::{StartRequest, StopRequest},
};
use std::{
    collections::VecDeque,
    fmt, io,
    path::PathBuf,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[cfg(target_os = "macos")]
static REGISTERED: std::sync::OnceLock<Arc<Bridge>> = std::sync::OnceLock::new();
mod gate;
use gate::Phase;

/// Bounds reserved before native provider callbacks can claim flows.
#[derive(Clone, Copy, Debug)]
pub struct ProviderLimits {
    /// Maximum pending incoming flows; resource loans also bound adopted flows.
    pub pending_flows: usize,
    /// Maximum original flow/connection groups, including outstanding callbacks.
    pub native_resources: usize,
}
impl Default for ProviderLimits {
    fn default() -> Self {
        Self {
            pending_flows: 64,
            native_resources: 256,
        }
    }
}
/// One original native provider event, with exclusive completion/flow ownership.
#[derive(Debug)]
pub enum Event {
    /// The host must establish its configured service before reporting readiness.
    Start(StartRequest),
    /// One original SDK flow retained before native acceptance.
    Flow(AcceptedFlow),
    /// Admission has closed; complete only after the host and native loans drain.
    Stop(StopRequest),
}
/// Unique Rust consumer for one native DNS provider session.
pub struct Controller {
    bridge: Arc<Bridge>,
}
/// Cloneable cancellation handle without event-receiving authority.
#[derive(Clone)]
pub struct ShutdownHandle {
    bridge: Arc<Bridge>,
}
impl ShutdownHandle {
    /// Close admission and wake the owner while retaining any accepted stop request.
    pub fn request_shutdown(&self) {
        self.bridge.request_shutdown();
    }
}
impl fmt::Debug for ShutdownHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsProviderShutdown")
    }
}
impl fmt::Debug for Controller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsProviderController")
    }
}
impl Controller {
    /// Retain cancellation authority while moving this unique consumer to a host.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            bridge: Arc::clone(&self.bridge),
        }
    }
    /// Define and register the native class without activating any provider.
    /// # Errors
    /// Refuses invalid bounds, unavailable SDK classes, allocation failure and a
    /// second controller registration in this process.
    #[cfg(target_os = "macos")]
    pub fn register(limits: ProviderLimits) -> io::Result<Self> {
        let controller = Self::new(limits)?;
        class::register()?;
        REGISTERED
            .set(Arc::clone(&controller.bridge))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "DNS provider controller already registered",
                )
            })?;
        Ok(controller)
    }

    /// Reserve one iOS app extension DNS provider session and its callback input.
    /// Each new session has independent admission and retirement state.
    ///
    /// # Errors
    /// Refuses unsupported SDK selectors, invalid bounds and allocation failure.
    #[cfg(target_os = "ios")]
    pub fn for_app_extension(
        limits: ProviderLimits,
    ) -> io::Result<(Self, super::AppExtensionCallbacks)> {
        super::availability::check()?;
        let controller = Self::new(limits)?;
        let callbacks = super::AppExtensionCallbacks(Arc::clone(&controller.bridge));
        Ok((controller, callbacks))
    }

    fn new(limits: ProviderLimits) -> io::Result<Self> {
        if limits.pending_flows == 0
            || limits.pending_flows > 1024
            || limits.native_resources < limits.pending_flows
            || limits.native_resources > 4096
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS provider bounds",
            ));
        }
        let mut flows = VecDeque::new();
        flows
            .try_reserve_exact(limits.pending_flows)
            .map_err(|_| io::Error::other("DNS provider queue reservation refused"))?;
        let bridge = Arc::new(Bridge {
            state: Mutex::new(State {
                phase: Phase::Registered,
                provider: None,
                start: None,
                stop: None,
                flows,
                flow_limit: limits.pending_flows,
                error: None,
                waker: None,
            }),
            session: Session {
                counter: Counter::new(limits.native_resources),
            },
        });
        Ok(Self { bridge })
    }
    /// Poll one bounded native event. No native SDK object pointer is exposed.
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Event>> {
        let candidate = cx.waker().clone();
        let (event, previous) = {
            let mut state = self
                .bridge
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let event = if let Some(start) = state.start.take() {
                Some(Ok(Event::Start(StartRequest::new(
                    Arc::clone(&self.bridge),
                    start,
                ))))
            } else if let Some(stop) = state.stop.take() {
                Some(Ok(Event::Stop(StopRequest::new(
                    Arc::clone(&self.bridge),
                    stop,
                ))))
            } else if let Some(flow) = state.flows.pop_front() {
                Some(Ok(Event::Flow(flow)))
            } else if let Some(error) = state.error.take() {
                Some(Err(error))
            } else if matches!(state.phase, Phase::Ended | Phase::Failed) {
                Some(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "DNS provider controller closed",
                )))
            } else {
                None
            };
            let previous = if event.is_some() {
                state.waker.take()
            } else {
                state.waker.replace(candidate)
            };
            (event, previous)
        };
        drop(previous);
        match event {
            Some(event) => Poll::Ready(event),
            None => Poll::Pending,
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.bridge.abandon();
    }
}

pub(super) struct StartData {
    pub provider: NativeProvider,
    pub callback: StartCompletion,
    pub configuration: PathBuf,
}
pub(super) struct StopData {
    pub provider: NativeProvider,
    pub callback: StopCompletion,
    pub reason: isize,
    pub queued: VecDeque<AcceptedFlow>,
}
struct State {
    phase: Phase,
    provider: Option<NativeProvider>,
    start: Option<StartData>,
    stop: Option<StopData>,
    flows: VecDeque<AcceptedFlow>,
    flow_limit: usize,
    error: Option<io::Error>,
    waker: Option<Waker>,
}
pub(super) struct Bridge {
    state: Mutex<State>,
    pub session: Session,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Close {
    PreserveStop,
    Abandon,
}
#[cfg(target_os = "macos")]
pub(super) fn registered() -> Option<&'static Arc<Bridge>> {
    REGISTERED.get()
}
impl Bridge {
    pub(super) fn start(
        &self,
        provider: NativeProvider,
        configuration: PathBuf,
        callback: StartCompletion,
    ) {
        let mut provider_owner = Some(provider.clone());
        let mut rejected = Some(StartData {
            provider,
            callback,
            configuration,
        });
        let wake = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.phase.begin_start(&self.session.counter) {
                if let Some(start) = rejected.take() {
                    state.provider = provider_owner.take();
                    state.start = Some(start);
                }
                state.waker.take()
            } else {
                None
            }
        };
        drop(provider_owner);
        drop(rejected); // StartCompletion Drop reports native failure.
        wake_owner(wake);
    }
    #[cfg(target_os = "macos")]
    pub(super) fn failed_start(&self, error: io::Error) {
        let wake = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.phase.fail_start(&self.session.counter) {
                state.error = Some(error);
                state.waker.take()
            } else {
                None
            }
        };
        wake_owner(wake);
    }
    pub(super) fn accept(
        &self,
        provider: &NativeProvider,
        native: NativeIncoming,
        udp: bool,
    ) -> bool {
        let mut native = Some(native);
        let (accepted, wake) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.phase != Phase::Running
                || !state
                    .provider
                    .as_ref()
                    .is_some_and(|original| original.same(provider))
                || state.flows.len() >= state.flow_limit
            {
                (false, None)
            } else if let Ok(lease) = self.session.lease() {
                if let Some(native) = native.take() {
                    state.flows.push_back(if udp {
                        AcceptedFlow::Udp(UdpFlowLoan { native, lease })
                    } else {
                        AcceptedFlow::Tcp(TcpFlowLoan { native, lease })
                    });
                }
                (true, state.waker.take())
            } else {
                (false, None)
            }
        };
        // A false native verdict leaves ownership with the framework. Do not
        // close its unopened flow redundantly when our retained loan is refused.
        if let Some(mut native) = native {
            native.disarm();
        }
        wake_owner(wake);
        accepted
    }
    pub(super) fn stop(
        &self,
        provider: NativeProvider,
        reason: isize,
        callback: StopCompletion,
    ) -> Result<(), NativeProvider> {
        let mut incoming = Some((provider, callback));
        let wake = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let matching = incoming.as_ref().is_some_and(|(provider, _)| {
                state
                    .provider
                    .as_ref()
                    .is_some_and(|original| original.same(provider))
            });
            if matching
                && matches!(state.phase, Phase::Starting | Phase::Running)
                && state.stop.is_none()
            {
                self.session.counter.close();
                state.phase = Phase::Stopping;
                let queued = std::mem::take(&mut state.flows);
                if let Some((provider, callback)) = incoming.take() {
                    state.stop = Some(StopData {
                        provider,
                        callback,
                        reason,
                        queued,
                    });
                }
                state.waker.take()
            } else {
                None
            }
        };
        if let Some((provider, _callback)) = incoming {
            return Err(provider);
        }
        wake_owner(wake);
        Ok(())
    }
    pub(super) fn ready(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != Phase::Starting {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DNS provider stopped before readiness",
            ));
        }
        state.phase = Phase::Running;
        Ok(())
    }
    pub(super) fn request_shutdown(&self) {
        self.close(Close::PreserveStop);
    }
    pub(super) fn abandon(&self) {
        self.close(Close::Abandon);
    }
    pub(super) fn stopped(&self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != Phase::Stopping {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "DNS provider stop obligation is no longer live",
            ));
        }
        state.phase = Phase::Ended;
        let provider = state.provider.take();
        drop(state);
        drop(provider);
        Ok(())
    }
    fn close(&self, mode: Close) {
        let (provider, start, stop, flows, wake) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.phase == Phase::Ended
                || (state.phase == Phase::Stopping && mode == Close::PreserveStop)
            {
                return;
            }
            state.phase.fail(&self.session.counter);
            (
                state.provider.take(),
                state.start.take(),
                state.stop.take(),
                std::mem::take(&mut state.flows),
                state.waker.take(),
            )
        };
        if let Some(provider) = provider {
            provider.cancel();
        }
        drop((start, stop, flows));
        wake_owner(wake);
    }
}
fn wake_owner(waker: Option<Waker>) {
    if let Some(waker) = waker {
        super::native::contain(|| waker.wake());
    }
}
