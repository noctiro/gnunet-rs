//! Real ARM managed listener ownership and nonconsuming readiness leases.
//! No method accepts a connection. Original descriptors remain parent-owned for
//! future child inheritance; only explicit Close or aggregate Drop consumes them.
use crate::{
    addresses::{Address, Addresses},
    registry::Registry,
};
use gnunet_arm_service_core::{ListenerAction, ListenerEffect, ListenerId, Owner, ReadinessId};
use gnunet_config::{Configuration, Environment};
use gnunet_service_runtime::readiness::{Readiness, RegisteredListener};
use gnunet_service_runtime::{ActivatedSocket, CreatedPath, LocalListenerAccess};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
use std::{
    fmt, io,
    task::{Context, Poll},
};
mod bind;
/// Observable nonfatal collection/bind failure. A registered service is retained
/// even when every configured listener fails, as in the official setup callback.
#[derive(Debug)]
pub enum Failure {
    /// Entire address collection for this service failed.
    Addresses {
        /// Registry entry index.
        service: usize,
        /// Actual collection failure.
        error: crate::addresses::Error,
    },
    /// Nonfatal collection diagnostic.
    Diagnostic {
        /// Registry entry index.
        service: usize,
        /// Actual source diagnostic.
        diagnostic: crate::addresses::Diagnostic,
    },
    /// Individual bind/listen/registration failed; no core listener was invented.
    Bind {
        /// Registry entry index.
        service: usize,
        /// Requested endpoint.
        address: Address,
        /// Actual failure.
        error: io::Error,
    },
    /// Permission, parent creation or source-nonfatal option failure.
    Warning {
        /// Registry entry index.
        service: usize,
        /// Requested endpoint.
        address: Address,
        /// Actual warning.
        error: io::Error,
    },
}
/// Host resource/protocol failure. Busy is retained as a retryable core outcome.
#[derive(Debug)]
pub enum Error {
    /// A registry preparation already completed, failed or was canceled. Retire
    /// the retained owner before starting another whole-registry preparation.
    PreparationStarted,
    /// Caller configured listener maximum is exhausted.
    Capacity,
    /// Source registry and core service IDs do not match, or no actual FD exists.
    Mapping,
    /// Checked core lifecycle/lease error; authority is not fabricated or replaced.
    Core(gnunet_arm_service_core::Error),
    /// Actual nonconsuming readiness probe failed.
    Io(io::Error),
    /// Actual exceptional readiness is retained, not treated as demand/spawn success.
    Exceptional(Readiness),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreparationStarted => {
                f.write_str("ARM registry listener preparation already started")
            }
            Self::Capacity => f.write_str("ARM listener capacity exhausted"),
            Self::Mapping => f.write_str("ARM listener ownership mapping mismatch"),
            Self::Core(error) => write!(f, "ARM listener state: {error:?}"),
            Self::Io(error) => error.fmt(f),
            Self::Exceptional(readiness) => {
                write!(f, "ARM listener exceptional readiness: {readiness:?}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<gnunet_arm_service_core::Error> for Error {
    fn from(error: gnunet_arm_service_core::Error) -> Self {
        Self::Core(error)
    }
}
/// Exact actual result of one nonfatal source-style binding attempt.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindOutcome {
    /// A real listener now exists at this registry index.
    Bound {
        /// Actual original-resource index.
        index: usize,
    },
    /// No listener was created; Failure::Bind records the actual OS error.
    Failed,
}
/// One exact armed registration observed ready, retained inside the owner until
/// delivery. Cancellation after polling cannot lose this one-shot authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event<'scope> {
    /// Actual original listener lifetime.
    pub listener: ListenerId<'scope>,
    /// Exact one-shot readiness epoch granted by the pure owner.
    pub registration: ReadinessId<'scope>,
    /// Nonconsuming kernel result, not inferred from a stale reactor hint.
    pub readiness: Readiness,
}
struct Entry<'scope> {
    // Field order is intentional: close/deregister the descriptor before unlink.
    port: Option<RegisteredListener>,
    path: Option<CreatedPath>,
    address: Address,
    service: usize,
    id: Option<ListenerId<'scope>>,
    armed: Option<ReadinessId<'scope>>,
}
/// Parent-owned listeners and pending core leases. Binding and attachment are
/// explicit startup phases; partially attached resources remain owned on error.
/// Drop closes all descriptors before their corresponding owned path guards.
pub struct ManagedListeners<'scope> {
    entries: Vec<Entry<'scope>>,
    failures: Vec<Failure>,
    maximum: usize,
    pending: Option<ListenerEffect<'scope>>,
    ready: Option<Event<'scope>>,
    preparation: Preparation,
}
/// Whole-registry preparation state, independent of core listener attachment.
/// Incomplete preparation can own actual listeners; it is never retry-from-zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preparation {
    /// No whole-registry preparation was admitted.
    NotStarted,
    /// Started but not returned successfully, including canceled or failed work.
    Incomplete,
    /// Completed all collection/bind attempts; inspect nonfatal failures too.
    Complete,
}
impl<'scope> ManagedListeners<'scope> {
    fn check_owner(&self, owner: &Owner<'scope, '_, '_, '_>) -> Result<(), Error> {
        for entry in &self.entries {
            if let Some(id) = entry.id {
                owner.readiness(id)?;
            }
        }
        Ok(())
    }
    /// Empty bounded native registry. No descriptor/configuration is assumed.
    pub fn new(maximum: usize) -> Self {
        Self {
            entries: Vec::new(),
            failures: Vec::new(),
            maximum,
            pending: None,
            ready: None,
            preparation: Preparation::NotStarted,
        }
    }
    /// Bind eligible entries from the immutable registry. Individual source
    /// address/bind failures are retained and do not unregister the service.
    /// On Windows, a malformed local restriction fails that AF_UNIX bind
    /// before selecting its account or creating the endpoint.
    /// Resource maximum errors reject before the next native bind, retaining all
    /// earlier real listeners in this value so shutdown can consume them safely.
    /// Call inside an entered Tokio runtime with its I/O driver enabled, as
    /// required by the shared descriptor registration.
    /// Cancellation retains partial original listeners and marks preparation
    /// incomplete. Retire this owner to abort; repeated preparation is refused.
    pub async fn bind_registry(
        &mut self,
        config: &Configuration,
        registry: &Registry,
        environment: &impl Environment,
        addresses_per_service: usize,
    ) -> Result<(), Error> {
        if self.preparation != Preparation::NotStarted {
            return Err(Error::PreparationStarted);
        }
        self.preparation = Preparation::Incomplete;
        let first = self.entries.len();
        for (index, service) in registry.services().iter().enumerate().rev() {
            if !service.bind {
                continue;
            }
            let addresses = match Addresses::from_config(
                config,
                &service.name,
                environment,
                addresses_per_service,
            ) {
                Ok(addresses) => addresses,
                Err(error) => {
                    self.failures.push(Failure::Addresses {
                        service: index,
                        error,
                    });
                    continue;
                }
            };
            for diagnostic in addresses.diagnostics {
                self.failures.push(Failure::Diagnostic {
                    service: index,
                    diagnostic,
                });
            }
            #[cfg(unix)]
            let access = if matches!(config.get_yesno(&service.name, b"UNIX_MATCH_UID"), Ok(true)) {
                LocalListenerAccess::Owner
            } else if matches!(config.get_yesno(&service.name, b"UNIX_MATCH_GID"), Ok(true)) {
                LocalListenerAccess::Group
            } else {
                LocalListenerAccess::Everyone
            };
            let start = self.entries.len();
            for address in addresses.addresses {
                #[cfg(windows)]
                let bind_access = if let Address::Unix(path) = &address {
                    use gnunet_service_runtime::credentials::UnixAccess;
                    let access = match UnixAccess::from_config(config, &service.name) {
                        Ok(access) => LocalListenerAccess::from(access.unwrap_or_default()),
                        Err(error) => {
                            self.failures.push(Failure::Bind {
                                service: index,
                                address,
                                error: io::Error::new(io::ErrorKind::InvalidInput, error),
                            });
                            continue;
                        }
                    };
                    if let crate::registry::WindowsAccount::Dedicated { sid, credential } =
                        &service.account
                    {
                        if self.entries.len() == self.maximum {
                            return Err(Error::Capacity);
                        }
                        match crate::process::AccountPreparation::for_listener(
                            sid,
                            credential,
                            path.clone(),
                            access.into(),
                        )
                        .await
                        {
                            Ok(bind) => bind::Access::Account(Box::new(bind)),
                            Err(error) => {
                                self.failures.push(Failure::Bind {
                                    service: index,
                                    address,
                                    error,
                                });
                                continue;
                            }
                        }
                    } else {
                        bind::Access::Current(access)
                    }
                } else {
                    bind::Access::Current(LocalListenerAccess::default())
                };
                #[cfg(unix)]
                let bind_access = bind::Access::Current(access);
                match self
                    .bind_address_with_access(index, address, bind_access)
                    .await?
                {
                    BindOutcome::Bound { .. } | BindOutcome::Failed => {}
                }
            }
            self.entries[start..].reverse();
        }
        // setup_service binds in config iterator order, while each listening
        // DLL and the service DLL are head-inserted for later traversal.
        self.entries[first..].sort_by_key(|entry| entry.service);
        self.preparation = Preparation::Complete;
        Ok(())
    }
    /// Actual whole-registry preparation state, including abandoned work.
    #[must_use]
    pub const fn preparation(&self) -> Preparation {
        self.preparation
    }
    /// Bind one explicit endpoint using the ARM reuse/V6ONLY/backlog5 policy.
    /// Direct ephemeral TCP addresses are permitted for owned local fixtures;
    /// configuration collection never turns PORT0 into an ephemeral listener.
    /// Requires an entered Tokio runtime with its I/O driver enabled.
    pub async fn bind_address(
        &mut self,
        service: usize,
        address: Address,
        access: LocalListenerAccess,
    ) -> Result<BindOutcome, Error> {
        self.bind_address_with_access(service, address, bind::Access::Current(access))
            .await
    }

    async fn bind_address_with_access(
        &mut self,
        service: usize,
        address: Address,
        access: bind::Access,
    ) -> Result<BindOutcome, Error> {
        if self.entries.len() == self.maximum {
            return Err(Error::Capacity);
        }
        let index = self.entries.len();
        let mut warnings = Vec::new();
        match bind::prepare(&address, access, &mut warnings).await {
            Ok(bind::Bound {
                port,
                path,
                address,
            }) => self.entries.push(Entry {
                port: Some(port),
                path,
                address,
                service,
                id: None,
                armed: None,
            }),
            Err(error) => self.failures.push(Failure::Bind {
                service,
                address: address.clone(),
                error,
            }),
        }
        for error in warnings {
            self.failures.push(Failure::Warning {
                service,
                address: address.clone(),
                error,
            });
        }
        Ok(if self.entries.len() > index {
            BindOutcome::Bound { index }
        } else {
            BindOutcome::Failed
        })
    }
    /// Adopt a separately captured, caller-offered managed listener, preserving
    /// its pathname ownership with the parent. This is not ARM's own generic
    /// CLOSE_LSOCKS activation mode and does not bypass ARM configuration.
    /// Requires an entered Tokio runtime with its I/O driver enabled.
    pub fn adopt(&mut self, service: usize, socket: ActivatedSocket) -> Result<(), Error> {
        if self.entries.len() == self.maximum {
            return Err(Error::Capacity);
        }
        let bind::Bound {
            port,
            address,
            path,
        } = bind::adopt(socket).map_err(Error::Io)?;
        self.entries.push(Entry {
            port: Some(port),
            path,
            address,
            service,
            id: None,
            armed: None,
        });
        Ok(())
    }
    /// Attach each real listener once while the core remains Configuring.
    /// A failure keeps earlier IDs/descriptors, so the owner can explicitly abort
    /// startup or finish shutdown; this never pretends attachment was atomic.
    pub fn attach(&mut self, owner: &mut Owner<'scope, '_, '_, '_>) -> Result<(), Error> {
        self.check_owner(owner)?;
        for entry in &mut self.entries {
            if entry.id.is_none() {
                let service = owner.service(entry.service).ok_or(Error::Mapping)?;
                entry.id = Some(owner.register_listener(service)?);
            }
        }
        Ok(())
    }
    /// Apply at most one leased listener effect, without await/callback points.
    /// The pending lease remains stored on validation/error for explicit retry.
    /// Close drops the actual FD then the inode guard before acknowledging core.
    pub fn apply_next(&mut self, owner: &mut Owner<'scope, '_, '_, '_>) -> Result<bool, Error> {
        self.check_owner(owner)?;
        let effect = if let Some(effect) = self.pending {
            Some(effect)
        } else {
            owner.take_listener()?
        };
        let Some(effect) = effect else {
            return Ok(false);
        };
        self.pending = Some(effect);
        if !owner.listener_current(effect.ticket) {
            return Err(Error::Core(gnunet_arm_service_core::Error::Stale));
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == Some(effect.listener))
            .ok_or(Error::Mapping)?;
        match effect.action {
            ListenerAction::Arm => {
                if entry.port.is_none() {
                    return Err(Error::Mapping);
                }
            }
            ListenerAction::Disarm => {
                entry.armed = None;
                if self
                    .ready
                    .is_some_and(|event| event.listener == effect.listener)
                {
                    self.ready = None;
                }
            }
            ListenerAction::Close => {
                entry.armed = None;
                if self
                    .ready
                    .is_some_and(|event| event.listener == effect.listener)
                {
                    self.ready = None;
                }
                drop(entry.port.take());
                drop(entry.path.take());
            }
        }
        owner.listener_applied(effect.ticket)?;
        if effect.action == ListenerAction::Arm {
            entry.armed = owner.readiness(effect.listener)?;
        }
        self.pending = None;
        Ok(true)
    }
    /// Poll only currently armed listeners without accepting or reading. The
    /// first observed event is stored before returning and retained across a
    /// canceled caller future. Exceptional kernel flags remain explicit.
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'scope>, Error>> {
        if let Some(event) = self.ready {
            return Poll::Ready(Ok(event));
        }
        for entry in &self.entries {
            let (Some(registration), Some(listener), Some(port)) =
                (entry.armed, entry.id, &entry.port)
            else {
                continue;
            };
            match port.poll_ready(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Error::Io(error))),
                Poll::Ready(Ok(readiness)) => {
                    let event = Event {
                        listener,
                        registration,
                        readiness,
                    };
                    self.ready = Some(event);
                    return Poll::Ready(Ok(event));
                }
            }
        }
        Poll::Pending
    }
    /// Confirm kernel readiness only for actually armed ordinary registrations.
    /// Unregistered/disarmed descriptors do not suppress source IDLE callbacks.
    pub fn ordinary_ready(&self) -> Result<bool, Error> {
        if self.ready.is_some() {
            return Ok(true);
        }
        for entry in &self.entries {
            if entry.armed.is_some()
                && let Some(port) = entry.port.as_ref()
            {
                match port.level() {
                    Ok(_level) => return Ok(true),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(Error::Io(error)),
                }
            }
        }
        Ok(false)
    }
    /// Await one readiness observation. Dropping this future leaves every FD,
    /// logical watcher, pending event and listener lease owned by this registry.
    pub async fn next_event(&mut self) -> Result<Event<'scope>, Error> {
        std::future::poll_fn(|cx| self.poll_event(cx)).await
    }
    /// Deliver the retained one-shot to core. Busy keeps it retryable. A consumed
    /// event (success or generation exhaustion) retires the matching watcher;
    /// sibling Disarm effects must then be applied before taking actual Spawn.
    pub fn deliver(&mut self, owner: &mut Owner<'scope, '_, '_, '_>) -> Result<(), Error> {
        self.check_owner(owner)?;
        let event = self.ready.ok_or(Error::Mapping)?;
        if !event.readiness.readable {
            return Err(Error::Exceptional(event.readiness));
        }
        let result = owner.demand(event.registration);
        if matches!(
            result,
            Ok(())
                | Err(gnunet_arm_service_core::Error::Exhausted
                    | gnunet_arm_service_core::Error::Stale
                    | gnunet_arm_service_core::Error::Closed)
        ) {
            self.ready = None;
            for entry in &mut self.entries {
                if entry.armed == Some(event.registration) {
                    entry.armed = None;
                }
            }
        }
        result.map_err(Error::Core)
    }
    /// Original actual descriptor, borrowed for a future checked inheritance port.
    /// Callers must not accept/read/modify it as an ARM readiness observation.
    pub fn descriptor(
        &self,
        id: ListenerId<'scope>,
    ) -> Option<gnunet_native::network::BorrowedStream<'_>> {
        self.entries
            .iter()
            .find(|entry| entry.id == Some(id))?
            .port
            .as_ref()
            .map(|port| {
                #[cfg(unix)]
                {
                    port.as_fd()
                }
                #[cfg(windows)]
                {
                    port.as_socket()
                }
            })
    }
    #[cfg(windows)]
    pub(crate) fn launch_source(
        &self,
        id: ListenerId<'scope>,
    ) -> Option<gnunet_native::socket_activation::Source<'_>> {
        self.entries
            .iter()
            .find(|entry| entry.id == Some(id))?
            .port
            .as_ref()
            .map(RegisteredListener::launch_source)
    }
    /// Actual bound endpoint for a listener, including the chosen fixture port.
    pub fn address(&self, index: usize) -> Option<&Address> {
        self.entries.get(index).map(|entry| &entry.address)
    }
    /// Checked core identity for one actual bound entry after attachment.
    pub fn id(&self, index: usize) -> Option<ListenerId<'scope>> {
        self.entries.get(index)?.id
    }
    /// Registry service index associated with this original listener.
    /// This does not expose or duplicate descriptor ownership.
    pub fn service_index(&self, index: usize) -> Option<usize> {
        self.entries.get(index).map(|entry| entry.service)
    }
    /// Count of actual bound/adopted original listeners, including later closed entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no actual listeners were bound/adopted.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// All actual collection/bind/nonfatal option diagnostics.
    pub fn failures(&self) -> &[Failure] {
        &self.failures
    }
}
