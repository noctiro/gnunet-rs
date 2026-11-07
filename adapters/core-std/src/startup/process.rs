//! Explicit new-process listener and identity stages, separate from async embedding.
use super::{ForegroundPolicy, ForegroundResources, Limits, Report, run_foreground};
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    Activation, BoundListeners, ListenerPreparation,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
};
use gnunet_service_startup::{
    GroupsProfile, PrivilegePlan, PrivilegeReport, apply_privileges, configured_user, resolve_user,
};
use gnunet_wire::official::core::PeerId;
use std::{error::Error, future::Future, io, sync::Arc};

/// Original listeners and resolved account retained before an explicit process
/// identity transition. This value has no master, PILS or peer/session keys.
/// Dropping it closes its owned listeners through the shared listener owner.
pub struct ProcessPreparation<'config> {
    config: &'config Configuration,
    listeners: ListenerPreparation,
    policy: ForegroundPolicy,
    user: Option<PrivilegePlan>,
}

/// Original listeners after the actual synchronous identity sequence succeeded.
/// Only [`ProcessPreparation::apply_identity`] constructs this state; a caller
/// cannot substitute a configured name, scalar UID or fabricated report for it.
pub struct PreparedProcess<'config> {
    config: &'config Configuration,
    listeners: ListenerPreparation,
    policy: ForegroundPolicy,
    privilege: PrivilegeReport,
}

/// Prepare CORE in a fresh service process, before unrelated tasks/threads and
/// before account-dependent master/PILS/Resolver operations. Captured activation
/// listeners are adopted once; otherwise the shared runtime prebinds configured
/// TCP listeners while privileged ports can still be opened. New Unix sockets
/// are deferred until after identity selection so their private path belongs to
/// the target account. This function performs account lookup and TCP listener
/// I/O but never changes process identity or creates/chowns a Unix path.
///
/// Enter the caller-owned current-thread runtime later used for CORE, invoke
/// this synchronous preparation, then leave that entered scope before calling
/// the synchronous identity stage. No unrelated task is polled during either.
/// The inherited descriptor capture must already have run exactly once as the
/// first startup operation. Account lookup or binding failure returns its actual
/// cause and drops all resources already owned; no READY is emitted.
pub fn prepare_process(
    config: &Configuration,
    activation: Activation,
) -> Result<ProcessPreparation<'_>, Box<dyn Error>> {
    let user = configured_user(config, b"core")?
        .map(|name| resolve_user(&name))
        .transpose()?;
    let policy = ForegroundPolicy::read(config)?;
    let listeners = BoundListeners::prepare_before_identity(config, b"core", activation)?;
    Ok(ProcessPreparation {
        config,
        listeners,
        policy,
        user,
    })
}
impl<'config> ProcessPreparation<'config> {
    /// Change this fresh process's gid/groups/uid through the shared actual
    /// WithInitgroups sequence, retaining inherited and prebound TCP listeners
    /// across the change. New Unix paths remain uncreated until foreground.
    /// No configured USERNAME takes its real Unchanged branch. This operation is
    /// irreversible: an error may follow partial native identity changes; exit
    /// startup rather than retrying, continuing or attempting a rollback.
    ///
    /// Call synchronously from the new service process, outside unrelated async
    /// work. This method must not be used to change an embedding process with
    /// other active tasks or threads. It does not chown configured resources or
    /// grant access to account-inaccessible key/runtime directories.
    pub fn apply_identity(self) -> Result<PreparedProcess<'config>, Box<dyn Error>> {
        let privilege = apply_privileges(self.user.as_ref(), GroupsProfile::WithInitgroups)?;
        Ok(PreparedProcess {
            config: self.config,
            listeners: self.listeners,
            policy: self.policy,
            privilege,
        })
    }
}
impl PreparedProcess<'_> {
    /// Original successful native sequence report, including any actual fallback.
    /// It is a local process identity observation, not a saved-id/capability claim.
    #[must_use]
    pub const fn privilege_report(&self) -> PrivilegeReport {
        self.privilege
    }
    /// Start actual master/PILS/Resolver/CORE work after the explicit identity
    /// phase, using one shared native process clock. Original listener owners
    /// remain intact. Its first step binds only the deferred new Unix socket
    /// under the current selected account; it never changes identity or rebinds
    /// inherited/prebound TCP sockets.
    pub async fn foreground(
        self,
        limits: Limits,
        ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
        shutdown: impl Future<Output = io::Result<()>>,
        observe: impl FnMut(SocketEvent),
    ) -> Result<Report, Box<dyn Error>> {
        self.foreground_with_clock(limits, ready, shutdown, observe, Arc::new(SystemClock))
            .await
    }
    /// Use the caller's one canonical clock after actual process preparation.
    /// Canceling the whole service future closes its owned listeners and MQs;
    /// it never reverses the process-wide identity transition.
    pub async fn foreground_with_clock(
        self,
        limits: Limits,
        ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
        shutdown: impl Future<Output = io::Result<()>>,
        observe: impl FnMut(SocketEvent),
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Report, Box<dyn Error>> {
        let bound = self.listeners.finish().await?;
        let resources = ForegroundResources {
            config: self.config,
            bound,
            policy: self.policy,
        };
        run_foreground(resources, limits, ready, shutdown, observe, clock).await
    }
}
