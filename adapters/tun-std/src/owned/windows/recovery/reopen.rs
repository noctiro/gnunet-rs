//! Physical reopen owns selection intent after the missing original adapter retires.
use super::{WintunRecovery, WintunRestartError, WintunRestartStage};
use crate::{AsyncTun, Epoch, Limits, OwnedTun};
use gnunet_native::{
    interfaces::{Identity, InterfacePresence, RetiredScope, RetirementLimits},
    wintun::{Adapter, Driver, Recreation, RingCapacity, Selector},
};
use std::{fmt, io};
use tokio::time::Instant;
mod creation;

/// Physical recovery after the old adapter release, retaining the exact provider
/// and original logical selector. It owns no old adapter or session; an explicit
/// recreation attempt may retain one provisional creator through later failures.
#[derive(Debug)]
pub struct WintunReopen {
    driver: Driver,
    selector: Selector,
    previous: Identity,
    original: Epoch,
    capacity: RingCapacity,
    limits: Limits,
    retirement: Option<WintunScopeRetirement>,
    recreation: Option<Recreation>,
    provisional: Option<Adapter>,
}
/// Actual physical recovery stage; none implies route or packet readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WintunReopenStage {
    /// Complete old-interface/forwarding-table reconciliation.
    Scope,
    /// Qualified provider-name/GUID/compartment reopen.
    Open,
    /// Fresh native creation and exact alias restoration after old-scope absence.
    Create,
    /// Native session startup on the reopened or created adapter.
    Start,
    /// Packet device qualification.
    Qualify,
    /// Reactor registration.
    Register,
}
/// Physical refusal retains selection intent and the actual independent error.
#[derive(Debug)]
pub struct WintunReopenError {
    owner: Box<WintunReopen>,
    stage: WintunReopenStage,
    error: io::Error,
}
impl WintunReopenError {
    /// Inspect historical scope observations without consuming recovery intent.
    pub fn owner(&self) -> &WintunReopen {
        &self.owner
    }
    /// Retry or release the same physical recovery intent under its original target.
    pub fn into_parts(self) -> (WintunReopen, WintunReopenStage, io::Error) {
        (*self.owner, self.stage, self.error)
    }
}
impl fmt::Display for WintunReopenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wintun physical reopen {:?}: {}", self.stage, self.error)
    }
}
impl std::error::Error for WintunReopenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
/// A fresh qualified packet owner and sealed old-scope absence observation.
/// The consuming controller retires original control/flow jobs independently,
/// then settles only that old scope before admitting the new interface.
pub struct WintunReplacement {
    source: AsyncTun,
    retirement: WintunScopeRetirement,
    kind: WintunReplacementKind,
}
/// Actual provider provenance of the newly qualified physical packet source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WintunReplacementKind {
    /// Explicitly reopened external configuration must be verified unchanged.
    Reopened,
    /// A new creator owns this fresh device and may configure its new scope.
    Created,
}
/// Sealed old-scope observation bound to its actual retired packet epoch.
/// Cloning copies historical facts only; it never revives packet/device authority.
#[derive(Clone, Debug)]
pub struct WintunScopeRetirement {
    scope: RetiredScope,
    original: Epoch,
}
impl WintunScopeRetirement {
    /// Original permanently retired source whose old native scope was queried.
    pub fn original_epoch(&self) -> &Epoch {
        &self.original
    }
    /// Actual complete-table observation; no provider-close ACK is implied.
    pub fn scope(&self) -> &RetiredScope {
        &self.scope
    }
}
impl fmt::Debug for WintunReplacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunReplacement")
            .field("retirement", &self.retirement)
            .field("new_epoch", &self.source.epoch())
            .field("kind", &self.kind)
            .finish()
    }
}
impl WintunReplacement {
    /// Actual new-device provisioning responsibility, independent of old routes.
    pub const fn kind(&self) -> WintunReplacementKind {
        self.kind
    }
    /// The permanently retired original packet epoch.
    pub fn original_epoch(&self) -> &Epoch {
        self.retirement.original_epoch()
    }
    /// Actual time-local absence observation, never a provider-close ACK.
    pub fn previous_scope(&self) -> &RetiredScope {
        self.retirement.scope()
    }
    /// Transfer the actual new source and old-scope observation exactly once.
    pub fn into_parts(self) -> (AsyncTun, WintunScopeRetirement) {
        (self.source, self.retirement)
    }
}
impl WintunRecovery {
    /// Release an adapter only after a complete native table says its original
    /// physical interface is missing. A present/reused LUID or query error keeps
    /// this original adapter owned by the returned refusal.
    ///
    /// # Errors
    /// Returns the original owner on native observation, capacity or selector
    /// failure. No new provider search, creation or configuration occurs.
    pub fn detach_missing(self) -> Result<WintunReopen, WintunRestartError> {
        let prepared = (|| -> io::Result<_> {
            let previous = self.adapter.port().identity().clone();
            match previous.presence(RetirementLimits::default())? {
                InterfacePresence::Missing => {}
                InterfacePresence::Present => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "original Wintun interface is still present",
                    ));
                }
                InterfacePresence::Reused => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "original Wintun LUID was reused",
                    ));
                }
            }
            Ok((
                previous,
                self.adapter.selector()?,
                self.adapter.driver(),
                self.adapter.recreation()?,
            ))
        })();
        let (previous, selector, driver, recreation) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(WintunRestartError {
                    recovery: Box::new(self),
                    stage: WintunRestartStage::Detach,
                    error,
                });
            }
        };
        let Self {
            adapter,
            original,
            capacity,
            limits,
            ..
        } = self;
        // Release the old creator before opening a new physical owner. Its
        // void native close supplies no removal proof; reconciliation follows.
        drop(adapter);
        Ok(WintunReopen {
            driver,
            selector,
            previous,
            original,
            capacity,
            limits,
            retirement: None,
            recreation,
            provisional: None,
        })
    }
}
impl WintunReopen {
    /// Original retired packet source, not a capability to revive that epoch.
    pub fn original_epoch(&self) -> &Epoch {
        &self.original
    }
    /// Read-only original interface identity retained after adapter release.
    pub fn previous_identity(&self) -> &Identity {
        &self.previous
    }
    /// Historical retirement fact, if native reconciliation completed even when
    /// a later reopen/start failed. It is not a current replacement snapshot.
    pub fn retirement(&self) -> Option<&WintunScopeRetirement> {
        self.retirement.as_ref()
    }
    /// Observe the old scope once, after all original mutation jobs quiesce.
    /// Later calls retain that fact rather than relabeling a new interface's rows
    /// as old effects. The caller serializes administration across this boundary.
    ///
    /// # Errors
    /// Preserves native ambiguity, remaining old routes and the original deadline.
    pub fn observe_scope(&mut self, until: Instant) -> io::Result<&WintunScopeRetirement> {
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self.retirement.is_none() {
            let scope = self.previous.retired_scope(RetirementLimits::default())?;
            self.retirement = Some(WintunScopeRetirement {
                scope,
                original: self.original.clone(),
            });
        }
        self.retirement
            .as_ref()
            .ok_or_else(|| io::Error::other("missing original scope observation"))
    }
    /// Observe old-scope absence and reopen the exact logical GUID as borrowed.
    /// A previously admitted provisional creator resumes without new creation.
    /// The caller excludes concurrent administration and retains one finite
    /// outage deadline across retries. This never configures or creates a device.
    ///
    /// # Errors
    /// Preserves the recovery intent and actual failed stage. Provisional borrowed
    /// adapters close on refusal; a previously admitted creator remains retained.
    pub fn open(self, until: Instant) -> Result<WintunReplacement, WintunReopenError> {
        self.attempt(until, false)
    }
    /// Reopen first, or recreate only a provider-created original after an actual
    /// NotFound and complete old-scope absence. Borrowed originals never gain
    /// creation policy. A created replacement requires fresh provisioning.
    ///
    /// # Errors
    /// Retains the original intent, actual failed stage and old-scope observation.
    /// Collision, identity and permission errors never trigger creation.
    pub fn open_or_recreate(self, until: Instant) -> Result<WintunReplacement, WintunReopenError> {
        self.attempt(until, true)
    }
    fn attempt(
        mut self,
        until: Instant,
        recreate: bool,
    ) -> Result<WintunReplacement, WintunReopenError> {
        let mut stage = WintunReopenStage::Scope;
        let check = || -> io::Result<()> {
            if Instant::now() >= until {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original Wintun physical recovery target expired",
                ))
            } else {
                Ok(())
            }
        };
        let attempt = (|| -> io::Result<_> {
            check()?;
            self.observe_scope(until)?;
            check()?;
            let (adapter, kind) = self.prepare_adapter(until, recreate, &mut stage)?;
            if let Err(error) = check() {
                self.retain_created(adapter, kind);
                return Err(error);
            }
            stage = WintunReopenStage::Start;
            let session = match adapter.start(self.capacity) {
                Ok(session) => session,
                Err(failure) => {
                    let (adapter, error) = failure.into_parts();
                    self.retain_created(adapter, kind);
                    return Err(error);
                }
            };
            if let Err(error) = check() {
                self.retain_created(session.end(), kind);
                return Err(error);
            }
            stage = WintunReopenStage::Qualify;
            let owner = match OwnedTun::try_from_wintun(session, self.limits) {
                Ok(owner) => owner,
                Err(failure) => {
                    let (session, error) = failure.into_parts();
                    self.retain_created(session.end(), kind);
                    return Err(error);
                }
            };
            if let Err(error) = check() {
                self.retain_created(owner.retain_wintun().into_adapter(), kind);
                return Err(error);
            }
            stage = WintunReopenStage::Register;
            let mut source = match AsyncTun::try_new(owner) {
                Ok(source) => source,
                Err(failure) => {
                    let (owner, error) = failure.into_parts();
                    self.retain_created(owner.retain_wintun().into_adapter(), kind);
                    return Err(error);
                }
            };
            if let Err(error) = check() {
                let mut loss = source.retire_wintun_session();
                if let Some(recovery) = loss.recovery.take() {
                    self.retain_created(recovery.into_adapter(), kind);
                }
                if let Some(close) = loss.close_error {
                    return Err(io::Error::other(LateRegistration {
                        original: error,
                        close,
                    }));
                }
                return Err(error);
            }
            Ok((source, kind))
        })();
        match attempt {
            Ok((source, kind)) => match self.retirement.take() {
                Some(retirement) => Ok(WintunReplacement {
                    source,
                    retirement,
                    kind,
                }),
                None => Err(WintunReopenError {
                    owner: Box::new(self),
                    stage: WintunReopenStage::Scope,
                    error: io::Error::other("missing original scope retirement"),
                }),
            },
            Err(error) => Err(WintunReopenError {
                owner: Box::new(self),
                stage,
                error,
            }),
        }
    }
}

#[derive(Debug)]
struct LateRegistration {
    original: io::Error,
    close: io::Error,
}
impl fmt::Display for LateRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; independent registration retirement failure: {}",
            self.original, self.close
        )
    }
}
impl std::error::Error for LateRegistration {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
