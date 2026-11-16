//! Qualified original Wintun packet ownership under the shared source lifetime.
use crate::{Epoch, Info, Limits, Mode, Stamp};
use gnunet_native::wintun::Session;
use std::{cell::Cell, io, rc::Rc};
mod recovery;
pub use recovery::{
    WintunRecovery, WintunReopen, WintunReopenError, WintunReopenStage, WintunReplacement,
    WintunReplacementKind, WintunRestartError, WintunRestartStage, WintunScopeRetirement,
};
/// Original session returned when packet-owner qualification is refused.
#[derive(Debug)]
pub struct WintunAdoptionError {
    session: Session,
    error: io::Error,
}
impl WintunAdoptionError {
    /// Recover the unchanged original session and its qualification error.
    pub fn into_parts(self) -> (Session, io::Error) {
        (self.session, self.error)
    }
}
impl std::fmt::Display for WintunAdoptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wintun packet-owner qualification: {}", self.error)
    }
}
impl std::error::Error for WintunAdoptionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
/// One qualified original Wintun session. Its source epoch retires before native
/// session/adapter release. Names never reselect a replacement interface.
#[derive(Debug)]
pub struct OwnedTun {
    // Retire the source before session/adapter release on every ordinary Drop.
    retirement: Retirement,
    session: Session,
    pub(crate) info: Info,
    pub(crate) limits: Limits,
    pub(crate) epoch: Epoch,
    pub(crate) next_effect: u64,
    pub(crate) ipv4: Option<std::net::Ipv4Addr>,
}
#[derive(Debug)]
struct Retirement(Epoch);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.0.alive.set(false);
    }
}
impl OwnedTun {
    /// Consume an actual Wintun session from the explicit trusted native provider.
    /// Qualification failure closes it. No DLL, driver, device, worker or runtime
    /// is implicitly created; provider trust belongs to the original DLL loader.
    pub fn from_wintun(session: Session, limits: Limits) -> io::Result<Self> {
        Self::try_from_wintun(session, limits).map_err(|failure| failure.error)
    }
    /// Qualify an original session, returning that same owner on refusal.
    pub fn try_from_wintun(session: Session, limits: Limits) -> Result<Self, WintunAdoptionError> {
        let prepared = (|| -> io::Result<Info> {
            limits.validate()?;
            let actual = session.adapter().port().interface()?;
            let name = actual.alias.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-Unicode Wintun interface alias",
                )
            })?;
            Ok(Info {
                name,
                index: actual.index,
                mode: Mode::RawIp,
            })
        })();
        let info = match prepared {
            Ok(info) => info,
            Err(error) => return Err(WintunAdoptionError { session, error }),
        };
        let epoch = Epoch(Rc::new(Stamp {
            alive: Cell::new(true),
            route_table: None,
        }));
        Ok(Self {
            retirement: Retirement(epoch.clone()),
            session,
            next_effect: 0,
            ipv4: None,
            info,
            limits,
            epoch,
        })
    }
    /// Original qualified immutable metadata.
    pub const fn info(&self) -> &Info {
        &self.info
    }
    /// Original source identity; cloning it keeps no native session alive.
    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }
    pub(crate) fn session(&self) -> &Session {
        &self.session
    }
    pub(crate) fn setup_error(self, error: io::Error) -> io::Error {
        drop(self);
        error
    }
    /// Retire this source and invoke the provider's session/adapter release once.
    /// The provider's void ABI supplies no separate kernel-close/removal errno.
    pub fn close(self) -> io::Result<()> {
        drop(self);
        Ok(())
    }
    /// Transfer the original session while retiring this packet/effect epoch.
    /// Re-adoption must qualify it and allocate a fresh source identity.
    pub fn into_wintun(self) -> Session {
        let Self {
            retirement,
            session,
            ..
        } = self;
        drop(retirement);
        session
    }
}
