//! Original PILS announcements and verified active CORE key derivation.
use crate::{HostError, io::Link};
use gnunet_core::session::Identity;
use gnunet_hello::Hello;
use gnunet_pils::{MasterKey, Profile};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    connection::Connection,
};
use gnunet_types::Error;
use gnunet_wire::official::pils::PeerUpdate;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use zeroize::Zeroizing;
/// Actual official PILS1831 feed. Its update derives and verifies a new local
/// identity before the enclosing owner replaces any active CORE sessions.
/// It implements neither the PILS service nor signing/ECDH operation APIs.
pub struct PilsFeed {
    link: Link,
    scratch: Zeroizing<Vec<u8>>,
    clock: Arc<dyn RuntimeClock>,
    profile: Profile,
}
impl PilsFeed {
    /// Take an already connected, original official PILS stream.
    pub fn new(connection: Connection) -> Result<Self, Error> {
        Self::with_clock(connection, Arc::new(SystemClock))
    }
    /// Join the same absolute source used by the process and CORE owner.
    pub fn with_clock(connection: Connection, clock: Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        Self::with_profile(connection, clock, Profile::Reference029)
    }
    /// Choose one explicit official source/draft identity profile; failed
    /// verification never tries another interpretation of the announcement.
    pub fn with_profile(
        connection: Connection,
        clock: Arc<dyn RuntimeClock>,
        profile: Profile,
    ) -> Result<Self, Error> {
        Ok(Self {
            link: Link::new(connection, 65535, 1, 65535)?,
            scratch: Zeroizing::new(vec![0; 65535]),
            clock,
            profile,
        })
    }
    fn identity(&mut self, master: &MasterKey) -> Result<Identity, HostError> {
        let bytes = self.link.frame().ok_or(Error::NotReady)?;
        let update = PeerUpdate::decode(bytes)?;
        let hello = Hello::parse_block(
            update.block,
            &mut self.scratch,
            gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 128,
            },
        )?;
        let now = self
            .clock
            .sample()
            .map_err(HostError::Clock)?
            .now
            .as_micros();
        hello.verify_at(
            self.profile.hello(),
            gnunet_wire::official::AbsoluteTime::from_micros(now),
        )?;
        // The selected official build fixes address coverage. Reference029
        // verifies metadata binding; deterministic also authenticates addresses.
        if hello.address_hash(self.profile.hello()) != update.hash {
            return Err(Error::Authentication.into());
        }
        let identity = master.with_active_seed(&update.hash, self.profile, |seed| {
            Identity::from_seed(*seed)
        })?;
        if identity.public_key() != hello.peer() {
            return Err(Error::Authentication.into());
        }
        Ok(identity)
    }
    /// Poll one actual complete verified update; canceled waits retain the
    /// original partial bytes. No fabricated identity is emitted while offline.
    pub fn poll_identity(
        &mut self,
        cx: &mut Context<'_>,
        master: &MasterKey,
    ) -> Poll<Result<Identity, HostError>> {
        if self.link.frame().is_none() {
            match self.link.poll_rx(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(false)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Ok(true)) => {}
            }
        }
        let result = self.identity(master);
        self.link.release();
        Poll::Ready(result)
    }
}
