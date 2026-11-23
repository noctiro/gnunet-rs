//! Reference PILS authority for an identity selected by the platform.

use super::{Action, ActiveIdentity, Announcement, Profile, fed_addresses};
use gnunet_hello::{HelloBuilder, Limits};
use gnunet_types::Error;
use gnunet_wire::official::pils::{PeerUpdate, Request};
use zeroize::Zeroize;

/// PILS over one already active identity and caller-owned announcement memory.
///
/// Address feeds replace the announcement in the normal reference profile.
/// Key operations always use the supplied active identity.
pub struct FixedService<'memory> {
    identity: ActiveIdentity,
    announcement: &'memory mut [u8],
    length: usize,
    limits: Limits,
}

impl<'memory> FixedService<'memory> {
    /// Bind the platform key and storage without opening an announcement.
    #[must_use]
    pub fn new(identity: ActiveIdentity, limits: Limits, announcement: &'memory mut [u8]) -> Self {
        Self {
            identity,
            announcement,
            length: 0,
            limits,
        }
    }

    /// Sign the initial empty-address HELLO after the previous generation stops.
    pub fn start(&mut self, now: u64) -> Result<(), Error> {
        if self.length != 0 {
            return Err(Error::Conflict);
        }
        self.publish(&HelloBuilder::new(&mut [], self.limits), now)
    }

    /// Retire the current announcement after its original readers have stopped.
    pub fn stop(&mut self) {
        self.announcement.zeroize();
        self.length = 0;
    }

    /// The current exact `PILS_PEER_ID` frame, empty while stopped.
    #[must_use]
    pub fn announcement(&self) -> &[u8] {
        &self.announcement[..self.length]
    }

    /// Process one decoded original request. The host serializes publication
    /// with any outstanding writes borrowing the old announcement.
    pub fn receive(
        &mut self,
        request: Request<'_>,
        scratch: &mut [u8],
        now: u64,
        out: &mut [u8],
    ) -> Result<Action, Error> {
        self.check_started()?;
        let Request::Feed { block } = request else {
            return self.identity.reply(request, out);
        };
        let addresses = fed_addresses(block, scratch, self.limits)?;
        self.publish(&addresses, now)?;
        Ok(Action::Broadcast {
            identity_changed: false,
        })
    }

    /// Renew the current address set with a fresh signed expiration.
    /// The host observes the same publication ownership as for an address feed.
    pub fn refresh(&mut self, scratch: &mut [u8], now: u64) -> Result<(), Error> {
        self.check_started()?;
        let current = PeerUpdate::decode(self.announcement())?;
        let addresses = fed_addresses(current.block, scratch, self.limits)?;
        self.publish(&addresses, now)
    }

    fn check_started(&self) -> Result<(), Error> {
        if self.length == 0 {
            Err(Error::NotReady)
        } else {
            Ok(())
        }
    }

    fn publish(&mut self, addresses: &HelloBuilder<'_>, now: u64) -> Result<(), Error> {
        const PROFILE: Profile = Profile::Reference029;
        let hash = addresses.address_hash(PROFILE.hello());
        let update = Announcement::new(addresses, &self.identity, hash, PROFILE, now)?;
        self.length = update.encode(self.announcement)?;
        Ok(())
    }
}
