//! Exact current verified PILS observation bound to a UDP key owner.
//! Public cached observations alone never authorize a fresh private-key borrow.
use gnunet_pils::client::{ByteStorage, Client, Identity as Observation, LocalKeyStatus};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{Identity, PeerId};
use gnunet_wire::official::AbsoluteTime;
/// One current local UDP key owner bound to the exact PILS MQ observation. It has
/// no Clone/Debug/master exporter. Old epochs must be closed by the enclosing
/// communicator; stale cached observations cannot regain private-key access.
pub struct IdentityEpoch<'a> {
    binding: Observation<'a>,
    identity: Option<Identity>,
}
impl<'a> IdentityEpoch<'a> {
    fn checked(
        binding: Observation<'a>,
        identity: Identity,
        now: AbsoluteTime,
    ) -> Result<Self, Error> {
        if identity.peer() != *binding.peer().as_bytes() {
            return Err(Error::Authentication);
        }
        if binding.expiration() <= now {
            return Err(Error::Timeout);
        }
        Ok(Self {
            binding,
            identity: Some(identity),
        })
    }
    /// Derive only from a matched current verified pure PILS client. Its original
    /// explicit source profile and shared derivation remain unchanged.
    pub fn from_client<
        const O: usize,
        const F: usize,
        const H: usize,
        R: ByteStorage,
        A: ByteStorage,
    >(
        source: &Client<'a, O, F, H, R, A>,
        now: AbsoluteTime,
    ) -> Result<Self, Error> {
        let binding = source.identity().ok_or(Error::NotReady)?;
        let identity = source.with_active_seed(|seed| Identity::from_seed(*seed))?;
        Self::checked(binding, identity, now)
    }
    /// Derive from the actual native PILS client's matched current announcement.
    /// Native/client errors retain their original cause; no file is created.
    pub fn from_native<const O: usize>(
        source: &gnunet_pils_host::client::Client<'a, O>,
        now: AbsoluteTime,
    ) -> Result<Self, gnunet_pils_host::client::Error> {
        let binding = source.identity().ok_or(Error::NotReady)?;
        let identity = source.with_active_seed(|seed| Identity::from_seed(*seed))?;
        Ok(Self::checked(binding, identity, now)?)
    }
    fn current(
        &self,
        observation: Option<Observation<'a>>,
        status: LocalKeyStatus,
        now: AbsoluteTime,
    ) -> Result<&Identity, Error> {
        if observation != Some(self.binding) {
            return Err(Error::Stale);
        }
        if status != LocalKeyStatus::Matched {
            return Err(Error::NotReady);
        }
        if self.binding.expiration() <= now {
            return Err(Error::Timeout);
        }
        self.identity.as_ref().ok_or(Error::Closed)
    }
    fn refresh(
        &mut self,
        observation: Option<Observation<'a>>,
        status: LocalKeyStatus,
        now: AbsoluteTime,
    ) -> Result<bool, Error> {
        // Closing permanently erases this owner. An unchanged public identity
        // cannot recreate a key or revive a retired physical PILS epoch.
        if self.identity.is_none() {
            return Err(Error::Closed);
        }
        let observation = observation.ok_or(Error::NotReady)?;
        if status != LocalKeyStatus::Matched {
            return Err(Error::NotReady);
        }
        if observation.epoch() != self.binding.epoch()
            || observation.peer() != self.binding.peer()
            || observation.peer_hash() != self.binding.peer_hash()
            || observation.address_hash() != self.binding.address_hash()
            || observation.coverage() != self.binding.coverage()
            || observation.revision() < self.binding.revision()
            || (observation.revision() == self.binding.revision() && observation != self.binding)
        {
            return Err(Error::Stale);
        }
        if observation.expiration() <= now {
            return Err(Error::Timeout);
        }
        let changed = observation != self.binding;
        // The verified current client retains the same original source and
        // selected profile; exact derivation context and matched public key
        // identify the same retained seed. Only public observation metadata
        // change. No private-key read, derivation, nonce or deadline reset.
        self.binding = observation;
        Ok(changed)
    }
    /// Explicitly adopt a verified HELLO refresh from this same pure PILS MQ.
    /// Revision/expiration changes are allowed only with the identical peer,
    /// derivation context and signature coverage and a still-matched local key.
    /// The original UDP key is retained. A changed source/context, rollback,
    /// expired refresh or closed owner is rejected without mutation.
    pub fn refresh_client<
        const O: usize,
        const F: usize,
        const H: usize,
        R: ByteStorage,
        A: ByteStorage,
    >(
        &mut self,
        source: &Client<'a, O, F, H, R, A>,
        now: AbsoluteTime,
    ) -> Result<bool, Error> {
        self.refresh(source.identity(), source.local_key_status(), now)
    }
    /// Adopt only the actual native PILS client's latest verified same-context
    /// announcement. This does not reconnect PILS, recreate the UDP key or
    /// renew an existing packet, ACK, address-publication or native deadline.
    pub fn refresh_native<const O: usize>(
        &mut self,
        source: &gnunet_pils_host::client::Client<'a, O>,
        now: AbsoluteTime,
    ) -> Result<bool, Error> {
        self.refresh(source.identity(), source.local_key_status(), now)
    }
    /// Borrow a key only while both this original owner and the actual current
    /// pure client stay borrowed. Source loss, disable, rotation or a distinct
    /// branded client refuses access. Caller supplies trusted current UTC.
    ///
    /// ```compile_fail
    /// use gnunet_pils::client::Client;
    /// use gnunet_udp_communicator_host::identity::IdentityEpoch;
    /// use gnunet_wire::official::AbsoluteTime;
    /// fn rotate_while_udp_key_is_borrowed<'brand>(owner:&IdentityEpoch<'brand>,source:&mut Client<'brand>) {
    ///     let key=owner.current_client(source,AbsoluteTime::UNIX_EPOCH);
    ///     source.close();
    ///     if let Ok(key)=key {let _peer=key.peer();}
    /// }
    /// ```
    pub fn current_client<
        'borrow,
        const O: usize,
        const F: usize,
        const H: usize,
        R: ByteStorage,
        A: ByteStorage,
    >(
        &'borrow self,
        source: &'borrow Client<'a, O, F, H, R, A>,
        now: AbsoluteTime,
    ) -> Result<&'borrow Identity, Error> {
        self.current(source.identity(), source.local_key_status(), now)
    }
    /// Borrow against the actual native PILS owner; cancellation or physical MQ
    /// replacement cannot be represented by a cached public peer or revision.
    pub fn current_native<'borrow, const O: usize>(
        &'borrow self,
        source: &'borrow gnunet_pils_host::client::Client<'a, O>,
        now: AbsoluteTime,
    ) -> Result<&'borrow Identity, Error> {
        self.current(source.identity(), source.local_key_status(), now)
    }
    /// Cached public peer for namespace/teardown diagnostics only. It does not
    /// prove that a current signer, UDP address, queue or IPC connection exists.
    #[must_use]
    pub fn peer(&self) -> PeerId {
        *self.binding.peer().as_bytes()
    }
    /// Public original verified observation, with its exact epoch and revision.
    #[must_use]
    pub const fn observation(&self) -> Observation<'a> {
        self.binding
    }
    /// Erase the original UDP signing/exchange owner. This closed epoch can never
    /// regain keys, even if the same peer returns on another PILS MQ.
    pub fn close(&mut self) {
        drop(self.identity.take());
    }
}
