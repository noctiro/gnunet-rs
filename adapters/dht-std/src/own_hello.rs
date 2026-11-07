//! A local DHT HELLO assembled from actual public sources and signed by PILS.
//! No address FEED/global PID derivation, private key or fabricated PILS update.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_hello::{BLOCK_HEADER_LEN, Hello, HelloBuilder, Limits, SignatureProfile};
use gnunet_pils::client::Identity;
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::pils::PeerUpdate;

struct Snapshot<'id> {
    identity: Identity<'id>,
    revision: u64,
    expiration: AbsoluteTime,
    addresses: Vec<u8>,
}
struct Signed<'id> {
    identity: Identity<'id>,
    revision: u64,
    expiration: AbsoluteTime,
    block: Vec<u8>,
}
/// Borrowed caller scratch, not a second retained maximum-sized address buffer.
pub(crate) struct SignRequest<'scratch, 'id> {
    pub revision: u64,
    pub identity: Identity<'id>,
    pub expiration: AbsoluteTime,
    pub builder: HelloBuilder<'scratch>,
}
pub(crate) struct OwnHello<'id> {
    limits: Limits,
    profile: SignatureProfile,
    maximum: usize,
    revision: u64,
    desired: Option<Snapshot<'id>>,
    inflight: Option<Snapshot<'id>>,
    installed: Option<Signed<'id>>,
}
impl<'id> OwnHello<'id> {
    pub fn new(limits: Limits, profile: SignatureProfile, maximum: usize) -> Result<Self, Error> {
        if limits.maximum_input_bytes < BLOCK_HEADER_LEN || maximum < core::mem::size_of::<Self>() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            limits,
            profile,
            maximum,
            revision: 0,
            desired: None,
            inflight: None,
            installed: None,
        })
    }
    fn retained(&self) -> Result<usize, Error> {
        let mut bytes = core::mem::size_of::<Self>();
        for snapshot in [&self.desired, &self.inflight].into_iter().flatten() {
            bytes = bytes
                .checked_add(snapshot.addresses.capacity())
                .ok_or(Error::Overflow)?;
        }
        if let Some(signed) = &self.installed {
            bytes = bytes
                .checked_add(signed.block.capacity())
                .ok_or(Error::Overflow)?;
        }
        Ok(bytes)
    }
    fn buffer(&self, n: usize, temporary: usize) -> Result<Vec<u8>, Error> {
        let remaining = self
            .maximum
            .checked_sub(self.retained()?)
            .and_then(|v| v.checked_sub(temporary))
            .ok_or(Error::Capacity)?;
        if n > remaining {
            return Err(Error::Capacity);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
        if bytes.capacity() > remaining {
            return Err(Error::Capacity);
        }
        bytes.resize(n, 0);
        Ok(bytes)
    }
    fn same(&self, identity: Identity<'id>, expiration: AbsoluteTime, addresses: &[u8]) -> bool {
        if let Some(snapshot) = self.desired.as_ref().or(self.inflight.as_ref()) {
            return snapshot.identity == identity
                && snapshot.expiration == expiration
                && snapshot.addresses == addresses;
        }
        self.installed.as_ref().is_some_and(|signed| {
            signed.revision == self.revision
                && signed.identity == identity
                && signed.expiration == expiration
                && signed.block.get(BLOCK_HEADER_LEN..) == Some(addresses)
        })
    }
    /// `announcement` is the actual latest original PILS_PEER_ID frame. The
    /// iterator contains the IP owner's current real local interface URLs.
    /// Preserve the original HELLO expiration; an address refresh cannot renew it.
    pub fn refresh<'address>(
        &mut self,
        announcement: &[u8],
        identity: Identity<'id>,
        ip_urls: impl Iterator<Item = &'address [u8]> + Clone,
        now: AbsoluteTime,
    ) -> Result<bool, Error> {
        let update = PeerUpdate::decode(announcement)?;
        let original_bytes = update
            .block
            .len()
            .checked_sub(BLOCK_HEADER_LEN)
            .ok_or(Error::Truncated)?;
        if update.block.len() > self.limits.maximum_input_bytes
            || original_bytes > self.limits.maximum_address_bytes
        {
            return Err(Error::TooLarge);
        }
        let mut scratch = self.buffer(original_bytes, 0)?;
        let scratch_capacity = scratch.capacity();
        let hello = Hello::parse_block(update.block, &mut scratch, self.limits)?;
        hello.verify_at(self.profile, now)?;
        if hello.peer() != identity.peer()
            || hello.expiration() != identity.expiration()
            || update.hash != identity.address_hash()
        {
            return Err(Error::StaleGeneration);
        }
        let capacity = ip_urls
            .clone()
            .try_fold(hello.address_bytes().len(), |n, url| {
                n.checked_add(url.len())
                    .and_then(|n| n.checked_add(1))
                    .ok_or(Error::Overflow)
            })?;
        if capacity > self.limits.maximum_address_bytes {
            return Err(Error::TooLarge);
        }
        let mut addresses = self.buffer(capacity, scratch_capacity)?;
        let used = {
            let mut builder = HelloBuilder::new(&mut addresses, self.limits);
            for address in hello.addresses() {
                builder.add_address(address.as_bytes())?;
            }
            for address in ip_urls {
                builder.add_address(address)?;
            }
            let unsigned = builder.with_signature(
                identity.peer(),
                EddsaSignature::from_bytes([0; 64]),
                hello.expiration(),
            );
            if unsigned.block_len()? > self.limits.maximum_input_bytes {
                return Err(Error::TooLarge);
            }
            unsigned.message_len()?;
            unsigned.dht_message_len()?;
            builder.address_bytes().len()
        };
        addresses.truncate(used);
        if self.same(identity, hello.expiration(), &addresses) {
            return Ok(false);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        self.desired = Some(Snapshot {
            identity,
            revision,
            expiration: hello.expiration(),
            addresses,
        });
        self.revision = revision;
        Ok(true)
    }
    /// A real local identity change withdraws the old announcement at once.
    /// Keep any actual old SIGN debt until its original completion/retirement;
    /// an address rescan or a failed replacement cannot resurrect that result.
    pub fn identity_changed(&mut self) -> Result<(), Error> {
        self.revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        self.desired = None;
        self.installed = None;
        Ok(())
    }
    /// Only read the immutable prepared set; this does not admit a signature.
    pub fn request<'scratch>(
        &self,
        scratch: &'scratch mut [u8],
        now: AbsoluteTime,
    ) -> Result<Option<SignRequest<'scratch, 'id>>, Error> {
        if self.inflight.is_some() {
            return Ok(None);
        }
        let Some(snapshot) = &self.desired else {
            return Ok(None);
        };
        if snapshot.expiration < now {
            return Err(Error::Deadline);
        }
        let mut builder = HelloBuilder::new(scratch, self.limits);
        for address in snapshot
            .addresses
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
        {
            builder.add_address(address)?;
        }
        Ok(Some(SignRequest {
            revision: snapshot.revision,
            identity: snapshot.identity,
            expiration: snapshot.expiration,
            builder,
        }))
    }
    /// Call after the same SignRequest was really admitted to the shared Signer.
    /// The exact original set remains owned until that original operation retires.
    pub fn started(&mut self, revision: u64) -> Result<(), Error> {
        if self.inflight.is_some() || self.desired.as_ref().is_none_or(|s| s.revision != revision) {
            return Err(Error::StaleGeneration);
        }
        self.inflight = self.desired.take();
        Ok(())
    }
    /// Only an actual matching Signature completion, after its copied frame is
    /// quiescent, can install a HELLO. Newer addresses do not borrow an old result.
    pub fn complete(
        &mut self,
        revision: u64,
        identity: Identity<'id>,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        now: AbsoluteTime,
    ) -> Result<bool, Error> {
        let snapshot = self.inflight.as_ref().ok_or(Error::StaleGeneration)?;
        if snapshot.revision != revision || snapshot.identity != identity || identity.peer() != peer
        {
            return Err(Error::StaleGeneration);
        }
        if self.desired.is_some() || revision != self.revision {
            self.inflight = None;
            return Ok(false);
        }
        let mut block = self.buffer(
            BLOCK_HEADER_LEN
                .checked_add(snapshot.addresses.len())
                .ok_or(Error::Overflow)?,
            0,
        )?;
        // Builder scratch is external to the retained final block, and its real
        // capacity remains charged in this owner until verification/copy ends.
        let mut scratch = self.buffer(snapshot.addresses.len(), block.capacity())?;
        let mut builder = HelloBuilder::new(&mut scratch, self.limits);
        for address in snapshot
            .addresses
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
        {
            builder.add_address(address)?;
        }
        let hello = builder.with_signature(peer, signature, snapshot.expiration);
        hello.verify_at(self.profile, now)?;
        hello.encode_block(&mut block)?;
        let signed = Signed {
            identity,
            revision,
            expiration: snapshot.expiration,
            block,
        };
        self.inflight = None;
        self.installed = Some(signed);
        Ok(true)
    }
    /// Retire this exact original failed/cancelled SIGN; never manufacture a result.
    pub fn abandon(&mut self, revision: u64) -> Result<(), Error> {
        if self
            .inflight
            .as_ref()
            .is_none_or(|s| s.revision != revision)
        {
            return Err(Error::StaleGeneration);
        }
        self.inflight = None;
        Ok(())
    }
    fn current(&self) -> Option<&Signed<'id>> {
        self.installed.as_ref().filter(|s| {
            s.revision == self.revision && self.desired.is_none() && self.inflight.is_none()
        })
    }
    pub fn block(&self) -> Option<&[u8]> {
        self.current().map(|s| s.block.as_slice())
    }
    pub fn message(&self) -> Result<Option<Vec<u8>>, Error> {
        let Some(signed) = self.current() else {
            return Ok(None);
        };
        let mut scratch = self.buffer(signed.block.len().saturating_sub(BLOCK_HEADER_LEN), 0)?;
        let scratch_capacity = scratch.capacity();
        let hello = Hello::parse_block(&signed.block, &mut scratch, self.limits)?;
        let mut message = self.buffer(hello.dht_message_len()?, scratch_capacity)?;
        hello.encode_dht_message(&mut message)?;
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_crypto::EddsaPrivateKey;
    use gnunet_pils::{
        Profile,
        client::{Client, Inbound, Instance},
    };
    fn check(value: bool) -> Result<(), Error> {
        if value { Ok(()) } else { Err(Error::Conflict) }
    }
    #[test]
    fn original_signed_set_cannot_authorize_later_ip_addresses_or_extend_expiration()
    -> Result<(), Error> {
        // Actual pure PILS codec/identity verification and real EdDSA with a
        // public fixture seed. The SIGN completion below is explicitly modeled;
        // this case makes no native-service or C interoperability assertion.
        let limits = Limits {
            maximum_input_bytes: 1024,
            maximum_address_bytes: 512,
            maximum_addresses: 16,
        };
        let profile = Profile::Reference029;
        let key = EddsaPrivateKey::from_seed([7; 32]);
        let expiration = AbsoluteTime::from_micros(100);
        let mut base_bytes = [0; 256];
        let mut base = HelloBuilder::new(&mut base_bytes, limits);
        base.add_address(b"tcp://192.0.2.1:2086")?;
        let hello = base.sign(&key, expiration, profile.hello())?;
        let mut block = vec![0; hello.block_len()?];
        hello.encode_block(&mut block)?;
        let update = PeerUpdate {
            hash: base.address_hash(profile.hello()),
            block: &block,
        };
        let mut announcement =
            vec![0; gnunet_wire::official::pils::PEER_UPDATE_PREFIX + block.len()];
        update.encode(&mut announcement)?;
        let mut instance = Instance::new();
        let mut client = Client::<1, 256, 1024>::new(&mut instance, profile, limits)?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut observed = announcement.clone();
        let mut scratch = [0; 512];
        let Inbound::Identity { identity, .. } = client.receive(
            epoch,
            &mut observed,
            &mut scratch,
            AbsoluteTime::from_micros(1),
        )?
        else {
            return Err(Error::Conflict);
        };
        let mut own = OwnHello::new(limits, profile.hello(), 4096)?;
        own.refresh(
            &announcement,
            identity,
            [b"ip+udp://192.0.2.2:6666".as_slice()].into_iter(),
            AbsoluteTime::from_micros(2),
        )?;
        let (original_revision, signature) = {
            let original = own
                .request(&mut scratch, AbsoluteTime::from_micros(2))?
                .ok_or(Error::NotReady)?;
            let signature = original
                .builder
                .sign(&key, original.expiration, profile.hello())?
                .signature();
            check(original.expiration == expiration && original.identity == identity)?;
            (original.revision, signature)
        };
        own.started(original_revision)?;
        own.refresh(
            &announcement,
            identity,
            [b"ip+udp://192.0.2.3:6666".as_slice()].into_iter(),
            AbsoluteTime::from_micros(3),
        )?;
        check(
            !own.complete(
                original_revision,
                identity,
                key.public_key(),
                signature,
                AbsoluteTime::from_micros(3),
            )? && own.block().is_none(),
        )?;
        let (revision, signature) = {
            let current = own
                .request(&mut scratch, AbsoluteTime::from_micros(3))?
                .ok_or(Error::NotReady)?;
            check(current.revision != original_revision && current.expiration == expiration)?;
            let signature = current
                .builder
                .sign(&key, current.expiration, profile.hello())?
                .signature();
            (current.revision, signature)
        };
        own.started(revision)?;
        check(own.complete(
            revision,
            identity,
            key.public_key(),
            signature,
            AbsoluteTime::from_micros(3),
        )?)?;
        let installed =
            Hello::parse_block(own.block().ok_or(Error::NotReady)?, &mut scratch, limits)?;
        installed.verify_at(profile.hello(), AbsoluteTime::from_micros(3))?;
        check(installed.expiration() == expiration && installed.address_count() == 2)?;
        check(
            installed
                .addresses()
                .any(|a| a.as_bytes() == b"tcp://192.0.2.1:2086"),
        )?;
        check(
            installed
                .addresses()
                .any(|a| a.as_bytes() == b"ip+udp://192.0.2.3:6666"),
        )?;
        check(
            !installed
                .addresses()
                .any(|a| a.as_bytes() == b"ip+udp://192.0.2.2:6666"),
        )?;
        let message = own.message()?.ok_or(Error::NotReady)?;
        let installed =
            Hello::parse_message(&message, Some(key.public_key()), &mut scratch, limits)?;
        check(installed.expiration() == expiration && installed.address_count() == 2)?;
        // An actual later address snapshot immediately makes the old signed
        // set unavailable, including after its replacement SIGN fails/retire.
        own.refresh(
            &announcement,
            identity,
            [b"ip+udp://192.0.2.4:6666".as_slice()].into_iter(),
            AbsoluteTime::from_micros(4),
        )?;
        check(own.block().is_none() && own.message()?.is_none())?;
        let failed_revision = own
            .request(&mut scratch, AbsoluteTime::from_micros(4))?
            .ok_or(Error::NotReady)?
            .revision;
        own.started(failed_revision)?;
        own.abandon(failed_revision)?;
        check(own.block().is_none() && own.message()?.is_none())?;
        own.refresh(
            &announcement,
            identity,
            [b"ip+udp://192.0.2.5:6666".as_slice()].into_iter(),
            AbsoluteTime::from_micros(5),
        )?;
        let (revision, signature) = {
            let request = own
                .request(&mut scratch, AbsoluteTime::from_micros(5))?
                .ok_or(Error::NotReady)?;
            (
                request.revision,
                request
                    .builder
                    .sign(&key, request.expiration, profile.hello())?
                    .signature(),
            )
        };
        own.started(revision)?;
        check(own.block().is_none() && own.message()?.is_none())?;
        check(
            own.complete(
                failed_revision,
                identity,
                key.public_key(),
                signature,
                AbsoluteTime::from_micros(5),
            ) == Err(Error::StaleGeneration),
        )?;
        check(own.block().is_none() && own.message()?.is_none())?;
        check(
            own.complete(
                revision,
                identity,
                key.public_key(),
                signature,
                AbsoluteTime::from_micros(5),
            )? && own.block().is_some(),
        )?;
        let installed =
            Hello::parse_block(own.block().ok_or(Error::NotReady)?, &mut scratch, limits)?;
        check(
            installed.expiration() == expiration
                && installed
                    .addresses()
                    .any(|a| a.as_bytes() == b"ip+udp://192.0.2.5:6666"),
        )?;
        // A new actual PILS PID withdraws even an installed announcement
        // before new addresses are available, releasing its retained block.
        own.identity_changed()?;
        check(own.block().is_none() && own.message()?.is_none() && own.installed.is_none())?;
        own.refresh(
            &announcement,
            identity,
            [b"ip+udp://192.0.2.6:6666".as_slice()].into_iter(),
            AbsoluteTime::from_micros(6),
        )?;
        let (retiring_revision, retiring_signature) = {
            let request = own
                .request(&mut scratch, AbsoluteTime::from_micros(6))?
                .ok_or(Error::NotReady)?;
            (
                request.revision,
                request
                    .builder
                    .sign(&key, request.expiration, profile.hello())?
                    .signature(),
            )
        };
        own.started(retiring_revision)?;
        own.identity_changed()?;
        check(own.inflight.is_some())?;
        check(!own.complete(
            retiring_revision,
            identity,
            key.public_key(),
            retiring_signature,
            AbsoluteTime::from_micros(7),
        )?)?;
        check(own.inflight.is_none() && own.block().is_none() && own.message()?.is_none())?;
        Ok(())
    }
}
