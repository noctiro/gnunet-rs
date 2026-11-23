//! Client composition of private, group and key-control messages.

use crate::{engine::Core, graph::owner, recipient::MemberRecipient, *};
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind};

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Actual private-message composition for one real advertised recipient.
    /// The caller owns bounded encrypted/plain scratch and real entropy.
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    pub fn prepare_private<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        recipient: MemberSession<'id>,
        body: Body<'_>,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.prepare_private_profiled(
            source,
            member,
            recipient,
            body,
            ShortLayout::same(self.profile),
            encrypted,
            scratch,
            entropy,
            now,
            deadline,
        )
    }
    /// Real recipient-specific short encoding, independent from this sender's
    /// signed outer grammar and any later relay padding. Recipient/id/public
    /// key remain exact raw protocol bytes, never byte-swapped by this method.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original source/member/recipient, explicit payload and bounded crypto owners stay separate"
    )]
    pub fn prepare_private_profiled<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        recipient: MemberSession<'id>,
        body: Body<'_>,
        payload: ShortLayout,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        self.check_member(recipient)?;
        if recipient.room != source.room {
            return Err(Error::Permission);
        }
        let recipient = self
            .rooms
            .get(recipient.room)?
            .sessions
            .get(recipient.slot)?;
        if recipient.phase != SessionPhase::Active {
            return Err(Fault::NotReady.into());
        }
        let attribution = MemberRecipient::new(owner(recipient), recipient.public);
        let (key, _) = crypto::EcdhePublic::decode_hpke(&recipient.hpke)?;
        encrypted.seal_private_profiled(key, body, payload, scratch, entropy)?;
        let result = self.queue_sign(
            source,
            Some(member),
            Some(attribution),
            public,
            sender,
            crypto::message::private_body(encrypted),
            now,
            deadline,
        );
        encrypted.clear();
        result
    }
    /// Encrypt only with an actual admitted current-epoch announcement key.
    /// Group-subset identifiers cannot silently become whole-room SECRET keys.
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    pub fn prepare_secret<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        body: Body<'_>,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.prepare_secret_profiled(
            source,
            member,
            body,
            ShortLayout::same(self.profile),
            encrypted,
            scratch,
            entropy,
            now,
            deadline,
        )
    }
    /// Actually encrypt the selected epoch announcement using independent
    /// plaintext encoders. The raw identifier and sender/recipient capabilities
    /// are never normalized into this host's bitfield order.
    #[expect(
        clippy::too_many_arguments,
        reason = "Actual scoped providers and explicit plaintext profile require independent owners"
    )]
    pub fn prepare_secret_profiled<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        body: Body<'_>,
        payload: ShortLayout,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        if !crypto::message::permits_private(body.kind()) {
            return Err(Fault::InvalidInput.into());
        }
        let row = self.rooms.get(source.room)?;
        let epoch = row
            .epochs
            .get(row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?)?;
        let contact = row.sessions.get(member.slot)?.contact;
        if !epoch.complete || !row.epoch_has_member(epoch, contact) {
            return Err(Error::Permission);
        }
        let group = epoch
            .groups
            .get(epoch.best_announcement.ok_or(Fault::NotReady)?)?;
        if !group.valid
            || crate::epoch::identifier_order(group.identifier_order, &group.identifier).0
        {
            return Err(Error::Permission);
        }
        encrypted.seal_secret_profiled(
            &group.identifier,
            group.key.as_ref().ok_or(Fault::NotReady)?,
            body,
            payload,
            scratch,
            entropy,
        )?;
        let encoded = Body::decode(Kind::SECRET, encrypted.expose(), self.profile)?;
        let result = self.queue_sign(
            source,
            Some(member),
            None,
            public,
            sender,
            encoded,
            now,
            deadline,
        );
        encrypted.clear();
        result
    }
    /// Create the exact official identifier bits from an explicit entropy port.
    /// None means announcement(level0, group0); Some(level) means a group.
    pub fn fresh_identifier(
        &self,
        level: Option<u32>,
        entropy: &mut impl crypto::Entropy,
    ) -> Result<ShortHash, Error> {
        if level.is_some_and(|l| {
            l >= usize::BITS
                || l >= 128
                || 1usize
                    .checked_shl(l)
                    .is_none_or(|n| n > self.limits.sessions_per_room)
        }) {
            return Err(Fault::InvalidInput.into());
        }
        let mut id = [0; 32];
        entropy.fill(&mut id).map_err(|_| Fault::Entropy)?;
        id[0] = match (self.profile.endian, level) {
            (wire::profile::Endian::Little, Some(l)) => ((l as u8) << 1) | 1,
            (wire::profile::Endian::Big, Some(l)) => (l as u8) | 0x80,
            (_, None) => 0,
        };
        Ok(id)
    }
    /// Prepare the official AUTHORIZATION transfer for one admitted announcement
    /// or group proposal, using the possessed target and wrapping-group keys.
    ///
    /// # Errors
    /// Refuses stale epochs, invalid group relations, missing keys and original
    /// member/source failures before queuing the signer operation.
    pub fn prepare_authorization(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        identifier: ShortHash,
        event: Hash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.local_sender(source, member)?;
        let (authorization, expires) =
            self.authorization_fields(source, member, identifier, event)?;
        self.prepare_send(
            source,
            member,
            authorization.body(),
            now,
            deadline.min(expires),
        )
    }
    /// Compute and queue an actual key-authenticated revolution; receipt changes validity.
    pub fn prepare_revolution(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        id: ShortHash,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let e = row
            .epochs
            .get(row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?)?;
        let (_, g) = e
            .groups
            .iter()
            .find(|(_, g)| g.identifier == id && g.valid)
            .ok_or(Fault::NotReady)?;
        let mut nonce = [0; 32];
        entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
        if e.nonces.iter().any(|n| n.value == nonce) {
            return Err(Fault::Replay.into());
        }
        let zero = [0; 64];
        let draft = Body::Revolution {
            identifier: &id,
            nonce: &nonce,
            hmac: &zero,
        };
        let mac = crypto::group::message_mac(draft, g.key.as_ref().ok_or(Fault::NotReady)?)?;
        self.prepare_send(
            source,
            member,
            Body::Revolution {
                identifier: &id,
                nonce: &nonce,
                hmac: &mac,
            },
            now,
            deadline,
        )
    }
}
