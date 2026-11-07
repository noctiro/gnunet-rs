//! Callable actual advanced epoch/group operations. All use the original room
//! source/member and real Core signer/key/provider bindings. AUTHORIZATION's
//! omitted wire MAC is never invented; it remains a real refusal in Core/M3.
use crate::{types::*, *};
use gnunet_types::Error as Fault;
use std::time::Duration;
use wire::body::Body;
fn micros(duration: Duration) -> Result<u64, Fault> {
    u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    /// Request actual original entropy under the Core's epoch/group authority.
    /// This is a provider job, not a key/published-announcement receipt.
    pub fn generate_epoch_key(
        &mut self,
        room: Room<'a>,
        epoch: Hash,
        id: ShortHash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, native_epoch, member) = self.sending(room)?;
        let operation =
            self.core
                .request_shared_key(source, member, epoch, id, now, span.logical)?;
        self.record_job(room, source, native_epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Prepare a fresh actual encrypted-record read with independent identifier
    /// provenance. This returns its original operation, never a restored key.
    pub fn recover_epoch_key(
        &mut self,
        room: Room<'a>,
        epoch: Hash,
        id: ShortHash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, native_epoch, member) = self.sending(room)?;
        let key = self.core.room_key(room)?;
        let order = self
            .core
            .group_identifier_order(room, &id)?
            .or_else(|| self.profiles.identifier_origin(key, &epoch, &id))
            .or_else(|| self.profiles.common_identifier_order());
        if order.is_none() {
            return Err(Fault::Unavailable.into());
        }
        let operation = self.core.request_epoch_record_profiled(
            source,
            member,
            domain::EpochRecordTarget {
                epoch,
                identifier: id,
                identifier_order: order,
            },
            now,
            span.logical,
        )?;
        self.record_job(room, source, native_epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Announce a genuinely possessed key using the actual retained epoch DH
    /// recipient and real HMAC/nonce. A signed echo is still required for apply.
    pub fn announce_epoch_key(
        &mut self,
        room: Room<'a>,
        id: ShortHash,
        lifetime: Duration,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let operation = self.core.prepare_announcement(
            source,
            member,
            id,
            micros(lifetime)?,
            &mut self.entropy,
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Request a key through an actual referenced announcement/APPEAL. Group
    /// appeals remain refused where the pinned active consumer refuses them.
    pub fn appeal_epoch_key(
        &mut self,
        room: Room<'a>,
        event: Hash,
        lifetime: Duration,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let operation = self.core.prepare_appeal(
            source,
            member,
            event,
            micros(lifetime)?,
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Send genuine HPKE ACCESS for an actually authorized original request.
    pub fn grant_epoch_access(
        &mut self,
        room: Room<'a>,
        event: Hash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let operation = self.core.prepare_access(
            source,
            member,
            event,
            &mut self.entropy,
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Actual key-holder REVOLUTION with a fresh nonce and genuine group HMAC.
    pub fn revoke_epoch_key(
        &mut self,
        room: Room<'a>,
        id: ShortHash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let operation = self.core.prepare_revolution(
            source,
            member,
            id,
            &mut self.entropy,
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Prepare an official signed group proposal with two original announcement
    /// references. Actual applied state checks ownership, completed cohorts,
    /// disjointness and level. No new cohort/key is granted at admission.
    pub fn propose_group(
        &mut self,
        room: Room<'a>,
        level: u32,
        initiator: Hash,
        partner: Hash,
        lifetime: Duration,
        timeout: Duration,
    ) -> Result<(ShortHash, Operation<'a>), Error> {
        if level == 0 || initiator == partner {
            return Err(Fault::InvalidInput.into());
        }
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let id = self.core.fresh_identifier(Some(level), &mut self.entropy)?;
        let operation = self.core.prepare_send(
            source,
            member,
            Body::Group {
                identifier: &id,
                initiator: &initiator,
                partner: &partner,
                timeout: gnunet_wire::official::RelativeTime::from_micros(micros(lifetime)?),
            },
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok((id, operation))
    }
}
