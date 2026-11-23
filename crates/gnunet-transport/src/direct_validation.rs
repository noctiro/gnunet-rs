//! Allocation-free address validation for one authenticated direct carrier.
//!
//! The embedding binds this owner to its original TCP session and drives it
//! with that session's authenticated receive and local BOX admission events.
//! Carrier replacement requires another owner. Methods here manage only the
//! official address-validation messages and local reachability lease.
use crate::p2p::{CHALLENGE_PURPOSE, Challenge, MAX_VALIDITY, VALIDATION_INTERVAL, Validation};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, Entropy};
use gnunet_types::{Error, MonoInstant, RelativeTime};
use zeroize::Zeroizing;

const RETRY_MICROS: u64 = 1_000_000;

/// Whether this carrier currently has a valid remote reachability proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// An initial or replacement proof is required.
    Unvalidated,
    /// The current proof remains valid strictly before this local deadline.
    Ready(MonoInstant),
    /// The original carrier owner has retired.
    Closed,
}

#[derive(Debug)]
struct Probe {
    challenge: Challenge,
    expires_at: MonoInstant,
    retry_at: Option<MonoInstant>,
    first_admission: Option<MonoInstant>,
    retried: bool,
}

/// Original verified challenge result and its local lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationObservation {
    /// Elapsed instant when the original response verified.
    pub accepted_at: MonoInstant,
    /// End of the original reachability proof.
    pub expires_at: MonoInstant,
    /// Measured response time from the first admitted probe, if unambiguous.
    pub rtt: Option<u64>,
}

#[derive(Debug)]
struct Lease {
    report: ValidationObservation,
    renew_at: MonoInstant,
}

#[derive(Debug)]
struct Link {
    probe: Option<Probe>,
    lease: Option<Lease>,
}

/// One direction of GNUnet TRANSPORT reachability for a fixed peer and carrier.
#[derive(Debug)]
pub struct DirectValidation {
    local: EddsaPublicKey,
    remote: EddsaPublicKey,
    response_timeout: RelativeTime,
    last_observed: MonoInstant,
    last_validation: Option<ValidationObservation>,
    link: Option<Link>,
}

impl DirectValidation {
    /// Create an unvalidated owner for an original authenticated direct carrier.
    ///
    /// The local and expected remote identities come from that carrier. The
    /// finite response timeout covers both output admission and peer response.
    ///
    /// # Errors
    /// Rejects a self-link or a zero or infinite response timeout.
    pub fn new(
        local: EddsaPublicKey,
        remote: EddsaPublicKey,
        response_timeout: RelativeTime,
    ) -> Result<Self, Error> {
        if local == remote || response_timeout.as_micros() == 0 || response_timeout.is_forever() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            local,
            remote,
            response_timeout,
            last_observed: MonoInstant(0),
            last_validation: None,
            link: Some(Link {
                probe: None,
                lease: None,
            }),
        })
    }

    /// Prepare the due challenge for the original carrier.
    ///
    /// The same bytes can be offered again after backpressure or the one-second
    /// retry interval. The bound response interval starts at first preparation.
    /// Report each successful local BOX admission with `challenge_admitted`.
    ///
    /// # Errors
    /// Fails on a closed owner, invalid clock, deadline overflow or unavailable entropy.
    pub fn poll_challenge(
        &mut self,
        now: MonoInstant,
        entropy: &mut impl Entropy,
    ) -> Result<Option<Challenge>, Error> {
        let timeout = self.response_timeout.as_micros();
        let link = self.advance(now)?;
        if let Some(probe) = &link.probe {
            return Ok(probe
                .retry_at
                .is_none_or(|retry| now >= retry)
                .then_some(probe.challenge));
        }
        if link
            .lease
            .as_ref()
            .is_some_and(|lease| now < lease.renew_at)
        {
            return Ok(None);
        }

        let expires_at = after(now, timeout)?;
        let mut nonce = Zeroizing::new([0; 32]);
        entropy.fill(&mut *nonce)?;
        let challenge = Challenge {
            nonce: *nonce,
            origin: now.0,
        };
        link.probe = Some(Probe {
            challenge,
            expires_at,
            retry_at: None,
            first_admission: None,
            retried: false,
        });
        Ok(Some(challenge))
    }

    /// Record successful local admission of the exact challenge on this carrier.
    ///
    /// This receipt enables response validation. It grants neither a delivery
    /// receipt nor a new retry credit before the retry deadline.
    ///
    /// # Errors
    /// Rejects retired, stale, early or differently bound admission receipts.
    pub fn challenge_admitted(
        &mut self,
        now: MonoInstant,
        challenge: Challenge,
    ) -> Result<(), Error> {
        let probe = self.advance(now)?.probe.as_mut().ok_or(Error::Stale)?;
        if challenge != probe.challenge {
            return Err(Error::Stale);
        }
        if probe.retry_at.is_some_and(|retry| now < retry) {
            return Err(Error::WouldBlock);
        }
        if probe.first_admission.is_some() {
            probe.retried = true;
        } else {
            probe.first_admission = Some(now);
        }
        let remaining = probe.expires_at.0 - now.0;
        probe.retry_at = Some(MonoInstant(now.0 + RETRY_MICROS.min(remaining)));
        Ok(())
    }

    /// Sign a remote challenge received on the original direct carrier.
    ///
    /// The advertised duration is capped at the official one-month limit.
    /// Answering an inbound probe leaves this owner's reachability unchanged.
    ///
    /// # Errors
    /// Rejects a closed owner, a mismatched local key or a zero validity.
    pub fn answer(
        &self,
        challenge: Challenge,
        signer: &EddsaPrivateKey,
        offered_validity: RelativeTime,
    ) -> Result<Validation, Error> {
        if self.link.is_none() {
            return Err(Error::Closed);
        }
        if signer.public_key() != self.local {
            return Err(Error::Authentication);
        }
        let validity = offered_validity.as_micros().min(MAX_VALIDITY);
        if validity == 0 {
            return Err(Error::InvalidInput);
        }
        let region = Validation::signed_region(&challenge.nonce, validity);
        let signature = signer.sign(CHALLENGE_PURPOSE, &region)?;
        Ok(Validation {
            signature: *signature.as_bytes(),
            nonce: challenge.nonce,
            origin: challenge.origin,
            validity,
        })
    }

    /// Verify a response from the original carrier and install its local lease.
    ///
    /// The echo must match the current probe and its admitted origin. Local
    /// reachability is capped at four hours and renews during its last eighth.
    ///
    /// # Errors
    /// Rejects missing, expired and replayed probes, mismatched echoes,
    /// signature failure, zero validity and invalid local deadlines.
    pub fn receive_response(
        &mut self,
        now: MonoInstant,
        response: Validation,
    ) -> Result<MonoInstant, Error> {
        let remote = self.remote;
        let link = self.advance(now)?;
        let probe = link.probe.as_ref().ok_or(Error::Replay)?;
        if probe.retry_at.is_none()
            || response.nonce != probe.challenge.nonce
            || response.origin != probe.challenge.origin
        {
            return Err(Error::Replay);
        }
        response.verify(*remote.as_bytes())?;
        let duration = response.validity.min(MAX_VALIDITY).min(VALIDATION_INTERVAL);
        if duration == 0 {
            return Err(Error::Authentication);
        }
        let expires_at = after(now, duration)?;
        let renew_at = MonoInstant(expires_at.0 - duration / 8);
        let rtt = probe
            .first_admission
            .filter(|_| !probe.retried)
            .map(|sent| now.0 - sent.0);
        let report = ValidationObservation {
            accepted_at: now,
            expires_at,
            rtt,
        };
        link.lease = Some(Lease { report, renew_at });
        link.probe = None;
        self.last_validation = Some(report);
        Ok(expires_at)
    }

    /// Advance deadlines and observe readiness before handling CORE payload.
    ///
    /// # Errors
    /// A live owner rejects backward or infinite local time samples.
    pub fn status(&mut self, now: MonoInstant) -> Result<Status, Error> {
        if self.link.is_none() {
            return Ok(Status::Closed);
        }
        Ok(self
            .advance(now)?
            .lease
            .as_ref()
            .map_or(Status::Unvalidated, |lease| {
                Status::Ready(lease.report.expires_at)
            }))
    }

    /// Next local timer for renewal, a retry, expiration or immediate work.
    ///
    /// An offered probe awaiting initial admission also requires a wake from
    /// the original carrier when its output becomes writable.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        let link = self.link.as_ref()?;
        let Some(probe) = &link.probe else {
            return Some(
                link.lease
                    .as_ref()
                    .map_or(self.last_observed, |lease| lease.renew_at),
            );
        };
        let deadline = probe.retry_at.unwrap_or(probe.expires_at);
        Some(
            link.lease
                .as_ref()
                .map_or(deadline, |lease| deadline.min(lease.report.expires_at)),
        )
    }

    /// Expiry of the active proof, independent of control send readiness.
    #[must_use]
    pub fn expires_at(&self) -> Option<MonoInstant> {
        self.link
            .as_ref()?
            .lease
            .as_ref()
            .map(|lease| lease.report.expires_at)
    }

    /// Deadline owned by the current probe or renewal. A first probe is
    /// reported once it has an actual prepared original.
    #[must_use]
    pub fn scheduled_validation(&self) -> Option<MonoInstant> {
        let link = self.link.as_ref()?;
        link.probe.as_ref().map_or_else(
            || link.lease.as_ref().map(|lease| lease.renew_at),
            |probe| Some(probe.retry_at.unwrap_or(probe.expires_at)),
        )
    }

    /// Last verified response of this original, even after its proof expired.
    #[must_use]
    pub const fn observation(&self) -> Option<ValidationObservation> {
        self.last_validation
    }

    /// Retire the original carrier's proof, pending probe and timers.
    pub fn cancel(&mut self) {
        self.link = None;
    }

    fn advance(&mut self, now: MonoInstant) -> Result<&mut Link, Error> {
        let link = self.link.as_mut().ok_or(Error::Closed)?;
        if now.0 == u64::MAX {
            return Err(Error::InvalidInput);
        }
        if now < self.last_observed {
            return Err(Error::TimeUncertain);
        }
        self.last_observed = now;
        if link
            .probe
            .as_ref()
            .is_some_and(|probe| now >= probe.expires_at)
        {
            link.probe = None;
        }
        if link
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.report.expires_at)
        {
            link.lease = None;
        }
        Ok(link)
    }
}

fn after(now: MonoInstant, micros: u64) -> Result<MonoInstant, Error> {
    now.0
        .checked_add(micros)
        .filter(|deadline| *deadline != u64::MAX)
        .map(MonoInstant)
        .ok_or(Error::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EntropyFixture(u8);

    impl Entropy for EntropyFixture {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            output.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    fn admitted_original_lease_renews_and_retires() -> Result<(), Error> {
        let local = EddsaPrivateKey::from_seed([1; 32]);
        let remote = EddsaPrivateKey::from_seed([2; 32]);
        let timeout = RelativeTime::from_micros(4 * RETRY_MICROS);
        let mut owner = DirectValidation::new(local.public_key(), remote.public_key(), timeout)?;
        let peer = DirectValidation::new(remote.public_key(), local.public_key(), timeout)?;
        let mut entropy = EntropyFixture(1);
        let start = MonoInstant(10);
        let challenge = owner
            .poll_challenge(start, &mut entropy)?
            .ok_or(Error::NotReady)?;
        let offer = RelativeTime::from_micros(80);
        let response = peer.answer(challenge, &remote, offer)?;
        if owner.receive_response(start, response) != Err(Error::Replay) {
            return Err(Error::Authentication);
        }
        owner.challenge_admitted(start, challenge)?;
        let before_retry = MonoInstant(RETRY_MICROS + 9);
        let retry = MonoInstant(RETRY_MICROS + 10);
        let wrong_signer = owner.answer(challenge, &local, offer)?;
        if owner.poll_challenge(before_retry, &mut entropy)?.is_some()
            || owner.poll_challenge(retry, &mut entropy)? != Some(challenge)
            || owner.receive_response(retry, wrong_signer) != Err(Error::Authentication)
            || owner.receive_response(
                retry,
                Validation {
                    origin: 11,
                    ..response
                },
            ) != Err(Error::Replay)
        {
            return Err(Error::InvalidInput);
        }
        owner.challenge_admitted(retry, challenge)?;
        let accepted = MonoInstant(retry.0 + 12);
        let expires = owner.receive_response(accepted, response)?;
        if expires != MonoInstant(accepted.0 + 80)
            || owner.observation()
                != Some(ValidationObservation {
                    accepted_at: accepted,
                    expires_at: expires,
                    rtt: None,
                })
            || owner.receive_response(accepted, response) != Err(Error::Replay)
        {
            return Err(Error::InvalidInput);
        }

        let renew_at = MonoInstant(expires.0 - 10);
        let renewal = owner
            .poll_challenge(renew_at, &mut entropy)?
            .ok_or(Error::NotReady)?;
        if renewal.nonce == challenge.nonce
            || owner.status(renew_at)? != Status::Ready(expires)
            || owner.status(expires)? != Status::Unvalidated
        {
            return Err(Error::InvalidInput);
        }
        let later = MonoInstant(expires.0 + 1);
        owner.challenge_admitted(later, renewal)?;
        let reply = peer.answer(renewal, &remote, offer)?;
        let verified = MonoInstant(later.0 + 12);
        let until = owner.receive_response(verified, reply)?;
        if owner.observation()
            != Some(ValidationObservation {
                accepted_at: verified,
                expires_at: until,
                rtt: Some(12),
            })
        {
            return Err(Error::Conflict);
        }
        owner.cancel();
        if owner.status(expires)? != Status::Closed
            || owner.next_deadline().is_some()
            || owner.challenge_admitted(expires, renewal) != Err(Error::Closed)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
