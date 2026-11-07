//! CORE application epochs and anti-replay ownership. State changes only after
//! authenticated records; failed speculative ratchets cannot erase replay state.
use crate::wire::{self, RECORD_PREFIX};
use gnunet_session_crypto::{Prk, session};
use gnunet_types::Error;
use zeroize::Zeroize;

const EPOCHS: usize = 10;
const EPOCH_US: u64 = 12 * 60 * 60 * 1_000_000;

/// Rejection of the public epoch field before key derivation or authentication.
/// It says nothing about peer identity or transport health and changes no keys,
/// replay window, association or activity deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochRejection {
    /// The offered epoch is beyond the bounded speculative-derivation policy.
    TooNew,
    /// The offered epoch is outside the retained receive-key ring.
    TooOld,
}
impl EpochRejection {
    /// Preserve the original error classification for diagnostic/API consumers.
    #[must_use]
    pub const fn cause(self) -> Error {
        match self {
            Self::TooNew => Error::TooLarge,
            Self::TooOld => Error::Stale,
        }
    }
}
/// A receive failure classified at the actual record boundary. Only the two
/// public epoch-policy checks produce `RejectedEpoch`; a similarly named error
/// from local capacity, ownership or cryptographic work stays `Failed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    /// A single untrusted record must be discarded without retiring its owner.
    RejectedEpoch(EpochRejection),
    /// Original unmodified error from another receive step.
    Failed(Error),
}
impl ReceiveError {
    /// Return the original error; this projection does not authorize discarding
    /// local failures merely because their value equals an epoch-policy error.
    #[must_use]
    pub const fn cause(self) -> Error {
        match self {
            Self::RejectedEpoch(reason) => reason.cause(),
            Self::Failed(error) => error,
        }
    }
}
impl From<Error> for ReceiveError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

#[derive(Clone, Copy, Default)]
struct Window {
    maximum: u64,
    bits: u64,
}
impl Window {
    fn check(self, sequence: u64) -> Result<(), Error> {
        if sequence <= self.maximum {
            let behind = self.maximum - sequence;
            if behind >= 64 || self.bits & (1_u64 << behind) != 0 {
                return Err(Error::Replay);
            }
        }
        Ok(())
    }
    fn commit(&mut self, sequence: u64) {
        if sequence > self.maximum {
            let shift = sequence - self.maximum;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.maximum = sequence;
        }
        self.bits |= 1_u64 << (self.maximum - sequence);
    }
}
struct Epoch {
    number: u64,
    key: Prk,
    replay: Window,
}

/// One sending direction. No Clone, secret export or implicit randomness.
pub struct Sender {
    key: Prk,
    epoch: u64,
    sequence: u64,
    expires: u64,
}
impl Sender {
    /// Install a verified direction's key, with its already-consumed sequence count.
    #[must_use]
    pub const fn new(key: Prk, next_sequence: u64, now: u64) -> Self {
        Self {
            key,
            epoch: 0,
            sequence: next_sequence,
            expires: now.saturating_add(EPOCH_US),
        }
    }
    /// Current public epoch and next sequence; these disclose no key bytes.
    #[must_use]
    pub const fn position(&self) -> (u64, u64) {
        (self.epoch, self.sequence)
    }
    /// Advance due to an authenticated heartbeat's key-update request.
    pub fn update(&mut self, now: u64) -> Result<(), Error> {
        let epoch = self.epoch.checked_add(1).ok_or(Error::TooLarge)?;
        let key = session::next_application(&self.key)?;
        self.key = key;
        self.epoch = epoch;
        self.sequence = 0;
        self.expires = now.saturating_add(EPOCH_US);
        Ok(())
    }
    /// Protect complete messages. The returned frame must be retained by its host
    /// until transport admission; encoding establishes no send/processing ACK.
    pub fn seal(&mut self, now: u64, plaintext: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        wire::messages(plaintext)?;
        let size = plaintext
            .len()
            .checked_add(RECORD_PREFIX)
            .ok_or(Error::Overflow)?;
        if size > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        if output.len() < size {
            return Err(Error::Capacity);
        }
        if self.sequence == u64::MAX || now > self.expires {
            self.update(now)?;
        }
        output[RECORD_PREFIX..size].copy_from_slice(plaintext);
        let (tag, sequence) =
            session::seal_record(&self.key, self.sequence, &mut output[RECORD_PREFIX..size])?;
        wire::header(output, size, 83)?;
        output[4..12].copy_from_slice(&self.epoch.to_be_bytes());
        output[12..20].copy_from_slice(&sequence);
        output[20..36].copy_from_slice(&tag);
        self.sequence += 1;
        Ok(size)
    }
}

/// One receiving direction. Speculative keys are committed only after AEAD.
pub struct Receiver {
    slots: [Option<Epoch>; EPOCHS],
    maximum: u64,
}
impl Receiver {
    /// Install an authenticated traffic secret. The source initiator prefetches
    /// nine future epochs; the source responder starts its high-water mark at zero.
    pub fn new(key: Prk, initiator: bool, consumed_zero: bool) -> Result<Self, Error> {
        let mut slots = core::array::from_fn(|_| None);
        slots[0] = Some(Epoch {
            number: 0,
            key,
            replay: Window::default(),
        });
        for index in 1..EPOCHS {
            let previous = slots[index - 1].as_ref().ok_or(Error::NotReady)?;
            let key = session::next_application(&previous.key)?;
            slots[index] = Some(Epoch {
                number: index as u64,
                key,
                replay: Window::default(),
            });
        }
        if consumed_zero {
            slots[0].as_mut().ok_or(Error::NotReady)?.replay.commit(0);
        }
        Ok(Self {
            slots,
            maximum: if initiator { EPOCHS as u64 - 1 } else { 0 },
        })
    }
    /// Highest authenticated/source-prefetched epoch. It never regresses on reorder.
    #[must_use]
    pub const fn maximum_epoch(&self) -> u64 {
        self.maximum
    }
    /// Deprotect into caller storage and return authenticated `(sequence, bytes)`.
    /// A failure preserves keys/windows; authentication failure erases copied data.
    pub fn open(&mut self, frame: &[u8], plaintext: &mut [u8]) -> Result<(u64, usize), Error> {
        self.open_classified(frame, plaintext)
            .map_err(ReceiveError::cause)
    }
    /// Deprotect with precise epoch-policy rejection provenance. The same
    /// algorithm backs [`Self::open`]; this adds no success or authenticity fact.
    /// An epoch rejection precedes speculative derivation and all mutation.
    /// Local scratch/key/crypto failures are never reclassified by error value.
    pub fn open_classified(
        &mut self,
        frame: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(u64, usize), ReceiveError> {
        if wire::kind(frame)? != 83 || frame.len() < RECORD_PREFIX + 4 {
            return Err(Error::InvalidInput.into());
        }
        let size = frame.len() - RECORD_PREFIX;
        if plaintext.len() < size {
            return Err(Error::Capacity.into());
        }
        let epoch = u64::from_be_bytes(wire::array(frame, 4)?);
        if epoch > self.maximum && epoch - self.maximum > 2 * EPOCHS as u64 {
            return Err(ReceiveError::RejectedEpoch(EpochRejection::TooNew));
        }
        if epoch < self.maximum && self.maximum - epoch >= EPOCHS as u64 {
            return Err(ReceiveError::RejectedEpoch(EpochRejection::TooOld));
        }
        let mut future: [Option<Epoch>; EPOCHS] = core::array::from_fn(|_| None);
        if epoch > self.maximum {
            for number in self.maximum + 1..=epoch {
                let old = ((number - 1) % EPOCHS as u64) as usize;
                let previous = future[old]
                    .as_ref()
                    .or(self.slots[old].as_ref())
                    .ok_or(Error::NotReady)?;
                let key = session::next_application(&previous.key)?;
                future[(number % EPOCHS as u64) as usize] = Some(Epoch {
                    number,
                    key,
                    replay: Window::default(),
                });
            }
        }
        let index = (epoch % EPOCHS as u64) as usize;
        let selected = future[index]
            .as_ref()
            .or(self.slots[index].as_ref())
            .ok_or(Error::NotReady)?;
        if selected.number != epoch {
            return Err(Error::Stale.into());
        }
        let tag = wire::array(frame, 20)?;
        let protected = wire::array(frame, 12)?;
        let sequence =
            u64::from_be_bytes(session::protect_sequence(&selected.key, &tag, &protected)?);
        selected.replay.check(sequence)?;
        plaintext[..size].copy_from_slice(&frame[RECORD_PREFIX..]);
        if let Err(error) = session::record_material(&selected.key, sequence)?.open(
            &[],
            &mut plaintext[..size],
            &tag,
        ) {
            plaintext[..size].zeroize();
            return Err(error.into());
        }
        for (slot, proposed) in self.slots.iter_mut().zip(future) {
            if proposed.is_some() {
                *slot = proposed;
            }
        }
        self.maximum = self.maximum.max(epoch);
        self.slots[index]
            .as_mut()
            .ok_or(Error::NotReady)?
            .replay
            .commit(sequence);
        Ok((sequence, size))
    }
}
