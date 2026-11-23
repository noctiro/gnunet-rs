//! Send one borrowed original as official fragments on a reliable carrier.
use crate::p2p::{FRAGMENT_HEADER_LEN, Fragment};
use core::{fmt, num::NonZeroU16};
use gnunet_crypto::{Entropy, hash256, symmetric::aes256ctr};
use gnunet_types::{Duration, Error, MonoInstant, RelativeTime};
use gnunet_wire::official::Frame;
use zeroize::Zeroizing;

/// Progress reported by the original carrier admission callback.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub enum Progress<T> {
    /// This fragment entered the carrier. The original has bytes remaining.
    Partial(T),
    /// Every fragment entered the carrier. The caller can release the original.
    Complete(T),
}

/// The position of one admitted BOX in its original frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Span {
    /// The original has bytes after this BOX.
    Partial,
    /// This BOX completes the original frame.
    Final,
}

struct Ids {
    key: Zeroizing<[u8; 32]>,
    original_base: u64,
}

impl Ids {
    fn new(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut key = Zeroizing::new([0; 32]);
        entropy.fill(&mut *key)?;
        let mut base = [0; 8];
        aes256ctr(&key, b"GNUNET Fragment\0", &mut base)?;
        Ok(Self {
            key,
            original_base: u64::from_be_bytes(base),
        })
    }

    fn original(&self, first_attempt: u64) -> [u8; 8] {
        self.original_base.wrapping_add(first_attempt).to_be_bytes()
    }

    fn attempt(&self, serial: u64) -> Result<[u8; 16], Error> {
        // An AES block is a permutation of these non-reused counter inputs.
        let mut iv = [0; 16];
        iv[..8].copy_from_slice(b"FRAGACK\0");
        iv[8..].copy_from_slice(&serial.to_be_bytes());
        let mut id = [0; 16];
        aes256ctr(&self.key, &iv, &mut id)?;
        Ok(id)
    }
}

struct Original {
    id: [u8; 8],
    fingerprint: [u8; 32],
    offset: u16,
    deadline: MonoInstant,
}

/// One original with constant metadata and no retained frame or wire packet.
///
/// The carrier supplies reliable byte delivery after native admission. Peer
/// ACKs are advisory and cannot grant additional progress or retransmissions.
pub(crate) struct Sender {
    mtu: NonZeroU16,
    retention: Duration,
    clock: MonoInstant,
    ids: Option<Ids>,
    attempt_serial: u64,
    original: Option<Original>,
}

impl Sender {
    /// Use the carrier's fixed whole-frame limit and a finite original deadline.
    pub(crate) fn new(mtu: NonZeroU16, retention: RelativeTime) -> Result<Self, Error> {
        if retention == RelativeTime::ZERO || retention.is_forever() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            mtu,
            retention: Duration(retention.as_micros()),
            clock: MonoInstant(0),
            ids: None,
            attempt_serial: 0,
            original: None,
        })
    }

    /// Whether the caller still owns the retained original.
    pub(crate) const fn is_active(&self) -> bool {
        self.original.is_some()
    }

    /// Deadline of the original, including periods of native backpressure.
    pub(crate) const fn deadline(&self) -> Option<MonoInstant> {
        match &self.original {
            Some(original) => Some(original.deadline),
            None => None,
        }
    }

    /// Retire the original when its validation ends. Already-issued wire IDs
    /// remain unavailable after this carrier is validated again.
    pub(crate) fn cancel(&mut self) {
        if self.original.take().is_some() {
            // Burn the next attempt because it may already have been offered.
            self.attempt_serial = self.attempt_serial.saturating_add(1);
        }
    }

    /// Submit the next fragment of the same original frame.
    ///
    /// The callback must return an error only before native admission. A known
    /// refusal retains the exact original, byte offset, attempt ID and deadline.
    /// The caller retires the carrier if the original's deadline expires.
    pub(crate) fn send<T>(
        &mut self,
        now: MonoInstant,
        frame: &[u8],
        scratch: &mut [u8],
        entropy: &mut impl Entropy,
        admit: impl FnOnce(&[u8], Span) -> Result<T, Error>,
    ) -> Result<Progress<T>, Error> {
        if now < self.clock || now.0 == u64::MAX {
            return Err(Error::TimeUncertain);
        }
        self.clock = now;
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            return Err(Error::Deadline);
        }

        let mtu = usize::from(self.mtu.get());
        let maximum_body = mtu
            .checked_sub(FRAGMENT_HEADER_LEN)
            .filter(|&body| body != 0)
            .ok_or(Error::TooLarge)?;
        let original_size = Frame::decode(frame)?.header().size();
        let total = u16::try_from(original_size).map_err(|_| Error::TooLarge)?;
        let fingerprint = hash256(frame);
        let offset = match &self.original {
            Some(original) if original.fingerprint != fingerprint => return Err(Error::Conflict),
            Some(original) => original.offset,
            None if original_size <= mtu => return Err(Error::InvalidInput),
            None => 0,
        };
        let start = usize::from(offset);
        let end = (start + maximum_body).min(original_size);
        let body = frame.get(start..end).ok_or(Error::Conflict)?;
        if scratch.len() < FRAGMENT_HEADER_LEN + body.len() {
            return Err(Error::Capacity);
        }
        let next_offset = u16::try_from(end).map_err(|_| Error::TooLarge)?;
        let serial = self.attempt_serial.checked_add(1).ok_or(Error::Overflow)?;
        let ids = match &mut self.ids {
            Some(ids) => ids,
            vacant @ None => vacant.insert(Ids::new(entropy)?),
        };
        let original = match &mut self.original {
            Some(original) => original,
            vacant @ None => {
                let deadline = now.after(self.retention)?;
                if deadline.0 == u64::MAX {
                    return Err(Error::Overflow);
                }
                vacant.insert(Original {
                    id: ids.original(serial),
                    fingerprint,
                    offset,
                    deadline,
                })
            }
        };
        let size = Fragment {
            offset,
            total,
            ack: ids.attempt(serial)?,
            message_id: original.id,
            body,
        }
        .encode(scratch)?;
        let span = if next_offset == total {
            Span::Final
        } else {
            Span::Partial
        };
        let admitted = admit(&scratch[..size], span)?;
        self.attempt_serial = serial;
        if next_offset == total {
            self.original = None;
            Ok(Progress::Complete(admitted))
        } else {
            original.offset = next_offset;
            Ok(Progress::Partial(admitted))
        }
    }
}

impl fmt::Debug for Sender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Sender")
            .field("mtu", &self.mtu)
            .field(
                "offset",
                &self.original.as_ref().map(|original| original.offset),
            )
            .field("deadline", &self.deadline())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
