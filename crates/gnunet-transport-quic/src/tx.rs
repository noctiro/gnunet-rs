//! Immutable original application bytes and an exact partial plaintext cursor.
use gnunet_types::Error;
use gnunet_wire::official::Frame;
/// Local cancellation disposition, not a remote application result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Canceled {
    /// No byte entered the QUIC/HTTP3 provider.
    Unsubmitted,
    /// Provider accepted original plaintext; stop/reset/close original stream
    /// and retain its independent actual IO cleanup outcome.
    ProviderAccepted {
        /// Exact original accepted plaintext prefix.
        bytes: usize,
    },
}
/// Original immutable plaintext. Provider admission is kept separate from UDP
/// byte exposure and peer stream acknowledgment (neither is inferred here).
pub struct Cursor<'a> {
    bytes: &'a [u8],
    accepted: usize,
    canceled: bool,
}
impl<'a> Cursor<'a> {
    /// Canonical complete GNUnet payload, including its existing4-byte header.
    pub fn frame(bytes: &'a [u8]) -> Result<Self, Error> {
        Frame::decode(bytes)?;
        Ok(Self::body(bytes))
    }
    /// Identity or checked HTTP body; no private length prefix is added.
    pub const fn body(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            accepted: 0,
            canceled: false,
        }
    }
    /// Exact immutable suffix. A future adapter must retry this same suffix,
    /// not reconstruct/replay the whole message on a partial provider write.
    pub fn pending(&self) -> Result<&'a [u8], Error> {
        if self.canceled {
            return Err(Error::Closed);
        }
        Ok(&self.bytes[self.accepted..])
    }
    /// Record actual provider return count only. Zero is WouldBlock, not done;
    /// overshoot fails without moving the original cursor.
    pub fn accepted(&mut self, count: usize) -> Result<bool, Error> {
        if self.canceled {
            return Err(Error::Closed);
        }
        if count == 0 {
            return Err(Error::WouldBlock);
        }
        let next = self.accepted.checked_add(count).ok_or(Error::Overflow)?;
        if next > self.bytes.len() {
            return Err(Error::InvalidInput);
        }
        self.accepted = next;
        Ok(next == self.bytes.len())
    }
    /// Local provider-admission completion only; never SEND/network success.
    pub fn is_accepted(&self) -> bool {
        !self.canceled && self.accepted == self.bytes.len()
    }
    /// Exact provider-admitted original bytes.
    pub const fn accepted_bytes(&self) -> usize {
        self.accepted
    }
    /// Clock-free original-interest cancellation. Positive admission cannot be
    /// relabelled unsent; actual stream reset/connection close remains external.
    pub fn cancel(&mut self) -> Canceled {
        self.canceled = true;
        if self.accepted == 0 {
            Canceled::Unsubmitted
        } else {
            Canceled::ProviderAccepted {
                bytes: self.accepted,
            }
        }
    }
}
