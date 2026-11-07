//! Persistent ordered AES-CTR and source32-byte truncated ratcheting HMAC.
//! This component does not grant a key/record any session or peerstore authority.
use crate::wire::{self, Shape};
use gnunet_session_crypto::{
    Prk,
    session::{TcpStream, tcp_material},
};
use gnunet_types::{Error, Rejected};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
/// Exclusively owned one-direction stream with source-independent MAC ratchet.
/// No clone, debug dump, rewind, automatic entropy or hidden message sequence.
pub struct Direction {
    cipher: TcpStream,
    failed: bool,
}
impl Direction {
    /// Derive the exact official TCP labels from an already-established PRK.
    /// The caller must obtain it with the source-selected KEM, never substitute
    /// ordinary X25519 for the initial Elligator shared secret.
    pub fn new(prk: &Prk) -> Result<Self, Error> {
        let cipher = tcp_material(prk)?.into_stream();
        Ok(Self {
            cipher,
            failed: false,
        })
    }
    fn crypt(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if let Err(e) = self.cipher.crypt(bytes) {
            self.failed = true;
            return Err(e);
        }
        Ok(())
    }
    fn authenticate(&mut self, parts: &[&[u8]]) -> [u8; 32] {
        self.cipher.hmac_ratchet(parts)
    }
    /// Encrypt/decrypt the exact initial confirmation or signed ACK continuation.
    /// These source items are not passed through calculate_hmac, so this changes
    /// only CTR position. Framing/identity/challenge checks belong to the owner.
    pub fn handshake_fragment(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.crypt(bytes)
    }
    /// Encode and encrypt one complete official transport message inside a BOX.
    /// Capacity/framing refusal precedes any ratchet/cipher/output mutation.
    pub fn seal_box(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let n = self.stage_box(payload, out)?;
        self.crypt(&mut out[..n])?;
        Ok(n)
    }
    /// Source mq_send preparation: ratchet the MAC without encrypting yet.
    /// This commits the ordered BOX; the caller must drain or retire its stream.
    pub(crate) fn stage_box(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if payload.len() < 4 || payload.len() > u16::MAX as usize {
            return Err(Error::Malformed);
        }
        let declared = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if declared != payload.len() {
            return Err(Error::Malformed);
        }
        let n = wire::BOX_PREFIX + payload.len();
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out[2..4].copy_from_slice(&wire::BOX_TYPE.to_be_bytes());
        out[4..36].copy_from_slice(&self.authenticate(&[payload]));
        out[36..n].copy_from_slice(payload);
        Ok(n)
    }
    /// Encrypt the next complete source-prepared plaintext without a second MAC.
    pub(crate) fn encrypt_prepared(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
    ) -> Result<(), Error> {
        if cipher.len() < plain.len() {
            return Err(Error::Capacity);
        }
        cipher[..plain.len()].copy_from_slice(plain);
        self.crypt(&mut cipher[..plain.len()])
    }
    /// Encode the source FINISH, authenticating all36bytes with its MAC zeroed.
    /// Capacity failure leaves the stream, ratchet and caller output untouched.
    pub fn seal_finish(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.stage_finish(out)?;
        self.crypt(&mut out[..n])?;
        Ok(n)
    }
    pub(crate) fn stage_finish(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if out.len() < wire::BOX_PREFIX {
            return Err(Error::Capacity);
        }
        let mut fin = [0; wire::BOX_PREFIX];
        fin[..2].copy_from_slice(&(wire::BOX_PREFIX as u16).to_be_bytes());
        fin[2..4].copy_from_slice(&wire::FINISH_TYPE.to_be_bytes());
        let tag = self.authenticate(&[&fin]);
        fin[4..].copy_from_slice(&tag);
        out[..wire::BOX_PREFIX].copy_from_slice(&fin);
        Ok(wire::BOX_PREFIX)
    }
    /// Authenticate a caller-prepared signed rekey using the old cipher, then
    /// replace both contexts with the new KEM PRK at the exact record boundary.
    /// All fallible framing/capacity/new-material validation happens beforehand.
    pub fn seal_rekey(
        &mut self,
        plaintext: &[u8; wire::REKEY],
        new_prk: &Prk,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if Shape::decode(plaintext)? != Shape::Rekey {
            return Err(Error::Malformed);
        }
        if out.len() < wire::REKEY {
            return Err(Error::Capacity);
        }
        let next = Self::new(new_prk)?;
        let zero = [0; 32];
        let tag = self.authenticate(&[&plaintext[..4], &zero, &plaintext[36..]]);
        out[..wire::REKEY].copy_from_slice(plaintext);
        out[4..36].copy_from_slice(&tag);
        self.crypt(&mut out[..wire::REKEY])?;
        *self = next;
        Ok(wire::REKEY)
    }
}
/// One complete record. Non-ACK MACs are verified; ACK's signature is still
/// unverified here because its wire layout has no record MAC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Record<'a> {
    /// Verified source ratcheting MAC; inner transport framing needs owner check.
    Box(&'a [u8]),
    /// Signature/challenge unverified; use wire::verify_ack before admission.
    Ack(&'a [u8]),
    /// MAC verified; signed identity/replay and replacement PRK remain pending.
    Rekey(&'a [u8]),
    /// Authenticated source request to destroy the queue.
    Finish,
}
/// Caller-buffered record decoder that never decrypts past a record boundary.
/// This avoids advancing the old CTR context over ciphertext after a rekey.
/// Its buffer is exclusively borrowed and plaintext is erased on failure/drop.
pub struct Receiver<'a> {
    direction: Direction,
    buffer: &'a mut [u8],
    filled: usize,
    shape: Option<Shape>,
    verified: bool,
    terminal: bool,
}
impl<'a> Receiver<'a> {
    /// Reserve enough caller storage for a full65535-byte payload plus prefix.
    pub fn new(prk: &Prk, buffer: &'a mut [u8]) -> Result<Self, Error> {
        if buffer.len() < wire::MAX_RECORD {
            return Err(Error::Capacity);
        }
        Self::with_direction(Direction::new(prk)?, buffer).map_err(|r| r.reason)
    }
    /// Continue the exact unique CTR/MAC owner after the initial136-byte
    /// confirmation has consumed stream position. No cipher context is cloned.
    /// Capacity rejection returns the original consumed-position Direction.
    #[expect(
        clippy::result_large_err,
        reason = "The no-alloc rejection must return the unique live expanded cipher rather than drop, clone or reset its authority"
    )]
    pub fn with_direction(
        direction: Direction,
        buffer: &'a mut [u8],
    ) -> Result<Self, Rejected<Direction>> {
        if buffer.len() < wire::MAX_RECORD {
            return Err(Rejected {
                value: direction,
                reason: Error::Capacity,
            });
        }
        Ok(Self {
            direction,
            buffer,
            filled: 0,
            shape: None,
            verified: false,
            terminal: false,
        })
    }
    pub(crate) fn into_storage(mut self) -> &'a mut [u8] {
        self.buffer[..self.filled].zeroize();
        self.filled = 0;
        core::mem::take(&mut self.buffer)
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.buffer[..self.filled].zeroize();
        self.terminal = true;
        Err(error)
    }
    /// Consume only bytes for the next record, preserving unconsumed ciphertext
    /// in the caller. Pending/partial input retains exact stream position.
    pub fn push(&mut self, input: &[u8]) -> Result<usize, Error> {
        if self.terminal {
            return Err(Error::Closed);
        }
        if self
            .shape
            .is_some_and(|shape| self.filled == shape.length())
        {
            return Err(Error::WouldBlock);
        }
        let mut taken = 0;
        while taken < input.len() {
            let end = self.shape.map_or(4, Shape::length);
            let n = core::cmp::min(end - self.filled, input.len() - taken);
            self.buffer[self.filled..self.filled + n].copy_from_slice(&input[taken..taken + n]);
            if let Err(e) = self
                .direction
                .crypt(&mut self.buffer[self.filled..self.filled + n])
            {
                self.filled += n;
                return self.fail(e);
            }
            self.filled += n;
            taken += n;
            if self.filled == 4 && self.shape.is_none() {
                match Shape::decode(&self.buffer[..4]) {
                    Ok(shape) => self.shape = Some(shape),
                    Err(e) => return self.fail(e),
                }
            }
            if self
                .shape
                .is_some_and(|shape| self.filled == shape.length())
            {
                break;
            }
        }
        Ok(taken)
    }
    /// Whether this same current record already passed its one MAC verification.
    /// This is diagnostic sequencing, not a new authentication capability.
    pub(crate) const fn is_verified(&self) -> bool {
        self.verified
    }
    /// Authenticate exactly once before exposing record bytes. Source MAC keys
    /// ratchet on each verification attempt, including a failed tag; failure
    /// closes this decoder and erases its plaintext. No packet is replayed.
    pub fn record(&mut self) -> Result<Record<'_>, Error> {
        if self.terminal {
            return Err(Error::Closed);
        }
        let shape = self.shape.ok_or(Error::WouldBlock)?;
        if self.filled != shape.length() {
            return Err(Error::WouldBlock);
        }
        if !self.verified {
            let tag = match shape {
                Shape::Box(_) => Some(
                    self.direction
                        .authenticate(&[&self.buffer[36..self.filled]]),
                ),
                Shape::Rekey | Shape::Finish => Some(self.direction.authenticate(&[
                    &self.buffer[..4],
                    &[0; 32],
                    &self.buffer[36..self.filled],
                ])),
                Shape::Ack => None,
            };
            if tag.is_some_and(|tag| !bool::from(tag.ct_eq(&self.buffer[4..36]))) {
                return self.fail(Error::Authentication);
            }
            self.verified = true;
        }
        Ok(match shape {
            Shape::Box(_) => Record::Box(&self.buffer[36..self.filled]),
            Shape::Ack => Record::Ack(&self.buffer[..self.filled]),
            Shape::Rekey => Record::Rekey(&self.buffer[..self.filled]),
            Shape::Finish => Record::Finish,
        })
    }
    /// Borrow an already authenticated record without repeating its ratchet.
    pub(crate) fn verified_record(&self) -> Result<Record<'_>, Error> {
        if self.terminal {
            return Err(Error::Closed);
        }
        if !self.verified {
            return Err(Error::NotReady);
        }
        let shape = self.shape.ok_or(Error::NotReady)?;
        Ok(match shape {
            Shape::Box(_) => Record::Box(&self.buffer[36..self.filled]),
            Shape::Ack => Record::Ack(&self.buffer[..self.filled]),
            Shape::Rekey => Record::Rekey(&self.buffer[..self.filled]),
            Shape::Finish => Record::Finish,
        })
    }
    /// Release one already verified BOX/ACK record. A rekey requires the actual
    /// checked new PRK; FINISH makes further stream operations permanently closed.
    pub fn release(&mut self) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::Closed);
        }
        if !self.verified {
            return Err(Error::NotReady);
        }
        match self.shape {
            Some(Shape::Rekey) => return Err(Error::NotReady),
            Some(Shape::Finish) => self.terminal = true,
            _ => {}
        }
        self.buffer[..self.filled].zeroize();
        self.filled = 0;
        self.shape = None;
        self.verified = false;
        Ok(())
    }
    /// Commit a signature/replay-checked rekey and release exactly its old-key
    /// record. Source ciphertext following it has not been decrypted yet.
    pub fn rekey(&mut self, prk: &Prk) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::Closed);
        }
        if !self.verified || self.shape != Some(Shape::Rekey) {
            return Err(Error::NotReady);
        }
        let next = Direction::new(prk)?;
        self.direction = next;
        self.buffer[..self.filled].zeroize();
        self.filled = 0;
        self.shape = None;
        self.verified = false;
        Ok(())
    }
}
impl Drop for Receiver<'_> {
    fn drop(&mut self) {
        self.buffer[..self.filled].zeroize();
    }
}
