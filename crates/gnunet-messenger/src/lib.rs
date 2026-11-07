//! Sensitive fixed-capacity ownership for official Messenger IPC, bodies and records.
//! Room/member/history/epoch authorization and native service ownership remain separate.
#![no_std]
#![forbid(unsafe_code)]
use core::fmt;
use gnunet_types::Error;
pub use gnunet_wire::official::messenger::{
    self as wire, Request, Response, SensitiveBytes, envelope,
};
use zeroize::{Zeroize, Zeroizing};

/// Fixed caller-selected sensitive storage. The entire array is erased on drop
/// and clear, including any old suffix. Debug reveals only length/capacity; there
/// is no Clone, Hash, serialization or implicit raw-byte conversion.
/// Select N according to the caller's actual stack/static/owned storage budget.
pub struct SensitiveBuffer<const N: usize> {
    bytes: Zeroizing<[u8; N]>,
    len: usize,
}
impl<const N: usize> fmt::Debug for SensitiveBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensitiveBuffer([REDACTED])")
            .field("length", &self.len)
            .field("capacity", &N)
            .finish()
    }
}
impl<const N: usize> Default for SensitiveBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> SensitiveBuffer<N> {
    /// Allocate no heap memory and create no key, entropy, native task or I/O.
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; N]),
            len: 0,
        }
    }
    /// Current retained encoded byte count.
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Whether this owner retains no message bytes.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Explicit sensitive borrow, suitable for actual protocol/persistence
    /// ownership only. It must never become an identifier or diagnostic.
    pub fn expose(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    /// Borrow the redacted opaque wire view without a hidden clone.
    pub fn view(&self) -> SensitiveBytes<'_> {
        SensitiveBytes::new(self.expose())
    }
    /// Erase all retained bytes and unused capacity, preserving only ownership.
    pub fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
    /// Copy explicitly exposed encoded data into this erased owner. The caller
    /// remains responsible for erasing its original separate source storage.
    /// Capacity failure leaves this original owner unchanged.
    pub fn copy_from(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > N {
            return Err(Error::Capacity);
        }
        self.clear();
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
        Ok(())
    }
    /// Encode an official outer request into zeroizing ownership. This does not
    /// assert validity/authentication of its opaque inner message body.
    pub fn encode_request(&mut self, request: Request<'_>) -> Result<(), Error> {
        let n = request.encoded_len()?;
        if n > N {
            return Err(Error::Capacity);
        }
        self.clear();
        match request.encode(&mut *self.bytes) {
            Ok(n) => {
                self.len = n;
                Ok(())
            }
            Err(e) => {
                self.clear();
                Err(e)
            }
        }
    }
    /// Encode an actual outer notification into zeroizing ownership, without a
    /// synthetic receipt or claim that a native/service event has occurred.
    pub fn encode_response(
        &mut self,
        response: Response<'_>,
        profile: wire::profile::Profile,
    ) -> Result<(), Error> {
        profile.validate()?;
        let n = response.encoded_len()?;
        if n > N {
            return Err(Error::Capacity);
        }
        self.clear();
        match response.encode(profile, &mut *self.bytes) {
            Ok(n) => {
                self.len = n;
                Ok(())
            }
            Err(e) => {
                self.clear();
                Err(e)
            }
        }
    }
    /// Structurally decode one retained original client IPC request.
    pub fn request(&self) -> Result<Request<'_>, Error> {
        Request::decode(self.expose())
    }
    /// Structurally decode one retained original service notification.
    pub fn response(&self, profile: wire::profile::Profile) -> Result<Response<'_>, Error> {
        Response::decode(self.expose(), profile)
    }
}

impl<const N: usize> SensitiveBuffer<N> {
    /// Encode every typed signed body and explicit original-producer padding
    /// directly into zeroizing ownership. Signature validity remains separate.
    pub fn encode_message(
        &mut self,
        header: envelope::Header<'_>,
        body: wire::body::Body<'_>,
        profile: wire::profile::Profile,
        padding: wire::padding::Encode<'_>,
    ) -> Result<(), Error> {
        if header.kind != body.kind() {
            return Err(Error::InvalidInput);
        }
        let n = wire::message::encoded_len(body, profile, padding)?;
        if n > N {
            return Err(Error::Capacity);
        }
        self.clear();
        match wire::message::encode(header, body, profile, padding, &mut *self.bytes) {
            Ok(n) => {
                self.len = n;
                Ok(())
            }
            Err(e) => {
                self.clear();
                Err(e)
            }
        }
    }
    /// Borrow all typed signed-message fields, with explicit padding context.
    /// This checks structure, not hash/signature/room authorization.
    pub fn message(
        &self,
        profile: wire::profile::Profile,
        padding: wire::padding::Decode,
    ) -> Result<wire::message::Message<'_>, Error> {
        wire::message::Message::decode(self.expose(), profile, padding)
    }
    /// Encode a typed short message into erased storage using a caller-provided
    /// carried digest. No cryptographic operation or decryption is performed.
    pub fn encode_short(
        &mut self,
        hash: &[u8; 64],
        body: wire::body::Body<'_>,
        profile: wire::profile::Profile,
        padding: wire::padding::Encode<'_>,
    ) -> Result<(), Error> {
        let unpadded = envelope::SHORT_PREFIX
            .checked_add(body.encoded_len(profile)?)
            .ok_or(Error::Overflow)?;
        let n = wire::padding::encoded_length(unpadded, padding)?;
        if n > N {
            return Err(Error::Capacity);
        }
        self.clear();
        match wire::message::encode_short(hash, body, profile, padding, &mut *self.bytes) {
            Ok(n) => {
                self.len = n;
                Ok(())
            }
            Err(e) => {
                self.clear();
                Err(e)
            }
        }
    }
    /// Borrow a typed short message; its carried hash is still unverified.
    pub fn short(
        &self,
        profile: wire::profile::Profile,
        padding: wire::padding::Decode,
    ) -> Result<wire::message::Short<'_>, Error> {
        wire::message::Short::decode(self.expose(), profile, padding)
    }
    /// Encode each packed record payload directly into erased storage. Private
    /// record ciphertext remains opaque; no NAMESTORE/storage receipt is implied.
    pub fn encode_record(
        &mut self,
        record: wire::records::Record<'_>,
        profile: wire::profile::Profile,
    ) -> Result<(), Error> {
        profile.validate()?;
        record.validate()?;
        let n = record.encoded_len();
        if n > N {
            return Err(Error::Capacity);
        }
        self.clear();
        match record.encode(profile, &mut *self.bytes) {
            Ok(n) => {
                self.len = n;
                Ok(())
            }
            Err(e) => {
                self.clear();
                Err(e)
            }
        }
    }
}

/// Official hash/signature/MAC/HPKE/AEAD operations over sealed original wire
/// views and explicit caller-owned keys, entropy and zeroizing storage.
pub mod crypto;
