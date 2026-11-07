//! Exact active28-kind body grammar, following actual encode/decode switches.
//! Borrowed fields are unverified; no secret is parsed into a key provider.
use super::{PublicKey, SensitiveBytes, envelope::Kind, keys::HpkePublicKey, profile::Profile};
use crate::official::RelativeTime;
use core::fmt;
use gnunet_types::Error;
/// C-string semantics without a wire terminator. Canonical producers omit NUL;
/// decoding preserves tolerated interior-NUL suffixes to avoid rewriting signed
/// bytes. Only content() applies the reference consumer's first-NUL semantics.
#[derive(Clone, Copy)]
pub struct Text<'a>(SensitiveBytes<'a>);
impl<'a> Text<'a> {
    /// Borrow a canonical producer string, excluding its implicit C terminator.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(SensitiveBytes::new(bytes)))
    }
    /// Preserve actual encoded string bytes, including a noncanonical suffix.
    pub const fn from_encoded(bytes: &'a [u8]) -> Self {
        Self(SensitiveBytes::new(bytes))
    }
    /// Actual first-NUL string content interpreted by C consumers.
    pub fn content(self) -> SensitiveBytes<'a> {
        let bytes = self.0.expose();
        SensitiveBytes::new(&bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())])
    }
    /// Exact raw encoded bytes; this borrow may contain sensitive chat material.
    pub const fn encoded(self) -> SensitiveBytes<'a> {
        self.0
    }
    /// Whether an ordinary C strlen-based producer can emit every encoded byte.
    pub fn is_canonical(self) -> bool {
        !self.0.expose().contains(&0)
    }
}
impl fmt::Debug for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Text([REDACTED])")
            .field(&self.0.len())
            .finish()
    }
}
/// Typed active message bodies. Variable uint16 C lengths are bookkeeping;
/// they are not added as invented serialized fields. All flags/types retain
/// their raw official numeric values. Debug never prints fields or payloads.
#[derive(Clone, Copy)]
pub enum Body<'a> {
    /// Actual INFO body.
    Info {
        /// Original version, in actual producer field order.
        version: u32,
    },
    /// Actual JOIN body.
    Join {
        /// Original epoch, in actual producer field order.
        epoch: &'a [u8; 64],
        /// Original public key, in actual producer field order.
        public_key: PublicKey<'a>,
        /// Original hpke key, in actual producer field order.
        hpke_key: HpkePublicKey<'a>,
    },
    /// Actual LEAVE body.
    Leave {
        /// Original epoch, in actual producer field order.
        epoch: &'a [u8; 64],
    },
    /// Actual NAME body.
    Name {
        /// Original name, in actual producer field order.
        name: Text<'a>,
    },
    /// Actual KEY body.
    Key {
        /// Original public key, in actual producer field order.
        public_key: PublicKey<'a>,
        /// Original hpke key, in actual producer field order.
        hpke_key: HpkePublicKey<'a>,
    },
    /// Actual PEER body.
    Peer {
        /// Original peer, in actual producer field order.
        peer: &'a [u8; 32],
    },
    /// Actual ID body.
    Id {
        /// Original id, in actual producer field order.
        id: &'a [u8; 32],
    },
    /// Actual MISS body.
    Miss {
        /// Original peer, in actual producer field order.
        peer: &'a [u8; 32],
    },
    /// Actual MERGE body.
    Merge {
        /// Original first epoch, in actual producer field order.
        first_epoch: &'a [u8; 64],
        /// Original second epoch, in actual producer field order.
        second_epoch: &'a [u8; 64],
        /// Original previous, in actual producer field order.
        previous: &'a [u8; 64],
    },
    /// Actual REQUEST body.
    Request {
        /// Original hash, in actual producer field order.
        hash: &'a [u8; 64],
    },
    /// Actual INVITE body.
    Invite {
        /// Original door, in actual producer field order.
        door: &'a [u8; 32],
        /// Original room key, in actual producer field order.
        room_key: &'a [u8; 64],
    },
    /// Actual TEXT body.
    Text {
        /// Original text, in actual producer field order.
        text: Text<'a>,
    },
    /// Actual FILE body.
    File {
        /// Original hash, in actual producer field order.
        hash: &'a [u8; 64],
        /// Original name, in actual producer field order.
        name: SensitiveBytes<'a>,
        /// Original uri, in actual producer field order.
        uri: Text<'a>,
    },
    /// Actual PRIVATE body.
    Private {
        /// Original data, in actual producer field order.
        data: SensitiveBytes<'a>,
    },
    /// Actual DELETION body.
    Deletion {
        /// Original hash, in actual producer field order.
        hash: &'a [u8; 64],
        /// Original delay, in actual producer field order.
        delay: RelativeTime,
    },
    /// Actual CONNECTION body.
    Connection {
        /// Original amount, in actual producer field order.
        amount: u32,
        /// Original flags, in actual producer field order.
        flags: u32,
    },
    /// Actual TICKET body.
    Ticket {
        /// Original identifier, in actual producer field order.
        identifier: Text<'a>,
    },
    /// Actual TRANSCRIPT body.
    Transcript {
        /// Original hash, in actual producer field order.
        hash: &'a [u8; 64],
        /// Original recipient key, in actual producer field order.
        recipient_key: PublicKey<'a>,
        /// Original data, in actual producer field order.
        data: SensitiveBytes<'a>,
    },
    /// Actual TAG body.
    Tag {
        /// Original hash, in actual producer field order.
        hash: &'a [u8; 64],
        /// Original tag, in actual producer field order.
        tag: Text<'a>,
    },
    /// Actual SUBSCRIPTION body.
    Subscription {
        /// Original discourse, in actual producer field order.
        discourse: &'a [u8; 32],
        /// Original time, in actual producer field order.
        time: RelativeTime,
        /// Original flags, in actual producer field order.
        flags: u32,
    },
    /// Actual TALK body.
    Talk {
        /// Original discourse, in actual producer field order.
        discourse: &'a [u8; 32],
        /// Original data, in actual producer field order.
        data: SensitiveBytes<'a>,
    },
    /// Actual ANNOUNCEMENT body.
    Announcement {
        /// Original identifier, in actual producer field order.
        identifier: &'a [u8; 32],
        /// Original public key, in actual producer field order.
        public_key: &'a [u8; 32],
        /// Original nonce, in actual producer field order.
        nonce: &'a [u8; 32],
        /// Original timeout, in actual producer field order.
        timeout: RelativeTime,
        /// Original hmac, in actual producer field order.
        hmac: &'a [u8; 64],
    },
    /// Actual SECRET body.
    Secret {
        /// Original identifier, in actual producer field order.
        identifier: &'a [u8; 32],
        /// Original nonce, in actual producer field order.
        nonce: &'a [u8; 24],
        /// Original mac, in actual producer field order.
        mac: &'a [u8; 16],
        /// Original data, in actual producer field order.
        data: SensitiveBytes<'a>,
    },
    /// Actual APPEAL body.
    Appeal {
        /// Original event, in actual producer field order.
        event: &'a [u8; 64],
        /// Original public key, in actual producer field order.
        public_key: &'a [u8; 32],
        /// Original timeout, in actual producer field order.
        timeout: RelativeTime,
    },
    /// Actual ACCESS body.
    Access {
        /// Original event, in actual producer field order.
        event: &'a [u8; 64],
        /// Original encrypted key, in actual producer field order.
        encrypted_key: &'a [u8; 80],
        /// Original hmac, in actual producer field order.
        hmac: &'a [u8; 64],
    },
    /// Actual REVOLUTION body.
    Revolution {
        /// Original identifier, in actual producer field order.
        identifier: &'a [u8; 32],
        /// Original nonce, in actual producer field order.
        nonce: &'a [u8; 32],
        /// Original hmac, in actual producer field order.
        hmac: &'a [u8; 64],
    },
    /// Actual GROUP body.
    Group {
        /// Original identifier, in actual producer field order.
        identifier: &'a [u8; 32],
        /// Original initiator, in actual producer field order.
        initiator: &'a [u8; 64],
        /// Original partner, in actual producer field order.
        partner: &'a [u8; 64],
        /// Original timeout, in actual producer field order.
        timeout: RelativeTime,
    },
    /// Actual AUTHORIZATION body.
    Authorization {
        /// Original identifier, in actual producer field order.
        identifier: &'a [u8; 32],
        /// Original event, in actual producer field order.
        event: &'a [u8; 64],
        /// Original encrypted32-byte key. The actual wire omits the separate C struct mac16; it cannot be recovered from this body.
        encrypted_key: &'a [u8; 32],
        /// Original hmac, in actual producer field order.
        hmac: &'a [u8; 64],
    },
}
impl fmt::Debug for Body<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body([REDACTED], unverified)")
            .field("kind", &self.kind())
            .finish()
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Overflow)?;
        let b = self.bytes.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(*self.array()?))
    }
    fn rest(&mut self) -> &'a [u8] {
        let b = &self.bytes[self.at..];
        self.at = self.bytes.len();
        b
    }
}
struct Writer<'a> {
    bytes: &'a mut [u8],
    at: usize,
}
impl Writer<'_> {
    fn put(&mut self, b: &[u8]) -> Result<(), Error> {
        let end = self.at.checked_add(b.len()).ok_or(Error::Overflow)?;
        self.bytes
            .get_mut(self.at..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(b);
        self.at = end;
        Ok(())
    }
}
/// Decoded fixed-field prefix. Any ignored extra bytes are explicit and remain
/// available to a caller; variable strings/data consume their complete tail.
#[derive(Clone, Copy, Debug)]
pub struct Prefix<'a> {
    /// Actual parsed body fields.
    pub body: Body<'a>,
    /// Exact number of parsed bytes.
    pub consumed: usize,
    /// Raw trailing bytes ignored by the fixed-body C switch.
    pub trailing: SensitiveBytes<'a>,
}
impl<'a> Body<'a> {
    /// Exact active numeric message kind.
    pub const fn kind(self) -> Kind {
        match self {
            Self::Info { .. } => Kind::INFO,
            Self::Join { .. } => Kind::JOIN,
            Self::Leave { .. } => Kind::LEAVE,
            Self::Name { .. } => Kind::NAME,
            Self::Key { .. } => Kind::KEY,
            Self::Peer { .. } => Kind::PEER,
            Self::Id { .. } => Kind::ID,
            Self::Miss { .. } => Kind::MISS,
            Self::Merge { .. } => Kind::MERGE,
            Self::Request { .. } => Kind::REQUEST,
            Self::Invite { .. } => Kind::INVITE,
            Self::Text { .. } => Kind::TEXT,
            Self::File { .. } => Kind::FILE,
            Self::Private { .. } => Kind::PRIVATE,
            Self::Deletion { .. } => Kind::DELETION,
            Self::Connection { .. } => Kind::CONNECTION,
            Self::Ticket { .. } => Kind::TICKET,
            Self::Transcript { .. } => Kind::TRANSCRIPT,
            Self::Tag { .. } => Kind::TAG,
            Self::Subscription { .. } => Kind::SUBSCRIPTION,
            Self::Talk { .. } => Kind::TALK,
            Self::Announcement { .. } => Kind::ANNOUNCEMENT,
            Self::Secret { .. } => Kind::SECRET,
            Self::Appeal { .. } => Kind::APPEAL,
            Self::Access { .. } => Kind::ACCESS,
            Self::Revolution { .. } => Kind::REVOLUTION,
            Self::Group { .. } => Kind::GROUP,
            Self::Authorization { .. } => Kind::AUTHORIZATION,
        }
    }
    /// Decode a fixed prefix or complete variable body without stripping any
    /// padding. Variable key tags/widths and every offset are checked safely.
    pub fn decode_prefix(
        kind: Kind,
        input: &'a [u8],
        profile: Profile,
    ) -> Result<Prefix<'a>, Error> {
        profile.validate()?;
        u16::try_from(input.len()).map_err(|_| Error::TooLarge)?;
        let mut r = Reader {
            bytes: input,
            at: 0,
        };
        let body = match kind {
            Kind::INFO => Self::Info { version: r.u32()? },
            Kind::JOIN => Self::Join {
                epoch: r.array()?,
                public_key: PublicKey::new(r.take(36)?)?,
                hpke_key: HpkePublicKey::new(r.take(36)?)?,
            },
            Kind::LEAVE => Self::Leave { epoch: r.array()? },
            Kind::NAME => Self::Name {
                name: Text::from_encoded(r.rest()),
            },
            Kind::KEY => Self::Key {
                public_key: PublicKey::new(r.take(36)?)?,
                hpke_key: HpkePublicKey::new(r.take(36)?)?,
            },
            Kind::PEER => Self::Peer { peer: r.array()? },
            Kind::ID => Self::Id { id: r.array()? },
            Kind::MISS => Self::Miss { peer: r.array()? },
            Kind::MERGE => Self::Merge {
                first_epoch: r.array()?,
                second_epoch: r.array()?,
                previous: r.array()?,
            },
            Kind::REQUEST => Self::Request { hash: r.array()? },
            Kind::INVITE => Self::Invite {
                door: r.array()?,
                room_key: r.array()?,
            },
            Kind::TEXT => Self::Text {
                text: Text::from_encoded(r.rest()),
            },
            Kind::FILE => Self::File {
                hash: r.array()?,
                name: SensitiveBytes::new(r.take(profile.file_name_bytes)?),
                uri: Text::from_encoded(r.rest()),
            },
            Kind::PRIVATE => Self::Private {
                data: SensitiveBytes::new(r.rest()),
            },
            Kind::DELETION => Self::Deletion {
                hash: r.array()?,
                delay: RelativeTime::decode(r.take(8)?)?,
            },
            Kind::CONNECTION => Self::Connection {
                amount: r.u32()?,
                flags: r.u32()?,
            },
            Kind::TICKET => Self::Ticket {
                identifier: Text::from_encoded(r.rest()),
            },
            Kind::TRANSCRIPT => Self::Transcript {
                hash: r.array()?,
                recipient_key: PublicKey::new(r.take(36)?)?,
                data: SensitiveBytes::new(r.rest()),
            },
            Kind::TAG => Self::Tag {
                hash: r.array()?,
                tag: Text::from_encoded(r.rest()),
            },
            Kind::SUBSCRIPTION => Self::Subscription {
                discourse: r.array()?,
                time: RelativeTime::decode(r.take(8)?)?,
                flags: r.u32()?,
            },
            Kind::TALK => Self::Talk {
                discourse: r.array()?,
                data: SensitiveBytes::new(r.rest()),
            },
            Kind::ANNOUNCEMENT => Self::Announcement {
                identifier: r.array()?,
                public_key: r.array()?,
                nonce: r.array()?,
                timeout: RelativeTime::decode(r.take(8)?)?,
                hmac: r.array()?,
            },
            Kind::SECRET => Self::Secret {
                identifier: r.array()?,
                nonce: r.array()?,
                mac: r.array()?,
                data: SensitiveBytes::new(r.rest()),
            },
            Kind::APPEAL => Self::Appeal {
                event: r.array()?,
                public_key: r.array()?,
                timeout: RelativeTime::decode(r.take(8)?)?,
            },
            Kind::ACCESS => Self::Access {
                event: r.array()?,
                encrypted_key: r.array()?,
                hmac: r.array()?,
            },
            Kind::REVOLUTION => Self::Revolution {
                identifier: r.array()?,
                nonce: r.array()?,
                hmac: r.array()?,
            },
            Kind::GROUP => Self::Group {
                identifier: r.array()?,
                initiator: r.array()?,
                partner: r.array()?,
                timeout: RelativeTime::decode(r.take(8)?)?,
            },
            Kind::AUTHORIZATION => Self::Authorization {
                identifier: r.array()?,
                event: r.array()?,
                encrypted_key: r.array()?,
                hmac: r.array()?,
            },
            _ => return Err(Error::Unsupported),
        };
        Ok(Prefix {
            body,
            consumed: r.at,
            trailing: SensitiveBytes::new(&input[r.at..]),
        })
    }
    /// Decode an exact unpadded body; fixed-body trailing bytes are rejected.
    /// Use decode_prefix to preserve the reference's explicitly ignored tail.
    pub fn decode(kind: Kind, input: &'a [u8], profile: Profile) -> Result<Self, Error> {
        let result = Self::decode_prefix(kind, input, profile)?;
        if !result.trailing.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(result.body)
    }
    /// Exact serialized body length, validating caller NAME_MAX profile and
    /// FILE array width. All actual bodies share the original u16 size domain.
    pub fn encoded_len(self, profile: Profile) -> Result<usize, Error> {
        profile.validate()?;
        let mut len = 0usize;
        match self {
            Self::Info { version: _ } => {
                len = len.checked_add(4).ok_or(Error::Overflow)?;
            }
            Self::Join {
                epoch: _,
                public_key: _,
                hpke_key: _,
            } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(36).ok_or(Error::Overflow)?;
                len = len.checked_add(36).ok_or(Error::Overflow)?;
            }
            Self::Leave { epoch: _ } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Name { name } => {
                len = len
                    .checked_add(name.encoded().len())
                    .ok_or(Error::Overflow)?;
            }
            Self::Key {
                public_key: _,
                hpke_key: _,
            } => {
                len = len.checked_add(36).ok_or(Error::Overflow)?;
                len = len.checked_add(36).ok_or(Error::Overflow)?;
            }
            Self::Peer { peer: _ } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
            }
            Self::Id { id: _ } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
            }
            Self::Miss { peer: _ } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
            }
            Self::Merge {
                first_epoch: _,
                second_epoch: _,
                previous: _,
            } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Request { hash: _ } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Invite {
                door: _,
                room_key: _,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Text { text } => {
                len = len
                    .checked_add(text.encoded().len())
                    .ok_or(Error::Overflow)?;
            }
            Self::File { hash: _, name, uri } => {
                if name.len() != profile.file_name_bytes {
                    return Err(Error::InvalidInput);
                }
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len
                    .checked_add(profile.file_name_bytes)
                    .ok_or(Error::Overflow)?;
                len = len
                    .checked_add(uri.encoded().len())
                    .ok_or(Error::Overflow)?;
            }
            Self::Private { data } => {
                len = len.checked_add(data.len()).ok_or(Error::Overflow)?;
            }
            Self::Deletion { hash: _, delay: _ } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(8).ok_or(Error::Overflow)?;
            }
            Self::Connection {
                amount: _,
                flags: _,
            } => {
                len = len.checked_add(4).ok_or(Error::Overflow)?;
                len = len.checked_add(4).ok_or(Error::Overflow)?;
            }
            Self::Ticket { identifier } => {
                len = len
                    .checked_add(identifier.encoded().len())
                    .ok_or(Error::Overflow)?;
            }
            Self::Transcript {
                hash: _,
                recipient_key: _,
                data,
            } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(36).ok_or(Error::Overflow)?;
                len = len.checked_add(data.len()).ok_or(Error::Overflow)?;
            }
            Self::Tag { hash: _, tag } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len
                    .checked_add(tag.encoded().len())
                    .ok_or(Error::Overflow)?;
            }
            Self::Subscription {
                discourse: _,
                time: _,
                flags: _,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(8).ok_or(Error::Overflow)?;
                len = len.checked_add(4).ok_or(Error::Overflow)?;
            }
            Self::Talk { discourse: _, data } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(data.len()).ok_or(Error::Overflow)?;
            }
            Self::Announcement {
                identifier: _,
                public_key: _,
                nonce: _,
                timeout: _,
                hmac: _,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(8).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Secret {
                identifier: _,
                nonce: _,
                mac: _,
                data,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(24).ok_or(Error::Overflow)?;
                len = len.checked_add(16).ok_or(Error::Overflow)?;
                len = len.checked_add(data.len()).ok_or(Error::Overflow)?;
            }
            Self::Appeal {
                event: _,
                public_key: _,
                timeout: _,
            } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(8).ok_or(Error::Overflow)?;
            }
            Self::Access {
                event: _,
                encrypted_key: _,
                hmac: _,
            } => {
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(80).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Revolution {
                identifier: _,
                nonce: _,
                hmac: _,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
            Self::Group {
                identifier: _,
                initiator: _,
                partner: _,
                timeout: _,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(8).ok_or(Error::Overflow)?;
            }
            Self::Authorization {
                identifier: _,
                event: _,
                encrypted_key: _,
                hmac: _,
            } => {
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
                len = len.checked_add(32).ok_or(Error::Overflow)?;
                len = len.checked_add(64).ok_or(Error::Overflow)?;
            }
        }
        u16::try_from(len).map_err(|_| Error::TooLarge)?;
        Ok(len)
    }
    /// Encode exact fields after all resource/shape checks. No padding, NUL,
    /// entropy, MAC or missing AUTHORIZATION field is silently invented.
    pub fn encode(self, profile: Profile, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len(profile)?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        let mut w = Writer {
            bytes: &mut output[..len],
            at: 0,
        };
        match self {
            Self::Info { version } => {
                w.put(&version.to_be_bytes())?;
            }
            Self::Join {
                epoch,
                public_key,
                hpke_key,
            } => {
                w.put(epoch)?;
                w.put(public_key.as_bytes())?;
                w.put(hpke_key.as_bytes())?;
            }
            Self::Leave { epoch } => {
                w.put(epoch)?;
            }
            Self::Name { name } => {
                w.put(name.encoded().expose())?;
            }
            Self::Key {
                public_key,
                hpke_key,
            } => {
                w.put(public_key.as_bytes())?;
                w.put(hpke_key.as_bytes())?;
            }
            Self::Peer { peer } => {
                w.put(peer)?;
            }
            Self::Id { id } => {
                w.put(id)?;
            }
            Self::Miss { peer } => {
                w.put(peer)?;
            }
            Self::Merge {
                first_epoch,
                second_epoch,
                previous,
            } => {
                w.put(first_epoch)?;
                w.put(second_epoch)?;
                w.put(previous)?;
            }
            Self::Request { hash } => {
                w.put(hash)?;
            }
            Self::Invite { door, room_key } => {
                w.put(door)?;
                w.put(room_key)?;
            }
            Self::Text { text } => {
                w.put(text.encoded().expose())?;
            }
            Self::File { hash, name, uri } => {
                w.put(hash)?;
                w.put(name.expose())?;
                w.put(uri.encoded().expose())?;
            }
            Self::Private { data } => {
                w.put(data.expose())?;
            }
            Self::Deletion { hash, delay } => {
                w.put(hash)?;
                w.put(&delay.to_be_bytes())?;
            }
            Self::Connection { amount, flags } => {
                w.put(&amount.to_be_bytes())?;
                w.put(&flags.to_be_bytes())?;
            }
            Self::Ticket { identifier } => {
                w.put(identifier.encoded().expose())?;
            }
            Self::Transcript {
                hash,
                recipient_key,
                data,
            } => {
                w.put(hash)?;
                w.put(recipient_key.as_bytes())?;
                w.put(data.expose())?;
            }
            Self::Tag { hash, tag } => {
                w.put(hash)?;
                w.put(tag.encoded().expose())?;
            }
            Self::Subscription {
                discourse,
                time,
                flags,
            } => {
                w.put(discourse)?;
                w.put(&time.to_be_bytes())?;
                w.put(&flags.to_be_bytes())?;
            }
            Self::Talk { discourse, data } => {
                w.put(discourse)?;
                w.put(data.expose())?;
            }
            Self::Announcement {
                identifier,
                public_key,
                nonce,
                timeout,
                hmac,
            } => {
                w.put(identifier)?;
                w.put(public_key)?;
                w.put(nonce)?;
                w.put(&timeout.to_be_bytes())?;
                w.put(hmac)?;
            }
            Self::Secret {
                identifier,
                nonce,
                mac,
                data,
            } => {
                w.put(identifier)?;
                w.put(nonce)?;
                w.put(mac)?;
                w.put(data.expose())?;
            }
            Self::Appeal {
                event,
                public_key,
                timeout,
            } => {
                w.put(event)?;
                w.put(public_key)?;
                w.put(&timeout.to_be_bytes())?;
            }
            Self::Access {
                event,
                encrypted_key,
                hmac,
            } => {
                w.put(event)?;
                w.put(encrypted_key)?;
                w.put(hmac)?;
            }
            Self::Revolution {
                identifier,
                nonce,
                hmac,
            } => {
                w.put(identifier)?;
                w.put(nonce)?;
                w.put(hmac)?;
            }
            Self::Group {
                identifier,
                initiator,
                partner,
                timeout,
            } => {
                w.put(identifier)?;
                w.put(initiator)?;
                w.put(partner)?;
                w.put(&timeout.to_be_bytes())?;
            }
            Self::Authorization {
                identifier,
                event,
                encrypted_key,
                hmac,
            } => {
                w.put(identifier)?;
                w.put(event)?;
                w.put(encrypted_key)?;
                w.put(hmac)?;
            }
        }
        Ok(w.at)
    }
}
