//! Official typed zone key bytes and GNUnet's Crockford text encoding.
use crate::{RecordData, RecordType};
use gnunet_types::Error;

/// Raw ECDSA/EdDSA zone public key bytes.
pub const ZONE_KEY_LEN: usize = 32;
/// Official key type32 followed by its 32-byte public key.
pub const ZONE_WIRE_LEN: usize = 4 + ZONE_KEY_LEN;
/// Unpadded Base32GNS length of the complete 36-byte typed public key.
pub const ZONE_TEXT_LEN: usize = 58;

/// Zone key kinds accepted by v0.29.1's `check_key_type`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ZoneKeyType {
    /// PKEY: the reference implementation's ECDSA zone type.
    Pkey,
    /// EDKEY: EdDSA zone type.
    Edkey,
}

impl ZoneKeyType {
    /// GANA zone type value, identical to the delegation record type.
    #[must_use]
    pub const fn record_type(self) -> RecordType {
        match self {
            Self::Pkey => RecordType::PKEY,
            Self::Edkey => RecordType::EDKEY,
        }
    }

    /// Validate a supported official zone type.
    pub fn from_record_type(record_type: RecordType) -> Result<Self, Error> {
        match record_type.value() {
            65536 => Ok(Self::Pkey),
            65556 => Ok(Self::Edkey),
            _ => Err(Error::Unsupported),
        }
    }
}

/// Typed public key bytes; decoding does not prove curve-point or signature validity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ZoneKey {
    kind: ZoneKeyType,
    key: [u8; ZONE_KEY_LEN],
}

impl ZoneKey {
    /// Construct a typed, unvalidated public key value.
    #[must_use]
    pub const fn new(kind: ZoneKeyType, key: [u8; ZONE_KEY_LEN]) -> Self {
        Self { kind, key }
    }

    /// Decode the complete official type-and-key encoding, with no trailing bytes.
    pub fn from_wire(input: &[u8]) -> Result<Self, Error> {
        if input.len() < ZONE_WIRE_LEN {
            return Err(Error::Truncated);
        }
        if input.len() != ZONE_WIRE_LEN {
            return Err(Error::Malformed);
        }
        let kind = ZoneKeyType::from_record_type(RecordType::new(u32::from_be_bytes(
            input[..4].try_into().map_err(|_| Error::Truncated)?,
        )))?;
        let key = input[4..].try_into().map_err(|_| Error::Truncated)?;
        Ok(Self { kind, key })
    }

    /// Decode a PKEY/EDKEY delegation record's 32-byte value and external type.
    pub fn from_record(record: &RecordData<'_>) -> Result<Self, Error> {
        let kind = ZoneKeyType::from_record_type(record.record_type)?;
        if record.data.len() != ZONE_KEY_LEN {
            return Err(Error::Malformed);
        }
        Ok(Self {
            kind,
            key: record.data.try_into().map_err(|_| Error::Malformed)?,
        })
    }

    /// Return the official 36-byte type-and-key serialization.
    #[must_use]
    pub fn to_wire(self) -> [u8; ZONE_WIRE_LEN] {
        let mut bytes = [0; ZONE_WIRE_LEN];
        bytes[..4].copy_from_slice(&self.kind.record_type().value().to_be_bytes());
        bytes[4..].copy_from_slice(&self.key);
        bytes
    }

    /// Key type; it is not inferred from the raw curve bytes.
    #[must_use]
    pub const fn kind(self) -> ZoneKeyType {
        self.kind
    }

    /// Borrow the 32-byte public key, excluding its type.
    #[must_use]
    pub const fn key(&self) -> &[u8; ZONE_KEY_LEN] {
        &self.key
    }

    /// Write the canonical uppercase zTLD label, without a dot, private prefix,
    /// padding character, or NUL terminator. Refusal changes no output.
    pub fn write_ztld<'a>(&self, output: &'a mut [u8]) -> Result<&'a str, Error> {
        let n = crate::encode_base32(&self.to_wire(), output)?;
        core::str::from_utf8(&output[..n]).map_err(|_| Error::InvalidInput)
    }

    /// Decode a bare zTLD label with the exact C implementation's text behavior.
    ///
    /// ASCII case is ignored; O means 0, I/L mean 1, and U means V. As in
    /// `GNUNET_STRINGS_string_to_data`, unused low bits in the last symbol are
    /// ignored. Re-encoding always produces the canonical uppercase form.
    pub fn from_ztld(text: &str) -> Result<Self, Error> {
        if text.len() != ZONE_TEXT_LEN {
            return Err(Error::Malformed);
        }
        let mut wire = [0; ZONE_WIRE_LEN];
        crate::decode_base32(text.as_bytes(), &mut wire)?;
        Self::from_wire(&wire)
    }
}
