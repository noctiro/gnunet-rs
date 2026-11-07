//! Exact packed room/epoch/encryption record payloads. Record flags and
//! encrypted-key length are producer-native u32 in actual C write/read paths;
//! the enclosing GNS record serialization is a separate existing layer.
use super::{array, profile::Profile};
use core::fmt;
/// Existing official GNS registry type, reused without private codepoints.
pub use gnunet_gnsrecord::RecordType;
use gnunet_types::Error;
/// Fixed ciphertext room entry payload size.
pub const ROOM_ENTRY_LEN: usize = 96;
/// Separate fixed room-details name256 plus native flags4.
pub const ROOM_DETAILS_LEN: usize = 260;
/// Epoch record payload with nonce24, mac16 and encrypted shared key32.
pub const EPOCH_KEY_LEN: usize = 236;
/// Encryption-key record payload, including all516 encrypted data bytes.
pub const ENCRYPTION_KEY_LEN: usize = 624;
/// Exact encrypted key-data array, including encrypted randomized suffix.
pub const ENCRYPTED_PRIVATE_DATA_LEN: usize = 516;
/// Borrowed record payloads. All crypto fields remain opaque and unverified;
/// no secret private key is decoded, generated, loaded, decrypted or exposed.
#[derive(Clone, Copy)]
pub enum Record<'a> {
    /// Official MESSENGER_ROOM_ENTRY payload.
    RoomEntry {
        /// Original door.
        door: &'a [u8; 32],
        /// Original room key.
        room_key: &'a [u8; 64],
    },
    /// Official MESSENGER_ROOM_DETAILS payload.
    RoomDetails {
        /// Original name.
        name: &'a [u8; 256],
        /// Original flags. Uses the explicitly selected producer endian, not an invented BE conversion.
        flags: u32,
    },
    /// Official MESSENGER_ROOM_EPOCH_KEY payload.
    EpochKey {
        /// Original room key.
        room_key: &'a [u8; 64],
        /// Original epoch.
        epoch: &'a [u8; 64],
        /// Original identifier.
        identifier: &'a [u8; 32],
        /// Original nonce.
        nonce: &'a [u8; 24],
        /// Original mac.
        mac: &'a [u8; 16],
        /// Original encrypted shared key.
        encrypted_shared_key: &'a [u8; 32],
        /// Original flags. Uses the explicitly selected producer endian, not an invented BE conversion.
        flags: u32,
    },
    /// Official MESSENGER_ENCRYPTION_KEY payload.
    EncryptionKey {
        /// Original room key.
        room_key: &'a [u8; 64],
        /// Original nonce.
        nonce: &'a [u8; 24],
        /// Original mac.
        mac: &'a [u8; 16],
        /// Original encrypted key length. Uses the explicitly selected producer endian, not an invented BE conversion.
        encrypted_key_length: u32,
        /// Original encrypted private data. This is ciphertext, not a serialized private key.
        encrypted_private_data: &'a [u8; 516],
    },
}
impl fmt::Debug for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerRecord([REDACTED], unverified)")
            .field("type", &self.record_type())
            .field("bytes", &self.encoded_len())
            .finish()
    }
}
impl<'a> Record<'a> {
    /// Existing official registry type; no private record number is introduced.
    pub const fn record_type(self) -> RecordType {
        match self {
            Self::RoomEntry { .. } => RecordType::MESSENGER_ROOM_ENTRY,
            Self::RoomDetails { .. } => RecordType::MESSENGER_ROOM_DETAILS,
            Self::EpochKey { .. } => RecordType::MESSENGER_ROOM_EPOCH_KEY,
            Self::EncryptionKey { .. } => RecordType::MESSENGER_ENCRYPTION_KEY,
        }
    }
    /// Exact fixed original record data length.
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::RoomEntry { .. } => 96,
            Self::RoomDetails { .. } => 260,
            Self::EpochKey { .. } => 236,
            Self::EncryptionKey { .. } => 624,
        }
    }
    /// Decode exact bytes and actual field order. This validates only structure
    /// and encrypted-key length bounds, not record authority or cryptography.
    pub fn decode(kind: RecordType, input: &'a [u8], profile: Profile) -> Result<Self, Error> {
        profile.validate()?;
        let need = match kind {
            RecordType::MESSENGER_ROOM_ENTRY => 96,
            RecordType::MESSENGER_ROOM_DETAILS => 260,
            RecordType::MESSENGER_ROOM_EPOCH_KEY => 236,
            RecordType::MESSENGER_ENCRYPTION_KEY => 624,
            _ => return Err(Error::Unsupported),
        };
        if input.len() != need {
            return Err(Error::Malformed);
        }
        let result = match kind {
            RecordType::MESSENGER_ROOM_ENTRY => Self::RoomEntry {
                door: array(input, 0)?,
                room_key: array(input, 32)?,
            },
            RecordType::MESSENGER_ROOM_DETAILS => Self::RoomDetails {
                name: array(input, 0)?,
                flags: profile.endian.read_u32(*array(input, 256)?),
            },
            RecordType::MESSENGER_ROOM_EPOCH_KEY => Self::EpochKey {
                room_key: array(input, 0)?,
                epoch: array(input, 64)?,
                identifier: array(input, 128)?,
                nonce: array(input, 160)?,
                mac: array(input, 184)?,
                encrypted_shared_key: array(input, 200)?,
                flags: profile.endian.read_u32(*array(input, 232)?),
            },
            RecordType::MESSENGER_ENCRYPTION_KEY => Self::EncryptionKey {
                room_key: array(input, 0)?,
                nonce: array(input, 64)?,
                mac: array(input, 88)?,
                encrypted_key_length: profile.endian.read_u32(*array(input, 104)?),
                encrypted_private_data: array(input, 108)?,
            },
            _ => return Err(Error::Unsupported),
        };
        result.validate()?;
        Ok(result)
    }
    /// Check structural encrypted-length bounds without decrypting any field.
    pub fn validate(self) -> Result<(), Error> {
        if let Self::EncryptionKey {
            encrypted_key_length,
            ..
        } = self
            && encrypted_key_length > 516
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    /// Encode unchanged packed field bytes into caller-owned sensitive storage.
    /// Invalid length/profile/capacity leaves output unchanged. No key/HMAC/MAC
    /// or record-store success is fabricated.
    pub fn encode(self, profile: Profile, output: &mut [u8]) -> Result<usize, Error> {
        profile.validate()?;
        self.validate()?;
        let n = self.encoded_len();
        if output.len() < n {
            return Err(Error::Capacity);
        }
        match self {
            Self::RoomEntry { door, room_key } => {
                output[0..32].copy_from_slice(door);
                output[32..96].copy_from_slice(room_key);
            }
            Self::RoomDetails { name, flags } => {
                output[0..256].copy_from_slice(name);
                output[256..260].copy_from_slice(&profile.endian.write_u32(flags));
            }
            Self::EpochKey {
                room_key,
                epoch,
                identifier,
                nonce,
                mac,
                encrypted_shared_key,
                flags,
            } => {
                output[0..64].copy_from_slice(room_key);
                output[64..128].copy_from_slice(epoch);
                output[128..160].copy_from_slice(identifier);
                output[160..184].copy_from_slice(nonce);
                output[184..200].copy_from_slice(mac);
                output[200..232].copy_from_slice(encrypted_shared_key);
                output[232..236].copy_from_slice(&profile.endian.write_u32(flags));
            }
            Self::EncryptionKey {
                room_key,
                nonce,
                mac,
                encrypted_key_length,
                encrypted_private_data,
            } => {
                output[0..64].copy_from_slice(room_key);
                output[64..88].copy_from_slice(nonce);
                output[88..104].copy_from_slice(mac);
                output[104..108].copy_from_slice(&profile.endian.write_u32(encrypted_key_length));
                output[108..624].copy_from_slice(encrypted_private_data);
            }
        }
        Ok(n)
    }
}
