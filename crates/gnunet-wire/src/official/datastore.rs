//! Official local DATASTORE IPC from datastore.h and the v0.29.1 service.
//! Each lookup returns exactly one DATA or DATA_END, not a multi-frame stream.
//! These bytes authenticate neither stored content nor the local service.
use super::{
    AbsoluteTime, Frame, MAX_MESSAGE_SIZE, MessageHeader, MessageType, message_type as mt,
};
use gnunet_types::Error;

/// Fixed DataMessage prefix, including common header and 64-byte key.
pub const DATA_LEN: usize = 112;
/// Largest value fitting the actual u16-sized IPC frame (not the API's 65536 macro).
pub const MAX_VALUE_BYTES: usize = MAX_MESSAGE_SIZE - DATA_LEN;
/// Fixed status prefix, before its optional terminated diagnostic.
pub const STATUS_LEN: usize = 16;
/// Fixed reservation request size.
pub const RESERVE_LEN: usize = 16;
/// Fixed reservation release request size.
pub const RELEASE_LEN: usize = 8;
/// Fixed lookup without a key.
pub const GET_LEN: usize = 20;
/// Fixed lookup with a key.
pub const GET_KEY_LEN: usize = 84;
/// Fixed zero-anonymity lookup.
pub const ZERO_ANONYMITY_LEN: usize = 16;

fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn wide(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn key(bytes: &[u8], offset: usize) -> Result<&[u8; 64], Error> {
    bytes
        .get(offset..offset + 64)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn header(kind: MessageType, length: usize, output: &mut [u8]) -> Result<(), Error> {
    let header = MessageHeader::from_total_size(kind, length)?;
    if output.len() < length {
        return Err(Error::Capacity);
    }
    header.encode(output)?;
    Ok(())
}

/// Full DataMessage fields. Reserved alignment bytes are ignored on decode and
/// zero on encode, as in the reference client. Value/key borrow the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Data<'a> {
    /// Reservation number; zero for no reservation and server replies.
    pub reservation: u32,
    /// Open GNUNET_BLOCK_Type; no private block type table is introduced.
    pub kind: u32,
    /// Requested/reported priority.
    pub priority: u32,
    /// Requested/reported anonymity.
    pub anonymity: u32,
    /// Requested/reported replication score.
    pub replication: u32,
    /// Backend unique identifier, zero in canonical client PUT/REMOVE.
    pub uid: u64,
    /// Public service expiration timestamp, not a local monotonic deadline.
    pub expiration: AbsoluteTime,
    /// Exact datastore lookup key. It need not be a ciphertext hash for every block type.
    pub key: &'a [u8; 64],
    /// Actual arbitrary value bytes, including zero-length values.
    pub value: &'a [u8],
}
impl<'a> Data<'a> {
    fn decode(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < DATA_LEN {
            return Err(Error::Truncated);
        }
        if usize::try_from(word(input, 8)?).map_err(|_| Error::TooLarge)? != input.len() - DATA_LEN
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            reservation: word(input, 4)?,
            kind: word(input, 12)?,
            priority: word(input, 16)?,
            anonymity: word(input, 20)?,
            replication: word(input, 24)?,
            uid: wide(input, 32)?,
            expiration: AbsoluteTime::from_micros(wide(input, 40)?),
            key: key(input, 48)?,
            value: &input[DATA_LEN..],
        })
    }
    fn encode(self, kind: MessageType, output: &mut [u8]) -> Result<usize, Error> {
        let length = DATA_LEN
            .checked_add(self.value.len())
            .ok_or(Error::Overflow)?;
        header(kind, length, output)?;
        output[4..8].copy_from_slice(&self.reservation.to_be_bytes());
        output[8..12].copy_from_slice(&(self.value.len() as u32).to_be_bytes());
        output[12..16].copy_from_slice(&self.kind.to_be_bytes());
        output[16..20].copy_from_slice(&self.priority.to_be_bytes());
        output[20..24].copy_from_slice(&self.anonymity.to_be_bytes());
        output[24..28].copy_from_slice(&self.replication.to_be_bytes());
        output[28..32].fill(0);
        output[32..40].copy_from_slice(&self.uid.to_be_bytes());
        output[40..48].copy_from_slice(&self.expiration.as_micros().to_be_bytes());
        output[48..112].copy_from_slice(self.key);
        output[112..length].copy_from_slice(self.value);
        Ok(length)
    }
}

/// All nine actual service requests. A keyed/unkeyed GET shares the public
/// query operation but retains its distinct official message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Reserve content bytes plus the service's per-entry overhead.
    Reserve {
        /// Content byte budget.
        amount: u64,
        /// Number of future PUT entries.
        entries: u32,
    },
    /// Release the remaining reservation owned by this physical connection.
    Release {
        /// Positive reservation value obtained from STATUS.
        reservation: u32,
    },
    /// Insert/update; duplicate PUTs can add priority/replication and are not idempotent.
    Put(Data<'a>),
    /// One result at/after next_uid, or a random result when random is true.
    Get {
        /// Optional exact lookup key; None selects DATASTORE_GET.
        key: Option<&'a [u8; 64]>,
        /// Zero matches every block type.
        kind: u32,
        /// Backend cursor, supplied by the caller.
        next_uid: u64,
        /// Select one random result instead of using next_uid.
        random: bool,
    },
    /// Select a replication candidate, decrementing a positive replication score.
    Replication,
    /// Select one zero-anonymity value of a nonzero block type.
    ZeroAnonymity {
        /// Nonzero GNUNET_BLOCK_Type.
        kind: u32,
        /// Backend cursor.
        next_uid: u64,
    },
    /// Remove the exact key/value. Other DataMessage fields are canonically zero.
    Remove {
        /// Exact datastore key.
        key: &'a [u8; 64],
        /// Exact stored value.
        value: &'a [u8],
    },
    /// Set the service's drop-on-shutdown flag. There is no reply or completion proof.
    Drop,
}
impl<'a> Request<'a> {
    /// Complete frame size, validating all bounds before destination writes.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let length = match self {
            Self::Reserve { .. } => RESERVE_LEN,
            Self::Release { .. } => RELEASE_LEN,
            Self::Put(data) => DATA_LEN
                .checked_add(data.value.len())
                .ok_or(Error::Overflow)?,
            Self::Get { key, .. } => {
                if key.is_some() {
                    GET_KEY_LEN
                } else {
                    GET_LEN
                }
            }
            Self::Replication | Self::Drop => 4,
            Self::ZeroAnonymity { kind: 0, .. } => return Err(Error::InvalidInput),
            Self::ZeroAnonymity { .. } => ZERO_ANONYMITY_LEN,
            Self::Remove { value, .. } => {
                DATA_LEN.checked_add(value.len()).ok_or(Error::Overflow)?
            }
        };
        MessageHeader::from_total_size(mt::DATASTORE_PUT, length)?;
        Ok(length)
    }
    /// Encode canonical fields. PUT uid/reserved are zero regardless of Data.uid.
    /// Any refusal preserves the whole output, including an oversized value.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let length = self.encoded_len()?;
        if output.len() < length {
            return Err(Error::Capacity);
        }
        match self {
            Self::Reserve { amount, entries } => {
                header(mt::DATASTORE_RESERVE, length, output)?;
                output[4..8].copy_from_slice(&entries.to_be_bytes());
                output[8..16].copy_from_slice(&amount.to_be_bytes());
            }
            Self::Release { reservation } => {
                header(mt::DATASTORE_RELEASE_RESERVE, length, output)?;
                output[4..8].copy_from_slice(&reservation.to_be_bytes());
            }
            Self::Put(mut data) => {
                data.uid = 0;
                return data.encode(mt::DATASTORE_PUT, output);
            }
            Self::Remove { key, value } => {
                return Data {
                    reservation: 0,
                    kind: 0,
                    priority: 0,
                    anonymity: 0,
                    replication: 0,
                    uid: 0,
                    expiration: AbsoluteTime::from_micros(0),
                    key,
                    value,
                }
                .encode(mt::DATASTORE_REMOVE, output);
            }
            Self::Get {
                key,
                kind,
                next_uid,
                random,
            } => {
                header(
                    if key.is_some() {
                        mt::DATASTORE_GET_KEY
                    } else {
                        mt::DATASTORE_GET
                    },
                    length,
                    output,
                )?;
                output[4..8].copy_from_slice(&kind.to_be_bytes());
                output[8..16].copy_from_slice(&next_uid.to_be_bytes());
                // The C API writes host-endian 0/1 here; the service passes it
                // directly to bool. Any nonzero word means true on either endian.
                output[16..20].copy_from_slice(&u32::from(random).to_be_bytes());
                if let Some(key) = key {
                    output[20..84].copy_from_slice(key);
                }
            }
            Self::Replication => header(mt::DATASTORE_GET_REPLICATION, length, output)?,
            Self::ZeroAnonymity { kind, next_uid } => {
                header(mt::DATASTORE_GET_ZERO_ANONYMITY, length, output)?;
                output[4..8].copy_from_slice(&kind.to_be_bytes());
                output[8..16].copy_from_slice(&next_uid.to_be_bytes());
            }
            Self::Drop => header(mt::DATASTORE_DROP, length, output)?,
        }
        Ok(length)
    }
    /// Decode an exact client frame. Unknown message codes are not requests.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let kind = frame.header().message_type();
        let exact = |length| {
            if input.len() == length {
                Ok(())
            } else {
                Err(Error::InvalidInput)
            }
        };
        Ok(match kind {
            mt::DATASTORE_RESERVE => {
                exact(RESERVE_LEN)?;
                Self::Reserve {
                    amount: wide(input, 8)?,
                    entries: word(input, 4)?,
                }
            }
            mt::DATASTORE_RELEASE_RESERVE => {
                exact(RELEASE_LEN)?;
                Self::Release {
                    reservation: word(input, 4)?,
                }
            }
            mt::DATASTORE_PUT => Self::Put(Data::decode(input)?),
            mt::DATASTORE_REMOVE => {
                let data = Data::decode(input)?;
                Self::Remove {
                    key: data.key,
                    value: data.value,
                }
            }
            mt::DATASTORE_GET | mt::DATASTORE_GET_KEY => {
                exact(if kind == mt::DATASTORE_GET {
                    GET_LEN
                } else {
                    GET_KEY_LEN
                })?;
                Self::Get {
                    key: if kind == mt::DATASTORE_GET {
                        None
                    } else {
                        Some(key(input, 20)?)
                    },
                    kind: word(input, 4)?,
                    next_uid: wide(input, 8)?,
                    random: word(input, 16)? != 0,
                }
            }
            mt::DATASTORE_GET_REPLICATION => {
                exact(4)?;
                Self::Replication
            }
            mt::DATASTORE_GET_ZERO_ANONYMITY => {
                exact(ZERO_ANONYMITY_LEN)?;
                let kind = word(input, 4)?;
                if kind == 0 {
                    return Err(Error::InvalidInput);
                }
                Self::ZeroAnonymity {
                    kind,
                    next_uid: wide(input, 8)?,
                }
            }
            mt::DATASTORE_DROP => {
                exact(4)?;
                Self::Drop
            }
            _ => return Err(Error::InvalidInput),
        })
    }
}

/// One authoritative raw service status. Code zero is not given a universal
/// meaning: this service folds duplicate PUT success to 1 and REMOVE errors to 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status<'a> {
    /// Signed status; positive reservation IDs must remain full i32 values.
    pub code: i32,
    /// Public service admission hint; zero means unknown/unlimited.
    pub min_expiration: AbsoluteTime,
    /// Optional original terminated bytes, without UTF8 or C-prefix conversion.
    pub message: Option<&'a [u8]>,
}
impl Status<'_> {
    /// Encode with the reference's terminated-error requirement for status -1.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let suffix = self.message.unwrap_or(&[]);
        if (self.message.is_some() && suffix.last() != Some(&0))
            || (self.code == -1 && suffix.is_empty())
        {
            return Err(Error::InvalidInput);
        }
        let length = STATUS_LEN
            .checked_add(suffix.len())
            .ok_or(Error::Overflow)?;
        header(mt::DATASTORE_STATUS, length, output)?;
        output[4..8].copy_from_slice(&self.code.to_be_bytes());
        output[8..16].copy_from_slice(&self.min_expiration.as_micros().to_be_bytes());
        output[16..length].copy_from_slice(suffix);
        Ok(length)
    }
}

/// Exactly one reply terminates each query/status request. DROP has no reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// Completion of reserve/release/put/remove, preserving raw status semantics.
    Status(Status<'a>),
    /// One selected value; no DATA_END follows a successful normal lookup.
    Data(Data<'a>),
    /// No matching value, also used by the C service for some backend errors.
    End,
}
impl<'a> Response<'a> {
    /// Decode one known exact response. It does not correlate a pending request.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        Ok(match frame.header().message_type() {
            mt::DATASTORE_STATUS => {
                if input.len() < STATUS_LEN {
                    return Err(Error::Truncated);
                }
                let code = word(input, 4)? as i32;
                let suffix = &input[STATUS_LEN..];
                if (!suffix.is_empty() && suffix.last() != Some(&0))
                    || (code == -1 && suffix.is_empty())
                {
                    return Err(Error::InvalidInput);
                }
                Self::Status(Status {
                    code,
                    min_expiration: AbsoluteTime::from_micros(wide(input, 8)?),
                    message: if suffix.is_empty() {
                        None
                    } else {
                        Some(suffix)
                    },
                })
            }
            mt::DATASTORE_DATA => Self::Data(Data::decode(input)?),
            mt::DATASTORE_DATA_END if input.len() == 4 => Self::End,
            _ => return Err(Error::InvalidInput),
        })
    }
    /// Encode actual server fields for offline tests/service adapters.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Status(status) => status.encode(output),
            Self::Data(data) => data.encode(mt::DATASTORE_DATA, output),
            Self::End => {
                header(mt::DATASTORE_DATA_END, 4, output)?;
                Ok(4)
            }
        }
    }
}
