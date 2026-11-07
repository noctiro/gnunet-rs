//! Official record framing and the reference implementation's padding rule.
use crate::{RecordFlags, RecordType};
use gnunet_types::Error;

/// Bytes in one `NetworkRecord`: expiration64, data size16, flags16, type32.
pub const RECORD_HEADER_LEN: usize = 16;
/// Reference maximum encrypted record-data block size; block owners must enforce it.
///
/// The low-level record serializer itself also serves IPC and accepts a caller-selected
/// destination size, so this separate block-policy limit is not silently imposed there.
pub const MAX_BLOCK_SIZE: usize = 63 * 1024;

/// A borrowed official GNS resource record; expiration is in microseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordData<'a> {
    /// Absolute UTC microseconds, or relative microseconds when the flag says so.
    pub expiration_time: u64,
    /// DNS/GNS type, including unrecognized extension codepoints.
    pub record_type: RecordType,
    /// Full 16-bit flags, with unknown bits preserved.
    pub flags: RecordFlags,
    /// Borrowed value; serialization requires its length to fit the 16-bit field.
    pub data: &'a [u8],
}

impl<'a> RecordData<'a> {
    /// Exact unpadded size of this record, refusing a value not representable on wire.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        if self.data.len() > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        RECORD_HEADER_LEN
            .checked_add(self.data.len())
            .ok_or(Error::Overflow)
    }

    /// Validate the fixed-length A/AAAA/PKEY/EDKEY schemas only.
    ///
    /// Variable-length and unknown types retain their bytes for the owning
    /// interpreter; success does not mean an arbitrary record's value is valid.
    pub fn validate_fixed_size(&self) -> Result<(), Error> {
        if self
            .record_type
            .fixed_size()
            .is_some_and(|size| size != self.data.len())
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Whether expiration is a relative microsecond duration.
    #[must_use]
    pub const fn has_relative_expiration(&self) -> bool {
        self.flags.contains(RecordFlags::RELATIVE_EXPIRATION)
    }

    /// Decode one record and return the unconsumed suffix.
    ///
    /// This is framing, not resolution policy: unknown flags/types and relative
    /// expiration are retained. A published encrypted block must separately
    /// convert relative expiration and omit private records.
    pub fn decode_prefix(input: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let header = input.get(..RECORD_HEADER_LEN).ok_or(Error::Truncated)?;
        let expiration_time =
            u64::from_be_bytes(header[..8].try_into().map_err(|_| Error::Truncated)?);
        let size = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let flags = RecordFlags::from_bits_preserve(u16::from_be_bytes([header[10], header[11]]));
        let record_type = RecordType::new(u32::from_be_bytes(
            header[12..16].try_into().map_err(|_| Error::Truncated)?,
        ));
        let end = RECORD_HEADER_LEN.checked_add(size).ok_or(Error::Overflow)?;
        let data = input.get(RECORD_HEADER_LEN..end).ok_or(Error::Truncated)?;
        Ok((
            Self {
                expiration_time,
                record_type,
                flags,
                data,
            },
            &input[end..],
        ))
    }

    /// Write one unpadded record; refusal leaves all output unchanged.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        let size = u16::try_from(self.data.len()).map_err(|_| Error::TooLarge)?;
        output[..8].copy_from_slice(&self.expiration_time.to_be_bytes());
        output[8..10].copy_from_slice(&size.to_be_bytes());
        output[10..12].copy_from_slice(&self.flags.bits().to_be_bytes());
        output[12..16].copy_from_slice(&self.record_type.value().to_be_bytes());
        output[RECORD_HEADER_LEN..len].copy_from_slice(self.data);
        Ok(len)
    }
}

fn unpadded_len(records: &[RecordData<'_>]) -> Result<usize, Error> {
    let mut length = 0_usize;
    for record in records {
        length = length
            .checked_add(record.encoded_len()?)
            .ok_or(Error::Overflow)?;
    }
    Ok(length)
}

/// Reference `records_get_size`: pad to a power of two unless the **first**
/// record is PKEY or EDKEY. An empty set has size zero.
///
/// The first-record rule matches v0.29.1 even for mixed sets. This helper does
/// not validate the higher-level rule that a delegation is normally standalone.
pub fn serialized_len(records: &[RecordData<'_>]) -> Result<usize, Error> {
    let length = unpadded_len(records)?;
    if length == 0
        || records
            .first()
            .is_some_and(|record| record.record_type.is_zone_delegation())
    {
        return Ok(length);
    }
    length.checked_next_power_of_two().ok_or(Error::Overflow)
}

/// Write the reference implementation's canonical padded size, returning bytes
/// written and preserving the unused output suffix. Refusal changes no output.
pub fn serialize(records: &[RecordData<'_>], output: &mut [u8]) -> Result<usize, Error> {
    let length = serialized_len(records)?;
    if output.len() < length {
        return Err(Error::Capacity);
    }
    serialize_to_size(records, &mut output[..length])
}

/// Match `records_serialize` with an explicit destination size: encode all
/// records then fill the remaining destination with zeroes.
///
/// The C function permits a caller-selected size larger than `records_get_size`;
/// this entry point preserves that behavior. Refusal changes no output.
pub fn serialize_to_size(records: &[RecordData<'_>], output: &mut [u8]) -> Result<usize, Error> {
    let required = unpadded_len(records)?;
    if output.len() < required {
        return Err(Error::Capacity);
    }
    let mut offset = 0_usize;
    for record in records {
        let written = record.encode(&mut output[offset..])?;
        offset = offset.checked_add(written).ok_or(Error::Overflow)?;
    }
    output[offset..].fill(0);
    Ok(output.len())
}

/// A completely validated borrowed serialized set with an explicit count.
///
/// Construction decodes at most the caller's `maximum_records` and checks zero
/// padding linearly in the supplied byte length; no record table or payload
/// allocation occurs. An encrypted-block owner must additionally apply
/// [`MAX_BLOCK_SIZE`]. Values are not interpreted or authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordSet<'a> {
    wire: &'a [u8],
    record_bytes: usize,
    count: usize,
}

impl<'a> RecordSet<'a> {
    /// Validate a caller-supplied record count and canonical zero padding.
    ///
    /// The count is required when a record's entire 16-byte header is zero;
    /// automatic padding discovery cannot distinguish that record from padding.
    /// Unknown record types and flags remain intact. Nonzero trailing bytes are
    /// rejected, rather than silently ignored by the low-level C deserializer.
    pub fn parse(input: &'a [u8], count: usize, maximum_records: usize) -> Result<Self, Error> {
        if count > maximum_records {
            return Err(Error::Capacity);
        }
        let mut tail = input;
        for _ in 0..count {
            let (_, remaining) = RecordData::decode_prefix(tail)?;
            tail = remaining;
        }
        if tail.iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            wire: input,
            record_bytes: input.len() - tail.len(),
            count,
        })
    }

    /// Discover count using the C reference's all-zero-header padding sentinel.
    ///
    /// A malformed record is reported as an error, whereas the C count helper
    /// returns zero on failure. The entire padding suffix must be zero. This
    /// cannot discover an all-zero record; use [`Self::parse`] when count is known.
    pub fn parse_padded(input: &'a [u8], maximum_records: usize) -> Result<Self, Error> {
        let mut tail = input;
        let mut count = 0_usize;
        while !tail.is_empty() {
            if tail.len() < RECORD_HEADER_LEN
                || tail[..RECORD_HEADER_LEN].iter().all(|byte| *byte == 0)
            {
                if tail.iter().any(|byte| *byte != 0) {
                    return Err(if tail.len() < RECORD_HEADER_LEN {
                        Error::Truncated
                    } else {
                        Error::Malformed
                    });
                }
                break;
            }
            if count == maximum_records {
                return Err(Error::Capacity);
            }
            let (_, remaining) = RecordData::decode_prefix(tail)?;
            tail = remaining;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
        }
        Ok(Self {
            wire: input,
            record_bytes: input.len() - tail.len(),
            count,
        })
    }

    /// Validated number of records.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the set contains no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Encoded records without padding.
    #[must_use]
    pub fn record_bytes(&self) -> &'a [u8] {
        &self.wire[..self.record_bytes]
    }

    /// Zero padding following the records.
    #[must_use]
    pub fn padding(&self) -> &'a [u8] {
        &self.wire[self.record_bytes..]
    }

    /// Iterate borrowed records without creating an owned record table.
    #[must_use]
    pub fn iter(&self) -> RecordIter<'a> {
        RecordIter {
            remaining: self.record_bytes(),
            count: self.count,
        }
    }
}

/// Bounded borrowed iteration over the records of a validated [`RecordSet`].
pub struct RecordIter<'a> {
    remaining: &'a [u8],
    count: usize,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Result<RecordData<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match RecordData::decode_prefix(self.remaining) {
            Ok((record, tail)) => {
                self.remaining = tail;
                Some(Ok(record))
            }
            Err(error) => {
                self.remaining = &[];
                self.count = 0;
                Some(Err(error))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}

impl ExactSizeIterator for RecordIter<'_> {}
impl core::iter::FusedIterator for RecordIter<'_> {}
