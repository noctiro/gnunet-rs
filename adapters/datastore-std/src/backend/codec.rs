//! Versioned metadata-only checkpoint and atomic WAL transaction encoding.
//!
//! These are private disk records, never GNUnet IPC frames. Values live outside
//! these records. SHA-256 covers the exact header and every fixed-width row/op;
//! a digest and distinct final footer seal each record. Only an incomplete last
//! WAL record is recoverable as Torn. A complete bad record is corruption.
use super::{Limits, Op, Stored};
use gnunet_crypto::Hash256State;
use gnunet_datastore::backend::Meta;
use gnunet_wire::official::AbsoluteTime;
use std::{
    fmt,
    io::{self, Read, Write},
};

/// Fixed metadata row width. No value bytes or host-layout padding are stored.
pub const STORED_BYTES: usize = 136;
/// One operation tag plus a canonical fixed metadata-sized body.
pub const OP_BYTES: usize = 144;
/// Header width common to checkpoints and WAL transactions.
pub const HEADER_BYTES: usize = 40;
/// Digest plus final record footer width.
pub const TRAILER_BYTES: usize = 40;
/// Largest value representable by the official DATASTORE_DATA IPC message.
pub const MAX_VALUE_BYTES: u64 = 65_423;

const SNAP_MAGIC: [u8; 8] = *b"GDSNP001";
const SNAP_FOOTER: [u8; 8] = *b"GDSNEND1";
const WAL_MAGIC: [u8; 8] = *b"GDWAL001";
const WAL_FOOTER: [u8; 8] = *b"GDWLEND1";

/// Disk codec failure, kept separate from the host's commit/recovery policy.
#[derive(Debug)]
pub(super) enum CodecError {
    /// Actual filesystem or reader/writer error. A write may already be partial.
    Io(io::Error),
    /// Complete invalid disk framing, metadata, checksum or footer.
    Corrupt,
    /// Caller-supplied metadata or high-water mark is inconsistent.
    InvalidInput,
    /// The explicit record/operation/byte limit or allocation capacity was hit.
    Limit,
    /// Caller-supplied count, length or usage cannot be represented.
    Overflow,
}
impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Corrupt => f.write_str("corrupt datastore disk record"),
            Self::InvalidInput => f.write_str("invalid datastore disk metadata"),
            Self::Limit => f.write_str("datastore disk record limit exceeded"),
            Self::Overflow => f.write_str("datastore disk record size overflow"),
        }
    }
}
impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for CodecError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Result of reading exactly one transaction at the reader's current position.
pub(super) enum TxRead {
    /// EOF before any next-record byte.
    End,
    /// EOF before this record's final footer. The host may truncate only this
    /// uncommitted trailing prefix, after preserving prior complete records.
    Torn {
        /// Actual prefix bytes consumed, excluding preceding transactions.
        bytes_read: u64,
    },
    /// One complete checksummed transaction, with no following bytes consumed.
    Complete {
        /// Host transaction sequence; cross-record monotonicity is host policy.
        seq: u64,
        /// Highest UID ever allocated, including removed records.
        hwm: u64,
        /// Ordered metadata mutations; value payloads are never collected here.
        ops: Vec<Op>,
        /// Exact complete transaction width, for aggregate WAL accounting.
        bytes: u64,
    },
}

/// Write one complete checkpoint without materializing its encoded rows.
/// All metadata and arithmetic are validated before the first output byte.
/// The caller owns atomic rename, synchronization and uncertain-I/O handling.
pub(super) fn write_snapshot<W: Write>(
    mut writer: W,
    rows: &[Stored],
    seq: u64,
    hwm: u64,
) -> Result<u64, CodecError> {
    let count = u64::try_from(rows.len()).map_err(|_| CodecError::Overflow)?;
    let bytes = total(count, STORED_BYTES).ok_or(CodecError::Overflow)?;
    let mut value_bytes = 0_u64;
    for row in rows {
        if !valid_stored(row, hwm) {
            return Err(CodecError::InvalidInput);
        }
        value_bytes = value_bytes
            .checked_add(row.len)
            .ok_or(CodecError::Overflow)?;
    }
    let mut header = [0; HEADER_BYTES];
    header[..8].copy_from_slice(&SNAP_MAGIC);
    put64(&mut header, 8, seq);
    put64(&mut header, 16, hwm);
    put64(&mut header, 24, count);
    put64(&mut header, 32, value_bytes);
    let mut hash = Hash256State::new();
    hashed_write(&mut writer, &mut hash, &header)?;
    for row in rows {
        hashed_write(&mut writer, &mut hash, &encode_stored(*row))?;
    }
    writer.write_all(&hash.finish())?;
    writer.write_all(&SNAP_FOOTER)?;
    Ok(bytes)
}

/// Read one exact checkpoint. Count and checked width bound allocation before
/// its metadata vector. Truncation or any trailing byte is corruption.
/// UID uniqueness and cross-file sequence monotonicity belong to recovery.
pub(super) fn read_snapshot<R: Read>(
    mut reader: R,
    limits: Limits,
) -> Result<(u64, u64, Vec<Stored>), CodecError> {
    let mut consumed = 0_u64;
    let mut header = [0; HEADER_BYTES];
    if !read_full(&mut reader, &mut header, &mut consumed)? {
        return Err(CodecError::Corrupt);
    }
    if header[..8] != SNAP_MAGIC {
        return Err(CodecError::Corrupt);
    }
    let seq = get64(&header, 8);
    let hwm = get64(&header, 16);
    let count = get64(&header, 24);
    let expected_values = get64(&header, 32);
    let bytes = total(count, STORED_BYTES).ok_or(CodecError::Corrupt)?;
    let count = usize::try_from(count).map_err(|_| CodecError::Limit)?;
    if count > limits.max_records {
        return Err(CodecError::Limit);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)
        .map_err(|_| CodecError::Limit)?;
    let mut hash = Hash256State::new();
    hash.update(&header);
    let mut value_bytes = 0_u64;
    for _ in 0..count {
        let mut raw = [0; STORED_BYTES];
        if !read_full(&mut reader, &mut raw, &mut consumed)? {
            return Err(CodecError::Corrupt);
        }
        hash.update(&raw);
        let row = decode_stored(&raw, hwm)?;
        value_bytes = value_bytes
            .checked_add(row.len)
            .ok_or(CodecError::Corrupt)?;
        rows.push(row);
    }
    let mut digest = [0; 32];
    let mut footer = [0; 8];
    if !read_full(&mut reader, &mut digest, &mut consumed)?
        || !read_full(&mut reader, &mut footer, &mut consumed)?
    {
        return Err(CodecError::Corrupt);
    }
    if digest != hash.finish()
        || footer != SNAP_FOOTER
        || value_bytes != expected_values
        || consumed != bytes
    {
        return Err(CodecError::Corrupt);
    }
    let mut trailing = [0; 1];
    if read_full(&mut reader, &mut trailing, &mut consumed)? {
        return Err(CodecError::Corrupt);
    }
    Ok((seq, hwm, rows))
}

/// Write one sealed transaction. Input validation precedes all writes; a later
/// I/O error may leave a trailing prefix and must be handled by the host.
pub(super) fn write_tx<W: Write>(
    mut writer: W,
    seq: u64,
    hwm: u64,
    ops: &[Op],
) -> Result<u64, CodecError> {
    let count = u32::try_from(ops.len()).map_err(|_| CodecError::Overflow)?;
    let bytes = total(u64::from(count), OP_BYTES).ok_or(CodecError::Overflow)?;
    for op in ops {
        if !valid_op(op, hwm) {
            return Err(CodecError::InvalidInput);
        }
    }
    let mut header = [0; HEADER_BYTES];
    header[..8].copy_from_slice(&WAL_MAGIC);
    put64(&mut header, 8, bytes);
    put64(&mut header, 16, seq);
    put64(&mut header, 24, hwm);
    header[32..36].copy_from_slice(&count.to_be_bytes());
    let mut hash = Hash256State::new();
    hashed_write(&mut writer, &mut hash, &header)?;
    for op in ops {
        hashed_write(&mut writer, &mut hash, &encode_op(*op))?;
    }
    writer.write_all(&hash.finish())?;
    writer.write_all(&WAL_FOOTER)?;
    Ok(bytes)
}

/// Read one WAL transaction, leaving any following transaction untouched.
/// Only actual EOF in an unfinished trailing record yields Torn. Format,
/// checksum and footer failures in complete records never become a clean EOF.
pub(super) fn read_tx<R: Read>(mut reader: R, limits: Limits) -> Result<TxRead, CodecError> {
    let mut consumed = 0_u64;
    let mut header = [0; HEADER_BYTES];
    if !read_full(&mut reader, &mut header, &mut consumed)? {
        return Ok(if consumed == 0 {
            TxRead::End
        } else {
            TxRead::Torn {
                bytes_read: consumed,
            }
        });
    }
    if header[..8] != WAL_MAGIC || get32(&header, 36) != 0 {
        return Err(CodecError::Corrupt);
    }
    let bytes = get64(&header, 8);
    let seq = get64(&header, 16);
    let hwm = get64(&header, 24);
    let count = get32(&header, 32);
    if total(u64::from(count), OP_BYTES) != Some(bytes) {
        return Err(CodecError::Corrupt);
    }
    let count = usize::try_from(count).map_err(|_| CodecError::Limit)?;
    if count > limits.max_transaction_ops || bytes > limits.max_wal_bytes {
        return Err(CodecError::Limit);
    }
    let mut ops = Vec::new();
    ops.try_reserve_exact(count)
        .map_err(|_| CodecError::Limit)?;
    let mut hash = Hash256State::new();
    hash.update(&header);
    for _ in 0..count {
        let mut raw = [0; OP_BYTES];
        if !read_full(&mut reader, &mut raw, &mut consumed)? {
            return Ok(TxRead::Torn {
                bytes_read: consumed,
            });
        }
        hash.update(&raw);
        ops.push(decode_op(&raw, hwm)?);
    }
    let mut digest = [0; 32];
    let mut footer = [0; 8];
    if !read_full(&mut reader, &mut digest, &mut consumed)?
        || !read_full(&mut reader, &mut footer, &mut consumed)?
    {
        return Ok(TxRead::Torn {
            bytes_read: consumed,
        });
    }
    if digest != hash.finish() || footer != WAL_FOOTER || consumed != bytes {
        return Err(CodecError::Corrupt);
    }
    Ok(TxRead::Complete {
        seq,
        hwm,
        ops,
        bytes,
    })
}

fn valid_stored(row: &Stored, hwm: u64) -> bool {
    row.meta.uid != 0 && row.meta.uid <= hwm && row.len <= MAX_VALUE_BYTES
}
fn valid_op(op: &Op, hwm: u64) -> bool {
    match op {
        Op::Upsert(row) => valid_stored(row, hwm),
        Op::Delete(uid) => *uid != 0 && *uid <= hwm,
        Op::Clear => true,
    }
}
fn encode_stored(row: Stored) -> [u8; STORED_BYTES] {
    let mut raw = [0; STORED_BYTES];
    put64(&mut raw, 0, row.meta.uid);
    raw[8..72].copy_from_slice(&row.meta.key);
    put32(&mut raw, 72, row.meta.kind);
    put32(&mut raw, 76, row.meta.priority);
    put32(&mut raw, 80, row.meta.anonymity);
    put32(&mut raw, 84, row.meta.replication);
    put64(&mut raw, 88, row.meta.expiration.as_micros());
    put64(&mut raw, 96, row.len);
    raw[104..136].copy_from_slice(&row.digest);
    raw
}
fn decode_stored(raw: &[u8; STORED_BYTES], hwm: u64) -> Result<Stored, CodecError> {
    let mut key = [0; 64];
    let mut digest = [0; 32];
    key.copy_from_slice(&raw[8..72]);
    digest.copy_from_slice(&raw[104..136]);
    let row = Stored {
        meta: Meta {
            uid: get64(raw, 0),
            key,
            kind: get32(raw, 72),
            priority: get32(raw, 76),
            anonymity: get32(raw, 80),
            replication: get32(raw, 84),
            expiration: AbsoluteTime::from_micros(get64(raw, 88)),
        },
        len: get64(raw, 96),
        digest,
    };
    if !valid_stored(&row, hwm) {
        return Err(CodecError::Corrupt);
    }
    Ok(row)
}
fn encode_op(op: Op) -> [u8; OP_BYTES] {
    let mut raw = [0; OP_BYTES];
    match op {
        Op::Clear => {}
        Op::Upsert(row) => {
            put64(&mut raw, 0, 1);
            raw[8..].copy_from_slice(&encode_stored(row));
        }
        Op::Delete(uid) => {
            put64(&mut raw, 0, 2);
            put64(&mut raw, 8, uid);
        }
    }
    raw
}
fn decode_op(raw: &[u8; OP_BYTES], hwm: u64) -> Result<Op, CodecError> {
    match get64(raw, 0) {
        0 if raw[8..].iter().all(|byte| *byte == 0) => Ok(Op::Clear),
        1 => {
            let body: &[u8; STORED_BYTES] = raw[8..].try_into().map_err(|_| CodecError::Corrupt)?;
            Ok(Op::Upsert(decode_stored(body, hwm)?))
        }
        2 if raw[16..].iter().all(|byte| *byte == 0) => {
            let uid = get64(raw, 8);
            if uid == 0 || uid > hwm {
                return Err(CodecError::Corrupt);
            }
            Ok(Op::Delete(uid))
        }
        _ => Err(CodecError::Corrupt),
    }
}
fn total(count: u64, row_bytes: usize) -> Option<u64> {
    count
        .checked_mul(row_bytes as u64)?
        .checked_add((HEADER_BYTES + TRAILER_BYTES) as u64)
}
fn put32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
fn get32(raw: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ])
}
fn get64(raw: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
        raw[offset + 4],
        raw[offset + 5],
        raw[offset + 6],
        raw[offset + 7],
    ])
}
fn hashed_write<W: Write>(
    writer: &mut W,
    hash: &mut Hash256State,
    raw: &[u8],
) -> Result<(), CodecError> {
    writer.write_all(raw)?;
    hash.update(raw);
    Ok(())
}
/// Read a fixed region, recording every consumed byte. False means actual EOF;
/// non-EOF reader errors remain Io instead of being treated as crash truncation.
fn read_full<R: Read>(
    reader: &mut R,
    raw: &mut [u8],
    consumed: &mut u64,
) -> Result<bool, CodecError> {
    let mut offset = 0;
    while offset < raw.len() {
        match reader.read(&mut raw[offset..]) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                if n > raw.len() - offset {
                    return Err(CodecError::Corrupt);
                }
                offset += n;
                *consumed = consumed.checked_add(n as u64).ok_or(CodecError::Overflow)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(error) => return Err(CodecError::Io(error)),
        }
    }
    Ok(true)
}
