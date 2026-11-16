//! Canonical private state frames; checksums detect damage, not hostile authors.
use super::{
    super::{Record, read_name},
    Intent, State,
};
use std::io;
pub(super) const BYTES: usize = 256;
pub(super) const FILE_BYTES: usize = 2 * BYTES;
const PAYLOAD: usize = 24;
const HASH: usize = BYTES - 32;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Frame {
    pub sequence: u64,
    pub state: State,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid TUN checkpoint frame")
}
impl Frame {
    pub(super) fn encode(&self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(b"GNTUNJ01");
        bytes[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        match &self.state {
            State::Empty => {}
            State::Creating(intent) => {
                bytes[16] = 1;
                bytes[PAYLOAD..PAYLOAD + 32].copy_from_slice(&intent.nonce);
                bytes[PAYLOAD + 32..PAYLOAD + 48].copy_from_slice(&intent.requested);
            }
            State::Active(record) => {
                bytes[16] = 2;
                bytes[PAYLOAD..PAYLOAD + 128].copy_from_slice(&record.encode());
            }
        }
        let checksum = gnunet_crypto::hash256(&bytes[..HASH]);
        bytes[HASH..].copy_from_slice(&checksum);
        bytes
    }
    pub(super) fn decode(bytes: &[u8; BYTES]) -> io::Result<Self> {
        if &bytes[..8] != b"GNTUNJ01"
            || bytes[17..PAYLOAD].iter().any(|byte| *byte != 0)
            || bytes[HASH..] != gnunet_crypto::hash256(&bytes[..HASH])
        {
            return Err(invalid());
        }
        let sequence = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| invalid())?);
        let (state, end) = match bytes[16] {
            0 => (State::Empty, PAYLOAD),
            1 if sequence != 0 => {
                let nonce = bytes[PAYLOAD..PAYLOAD + 32]
                    .try_into()
                    .map_err(|_| invalid())?;
                let requested = bytes[PAYLOAD + 32..PAYLOAD + 48]
                    .try_into()
                    .map_err(|_| invalid())?;
                if nonce == [0; 32] {
                    return Err(invalid());
                }
                if requested != [0; 16] {
                    read_name(&requested)?;
                }
                (State::Creating(Intent { nonce, requested }), PAYLOAD + 48)
            }
            2 if sequence != 0 => (
                State::Active(Record::decode(&bytes[PAYLOAD..PAYLOAD + 128])?),
                PAYLOAD + 128,
            ),
            _ => return Err(invalid()),
        };
        if bytes[end..HASH].iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
        Ok(Self { sequence, state })
    }
}
pub(super) fn select(bytes: &[u8; FILE_BYTES]) -> io::Result<(Frame, usize)> {
    let left = Frame::decode(bytes[..BYTES].try_into().map_err(|_| invalid())?);
    let right = Frame::decode(bytes[BYTES..].try_into().map_err(|_| invalid())?);
    match (left, right) {
        (Ok(a), Ok(b)) if a.sequence > b.sequence => Ok((a, 0)),
        (Ok(a), Ok(b)) if a.sequence < b.sequence => Ok((b, 1)),
        (Ok(a), Err(_))
            if !matches!(a.state, State::Empty) || bytes[BYTES..].iter().all(|byte| *byte == 0) =>
        {
            Ok((a, 0))
        }
        (Err(_), Ok(b))
            if !matches!(b.state, State::Empty) || bytes[..BYTES].iter().all(|byte| *byte == 0) =>
        {
            Ok((b, 1))
        }
        _ => Err(invalid()),
    }
}
