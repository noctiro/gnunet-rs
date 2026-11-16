//! Canonical full native selector in interface metadata, without file authority.
use super::{Intent, RECORD_BYTES, Record};
use std::io;
const PREFIX: &[u8] = b"gnunet-rs-tun:1:";
pub(crate) const BYTES: usize = PREFIX.len() + 2 * RECORD_BYTES + 1;
pub(crate) fn encode(record: &Record) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    bytes[..PREFIX.len()].copy_from_slice(PREFIX);
    for (ordinal, byte) in record.encode().iter().enumerate() {
        bytes[PREFIX.len() + 2 * ordinal] = b"0123456789abcdef"[(byte >> 4) as usize];
        bytes[PREFIX.len() + 2 * ordinal + 1] = b"0123456789abcdef"[(byte & 15) as usize];
    }
    bytes
}
pub(crate) fn decode(bytes: &[u8]) -> Option<Record> {
    if bytes.len() != BYTES || !bytes.starts_with(PREFIX) || bytes[BYTES - 1] != 0 {
        return None;
    }
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let mut record = [0; RECORD_BYTES];
    for (ordinal, byte) in record.iter_mut().enumerate() {
        *byte = (digit(bytes[PREFIX.len() + 2 * ordinal])? << 4)
            | digit(bytes[PREFIX.len() + 2 * ordinal + 1])?;
    }
    Record::decode(&record).ok()
}
/// Retained discovery metadata only; a selected record must still be physically
/// qualified before native cleanup. Duplicate matches never select a winner.
#[derive(Default)]
pub(crate) enum Matches {
    #[default]
    Unmatched,
    One(Record),
    Refused,
}
fn ambiguous() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "ambiguous or inconsistent native TUN allocation marker",
    )
}
impl Matches {
    pub(crate) fn observe(
        &mut self,
        intent: &Intent,
        name: &[u8; 16],
        index: u32,
        mut record: Record,
    ) -> io::Result<()> {
        if matches!(self, Self::Refused) {
            return Err(ambiguous());
        }
        if record.birth != intent.nonce {
            return Ok(());
        }
        if record.index != index
            || index == 0
            || !matches!(self, Self::Unmatched)
            || super::read_name(name).is_err()
        {
            *self = Self::Refused;
            return Err(ambiguous());
        }
        record.name = *name;
        *self = Self::One(record);
        Ok(())
    }
    pub(crate) fn selected(self) -> io::Result<Option<Record>> {
        match self {
            Self::Unmatched => Ok(None),
            Self::One(record) => Ok(Some(record)),
            Self::Refused => Err(ambiguous()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_native::filesystem::FileIdentity;
    fn check(value: bool) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other("native marker contract mismatch"))
        }
    }
    fn record() -> Record {
        let mut name = [0; 16];
        name[..5].copy_from_slice(b"tun17");
        Record {
            name,
            device: name,
            index: 41,
            birth: [3; 32],
            file: FileIdentity::unix(7, 123),
        }
    }
    #[test]
    fn full_marker_is_canonical_and_contains_the_original_devfs_selector() -> io::Result<()> {
        let original = record();
        let bytes = encode(&original);
        check(decode(&bytes).as_ref() == Some(&original))?;
        check(decode(&bytes[..bytes.len() - 1]).is_none())?;
        let mut bad = bytes;
        bad[PREFIX.len()] = b'G';
        check(decode(&bad).is_none())?;
        bad = bytes;
        bad[BYTES - 1] = b'x';
        check(decode(&bad).is_none())
    }
    #[test]
    fn discovery_retains_actual_renames_but_never_accepts_a_duplicate_marker() -> io::Result<()> {
        let intent = Intent::for_marker_test([3; 32]);
        let mut renamed = [0; 16];
        renamed[..8].copy_from_slice(b"vpn-test");
        let mut selected = Matches::default();
        let mut foreign = record();
        foreign.birth[0] ^= 1;
        selected.observe(&intent, &renamed, 41, foreign)?;
        selected.observe(&intent, &renamed, 41, record())?;
        let actual = selected
            .selected()?
            .ok_or_else(|| io::Error::other("matching selector lost"))?;
        check(
            actual.interface_name()? == "vpn-test"
                && actual.device_name()? == "tun17"
                && actual.same_identity(&record()),
        )?;
        let mut duplicate = Matches::default();
        duplicate.observe(&intent, &renamed, 41, record())?;
        check(duplicate.observe(&intent, &renamed, 41, record()).is_err())?;
        check(duplicate.selected().is_err())
    }
    #[test]
    fn locator_changes_preserve_identity_but_each_native_key_field_remains_required()
    -> io::Result<()> {
        let original = record();
        let mut renamed = original.clone();
        renamed.name = [0; 16];
        renamed.name[..3].copy_from_slice(b"vpn");
        check(original.same_identity(&renamed))?;
        let mut wrong = renamed.clone();
        wrong.index += 1;
        check(!original.same_identity(&wrong))?;
        wrong = renamed.clone();
        wrong.birth[0] ^= 1;
        check(!original.same_identity(&wrong))?;
        wrong = renamed.clone();
        wrong.device[4] = b'8';
        check(!original.same_identity(&wrong))?;
        wrong = renamed;
        wrong.file = FileIdentity::unix(7, 124);
        check(!original.same_identity(&wrong))
    }
}
