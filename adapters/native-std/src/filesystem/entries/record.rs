//! Bounded FILE_FULL_DIR_INFO records, independently of the host's pointer size.
use std::io;
pub(super) const NAME: usize = 68;
pub(super) const NAME_LENGTH: usize = 60;
pub(super) const NEXT: usize = 0;
pub(super) struct Record<'a> {
    pub name: &'a [u8],
    pub next: Option<usize>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid native directory record",
    )
}
fn word(bytes: &[u8], at: usize) -> io::Result<usize> {
    let mut value = [0; 4];
    value.copy_from_slice(
        bytes
            .get(at..at.checked_add(4).ok_or_else(invalid)?)
            .ok_or_else(invalid)?,
    );
    usize::try_from(u32::from_le_bytes(value)).map_err(|_| invalid())
}
pub(super) fn parse(buffer: &[u8], at: usize) -> io::Result<Record<'_>> {
    if !at.is_multiple_of(8) {
        return Err(invalid());
    }
    let bytes = buffer.get(at..).ok_or_else(invalid)?;
    let next = word(bytes, NEXT)?;
    let length = word(bytes, NAME_LENGTH)?;
    if length == 0 || !length.is_multiple_of(2) || length > 255 * 2 {
        return Err(invalid());
    }
    let end = NAME.checked_add(length).ok_or_else(invalid)?;
    let name = bytes.get(NAME..end).ok_or_else(invalid)?;
    if name
        .as_chunks::<2>()
        .0
        .iter()
        .any(|pair| matches!(u16::from_le_bytes([pair[0], pair[1]]), 0 | 47 | 58 | 92))
    {
        return Err(invalid());
    }
    let next = if next == 0 {
        None
    } else {
        if next < end
            || !next.is_multiple_of(8)
            || next.checked_add(NAME).is_none_or(|end| end > bytes.len())
        {
            return Err(invalid());
        }
        Some(at.checked_add(next).ok_or_else(invalid)?)
    };
    Ok(Record { name, next })
}

#[cfg(test)]
mod tests {
    use super::parse;
    #[test]
    #[expect(
        clippy::expect_used,
        reason = "The fixed valid record must parse before checking malformed variants"
    )]
    fn malformed_offsets_and_truncated_native_names_never_become_end_of_directory() {
        let mut bytes = [0; 160];
        bytes[60..64].copy_from_slice(&2_u32.to_le_bytes());
        bytes[68..70].copy_from_slice(&u16::from(b'a').to_le_bytes());
        let first = parse(&bytes, 0).expect("complete native directory record");
        assert_eq!(first.name, &[b'a', 0]);
        assert_eq!(first.next, None);
        for offset in [1, 64, 160, u32::MAX] {
            bytes[..4].copy_from_slice(&offset.to_le_bytes());
            assert!(parse(&bytes, 0).is_err(), "offset {offset}");
        }
        bytes[..4].copy_from_slice(&72_u32.to_le_bytes());
        bytes[132..136].copy_from_slice(&2_u32.to_le_bytes());
        bytes[140..142].copy_from_slice(&0xd800_u16.to_le_bytes());
        assert_eq!(
            parse(&bytes, 0).expect("first chained record").next,
            Some(72)
        );
        let last = parse(&bytes, 72).expect("native isolated surrogate is preserved");
        assert_eq!(last.name, &[0, 0xd8]);
        assert_eq!(last.next, None);
        bytes[..4].fill(0);
        bytes[60..64].copy_from_slice(&3_u32.to_le_bytes());
        assert!(parse(&bytes, 0).is_err());
        bytes[60..64].copy_from_slice(&510_u32.to_le_bytes());
        assert!(parse(&bytes, 0).is_err());
    }
}
