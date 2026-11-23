//! ICC profile envelope shared by container metadata readers.

pub(in crate::extraction) const KIND: u32 = 282;
pub(in crate::extraction) const MIME: &[u8] = b"application/vnd.iccprofile\0";
pub(super) const MIN_BYTES: usize = 132;
const TAG_BYTES: usize = 12;

/// An original, bounded ICC blob. Publishing it does not interpret its transforms.
pub(in crate::extraction) struct Profile<'a>(&'a [u8]);

impl<'a> Profile<'a> {
    pub(super) fn parse(bytes: &'a [u8], limit: usize) -> Option<Self> {
        if !(MIN_BYTES..=limit).contains(&bytes.len())
            || read_u32(bytes)? as usize != bytes.len()
            || bytes.get(36..40)? != b"acsp"
        {
            return None;
        }
        let count = read_u32(bytes.get(128..)?)? as usize;
        let tags_end = MIN_BYTES.checked_add(count.checked_mul(TAG_BYTES)?)?;
        for tag in bytes.get(MIN_BYTES..tags_end)?.as_chunks::<TAG_BYTES>().0 {
            let at = read_u32(&tag[4..])? as usize;
            let size = read_u32(&tag[8..])? as usize;
            if at < tags_end
                || !at.is_multiple_of(4)
                || size < 8
                || at.checked_add(size)? > bytes.len()
            {
                return None;
            }
        }
        Some(Self(bytes))
    }

    pub(in crate::extraction) const fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(*bytes.first_chunk()?))
}

#[cfg(test)]
pub(in crate::extraction) fn fixture() -> [u8; 156] {
    let mut bytes = [0; 156];
    bytes[..4].copy_from_slice(&156_u32.to_be_bytes());
    bytes[8] = 4;
    bytes[12..24].copy_from_slice(b"mntrRGB XYZ ");
    bytes[36..40].copy_from_slice(b"acsp");
    bytes[128..].copy_from_slice(b"\0\0\0\x01cprt\0\0\0\x90\0\0\0\x0ctext\0\0\0\0ICC\0");
    bytes
}
