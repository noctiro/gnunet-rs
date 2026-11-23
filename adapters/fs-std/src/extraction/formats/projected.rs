//! Read reconstructed BMFF coordinates over the original source and expanded boxes.

use super::boxes::compressed::{Projection, Segment};

#[derive(Clone, Copy)]
pub(super) struct Projected<'a> {
    pub(super) map: &'a Projection,
    pub(super) original_prefix: &'a [u8],
    pub(super) origin: u64,
}

impl<'a> Projected<'a> {
    pub(super) fn read<'s, E>(
        self,
        start: u64,
        len: usize,
        scratch: &'s mut [u8],
        remaining: &mut usize,
        read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<Option<&'s [u8]>, E>
    where
        'a: 's,
    {
        if len == 0 {
            return Ok(Some(&[]));
        }
        match self.map.source(start) {
            Some(Segment::Expanded(bytes)) if len <= bytes.len() => return Ok(Some(&bytes[..len])),
            Some(Segment::Original { offset, available }) if len as u64 <= available => {
                if let Some(bytes) = self.cached(offset, len) {
                    return Ok(Some(bytes));
                }
            }
            None => return Ok(None),
            _ => {}
        }

        if len > *remaining {
            return Ok(None);
        }
        let Some(bytes) = scratch.get_mut(..len) else {
            return Ok(None);
        };
        let mut out = &mut *bytes;
        let mut at = start;
        while !out.is_empty() {
            let Some(segment) = self.map.source(at) else {
                return Ok(None);
            };
            let count = match segment {
                Segment::Expanded(source) => {
                    let count = out.len().min(source.len());
                    out[..count].copy_from_slice(&source[..count]);
                    count
                }
                Segment::Original { offset, available } => {
                    let count = (out.len() as u64).min(available) as usize;
                    if let Some(source) = self.cached(offset, count) {
                        out[..count].copy_from_slice(source);
                    } else {
                        let Some(physical) = self.origin.checked_add(offset) else {
                            return Ok(None);
                        };
                        read(physical, &mut out[..count])?;
                    }
                    count
                }
            };
            if count == 0 {
                return Ok(None);
            }
            at += count as u64;
            out = &mut out[count..];
        }
        *remaining -= len;
        Ok(Some(bytes))
    }

    fn cached(self, offset: u64, len: usize) -> Option<&'a [u8]> {
        let start = usize::try_from(offset).ok()?;
        self.original_prefix.get(start..start.checked_add(len)?)
    }
}
