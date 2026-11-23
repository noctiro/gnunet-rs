//! Photoshop image resource blocks within JPEG and TIFF metadata.

use std::ops::Range;

use super::{Input, iptc};

pub(super) const IPTC_IIM: u16 = 0x0404;
pub(super) const XMP: u16 = 0x0424;
pub(super) const APP13_PREFIX: &[u8; 14] = b"Photoshop 3.0\0";
const MAX_FRAGMENTS: usize = 256;

pub(super) fn resource<E>(
    extent: usize,
    id: u16,
    read: impl FnMut(usize, &mut [u8]) -> Result<bool, E>,
) -> Result<Option<Range<usize>>, E> {
    Ok(resources(extent, [id], read)?.and_then(|[range]| range))
}

pub(super) fn resources<E, const N: usize>(
    extent: usize,
    ids: [u16; N],
    read: impl FnMut(usize, &mut [u8]) -> Result<bool, E>,
) -> Result<Option<[Option<Range<usize>>; N]>, E> {
    let mut found = [const { None }; N];
    let complete = scan(extent, read, |id, range| {
        if let Some(index) = ids.iter().position(|&wanted| wanted == id) {
            found[index].get_or_insert(range);
        }
        true
    })?;
    Ok(complete.then_some(found))
}

fn scan<E>(
    extent: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> Result<bool, E>,
    mut retain: impl FnMut(u16, Range<usize>) -> bool,
) -> Result<bool, E> {
    let mut offset = 0_usize;
    while offset < extent {
        let mut head = [0; 7];
        if extent - offset < 12 || !read(offset, &mut head)? {
            return Ok(false);
        }
        if !matches!(&head[..4], b"8BIM" | b"AgHg" | b"DCSR" | b"PHUT") {
            return Ok(false);
        }
        let kind = u16::from_be_bytes([head[4], head[5]]);
        let name_length = (1 + usize::from(head[6])).next_multiple_of(2);
        let Some(data_at) = offset
            .checked_add(10 + name_length)
            .filter(|&at| at <= extent)
        else {
            return Ok(false);
        };
        let mut length = [0; 4];
        if !read(data_at - 4, &mut length)? {
            return Ok(false);
        }
        let Ok(length) = usize::try_from(u32::from_be_bytes(length)) else {
            return Ok(false);
        };
        let Some(end) = data_at.checked_add(length).filter(|&end| end <= extent) else {
            return Ok(false);
        };
        if length > 0 && !retain(kind, data_at..end) {
            return Ok(false);
        }
        // Some writers omit the last data pad. Internal records always occupy even lengths.
        offset = if end == extent {
            end
        } else {
            end + (length & 1)
        };
    }
    Ok(true)
}

pub(super) fn visit_iptc<E>(
    bytes: &[u8],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let bytes = bytes.strip_prefix(APP13_PREFIX).unwrap_or(bytes);
    let read = |offset: usize, target: &mut [u8]| {
        let Some(part) = bytes
            .get(offset..)
            .and_then(|rest| rest.get(..target.len()))
        else {
            return Ok(false);
        };
        target.copy_from_slice(part);
        Ok(true)
    };
    let Some(payload) = IptcResources::locate(bytes.len(), bytes.len(), read)? else {
        return Ok(false);
    };
    if let [range] = payload.ranges.as_slice() {
        return emit_profile(&bytes[range.clone()], limit, emit);
    }
    let Some(joined) = payload.join(bytes.len(), read)? else {
        return Ok(false);
    };
    emit_profile(&joined, limit, emit)
}

fn emit_profile<E>(
    data: &[u8],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let Some(profile) = iptc::Profile::parse(data, 0) else {
        return Ok(false);
    };
    profile.emit(limit, emit)?;
    Ok(true)
}

struct IptcResources {
    ranges: Vec<Range<usize>>,
    length: usize,
}

impl IptcResources {
    fn locate<E>(
        extent: usize,
        byte_limit: usize,
        read: impl FnMut(usize, &mut [u8]) -> Result<bool, E>,
    ) -> Result<Option<Self>, E> {
        let mut ranges = Vec::new();
        let mut length = 0_usize;
        let complete = scan(extent, read, |id, range| {
            if id != IPTC_IIM {
                return true;
            }
            let Some(total) = length
                .checked_add(range.len())
                .filter(|&total| total <= byte_limit)
            else {
                return false;
            };
            if ranges.try_reserve(1).is_err() {
                return false;
            }
            length = total;
            ranges.push(range);
            true
        })?;
        Ok((complete && !ranges.is_empty()).then_some(Self { ranges, length }))
    }

    fn join<E>(
        self,
        byte_limit: usize,
        mut read: impl FnMut(usize, &mut [u8]) -> Result<bool, E>,
    ) -> Result<Option<Vec<u8>>, E> {
        if self.length > byte_limit {
            return Ok(None);
        }
        let mut data = Vec::new();
        if data.try_reserve_exact(self.length).is_err() {
            return Ok(None);
        }
        data.resize(self.length, 0);
        let mut tail = data.as_mut_slice();
        for range in self.ranges {
            let (part, rest) = tail.split_at_mut(range.len());
            if !read(range.start, part)? {
                return Ok(None);
            }
            tail = rest;
        }
        Ok(Some(data))
    }
}

struct Fragment {
    logical: usize,
    source: u64,
    len: usize,
}

#[derive(Default)]
pub(super) struct Fragments {
    parts: Vec<Fragment>,
    extent: usize,
}

impl Fragments {
    pub(super) fn push(&mut self, source: u64, len: usize) -> Option<()> {
        if len == 0 {
            return Some(());
        }
        if self.parts.len() == MAX_FRAGMENTS {
            return None;
        }
        let end = self.extent.checked_add(len)?;
        source.checked_add(len as u64)?;
        self.parts.try_reserve(1).ok()?;
        self.parts.push(Fragment {
            logical: self.extent,
            source,
            len,
        });
        self.extent = end;
        Some(())
    }

    pub(super) fn visit_iptc<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.parts.is_empty() {
            return Ok(());
        }
        let byte_limit = input.prefix.len().saturating_add(input.unread_bytes());
        let Some(payload) = IptcResources::locate(self.extent, byte_limit, |offset, bytes| {
            self.read(input, offset, bytes)
        })?
        else {
            return Ok(());
        };
        if let [range] = payload.ranges.as_slice()
            && let Some(fragment) = self.part_at(range.start)
            && range.end <= fragment.logical + fragment.len
        {
            let offset = fragment.source + (range.start - fragment.logical) as u64;
            if let Some(bytes) = input.range(offset, payload.length)? {
                emit_profile(bytes, limit, emit)?;
            }
            return Ok(());
        }
        let remaining = input.prefix.len().saturating_add(input.unread_bytes());
        if let Some(data) =
            payload.join(remaining, |offset, bytes| self.read(input, offset, bytes))?
        {
            emit_profile(&data, limit, emit)?;
        }
        Ok(())
    }

    fn part_at(&self, offset: usize) -> Option<&Fragment> {
        if offset >= self.extent {
            return None;
        }
        let next = self.parts.partition_point(|part| part.logical <= offset);
        self.parts.get(next.checked_sub(1)?)
    }

    fn read<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        mut offset: usize,
        mut target: &mut [u8],
    ) -> Result<bool, E> {
        while !target.is_empty() {
            let Some(part) = self.part_at(offset) else {
                return Ok(false);
            };
            let inside = offset - part.logical;
            let count = target.len().min(part.len - inside);
            let Some(bytes) = input.range(part.source + inside as u64, count)? else {
                return Ok(false);
            };
            let (front, rest) = target.split_at_mut(count);
            front.copy_from_slice(bytes);
            offset += count;
            target = rest;
        }
        Ok(true)
    }
}
