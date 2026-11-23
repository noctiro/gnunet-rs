//! Packed compact sample-to-group mappings.

use super::{GroupIndex, Level, MappingIndex, word};
use std::num::NonZeroU32;

pub(super) struct CompactMapping {
    layout: Layout,
    pattern_bytes: usize,
    // Retain the on-disk widths so repeated samples do not expand storage.
    packed: Vec<u8>,
    samples: u64,
}

impl CompactMapping {
    pub(super) fn parse(body: &[u8], level: Level) -> Option<Self> {
        let (&[0, 0, 0, flags, b's', b't', b'm', b'i'], mut bytes) = body.split_first_chunk()?
        else {
            return None;
        };
        let layout = Layout::parse(flags, level)?;
        if flags & 0x40 != 0 {
            // stmi has no grouping subtype.
            word(&mut bytes)?;
        }
        let count = usize::try_from(word(&mut bytes)?).ok()?;
        let pattern_bytes = count.checked_mul(layout.row_bytes())?;
        let (rows, indices) = bytes.split_at_checked(pattern_bytes)?;
        let mut samples = 0_u64;
        let mut index_count = 0_usize;
        for row in rows.chunks_exact(layout.row_bytes()) {
            let (length, count) = layout.pattern(row)?;
            if length == 0 || count < length {
                return None;
            }
            samples = samples.checked_add(u64::from(count))?;
            index_count = index_count.checked_add(usize::try_from(length).ok()?)?;
        }
        let index_bits = index_count.checked_mul(layout.index.bits())?;
        if indices.len() != index_bits.div_ceil(8)
            || (!index_bits.is_multiple_of(8)
                && indices.last().is_some_and(|byte| byte & 0x0f != 0))
        {
            return None;
        }
        let mut packed = Vec::new();
        packed.try_reserve_exact(bytes.len()).ok()?;
        packed.extend_from_slice(bytes);
        Some(Self {
            layout,
            pattern_bytes,
            packed,
            samples,
        })
    }

    pub(super) fn samples(&self) -> u64 {
        self.samples
    }

    pub(super) fn index(&self, level: Level, mut ordinal: u64) -> Option<MappingIndex> {
        if ordinal >= self.samples {
            return Some(MappingIndex::Uncovered);
        }
        let (rows, indices) = self.packed.split_at(self.pattern_bytes);
        let mut first_index = 0_usize;
        for row in rows.chunks_exact(self.layout.row_bytes()) {
            let (length, count) = self.layout.pattern(row)?;
            if ordinal < u64::from(count) {
                let offset = usize::try_from(ordinal % u64::from(length)).ok()?;
                let bits = (first_index + offset) * self.layout.index.bits();
                let index = self.layout.index.read(indices, bits)?;
                return self
                    .layout
                    .group_index(level, index)
                    .map(MappingIndex::Explicit);
            }
            ordinal -= u64::from(count);
            first_index += usize::try_from(length).ok()?;
        }
        None
    }
}

struct Layout {
    length: Width,
    count: Width,
    index: Width,
    fragment_bit: Option<u32>,
}

impl Layout {
    fn parse(flags: u8, level: Level) -> Option<Self> {
        let length = Width::decode(flags >> 4);
        let count = Width::decode(flags >> 2);
        let index = Width::decode(flags);
        let local = flags & 0x80 != 0;
        if !(length.bits() + count.bits()).is_multiple_of(8) || (local && level == Level::Track) {
            return None;
        }
        Some(Self {
            length,
            count,
            index,
            fragment_bit: local.then(|| 1 << (index.bits() - 1)),
        })
    }

    fn row_bytes(&self) -> usize {
        (self.length.bits() + self.count.bits()) / 8
    }

    fn pattern(&self, row: &[u8]) -> Option<(u32, u32)> {
        Some((
            self.length.read(row, 0)?,
            self.count.read(row, self.length.bits())?,
        ))
    }

    fn group_index(&self, level: Level, index: u32) -> Option<GroupIndex> {
        match self.fragment_bit {
            Some(bit) if index & bit != 0 => {
                NonZeroU32::new(index & !bit).map(GroupIndex::Fragment)
            }
            Some(_) => GroupIndex::numbered(Level::Track, index),
            None => GroupIndex::numbered(level, index),
        }
    }
}

#[derive(Clone, Copy)]
enum Width {
    Four,
    Eight,
    Sixteen,
    ThirtyTwo,
}

impl Width {
    fn decode(code: u8) -> Self {
        match code & 3 {
            0 => Self::Four,
            1 => Self::Eight,
            2 => Self::Sixteen,
            _ => Self::ThirtyTwo,
        }
    }

    fn bits(self) -> usize {
        match self {
            Self::Four => 4,
            Self::Eight => 8,
            Self::Sixteen => 16,
            Self::ThirtyTwo => 32,
        }
    }

    fn read(self, bytes: &[u8], bit: usize) -> Option<u32> {
        let bytes = bytes.get(bit / 8..)?;
        Some(match self {
            Self::Four => {
                let shift = if bit & 4 == 0 { 4 } else { 0 };
                u32::from((bytes.first()? >> shift) & 0x0f)
            }
            Self::Eight => u32::from(*bytes.first()?),
            Self::Sixteen => u32::from(u16::from_be_bytes(*bytes.first_chunk()?)),
            Self::ThirtyTwo => u32::from_be_bytes(*bytes.first_chunk()?),
        })
    }
}
