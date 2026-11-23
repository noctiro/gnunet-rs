//! Maps positions in the reconstructed ISO BMFF file to their byte source.

mod layout;

use std::ops::Range;

pub(in crate::extraction::formats) use layout::read;

pub(in crate::extraction::formats) struct Projection {
    extent: u64,
    replacements: Vec<Replacement>,
}

struct Replacement {
    logical: Range<u64>,
    physical_end: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::extraction::formats) enum Segment<'a> {
    Expanded(&'a [u8]),
    Original { offset: u64, available: u64 },
}

impl Projection {
    pub(in crate::extraction::formats) const fn extent(&self) -> u64 {
        self.extent
    }

    pub(in crate::extraction::formats) fn unchanged_prefix_len(&self) -> u64 {
        self.replacements
            .first()
            .map_or(self.extent, |first| first.logical.start)
    }

    /// Returns the contiguous source bytes starting at a reconstructed offset.
    pub(in crate::extraction::formats) fn source(&self, at: u64) -> Option<Segment<'_>> {
        if at >= self.extent {
            return None;
        }
        // An empty replacement removes a physical box. Its boundary still
        // advances the physical offset for subsequent unchanged bytes.
        let index = self
            .replacements
            .partition_point(|entry| entry.logical.end <= at);
        let next = self.replacements.get(index);
        if let Some(entry) = next.filter(|entry| entry.logical.start <= at) {
            let offset = usize::try_from(at - entry.logical.start).ok()?;
            return Some(Segment::Expanded(entry.bytes.get(offset..)?));
        }
        let (logical, physical) = index
            .checked_sub(1)
            .and_then(|previous| self.replacements.get(previous))
            .map_or((0, 0), |entry| (entry.logical.end, entry.physical_end));
        let boundary = next.map_or(self.extent, |entry| entry.logical.start);
        Some(Segment::Original {
            offset: physical.checked_add(at - logical)?,
            available: boundary - at,
        })
    }
}

struct Builder {
    physical_extent: u64,
    physical_end: u64,
    logical_end: u64,
    replacements: Vec<Replacement>,
}

impl Builder {
    const fn new(physical_extent: u64) -> Self {
        Self {
            physical_extent,
            physical_end: 0,
            logical_end: 0,
            replacements: Vec::new(),
        }
    }

    /// Adds a replacement for a disjoint physical range. Empty bytes remove it.
    fn replace(&mut self, physical: Range<u64>, bytes: Vec<u8>) -> Option<()> {
        if physical.start >= physical.end || physical.end > self.physical_extent {
            return None;
        }
        let unchanged = physical.start.checked_sub(self.physical_end)?;
        let start = self.logical_end.checked_add(unchanged)?;
        let end = start.checked_add(u64::try_from(bytes.len()).ok()?)?;
        self.replacements.try_reserve(1).ok()?;
        self.replacements.push(Replacement {
            logical: start..end,
            physical_end: physical.end,
            bytes,
        });
        self.physical_end = physical.end;
        self.logical_end = end;
        Some(())
    }

    fn finish(self) -> Option<Projection> {
        let tail = self.physical_extent.checked_sub(self.physical_end)?;
        Some(Projection {
            extent: self.logical_end.checked_add(tail)?,
            replacements: self.replacements,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Builder, Segment};

    #[test]
    fn maps_offsets_across_shrinking_expanding_and_removed_boxes() -> Result<(), &'static str> {
        let mut builder = Builder::new(40);
        builder.replace(4..9, b"ab".to_vec()).ok_or("shrink")?;
        builder.replace(9..11, Vec::new()).ok_or("delete")?;
        builder.replace(14..15, b"wxyz".to_vec()).ok_or("grow")?;
        let source = builder.finish().ok_or("valid projection")?;

        if source.extent() != 38 || source.unchanged_prefix_len() != 4 {
            return Err("wrong projected file bounds");
        }
        let expected = [
            (
                0,
                Some(Segment::Original {
                    offset: 0,
                    available: 4,
                }),
            ),
            (5, Some(Segment::Expanded(b"b"))),
            (
                6,
                Some(Segment::Original {
                    offset: 11,
                    available: 3,
                }),
            ),
            (9, Some(Segment::Expanded(b"wxyz"))),
            (
                13,
                Some(Segment::Original {
                    offset: 15,
                    available: 25,
                }),
            ),
            (38, None),
        ];
        for (at, segment) in expected {
            if source.source(at) != segment {
                return Err("wrong source at reconstructed position");
            }
        }
        Ok(())
    }

    #[test]
    fn rejects_overlap_and_an_unrepresentable_expanded_extent() {
        let mut builder = Builder::new(u64::MAX);
        assert_eq!(builder.replace(0..1, b"ab".to_vec()), Some(()));
        assert_eq!(builder.replace(0..1, Vec::new()), None);
        assert!(builder.finish().is_none());
    }
}
