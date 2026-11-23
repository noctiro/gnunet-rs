//! HEIF sample-to-metadata-item association tables and their fragment scope.

mod compact;

use super::{BoxSpan, Input};
use compact::CompactMapping;
use std::num::NonZeroU32;

const FRAGMENT_INDEX: u32 = 0x1_0000;
const STATIC_DESCRIPTIONS: u8 = 1;
const STATIC_MAPPING: u8 = 2;

pub(super) fn is_group_box(kind: &[u8; 4]) -> bool {
    matches!(kind, b"sgpd" | b"sbgp" | b"csgp")
}

pub(super) fn is_metadata_group<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<bool>, E> {
    if span.len() < 8 {
        return Ok(None);
    }
    Ok(input.range(span.data + 4, 4)?.map(|kind| kind == b"stmi"))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Level {
    Track,
    Fragment,
}

pub(super) struct Groups {
    level: Level,
    descriptions: Option<Descriptions>,
    mapping: Option<Mapping>,
}

pub(super) enum Selection<'a> {
    Unspecified,
    Unmapped,
    Items(&'a Group),
}

pub(super) struct Group {
    pub(super) handler: [u8; 4],
    pub(super) items: Vec<NonZeroU32>,
}

impl Group {
    pub(super) fn copy_selected(&self) -> Option<Self> {
        let mut items = Vec::new();
        items.try_reserve_exact(self.items.len()).ok()?;
        items.extend_from_slice(&self.items);
        items.sort_unstable();
        items.dedup();
        Some(Self {
            handler: self.handler,
            items,
        })
    }
}

struct Descriptions {
    flags: u8,
    default_index: u32,
    entries: Vec<Group>,
}

enum Mapping {
    Classic(ClassicMapping),
    Compact(CompactMapping),
}

struct ClassicMapping {
    runs: Vec<Run>,
    samples: u64,
}

#[derive(Clone, Copy)]
enum GroupIndex {
    Unmapped,
    Track(NonZeroU32),
    Fragment(NonZeroU32),
}

enum MappingIndex {
    Uncovered,
    Explicit(GroupIndex),
}

impl GroupIndex {
    fn numbered(level: Level, index: u32) -> Option<Self> {
        if index == 0 {
            return Some(Self::Unmapped);
        }
        match (level, index) {
            (Level::Track, _) | (Level::Fragment, 1..=0xffff) => {
                NonZeroU32::new(index).map(Self::Track)
            }
            (Level::Fragment, 0x1_0001..=0x1_ffff) => {
                NonZeroU32::new(index - FRAGMENT_INDEX).map(Self::Fragment)
            }
            (Level::Fragment, _) => None,
        }
    }
}

struct Run {
    end: u64,
    index: u32,
}

impl Groups {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        container: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        let level = match &container.kind {
            b"stbl" => Level::Track,
            b"traf" => Level::Fragment,
            _ => return Ok(None),
        };
        let mut groups = Self {
            level,
            descriptions: None,
            mapping: None,
        };
        let mut at = container.data;
        while at < container.end {
            let Some(span) = BoxSpan::read(input, at, container.end)? else {
                return Ok(None);
            };
            at = span.end;
            if !is_group_box(&span.kind) {
                continue;
            }
            let Some(is_metadata) = is_metadata_group(input, &span)? else {
                return Ok(None);
            };
            if !is_metadata {
                continue;
            }
            let Ok(length) = usize::try_from(span.len()) else {
                return Ok(None);
            };
            let Some(body) = input.range(span.data, length)? else {
                return Ok(None);
            };
            if span.kind == *b"sgpd" {
                let Some(descriptions) = Descriptions::parse(body, level) else {
                    return Ok(None);
                };
                if groups.descriptions.replace(descriptions).is_some() {
                    return Ok(None);
                }
            } else {
                let mapping = if span.kind == *b"csgp" {
                    CompactMapping::parse(body, level).map(Mapping::Compact)
                } else {
                    ClassicMapping::parse(body).map(Mapping::Classic)
                };
                let Some(mapping) = mapping else {
                    return Ok(None);
                };
                if groups.mapping.replace(mapping).is_some() {
                    return Ok(None);
                }
            }
        }
        if groups.flags() & STATIC_MAPPING != 0 && groups.mapping.is_some() {
            return Ok(None);
        }
        Ok(Some(groups))
    }

    pub(super) fn select<'a>(
        &'a self,
        ordinal: u64,
        sample_count: u64,
        init: Option<&'a Self>,
    ) -> Option<Selection<'a>> {
        if ordinal >= sample_count
            || self
                .mapping
                .as_ref()
                .is_some_and(|mapping| !mapping.covers(self.level, sample_count))
        {
            return None;
        }
        match (self.level, init) {
            (Level::Track, None) => {}
            (Level::Fragment, Some(init)) if init.level == Level::Track => {
                let flags = init.flags();
                if flags & STATIC_DESCRIPTIONS != 0 && self.descriptions.is_some()
                    || flags & STATIC_MAPPING != 0 && self.mapping.is_some()
                {
                    return None;
                }
            }
            _ => return None,
        }
        if !self.present() && init.is_none_or(|groups| !groups.present()) {
            return Some(Selection::Unspecified);
        }
        let descriptions = self
            .descriptions
            .as_ref()
            .or_else(|| init.and_then(|groups| groups.descriptions.as_ref()));
        let index = match &self.mapping {
            Some(mapping) => mapping.index(self.level, ordinal)?,
            None => MappingIndex::Uncovered,
        };
        let index = match index {
            MappingIndex::Uncovered => GroupIndex::numbered(
                self.level,
                descriptions.map_or(0, |descriptions| descriptions.default_index),
            )?,
            MappingIndex::Explicit(index) => index,
        };
        let group = match index {
            GroupIndex::Unmapped => return Some(Selection::Unmapped),
            GroupIndex::Track(index) => init.unwrap_or(self).description(index)?,
            GroupIndex::Fragment(index) => self.description(index)?,
        };
        Some(Selection::Items(group))
    }

    fn description(&self, index: NonZeroU32) -> Option<&Group> {
        self.descriptions
            .as_ref()?
            .entries
            .get(usize::try_from(index.get() - 1).ok()?)
    }

    fn present(&self) -> bool {
        self.descriptions.is_some() || self.mapping.is_some()
    }

    fn flags(&self) -> u8 {
        self.descriptions
            .as_ref()
            .map_or(0, |descriptions| descriptions.flags)
    }
}

enum EntryLength {
    Implicit,
    PerEntry,
    Fixed(usize),
}

impl Descriptions {
    fn parse(body: &[u8], level: Level) -> Option<Self> {
        let (&[version @ 0..=3, 0, 0, flags, b's', b't', b'm', b'i'], mut bytes) =
            body.split_first_chunk()?
        else {
            return None;
        };
        let allowed_flags = match level {
            Level::Track => STATIC_DESCRIPTIONS | STATIC_MAPPING,
            Level::Fragment => 0,
        };
        if flags & !allowed_flags != 0 {
            return None;
        }
        let length = match version {
            0 => EntryLength::Implicit,
            _ => match word(&mut bytes)? {
                0 => EntryLength::PerEntry,
                fixed_length @ 8.. => EntryLength::Fixed(usize::try_from(fixed_length).ok()?),
                _ => return None,
            },
        };
        let default_index = if version >= 2 { word(&mut bytes)? } else { 0 };
        let count = usize::try_from(word(&mut bytes)?).ok()?;
        let minimum = match length {
            EntryLength::Implicit => 8,
            EntryLength::PerEntry => 12,
            EntryLength::Fixed(length) => length,
        };
        if count > bytes.len() / minimum {
            return None;
        }
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).ok()?;
        for _ in 0..count {
            let group = match length {
                EntryLength::Implicit => Group::parse(&mut bytes)?,
                EntryLength::PerEntry => {
                    let length = usize::try_from(word(&mut bytes)?).ok()?;
                    Group::parse_sized(&mut bytes, length)?
                }
                EntryLength::Fixed(length) => Group::parse_sized(&mut bytes, length)?,
            };
            entries.push(group);
        }
        if !bytes.is_empty() {
            return None;
        }
        Some(Self {
            flags,
            default_index,
            entries,
        })
    }
}

impl Group {
    fn parse(bytes: &mut &[u8]) -> Option<Self> {
        let (handler, tail) = bytes.split_first_chunk()?;
        *bytes = tail;
        let count = usize::try_from(word(bytes)?).ok()?;
        let (ids, tail) = bytes.split_at_checked(count.checked_mul(4)?)?;
        let mut items = Vec::new();
        items.try_reserve_exact(count).ok()?;
        for id in ids.as_chunks::<4>().0 {
            items.push(NonZeroU32::new(u32::from_be_bytes(*id))?);
        }
        *bytes = tail;
        Some(Self {
            handler: *handler,
            items,
        })
    }

    fn parse_sized(bytes: &mut &[u8], length: usize) -> Option<Self> {
        let (mut entry, tail) = bytes.split_at_checked(length)?;
        let group = Self::parse(&mut entry)?;
        if !entry.is_empty() {
            return None;
        }
        *bytes = tail;
        Some(group)
    }
}

impl Mapping {
    fn covers(&self, level: Level, sample_count: u64) -> bool {
        match self {
            Self::Classic(mapping) if level == Level::Fragment => mapping.samples == sample_count,
            Self::Classic(mapping) => mapping.samples <= sample_count,
            Self::Compact(mapping) => mapping.samples() <= sample_count,
        }
    }

    fn index(&self, level: Level, ordinal: u64) -> Option<MappingIndex> {
        match self {
            Self::Classic(mapping) => match mapping.index(ordinal) {
                Some(index) => GroupIndex::numbered(level, index).map(MappingIndex::Explicit),
                None => Some(MappingIndex::Uncovered),
            },
            Self::Compact(mapping) => mapping.index(level, ordinal),
        }
    }
}

impl ClassicMapping {
    fn parse(body: &[u8]) -> Option<Self> {
        let (&[version @ 0..=1, 0, 0, 0, b's', b't', b'm', b'i'], mut bytes) =
            body.split_first_chunk()?
        else {
            return None;
        };
        if version == 1 {
            // stmi does not define subtypes. Its single mapping uses this table directly.
            word(&mut bytes)?;
        }
        let count = usize::try_from(word(&mut bytes)?).ok()?;
        if count.checked_mul(8)? != bytes.len() {
            return None;
        }
        let mut runs = Vec::new();
        runs.try_reserve_exact(count).ok()?;
        let mut samples = 0_u64;
        for _ in 0..count {
            let count = u64::from(word(&mut bytes)?);
            let index = word(&mut bytes)?;
            if count != 0 {
                samples = samples.checked_add(count)?;
                runs.push(Run {
                    end: samples,
                    index,
                });
            }
        }
        Some(Self { runs, samples })
    }

    fn index(&self, ordinal: u64) -> Option<u32> {
        self.runs
            .get(self.runs.partition_point(|run| run.end <= ordinal))
            .map(|run| run.index)
    }
}

fn word(bytes: &mut &[u8]) -> Option<u32> {
    let (word, tail) = bytes.split_first_chunk()?;
    *bytes = tail;
    Some(u32::from_be_bytes(*word))
}

#[cfg(test)]
mod tests;
