//! HEIF metadata item descriptors and local extent resolution.

mod locations;

use std::{num::NonZeroU32, ops::Range};

use gnunet_fs_codec::DeflateFormat;

use super::super::compression::{ContentCoding, Encoding};
use super::{BoxSpan, Input, read_body};

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ItemId(NonZeroU32);

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Exif,
    Xmp(Option<Encoding>),
}

pub(super) enum Scope<'a> {
    Describing {
        item: ItemId,
        references: &'a BoxSpan,
    },
    Track(Option<&'a BoxSpan>),
    Selected {
        ids: &'a [NonZeroU32],
        references: Option<&'a BoxSpan>,
    },
}

pub(super) struct Catalog<'a> {
    roots: Roots<'a>,
    references: Vec<References>,
    entries: Vec<Information>,
}

enum Roots<'a> {
    Descriptions(Vec<ItemId>),
    Track,
    Selected(&'a [NonZeroU32]),
}

struct References {
    from: ItemId,
    targets: Vec<ItemId>,
}

struct Information {
    id: ItemId,
    protected: bool,
    kind: Option<Kind>,
}

impl<'a> Catalog<'a> {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        scope: Scope<'a>,
    ) -> Result<Option<Self>, E> {
        let (item, references, roots) = match scope {
            Scope::Describing { item, references } => (Some(item), Some(references), Roots::Track),
            Scope::Track(references) => (None, references, Roots::Track),
            Scope::Selected { ids, references } => (None, references, Roots::Selected(ids)),
        };
        let Some(references) = references else {
            return Ok(Some(Self {
                roots,
                references: Vec::new(),
                entries: Vec::new(),
            }));
        };
        if references.len() < 4 {
            return Ok(None);
        }
        let width = match input.range(references.data, 4)? {
            Some([0, 0, 0, 0]) => 2,
            Some([1, 0, 0, 0]) => 4,
            _ => return Ok(None),
        };
        let mut described = Vec::new();
        let mut references_by_item = Vec::new();
        let mut offset = references.data + 4;
        while offset < references.end {
            let Some(reference) = BoxSpan::read(input, offset, references.end)? else {
                return Ok(None);
            };
            offset = reference.end;
            if reference.kind != *b"iloc" && !(item.is_some() && reference.kind == *b"cdsc") {
                continue;
            }
            let Some(bytes) = read_body(input, &reference)? else {
                return Ok(None);
            };
            let Some((from, count, mut ids)) = reference_header(bytes, width) else {
                return Ok(None);
            };
            if let Some(item) = item.filter(|_| reference.kind == *b"cdsc") {
                let mut linked = false;
                for _ in 0..count {
                    let Some(to) = ids.item_id(width) else {
                        return Ok(None);
                    };
                    linked |= to == item;
                }
                if linked && from != item {
                    if described.try_reserve(1).is_err() {
                        return Ok(None);
                    }
                    described.push(from);
                }
            } else {
                let mut targets = Vec::new();
                if targets.try_reserve_exact(count).is_err()
                    || references_by_item.try_reserve(1).is_err()
                {
                    return Ok(None);
                }
                for _ in 0..count {
                    let Some(to) = ids.item_id(width) else {
                        return Ok(None);
                    };
                    targets.push(to);
                }
                references_by_item.push(References { from, targets });
            }
        }
        described.sort_unstable();
        described.dedup();
        references_by_item.sort_unstable_by_key(|reference| reference.from);
        if references_by_item
            .windows(2)
            .any(|pair| pair[0].from == pair[1].from)
        {
            return Ok(None);
        }
        let roots = match item {
            Some(_) if described.is_empty() => return Ok(None),
            Some(_) => Roots::Descriptions(described),
            None => roots,
        };
        Ok(Some(Self {
            roots,
            references: references_by_item,
            entries: Vec::new(),
        }))
    }

    fn selects(&self, id: ItemId) -> bool {
        match &self.roots {
            Roots::Descriptions(ids) => ids.binary_search(&id).is_ok(),
            Roots::Track => true,
            Roots::Selected(ids) => ids.binary_search(&id.0).is_ok(),
        }
    }

    pub(super) fn classify<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        info: &BoxSpan,
    ) -> Result<bool, E> {
        if info.len() < 6 {
            return Ok(false);
        }
        let width = match input.range(info.data, 4)? {
            Some([0, 0, 0, 0]) => 2,
            Some([1, 0, 0, 0]) if info.len() >= 8 => 4,
            _ => return Ok(false),
        };
        let count_at = info.data + 4;
        let Some(count) = input
            .range(count_at, width)?
            .and_then(|bytes| Reader::new(bytes).integer(width))
        else {
            return Ok(false);
        };
        let mut offset = count_at + width as u64;
        if count > (info.end - offset) / 8 {
            return Ok(false);
        }
        for _ in 0..count {
            let Some(span) = BoxSpan::read(input, offset, info.end)? else {
                return Ok(false);
            };
            offset = span.end;
            if span.kind != *b"infe" {
                return Ok(false);
            }
            let Some(bytes) = read_body(input, &span)? else {
                return Ok(false);
            };
            if let Some(entry) = item_info(bytes) {
                if self.entries.try_reserve(1).is_err() {
                    return Ok(false);
                }
                self.entries.push(entry);
            }
        }
        self.entries.sort_unstable_by_key(|entry| entry.id);
        Ok(offset == info.end && !self.entries.windows(2).any(|pair| pair[0].id == pair[1].id))
    }

    pub(super) fn resolve(
        self,
        bytes: &[u8],
        file_extent: u64,
        item_data: Option<&BoxSpan>,
        payload_budget: usize,
    ) -> Option<Vec<Item>> {
        locations::resolve(&self, bytes, file_extent, item_data, payload_budget)
    }

    fn information(&self, id: ItemId) -> Option<&Information> {
        let index = self
            .entries
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()?;
        self.entries.get(index)
    }

    fn target(&self, from: ItemId, index: u64) -> Option<ItemId> {
        let at = self
            .references
            .binary_search_by_key(&from, |reference| reference.from)
            .ok()?;
        let target = usize::try_from(index.checked_sub(1)?).ok()?;
        self.references.get(at)?.targets.get(target).copied()
    }
}

fn reference_header(bytes: &[u8], width: usize) -> Option<(ItemId, usize, Reader<'_>)> {
    let mut reader = Reader::new(bytes);
    let from = reader.item_id(width)?;
    let count = reader.integer(2)? as usize;
    (reader.0.len() == count * width).then_some((from, count, reader))
}

fn item_info(bytes: &[u8]) -> Option<Information> {
    let mut reader = Reader::new(bytes);
    let &[version, 0, 0, 0 | 1] = reader.take(4)? else {
        return None;
    };
    let width = match version {
        2 => 2,
        3 => 4,
        _ => return None,
    };
    let id = reader.item_id(width)?;
    let protected = reader.integer(2)? != 0;
    let item_type = reader.take(4)?;
    let _name = reader.string()?;
    let kind = match (protected, item_type) {
        (false, b"Exif") => Some(Kind::Exif),
        (false, b"mime") if reader.string()? == b"application/rdf+xml" => {
            let token = if reader.is_empty() {
                Some(reader.0)
            } else {
                reader.0.strip_suffix(&[0])
            };
            // Existing libheif items can use raw DEFLATE under its HTTP name.
            token
                .and_then(|token| ContentCoding::parse(token, DeflateFormat::Raw))
                .map(|coding| Kind::Xmp(coding.encoding()))
        }
        _ => None,
    };
    Some(Information {
        id,
        protected,
        kind,
    })
}

#[derive(Clone, Copy)]
struct Widths {
    offset: usize,
    length: usize,
    base: usize,
    index: usize,
}

impl Widths {
    fn read(reader: &mut Reader<'_>, version: u8) -> Option<Self> {
        let &[a, b] = reader.take(2)? else {
            return None;
        };
        let sizes = [a >> 4, a & 15, b >> 4, b & 15];
        if !sizes.iter().all(|size| matches!(size, 0 | 4 | 8)) || (version == 0 && sizes[3] != 0) {
            return None;
        }
        let [offset, length, base, index] = sizes.map(usize::from);
        Some(Self {
            offset,
            length,
            base,
            index,
        })
    }

    fn extent_size(self) -> usize {
        self.index + self.offset + self.length
    }
}

pub(super) struct Item {
    pub(super) kind: Kind,
    pub(super) payload: Payload,
}

pub(super) struct Payload {
    first: Range<u64>,
    continuation: Vec<Range<u64>>,
    length: usize,
}

impl Payload {
    pub(super) fn read<'a, E>(
        &self,
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        buffer: &'a mut Vec<u8>,
    ) -> Result<Option<&'a [u8]>, E> {
        if self.continuation.is_empty() {
            return input.range(self.first.start, self.length);
        }
        buffer.clear();
        let prefix = input.prefix.len() as u64;
        let ranges = std::iter::once(&self.first).chain(&self.continuation);
        let cost = ranges
            .clone()
            .filter(|range| range.end > prefix)
            .try_fold(0usize, |total, range| {
                total.checked_add(usize::try_from(range.end - range.start).ok()?)
            });
        if cost.is_none_or(|size| size > input.unread_bytes())
            || buffer.try_reserve_exact(self.length).is_err()
        {
            return Ok(None);
        }
        for range in ranges {
            let Some(bytes) = input.range(range.start, (range.end - range.start) as usize)? else {
                return Ok(None);
            };
            buffer.extend_from_slice(bytes);
        }
        Ok(Some(buffer))
    }
}

pub(super) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (bytes, tail) = self.0.split_at_checked(length)?;
        self.0 = tail;
        Some(bytes)
    }

    pub(super) fn integer(&mut self, width: usize) -> Option<u64> {
        Some(
            self.take(width)?
                .iter()
                .fold(0, |value, byte| (value << 8) | u64::from(*byte)),
        )
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn version(&mut self) -> Option<u8> {
        let &[version, 0, 0, 0] = self.take(4)? else {
            return None;
        };
        Some(version)
    }

    pub(super) fn item_id(&mut self, width: usize) -> Option<ItemId> {
        NonZeroU32::new(u32::try_from(self.integer(width)?).ok()?).map(ItemId)
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let end = self.0.iter().position(|&byte| byte == 0)?;
        self.take(end + 1)?.get(..end)
    }
}
