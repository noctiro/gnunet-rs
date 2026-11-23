//! Resolves item-relative extents into positioned reads of the original file.

use std::{cell::Cell, ops::Range};

use super::{BoxSpan, Catalog, Item, ItemId, Payload, Reader, Widths};

// Acyclic input can still be nested or repeatedly slice the same items.
const MAX_ITEM_DEPTH: usize = 64;

pub(super) fn resolve(
    catalog: &Catalog<'_>,
    bytes: &[u8],
    file_extent: u64,
    item_data: Option<&BoxSpan>,
    mut payload_budget: usize,
) -> Option<Vec<Item>> {
    let (widths, locations) = read_locations(bytes, file_extent, item_data)?;
    let graph = Locations {
        catalog,
        widths,
        locations,
        work: Cell::new(bytes.len().saturating_mul(8)),
    };
    let mut roots = Vec::new();
    for location in &graph.locations {
        if !catalog.selects(location.id) {
            continue;
        }
        let Some(kind) = catalog
            .information(location.id)
            .and_then(|entry| entry.kind)
        else {
            continue;
        };
        roots.try_reserve(1).ok()?;
        roots.push((location, kind));
    }
    // Keep the order of the item location records for publication and budget admission.
    roots.sort_unstable_by_key(|(location, _)| location.order);
    let mut range_budget = payload_budget.div_ceil(std::mem::size_of::<Range<u64>>());
    let mut items = Vec::new();
    for (location, kind) in roots {
        let Some(length) = graph
            .length(location, 0)
            .and_then(|length| usize::try_from(length).ok())
            .filter(|&length| (1..=payload_budget).contains(&length))
        else {
            continue;
        };
        let mut plan = Plan {
            range_budget,
            payload: None,
        };
        if graph
            .project(location, 0..length as u64, 0, &mut plan)
            .is_none()
        {
            continue;
        }
        if let Some(payload) = plan.payload {
            payload_budget -= length;
            range_budget = plan.range_budget;
            items.try_reserve(1).ok()?;
            items.push(Item { kind, payload });
        }
    }
    Some(items)
}

#[derive(Clone, Copy)]
enum Source {
    Local { origin: u64, length: u64 },
    Item,
    Unsupported,
}

#[derive(Clone, Copy)]
enum Length {
    Unseen,
    Visiting,
    Measured(u64),
}

struct Location<'a> {
    id: ItemId,
    order: u64,
    base: u64,
    source: Source,
    rows: &'a [u8],
    count: usize,
    length: Cell<Length>,
}

fn read_locations<'a>(
    bytes: &'a [u8],
    file_extent: u64,
    item_data: Option<&BoxSpan>,
) -> Option<(Widths, Vec<Location<'a>>)> {
    let mut reader = Reader::new(bytes);
    let version = reader.version()?;
    if version > 2 {
        return None;
    }
    let widths = Widths::read(&mut reader, version)?;
    let id_width = if version == 2 { 4 } else { 2 };
    let count = reader.integer(id_width)?;
    let mut locations = Vec::new();
    for order in 0..count {
        let id = reader.item_id(id_width)?;
        let method = if version == 0 { 0 } else { reader.integer(2)? };
        let reference = reader.integer(2)?;
        let base = reader.integer(widths.base)?;
        let count = usize::try_from(reader.integer(2)?).ok()?;
        let rows = reader.take(widths.extent_size() * count)?;
        let source = match (method, reference, item_data) {
            (0, 0, _) => Source::Local {
                origin: 0,
                length: file_extent,
            },
            (1, _, Some(data)) => Source::Local {
                origin: data.data,
                length: data.len(),
            },
            (2, _, _) => Source::Item,
            _ => Source::Unsupported,
        };
        locations.try_reserve(1).ok()?;
        locations.push(Location {
            id,
            order,
            base,
            source,
            rows,
            count,
            length: Cell::new(Length::Unseen),
        });
    }
    locations.sort_unstable_by_key(|location| location.id);
    if !reader.is_empty() || locations.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return None;
    }
    Some((widths, locations))
}

struct Locations<'a, 'c> {
    catalog: &'c Catalog<'c>,
    widths: Widths,
    locations: Vec<Location<'a>>,
    work: Cell<usize>,
}

enum Extent<'a, 'b> {
    File(Range<u64>),
    Item(&'b Location<'a>, Range<u64>),
}

impl Extent<'_, '_> {
    fn span(&self) -> &Range<u64> {
        match self {
            Self::File(range) | Self::Item(_, range) => range,
        }
    }
}

impl<'a> Locations<'a, '_> {
    fn by_id(&self, id: ItemId) -> Option<&Location<'a>> {
        let index = self
            .locations
            .binary_search_by_key(&id, |location| location.id)
            .ok()?;
        self.locations.get(index)
    }

    fn spend(&self) -> Option<()> {
        self.work.set(self.work.get().checked_sub(1)?);
        Some(())
    }

    fn length(&self, location: &Location<'a>, depth: usize) -> Option<u64> {
        if depth >= MAX_ITEM_DEPTH {
            return None;
        }
        match location.length.get() {
            Length::Measured(length) => return Some(length),
            Length::Visiting => return None,
            Length::Unseen => {}
        }
        if location.count == 0 || self.catalog.information(location.id)?.protected {
            return None;
        }

        location.length.set(Length::Visiting);
        let mut reader = Reader::new(location.rows);
        let length = (0..location.count).try_fold(0u64, |length, _| {
            let extent = self.extent(location, &mut reader, depth)?;
            length.checked_add(extent.span().end - extent.span().start)
        });
        location
            .length
            .set(length.map_or(Length::Unseen, Length::Measured));
        length
    }

    fn extent<'b>(
        &'b self,
        location: &Location<'a>,
        reader: &mut Reader<'_>,
        depth: usize,
    ) -> Option<Extent<'a, 'b>> {
        self.spend()?;
        let index = if self.widths.index == 0 {
            1
        } else {
            reader.integer(self.widths.index)?
        };
        let start = location
            .base
            .checked_add(reader.integer(self.widths.offset)?)?;
        let length = reader.integer(self.widths.length)?;
        match location.source {
            Source::Local {
                origin,
                length: source_length,
            } => {
                let span = bounded_slice(start, length, location.count, source_length)?;
                Some(Extent::File(
                    origin.checked_add(span.start)?..origin.checked_add(span.end)?,
                ))
            }
            Source::Item => {
                let source = self.by_id(self.catalog.target(location.id, index)?)?;
                let source_length = self.length(source, depth + 1)?;
                let span = bounded_slice(start, length, location.count, source_length)?;
                Some(Extent::Item(source, span))
            }
            Source::Unsupported => None,
        }
    }

    fn project(
        &self,
        location: &Location<'a>,
        wanted: Range<u64>,
        depth: usize,
        plan: &mut Plan,
    ) -> Option<()> {
        if depth >= MAX_ITEM_DEPTH {
            return None;
        }
        let mut reader = Reader::new(location.rows);
        let mut offset = 0;
        for _ in 0..location.count {
            let extent = self.extent(location, &mut reader, depth)?;
            let range = extent.span();
            let end = offset + (range.end - range.start);
            let left = wanted.start.max(offset);
            let right = wanted.end.min(end);
            if left < right {
                let selected = (range.start + (left - offset))..(range.start + (right - offset));
                match extent {
                    Extent::File(_) => plan.append(selected)?,
                    Extent::Item(item, _) => self.project(item, selected, depth + 1, plan)?,
                }
            }
            if end >= wanted.end {
                return Some(());
            }
            offset = end;
        }
        None
    }
}

fn bounded_slice(start: u64, length: u64, count: usize, source_length: u64) -> Option<Range<u64>> {
    let length = match length {
        0 if count == 1 => source_length,
        0 => return None,
        length => length,
    };
    let end = start.checked_add(length)?;
    (start < end && end <= source_length).then_some(start..end)
}

struct Plan {
    range_budget: usize,
    payload: Option<Payload>,
}

impl Plan {
    fn append(&mut self, span: Range<u64>) -> Option<()> {
        self.range_budget = self.range_budget.checked_sub(1)?;
        let length = usize::try_from(span.end - span.start).ok()?;
        if let Some(payload) = &mut self.payload {
            payload.length = payload.length.checked_add(length)?;
            payload.continuation.try_reserve(1).ok()?;
            payload.continuation.push(span);
        } else {
            self.payload = Some(Payload {
                first: span,
                continuation: Vec::new(),
                length,
            });
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::heif::items::{Information, Kind, References, Roots};
    use std::num::NonZeroU32;

    #[test]
    fn derived_locations_keep_reference_order_and_slice_fragmented_items()
    -> Result<(), &'static str> {
        let [Some(derived), Some(intermediate), Some(local), Some(inline)] =
            [1, 2, 3, 4].map(|id| NonZeroU32::new(id).map(ItemId))
        else {
            return Err("invalid fixture ID");
        };
        let mut iloc = vec![1, 0, 0, 0, 0x44, 0x44, 0, 4];
        record(&mut iloc, 1, 2, 1, &[(2, 1, 5), (1, 2, 2)]);
        record(&mut iloc, 2, 2, 0, &[(1, 0, 0)]);
        record(&mut iloc, 3, 0, 0, &[(0, 100, 14)]);
        record(&mut iloc, 4, 1, 2, &[(0, 3, 4), (0, 20, 8)]);
        let idat = BoxSpan {
            kind: *b"idat",
            data: 20,
            end: 80,
        };

        for (source, protect_source, matches) in [
            (inline, false, true),
            (inline, true, false),
            (derived, false, false),
        ] {
            let catalog = Catalog {
                roots: Roots::Descriptions(vec![derived]),
                references: vec![
                    References {
                        from: derived,
                        targets: vec![local, intermediate],
                    },
                    References {
                        from: intermediate,
                        targets: vec![source],
                    },
                ],
                entries: [derived, intermediate, local, inline]
                    .into_iter()
                    .map(|id| Information {
                        id,
                        protected: id == inline && protect_source,
                        kind: (id == derived).then_some(Kind::Exif),
                    })
                    .collect(),
            };
            let items = catalog
                .resolve(&iloc, 256, Some(&idat), 64)
                .ok_or("invalid iloc fixture")?;
            if matches {
                let [item] = items.as_slice() else {
                    return Err("expected the derived item");
                };
                if item.payload.first != (27..29)
                    || item.payload.continuation != [42..45, 103..105]
                    || item.payload.length != 7
                {
                    return Err("unexpected derived extents");
                }
            } else if !items.is_empty() {
                return Err("resolved an unavailable source");
            }
        }
        Ok(())
    }

    fn record(iloc: &mut Vec<u8>, item: u16, method: u16, base: u32, extents: &[(u32, u32, u32)]) {
        iloc.extend(item.to_be_bytes());
        iloc.extend(method.to_be_bytes());
        iloc.extend(0u16.to_be_bytes());
        iloc.extend(base.to_be_bytes());
        iloc.extend((extents.len() as u16).to_be_bytes());
        for &(index, offset, length) in extents {
            iloc.extend(index.to_be_bytes());
            iloc.extend(offset.to_be_bytes());
            iloc.extend(length.to_be_bytes());
        }
    }
}
