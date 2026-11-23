//! Reconstructs the top-level layout of an ISO compressed BMFF file.

use super::{Builder, Projection};
use crate::extraction::formats::{
    Input,
    boxes::{BoxSpan, EXTENDED_BOX_BYTES},
    compression::{Decompression, Encoding},
};
use std::{cmp::Reverse, ops::Range};

#[derive(Clone, Copy)]
struct PhysicalBox {
    start: u64,
    span: BoxSpan,
}

impl PhysicalBox {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        start: u64,
        end: u64,
    ) -> Result<Option<Self>, E> {
        Ok(BoxSpan::read(input, start, end)?.map(|span| Self { start, span }))
    }

    fn range(self) -> Range<u64> {
        self.start..self.span.end
    }

    fn brand<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<Brand>, E> {
        if self.span.len() < 8
            || !self.span.len().is_multiple_of(4)
            || !input
                .range(self.start, 4)?
                .is_some_and(|size| size != [0; 4])
        {
            return Ok(None);
        }
        let Some(bytes) = bytes_at(input, self.span.data..self.span.end)? else {
            return Ok(None);
        };
        let (words, _) = bytes.as_chunks::<4>();
        Ok(Some(if words[0] == *b"comp" {
            Brand::Compressed
        } else if words[2..].contains(b"comp") {
            Brand::Compatible
        } else {
            Brand::Other
        }))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Brand {
    Compressed,
    Compatible,
    Other,
}

pub(in crate::extraction::formats) fn read<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
) -> Result<Option<Projection>, E> {
    let extent = input.extent;
    let Some(file_type) = PhysicalBox::read(input, 0, extent)? else {
        return Ok(None);
    };
    if file_type.span.kind != *b"ftyp" {
        return Ok(None);
    }
    let Some(brand @ (Brand::Compressed | Brand::Compatible)) = file_type.brand(input)? else {
        return Ok(None);
    };
    let mut projection = Builder::new(extent);
    let mut decompress =
        Decompression::for_probe(input.prefix.len().saturating_add(input.unread_bytes()));
    let Some(mut offset) = project_type(input, &mut projection, file_type, brand)? else {
        return Ok(None);
    };
    let (mut movie, mut random_access, mut expanded) = (false, false, false);
    while offset < extent {
        let Some(entry) = PhysicalBox::read(input, offset, extent)? else {
            return Ok(None);
        };
        offset = entry.span.end;
        if matches!(&entry.span.kind, b"moov" | b"!mov") {
            if movie {
                return Ok(None);
            }
            movie = true;
        }
        let replacement = match &entry.span.kind {
            b"ftyp" | b"otyp" => return Ok(None),
            b"styp" => {
                let Some(brand) = entry.brand(input)? else {
                    return Ok(None);
                };
                let Some(next) = project_type(input, &mut projection, entry, brand)? else {
                    return Ok(None);
                };
                offset = next;
                continue;
            }
            b"mfra" => {
                random_access = true;
                continue;
            }
            b"!mov" => b"moov",
            b"!mof" => b"moof",
            b"!six" => b"sidx",
            b"!ssx" => b"ssix",
            _ => continue,
        };
        let Some(bytes) = expand(input, entry, replacement, &mut decompress)? else {
            return Ok(None);
        };
        if projection.replace(entry.range(), bytes).is_none() {
            return Ok(None);
        }
        expanded = true;
    }
    if random_access && expanded {
        return Ok(None);
    }
    Ok(projection.finish())
}

fn project_type<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    projection: &mut Builder,
    outer: PhysicalBox,
    brand: Brand,
) -> Result<Option<u64>, E> {
    let mut offset = outer.span.end;
    let mut extended = None;
    while offset < input.extent {
        let Some(entry) = PhysicalBox::read(input, offset, input.extent)? else {
            return Ok(None);
        };
        match &entry.span.kind {
            b"free" | b"skip" => {}
            b"etyp" if extended.is_none() => extended = Some(entry),
            b"etyp" => return Ok(None),
            b"otyp" => {
                let Some(bytes) = original_type(input, entry, outer.span.kind)? else {
                    return Ok(None);
                };
                if projection.replace(outer.range(), bytes).is_none()
                    || extended
                        .is_some_and(|span| projection.replace(span.range(), Vec::new()).is_none())
                    || projection.replace(entry.range(), Vec::new()).is_none()
                {
                    return Ok(None);
                }
                return Ok(Some(entry.span.end));
            }
            _ => break,
        }
        offset = entry.span.end;
    }
    Ok((brand != Brand::Compressed).then_some(offset))
}

fn original_type<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    mut wrapper: PhysicalBox,
    kind: [u8; 4],
) -> Result<Option<Vec<u8>>, E> {
    let mut free = Vec::new();
    let mut depth = 0_u64;
    loop {
        let bound = wrapper.span.end;
        let Some(original) = PhysicalBox::read(input, wrapper.span.data, bound)? else {
            return Ok(None);
        };
        if original.span.kind != kind && !(kind == *b"styp" && original.span.kind == *b"ftyp") {
            return Ok(None);
        }
        let Some(brand) = original.brand(input)? else {
            return Ok(None);
        };
        let mut offset = original.span.end;
        let (mut extended, mut nested) = (None, None);
        while offset < bound {
            let Some(entry) = PhysicalBox::read(input, offset, bound)? else {
                return Ok(None);
            };
            offset = entry.span.end;
            match &entry.span.kind {
                b"etyp" if extended.is_none() && nested.is_none() => extended = Some(entry),
                b"otyp" if nested.is_none() => nested = Some(entry),
                b"free" | b"skip" if free.try_reserve(1).is_ok() => free.push((depth, entry)),
                _ => return Ok(None),
            }
        }
        if let Some(nested) = nested {
            wrapper = nested;
            depth += 1;
            continue;
        }
        if brand == Brand::Compressed {
            return Ok(None);
        }
        // Each transformation restores its own type before retaining free space.
        // The innermost type and free boxes therefore come first.
        free.sort_unstable_by_key(|&(depth, entry)| (Reverse(depth), entry.start));
        let mut restored = Vec::new();
        for entry in Some(original)
            .into_iter()
            .chain(extended)
            .chain(free.into_iter().map(|(_, entry)| entry))
        {
            let Some(bytes) = bytes_at(input, entry.range())? else {
                return Ok(None);
            };
            if restored.try_reserve(bytes.len()).is_err() {
                return Ok(None);
            }
            restored.extend_from_slice(bytes);
        }
        return Ok(Some(restored));
    }
}

fn expand<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    entry: PhysicalBox,
    kind: &[u8; 4],
    decompress: &mut Decompression,
) -> Result<Option<Vec<u8>>, E> {
    let Some(compressed) = bytes_at(input, entry.span.data..entry.span.end)? else {
        return Ok(None);
    };
    let Some(payload) = decompress.decode(Encoding::Deflate, compressed) else {
        return Ok(None);
    };
    let header_len = (entry.span.data - entry.start) as usize;
    let Some(length) = header_len.checked_add(payload.len()) else {
        return Ok(None);
    };
    let mut restored = Vec::new();
    if restored.try_reserve_exact(length).is_err() {
        return Ok(None);
    }
    if header_len == EXTENDED_BOX_BYTES {
        restored.extend_from_slice(&1_u32.to_be_bytes());
        restored.extend_from_slice(kind);
        restored.extend_from_slice(&(length as u64).to_be_bytes());
    } else {
        let Ok(length) = u32::try_from(length) else {
            return Ok(None);
        };
        restored.extend_from_slice(&length.to_be_bytes());
        restored.extend_from_slice(kind);
    }
    restored.extend_from_slice(payload);
    Ok(Some(restored))
}

fn bytes_at<'a, E>(
    input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    range: Range<u64>,
) -> Result<Option<&'a [u8]>, E> {
    let Ok(length) = usize::try_from(range.end - range.start) else {
        return Ok(None);
    };
    input.range(range.start, length)
}

#[cfg(test)]
mod tests {
    use super::super::Segment;
    use super::{Input, read};

    #[test]
    fn restores_nested_original_types_and_preserves_free_space() -> Result<(), &'static str> {
        let compression = boxed(b"ftyp", b"comp\0\0\0\0comp");
        let original = boxed(b"ftyp", b"avis\0\0\0\0avis");
        let outer_free = boxed(b"skip", b"physical");
        let middle_free = boxed(b"free", b"original wrapper");
        let inner_free = boxed(b"skip", b"original file");
        let inner = boxed(b"otyp", &[original.as_slice(), &inner_free].concat());
        let wrapper = boxed(
            b"otyp",
            &[compression.as_slice(), &middle_free, &inner].concat(),
        );
        let media = boxed(b"mdat", b"unchanged media");
        let physical = [compression.as_slice(), &outer_free, &wrapper, &media].concat();
        let expected = [
            original.as_slice(),
            &inner_free,
            &middle_free,
            &outer_free,
            &media,
        ]
        .concat();
        let mut input = Input::new(
            &physical,
            physical.len() as u64,
            &mut [],
            |_, _: &mut [u8]| Err("unexpected read outside the cached fixture"),
        );
        let projection = read(&mut input)?.ok_or("could not restore nested original file type")?;
        let mut at = 0;
        let mut restored = Vec::new();
        while at < projection.extent() {
            let bytes = match projection.source(at).ok_or("missing projected bytes")? {
                Segment::Expanded(bytes) => bytes,
                Segment::Original { offset, available } => physical
                    .get(offset as usize..(offset + available) as usize)
                    .ok_or("projected source escaped the input")?,
            };
            restored.extend_from_slice(bytes);
            at += bytes.len() as u64;
        }
        if restored != expected {
            return Err("incorrect restored type or free-space order");
        }
        Ok(())
    }

    fn boxed(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut bytes = ((8 + data.len()) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        bytes
    }
}
