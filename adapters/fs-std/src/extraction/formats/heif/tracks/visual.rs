//! Visual sample descriptions and the classic chunk index used for track selection.

use super::{BoxSpan, Codec, Dimensions, Input, groups, picture_handler};

pub(super) enum VisualSamples {
    Classic {
        dimensions: Dimensions,
        table: BoxSpan,
        metadata_groups: bool,
    },
    Fragmented(BoxSpan),
}

enum SampleIndex {
    Present,
    Empty,
}

impl VisualSamples {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        media: &BoxSpan,
        codec: Codec,
    ) -> Result<Option<Self>, E> {
        let (mut handler, mut information) = (None, None);
        let mut cursor = media.data;
        while cursor < media.end {
            let Some(child) = BoxSpan::read(input, cursor, media.end)? else {
                return Ok(None);
            };
            cursor = child.end;
            let slot = match &child.kind {
                b"hdlr" => &mut handler,
                b"minf" => &mut information,
                _ => continue,
            };
            if slot.replace(child).is_some() {
                return Ok(None);
            }
        }
        let (Some(handler), Some(information)) = (handler, information) else {
            return Ok(None);
        };
        if !picture_handler(input, &handler)? {
            return Ok(None);
        }
        let mut cursor = information.data;
        while let Some(box_span) = BoxSpan::read(input, cursor, information.end)? {
            cursor = box_span.end;
            if box_span.kind == *b"stbl" {
                return Self::read_boxes(input, &box_span, codec);
            }
        }
        Ok(None)
    }

    fn read_boxes<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        table: &BoxSpan,
        codec: Codec,
    ) -> Result<Option<Self>, E> {
        let mut description = None;
        let mut chunks = None;
        let mut metadata_groups = false;
        let mut cursor = table.data;
        while cursor < table.end {
            let Some(child) = BoxSpan::read(input, cursor, table.end)? else {
                return Ok(None);
            };
            cursor = child.end;
            let slot = match &child.kind {
                b"stsd" => &mut description,
                b"stco" | b"co64" => &mut chunks,
                kind if groups::is_group_box(kind) => {
                    metadata_groups |= groups::is_metadata_group(input, &child)?.unwrap_or(true);
                    continue;
                }
                _ => continue,
            };
            if slot.replace(child).is_some() {
                return Ok(None);
            }
        }
        let (Some(description), Some(chunks)) = (description, chunks) else {
            return Ok(None);
        };
        let Some(index) = SampleIndex::read(input, &chunks)? else {
            return Ok(None);
        };
        let Some(first) = Self::first_description(input, &description, codec)? else {
            return Ok(None);
        };
        let SampleIndex::Present = index else {
            return Ok(Some(Self::Fragmented(*table)));
        };
        let Some(dimensions) = entry_dimensions(input, &first, codec)? else {
            return Ok(None);
        };
        Ok(Some(Self::Classic {
            dimensions,
            table: *table,
            metadata_groups,
        }))
    }

    fn first_description<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        description: &BoxSpan,
        codec: Codec,
    ) -> Result<Option<BoxSpan>, E> {
        if description.len() < 8 {
            return Ok(None);
        }
        let Some(&[0, 0, 0, 0, a, b, c, d]) = input.range(description.data, 8)? else {
            return Ok(None);
        };
        let count = u32::from_be_bytes([a, b, c, d]);
        if count == 0 || (matches!(codec, Codec::Av1) && count != 1) {
            return Ok(None);
        }
        let Some(entry) = BoxSpan::read(input, description.data + 8, description.end)? else {
            return Ok(None);
        };
        Ok((count != 1 || entry.end == description.end).then_some(entry))
    }
}

pub(super) fn entry_dimensions<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    entry: &BoxSpan,
    codec: Codec,
) -> Result<Option<Dimensions>, E> {
    // A 'pict' track uses VisualSampleEntry. Its fixed fields precede codec config.
    if entry.len() < 78 || !codec.accepts(&entry.kind) {
        return Ok(None);
    }
    let Some(&[w0, w1, h0, h1]) = input.range(entry.data + 24, 4)? else {
        return Ok(None);
    };
    Ok(Dimensions::new(
        u32::from(u16::from_be_bytes([w0, w1])),
        u32::from(u16::from_be_bytes([h0, h1])),
    ))
}

impl SampleIndex {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        if span.len() < 8 {
            return Ok(None);
        }
        let Some(&[0, 0, 0, 0, a, b, c, d]) = input.range(span.data, 8)? else {
            return Ok(None);
        };
        let count = u64::from(u32::from_be_bytes([a, b, c, d]));
        let size = if span.kind == *b"stco" { 4 } else { 8 };
        if span.len() != 8 + count * size as u64 {
            return Ok(None);
        }
        if count == 0 {
            return Ok(Some(Self::Empty));
        }
        let Some(offset) = input
            .range(span.data + 8, size)?
            .and_then(|bytes| super::super::Reader::new(bytes).integer(size))
        else {
            return Ok(None);
        };
        Ok((1..input.extent).contains(&offset).then_some(Self::Present))
    }
}
