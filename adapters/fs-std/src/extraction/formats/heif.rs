//! HEIF and AVIF metadata for the primary image item or image sequence.

mod items;
mod properties;
#[cfg(test)]
mod tests;
mod tracks;

use super::{
    IMAGE_ORIENTATION, Input, ORIENTATION_LABELS,
    boxes::{BoxSpan, file_type},
    compression::Decompression,
    tiff, xmp,
};
use items::{Catalog, ItemId, Kind, Reader, Scope};

pub(super) const IDENTIFICATION_BYTES: usize = 64;

#[derive(Clone, Copy)]
pub(in crate::extraction) enum Brand {
    Avif,
    Heic,
    Heif,
    HeicSequence,
    HeifSequence,
}

impl Brand {
    pub(super) fn detect(prefix: &[u8]) -> Option<Self> {
        let file_type = file_type(prefix)?;
        let compatible = file_type.compatible;
        let from_brand = |brand: [u8; 4]| match &brand {
            b"avif" | b"avis" => Some(Self::Avif),
            b"heic" | b"heix" | b"heim" | b"heis" => Some(Self::Heic),
            b"hevc" | b"hevx" | b"hevm" | b"hevs" => Some(Self::HeicSequence),
            b"mif1" | b"mif2" => Some(Self::Heif),
            b"msf1" => Some(Self::HeifSequence),
            _ => None,
        };
        match from_brand(file_type.major) {
            brand @ Some(Self::Avif | Self::Heic | Self::HeicSequence) => brand,
            fallback => compatible
                .iter()
                .copied()
                .filter_map(from_brand)
                .find(|brand| matches!(brand, Self::Avif | Self::Heic | Self::HeicSequence))
                .or(fallback)
                .or_else(|| compatible.iter().copied().find_map(from_brand)),
        }
    }

    pub(super) const fn mime(self) -> &'static [u8] {
        match self {
            Self::Avif => b"image/avif",
            Self::Heic => b"image/heic",
            Self::Heif => b"image/heif",
            Self::HeicSequence => b"image/heic-sequence",
            Self::HeifSequence => b"image/heif-sequence",
        }
    }
}

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let extent = input.extent;
    let Some(file_type) = BoxSpan::read(&mut input, 0, extent)? else {
        return Ok(());
    };
    if file_type.kind != *b"ftyp" || file_type.len() < 8 {
        return Ok(());
    }
    let Some(major_brand) = input
        .range(file_type.data, 4)?
        .and_then(|bytes| bytes.first_chunk().copied())
    else {
        return Ok(());
    };
    let sequence = matches!(
        &major_brand,
        b"avis" | b"hevc" | b"hevx" | b"hevm" | b"hevs" | b"msf1"
    );
    let codec = tracks::Codec::for_brand(&major_brand);
    let (preferred, alternate) = if sequence {
        (*b"moov", *b"meta")
    } else {
        (*b"meta", *b"moov")
    };
    let mut preferred = Some(preferred);
    let mut fallback = None;
    let mut offset = file_type.end;
    while let Some(span) = BoxSpan::read(&mut input, offset, extent)? {
        offset = span.end;
        if preferred == Some(span.kind) {
            preferred = None;
            if let Some(image) = Image::read(&mut input, &span, codec)? {
                return image.visit(&mut input, limit, emit);
            }
        }
        if span.kind == alternate && fallback.is_none() {
            fallback = Some(span);
        }
    }
    if let Some(span) = fallback
        && let Some(image) = Image::read(&mut input, &span, codec)?
    {
        image.visit(&mut input, limit, emit)?;
    }
    Ok(())
}

enum Image {
    Item(Picture),
    Track(tracks::VisualTrack),
}

impl Image {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
        codec: tracks::Codec,
    ) -> Result<Option<Self>, E> {
        match &span.kind {
            b"meta" => Ok(Picture::read(input, span)?.map(Self::Item)),
            b"moov" => Ok(tracks::VisualTrack::read(input, span, codec)?.map(Self::Track)),
            _ => Ok(None),
        }
    }

    fn visit<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        match self {
            Self::Item(picture) => picture.visit(input, limit, emit),
            Self::Track(track) => {
                track.dimensions.emit(emit)?;
                emit_orientation(track.orientation, emit)?;
                let mut budget = Decompression::for_probe(
                    input.prefix.len().saturating_add(input.unread_bytes()),
                );
                track.visit_metadata(input, limit, &mut budget, emit)
            }
        }
    }
}

struct Picture {
    primary: ItemId,
    properties: Option<BoxSpan>,
    items: Option<Metadata>,
}

struct MetaBoxes {
    primary: Option<BoxSpan>,
    properties: Option<BoxSpan>,
    items: Option<Metadata>,
}

struct MetaBox {
    handler: [u8; 4],
    children_start: u64,
    end: u64,
}

struct Metadata {
    info: BoxSpan,
    references: Option<BoxSpan>,
    locations: BoxSpan,
    data: Option<BoxSpan>,
}

impl MetaBoxes {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        let Some(container) = MetaBox::read(input, span)? else {
            return Ok(None);
        };
        if container.handler != *b"pict" {
            return Ok(None);
        }
        Self::read_children(input, container)
    }

    fn read_children<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        container: MetaBox,
    ) -> Result<Option<Self>, E> {
        let mut offset = container.children_start;
        let mut primary = None;
        let mut info = None;
        let mut references = None;
        let mut locations = None;
        let mut data = None;
        let mut properties = None;
        while offset < container.end {
            let Some(child) = BoxSpan::read(input, offset, container.end)? else {
                return Ok(None);
            };
            offset = child.end;
            let slot = match &child.kind {
                b"pitm" => &mut primary,
                b"iinf" => &mut info,
                b"iref" => &mut references,
                b"iloc" => &mut locations,
                b"idat" => &mut data,
                b"iprp" => &mut properties,
                b"hdlr" => return Ok(None),
                _ => continue,
            };
            if slot.replace(child).is_some() {
                return Ok(None);
            }
        }
        let items = info.zip(locations).map(|(info, locations)| Metadata {
            info,
            references,
            locations,
            data,
        });
        Ok(Some(Self {
            primary,
            properties,
            items,
        }))
    }
}

impl Picture {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        let Some(meta) = MetaBoxes::read(input, span)? else {
            return Ok(None);
        };
        let Some(primary) = meta.primary else {
            return Ok(None);
        };
        let Some(primary) = read_body(input, &primary)?.and_then(primary_item) else {
            return Ok(None);
        };
        Ok(Some(Self {
            primary,
            properties: meta.properties,
            items: meta.items,
        }))
    }

    fn visit<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(properties) = self.properties
            && let Some(display) = properties::read(input, &properties, self.primary)?
        {
            if let Some(dimensions) = display.dimensions {
                dimensions.emit(emit)?;
            }
            emit_orientation(display.orientation, emit)?;
        }
        if let Some(items) = self.items
            && let Some(references) = &items.references
        {
            let scope = Scope::Describing {
                item: self.primary,
                references,
            };
            let mut budget =
                Decompression::for_probe(input.prefix.len().saturating_add(input.unread_bytes()));
            items.visit(input, scope, limit, &mut budget, None, emit)?;
        }
        Ok(())
    }
}

impl Metadata {
    fn visit<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        scope: Scope<'_>,
        limit: usize,
        decompression: &mut Decompression,
        mut exif: Option<&mut tiff::ExifOverlay>,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.for_each_payload(
            input,
            scope,
            |_| true,
            |kind, bytes| {
                match kind {
                    Kind::Exif => {
                        if let Some(exif) = exif.as_deref_mut() {
                            exif.add_block(bytes);
                        } else if let Some(tiff) = tiff::offset_payload(bytes) {
                            tiff::visit_exif(tiff, limit, &mut |kind, value| {
                                if kind != IMAGE_ORIENTATION {
                                    emit(kind, value)?;
                                }
                                Ok(())
                            })?;
                        }
                    }
                    Kind::Xmp(encoding) => {
                        let packet = match encoding {
                            Some(format) => decompression.decode(format, bytes),
                            None => Some(bytes),
                        };
                        if let Some(packet) = packet {
                            xmp::visit(packet, limit, emit)?;
                        }
                    }
                }
                Ok(())
            },
        )
    }

    fn for_each_payload<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        scope: Scope<'_>,
        accepts: impl Fn(Kind) -> bool,
        mut visit: impl FnMut(Kind, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(mut catalog) = Catalog::read(input, scope)? else {
            return Ok(());
        };
        if !catalog.classify(input, &self.info)? {
            return Ok(());
        }
        let file_extent = input.extent;
        let payload_budget = input.prefix.len().saturating_add(input.unread_bytes());
        let Some(locations) = read_body(input, &self.locations)? else {
            return Ok(());
        };
        let Some(items) =
            catalog.resolve(locations, file_extent, self.data.as_ref(), payload_budget)
        else {
            return Ok(());
        };
        let mut buffer = Vec::new();
        for item in items {
            if accepts(item.kind)
                && let Some(bytes) = item.payload.read(input, &mut buffer)?
            {
                visit(item.kind, bytes)?;
            }
        }
        Ok(())
    }
}

fn picture_handler<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<bool, E> {
    Ok(handler_type(input, span)? == Some(*b"pict"))
}

fn handler_type<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<[u8; 4]>, E> {
    if span.kind != *b"hdlr" || span.len() < 25 {
        return Ok(None);
    }
    let Some(&[0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d]) = input.range(span.data, 12)? else {
        return Ok(None);
    };
    Ok(Some([a, b, c, d]))
}

impl MetaBox {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        if span.len() < 4 || input.range(span.data, 4)? != Some(&[0; 4]) {
            return Ok(None);
        }
        let Some(handler) = BoxSpan::read(input, span.data + 4, span.end)? else {
            return Ok(None);
        };
        Ok(handler_type(input, &handler)?.map(|kind| Self {
            handler: kind,
            children_start: handler.end,
            end: span.end,
        }))
    }
}

fn emit_orientation<E>(
    orientation: Option<u8>,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(label) = orientation
        .and_then(|orientation| usize::from(orientation).checked_sub(1))
        .and_then(|index| ORIENTATION_LABELS.get(index))
    {
        emit(IMAGE_ORIENTATION, label.as_bytes())?;
    }
    Ok(())
}

fn primary_item(bytes: &[u8]) -> Option<ItemId> {
    let mut reader = Reader::new(bytes);
    let version = reader.version()?;
    let item = reader.item_id(match version {
        0 => 2,
        1 => 4,
        _ => return None,
    })?;
    reader.is_empty().then_some(item)
}

fn read_body<'a, E>(
    input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<&'a [u8]>, E> {
    let Ok(length) = usize::try_from(span.len()) else {
        return Ok(None);
    };
    input.range(span.data, length)
}
