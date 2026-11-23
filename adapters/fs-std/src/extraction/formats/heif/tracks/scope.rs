//! Resolve a sample's item IDs in the first metadata box named by its group.

use super::super::{
    Decompression, Kind, MetaBox, MetaBoxes, Scope,
    tiff::{ExifLayer, ExifOverlay},
};
use super::{BoxSpan, Input, TrackMetadata};
use std::ops::Range;

pub(super) fn visit<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    metadata: TrackMetadata,
    limit: usize,
    budget: &mut Decompression,
    exif: Option<&mut ExifOverlay>,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    match metadata {
        TrackMetadata::None => {}
        TrackMetadata::Whole(span) => {
            if let Some(meta) = MetaBoxes::read(input, &span)?
                && let Some(items) = meta.items
            {
                items.visit(
                    input,
                    Scope::Track(items.references.as_ref()),
                    limit,
                    budget,
                    exif,
                    emit,
                )?;
            }
        }
        TrackMetadata::Sample {
            track,
            movie,
            group,
        } => {
            let extent = input.extent;
            for scope in [track.data..track.end, movie.data..movie.end, 0..extent] {
                let container = match find(input, scope, &group.handler)? {
                    Search::Found(container) => container,
                    Search::Absent => continue,
                    Search::Incomplete => break,
                };
                if let Some(meta) = MetaBoxes::read_children(input, container)?
                    && let Some(items) = meta.items
                {
                    let scope = Scope::Selected {
                        ids: &group.items,
                        references: items.references.as_ref(),
                    };
                    items.visit(input, scope, limit, budget, exif, emit)?;
                }
                break;
            }
        }
    }
    Ok(())
}

pub(super) fn add_track_exif<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: BoxSpan,
    reserved: usize,
    overlay: &mut ExifOverlay,
) -> Result<(), E> {
    let Some(container) = MetaBox::read(input, &span)? else {
        return Ok(());
    };
    let Some(meta) = MetaBoxes::read_children(input, container)? else {
        return Ok(());
    };
    if let Some(items) = meta.items {
        let scope = Scope::Track(items.references.as_ref());
        items.for_each_payload(
            input,
            scope,
            |kind| matches!(kind, Kind::Exif),
            |_, bytes| {
                if let Some(allowance) = overlay.remaining_bytes().checked_sub(reserved)
                    && let Some(layer) = ExifLayer::read(bytes, allowance)
                {
                    overlay.add_sample(None, layer);
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

enum Search {
    Found(MetaBox),
    Absent,
    Incomplete,
}

fn find<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    mut region: Range<u64>,
    handler: &[u8; 4],
) -> Result<Search, E> {
    let mut in_meco = false;
    loop {
        let mut additional = None;
        let mut offset = region.start;
        while offset < region.end {
            let Some(span) = BoxSpan::read(input, offset, region.end)? else {
                return Ok(Search::Incomplete);
            };
            offset = span.end;
            match &span.kind {
                b"meta" => {
                    let Some(container) = MetaBox::read(input, &span)? else {
                        return Ok(Search::Incomplete);
                    };
                    if &container.handler == handler {
                        return Ok(Search::Found(container));
                    }
                }
                b"meco" if !in_meco && additional.is_none() => additional = Some(span),
                b"meco" if !in_meco => return Ok(Search::Incomplete),
                _ => {}
            }
        }
        let Some(span) = additional else {
            return Ok(Search::Absent);
        };
        region = span.data..span.end;
        in_meco = true;
    }
}
