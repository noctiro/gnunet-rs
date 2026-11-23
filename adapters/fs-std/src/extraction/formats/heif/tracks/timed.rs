//! Timed metadata tracks describing the selected HEIF image sequence.

use super::super::{
    super::{
        boxes::samples::{SampleExtent, SampleSpan, TimedSelection},
        compression::{ContentCoding, Decompression},
        tiff, xmp,
    },
    BoxSpan, Input, read_body,
};
use super::{SampleTable, TimedMetadata, TrackIdentity, scope};
use gnunet_fs_codec::DeflateFormat;
use std::num::{NonZeroU16, NonZeroU32};

pub(super) fn visit<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    timed: &mut TimedMetadata,
    limit: usize,
    decompress: &mut Decompression,
    exif: &mut tiff::ExifOverlay,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let TimedMetadata { id, movie, anchor } = timed;
    if movie.fragmented && movie.fragments.is_empty() {
        return Ok(());
    }
    let mut alternate_groups = Vec::new();
    let mut at = movie.span.data;
    while let Some(span) = BoxSpan::read(input, at, movie.span.end)? {
        at = span.end;
        if span.kind != *b"trak" {
            continue;
        }
        let Some(track) = Track::read(input, &span, *id)? else {
            continue;
        };
        if track
            .alternate_group
            .is_some_and(|group| alternate_groups.contains(&group))
        {
            continue;
        }
        let Some(table) = SampleTable::read_timed(input, &track.media)? else {
            continue;
        };
        if !table
            .descriptions()
            .any(|entry| matches!(&entry.kind, b"Exif" | b"metx"))
        {
            continue;
        }
        let Some(sample) = movie
            .seek_metadata(input, &table, track.id, *anchor)?
            .and_then(SampleMetadata::from_selection)
        else {
            continue;
        };
        if visit_sample(input, sample, track.meta, limit, decompress, exif, emit)?
            && let Some(group) = track.alternate_group
        {
            if alternate_groups.try_reserve(1).is_err() {
                break;
            }
            alternate_groups.push(group);
        }
    }
    Ok(())
}

struct Track {
    id: NonZeroU32,
    media: BoxSpan,
    meta: Option<BoxSpan>,
    alternate_group: Option<NonZeroU16>,
}

impl Track {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        track: &BoxSpan,
        visual_id: NonZeroU32,
    ) -> Result<Option<Self>, E> {
        let (mut header, mut references, mut media, mut meta) = (None, None, None, None);
        let mut at = track.data;
        while at < track.end {
            let Some(span) = BoxSpan::read(input, at, track.end)? else {
                return Ok(None);
            };
            at = span.end;
            let slot = match &span.kind {
                b"tkhd" => &mut header,
                b"tref" => &mut references,
                b"mdia" => &mut media,
                b"meta" => &mut meta,
                _ => continue,
            };
            if slot.replace(span).is_some() {
                return Ok(None);
            }
        }
        let (Some(header), Some(references), Some(media)) = (header, references, media) else {
            return Ok(None);
        };
        if !describes(input, &references, visual_id)? || !metadata_handler(input, &media)? {
            return Ok(None);
        }
        if !matches!(header.len(), 84 | 96) {
            return Ok(None);
        }
        let Some(identity) = read_body(input, &header)?
            .and_then(TrackIdentity::parse)
            .filter(|identity| identity.id != visual_id)
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            id: identity.id,
            media,
            meta,
            alternate_group: NonZeroU16::new(identity.alternate_group),
        }))
    }
}

fn describes<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    references: &BoxSpan,
    visual_id: NonZeroU32,
) -> Result<bool, E> {
    let mut at = references.data;
    let mut describes = false;
    while at < references.end {
        let Some(span) = BoxSpan::read(input, at, references.end)? else {
            return Ok(false);
        };
        at = span.end;
        if span.kind != *b"cdsc" {
            continue;
        }
        if span.len() == 0 || !span.len().is_multiple_of(4) {
            return Ok(false);
        }
        let Some(targets) = read_body(input, &span)? else {
            return Ok(false);
        };
        let id = visual_id.get().to_be_bytes();
        let targets = targets.as_chunks::<4>().0;
        if targets.contains(&[0; 4]) {
            return Ok(false);
        }
        describes |= targets.contains(&id);
    }
    Ok(describes)
}

fn metadata_handler<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    media: &BoxSpan,
) -> Result<bool, E> {
    let mut at = media.data;
    let mut handler = None;
    while at < media.end {
        let Some(span) = BoxSpan::read(input, at, media.end)? else {
            return Ok(false);
        };
        at = span.end;
        if span.kind == *b"hdlr" {
            if handler.is_some() || span.len() < 25 {
                return Ok(false);
            }
            handler = Some(input.range(span.data, 12)? == Some(b"\0\0\0\0\0\0\0\0meta"));
        }
    }
    Ok(handler.unwrap_or(false))
}

enum SampleMetadata {
    Exif(ExifSample),
    Xmp(SampleSpan),
}

impl SampleMetadata {
    fn from_selection(TimedSelection { sample, prior_sync }: TimedSelection) -> Option<Self> {
        match &sample.description.kind {
            b"Exif" if sample.sync => Some(Self::Exif(ExifSample::Sync(sample.extent()))),
            b"Exif" => Some(Self::Exif(ExifSample::Delta {
                sync: prior_sync?,
                sample: sample.extent(),
            })),
            b"metx" => Some(Self::Xmp(sample)),
            _ => None,
        }
    }
}

enum ExifSample {
    Sync(SampleExtent),
    Delta {
        sync: SampleExtent,
        sample: SampleExtent,
    },
}

fn read_exif<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    extent: SampleExtent,
    allowance: usize,
) -> Result<Option<tiff::ExifLayer>, E> {
    let Ok(length) = usize::try_from(extent.length) else {
        return Ok(None);
    };
    if length > allowance {
        return Ok(None);
    }
    Ok(input
        .range(extent.start, length)?
        .and_then(|bytes| tiff::ExifLayer::read(bytes, allowance)))
}

fn visit_sample<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    selected: SampleMetadata,
    meta: Option<BoxSpan>,
    limit: usize,
    decompress: &mut Decompression,
    exif: &mut tiff::ExifOverlay,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    match selected {
        SampleMetadata::Exif(sample) => {
            let (sync, sample) = match sample {
                ExifSample::Sync(sample) => (None, sample),
                ExifSample::Delta { sync, sample } => {
                    let Some(layer) = read_exif(input, sync, exif.remaining_bytes())? else {
                        return Ok(false);
                    };
                    (Some(layer), sample)
                }
            };
            let sync_bytes = sync.as_ref().map_or(0, tiff::ExifLayer::cost);
            let Some(layer) = read_exif(input, sample, exif.remaining_bytes() - sync_bytes)? else {
                return Ok(false);
            };
            if let Some(meta) = meta {
                scope::add_track_exif(input, meta, sync_bytes + layer.cost(), exif)?;
            }
            Ok(exif.add_sample(sync, layer))
        }
        SampleMetadata::Xmp(sample) => {
            let Ok(length) = usize::try_from(sample.length) else {
                return Ok(false);
            };
            let Some(coding) = read_body(input, &sample.description)?.and_then(xmp_coding) else {
                return Ok(false);
            };
            let Some(bytes) = input.range(sample.start, length)? else {
                return Ok(false);
            };
            let packet = match coding {
                ContentCoding::Identity => Some(bytes),
                ContentCoding::Compressed(encoding) => decompress.decode(encoding, bytes),
            };
            if let Some(packet) = packet {
                return xmp::visit(packet, limit, emit);
            }
            Ok(false)
        }
    }
}

fn xmp_coding(entry: &[u8]) -> Option<ContentCoding> {
    let fields = entry.get(8..)?;
    let mut fields = fields.split_inclusive(|&byte| byte == 0);
    // ISO BMFF represents an absent coding with an empty string.
    let coding = fields.next()?.strip_suffix(&[0])?;
    let namespaces = std::str::from_utf8(fields.next()?.strip_suffix(&[0])?).ok()?;
    let xmp = namespaces
        .split(' ')
        .any(|namespace| matches!(namespace, "adobe:ns:meta/" | "http://ns.adobe.com/xap/1.0/"));
    if xmp {
        ContentCoding::parse(coding, DeflateFormat::Zlib)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
