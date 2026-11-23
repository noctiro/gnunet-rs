//! JPEG XL codestream headers and metadata stored in top-level boxes.

mod header;
mod profile;

#[cfg(test)]
mod profile_tests;

use std::collections::HashMap;

use super::{
    Field, FieldLimits, IMAGE_ORIENTATION, Input,
    boxes::{BoxSpan, EXTENDED_BOX_BYTES, file_type},
    compression::{Decompression, Encoding},
    tiff, xmp,
};
use header::{Header, Prefix};

pub(super) const SIGNATURE: &[u8; 12] = b"\0\0\0\x0cJXL \x0d\x0a\x87\x0a";
pub(super) const HEADER_BYTES: usize = SIGNATURE.len() + EXTENDED_BOX_BYTES + 8;
const CODESTREAM: &[u8; 2] = b"\xff\x0a";
const BRAND: &[u8; 4] = b"jxl ";

enum FileVersion {
    Original,
    Reordered,
}

impl FileVersion {
    fn from_minor(minor: u32) -> Option<Self> {
        Some(match minor {
            0 => Self::Original,
            1 => Self::Reordered,
            _ => return None,
        })
    }
}

pub(super) fn is_jxl(prefix: &[u8]) -> bool {
    if prefix.starts_with(CODESTREAM) {
        return true;
    }
    let Some(file_type) = prefix.strip_prefix(SIGNATURE).and_then(file_type) else {
        return false;
    };
    file_type.major == *BRAND
        && file_type.payload_bytes >= 12
        && file_type.minor.and_then(FileVersion::from_minor).is_some()
}

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limits: FieldLimits,
    emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let extent = input.extent;
    let available = input.prefix.len().saturating_add(input.unread_bytes());
    let mut codestream = CodestreamPrefix::new(profile::Probe::new(available, limits.icc));
    if input.prefix.starts_with(CODESTREAM) {
        return codestream.append(&mut input, 0, extent, true, emit);
    }
    if input.range(0, SIGNATURE.len())? != Some(SIGNATURE.as_slice()) {
        return Ok(());
    }
    let Some(file_type) = BoxSpan::read(&mut input, SIGNATURE.len() as u64, extent)? else {
        return Ok(());
    };
    if file_type.kind != *b"ftyp" || file_type.len() < 12 || !file_type.len().is_multiple_of(4) {
        return Ok(());
    }
    let Some(&[b'j', b'x', b'l', b' ', a, b, c, d]) = input.range(file_type.data, 8)? else {
        return Ok(());
    };
    let Some(version) = FileVersion::from_minor(u32::from_be_bytes([a, b, c, d])) else {
        return Ok(());
    };
    codestream.deferred = Some(DeferredProfile::default());
    if matches!(version, FileVersion::Reordered) {
        codestream.indexed = Some(IndexedFragments::default());
    }
    let mut at = file_type.end;
    let mut seen_exif = false;
    let mut decompression = Decompression::for_probe(available);
    let limit = limits.text;
    while let Some(span) = BoxSpan::read(&mut input, at, extent)? {
        at = span.end;
        match &span.kind {
            b"jxlc" if !codestream.is_finished() => {
                if codestream.next_part == 0
                    && codestream
                        .indexed
                        .as_ref()
                        .is_none_or(|index| index.pending.is_empty())
                {
                    codestream.append(&mut input, span.data, span.len(), true, emit)?;
                } else {
                    codestream.stage = Stage::Done;
                }
            }
            b"jxlp" if !codestream.is_finished() => {
                codestream.part(&mut input, &span, emit)?;
            }
            b"Exif" if !seen_exif => {
                seen_exif = visit_exif(&mut input, &span, limit, &mut |kind, bytes| {
                    emit(Field::Text(kind, bytes))
                })?;
            }
            b"xml " => {
                if let Ok(length) = usize::try_from(span.len())
                    && let Some(packet) = input.range(span.data, length)?
                {
                    xmp::visit(packet, limit, &mut |kind, bytes| {
                        emit(Field::Text(kind, bytes))
                    })?;
                }
            }
            b"brob" => {
                let Some(packet) = CompressedBox::read(&mut input, &span, seen_exif)? else {
                    continue;
                };
                let Some(bytes) = decompression.decode(Encoding::Brotli, packet.bytes) else {
                    continue;
                };
                match packet.kind {
                    MetadataKind::Exif => {
                        if let Some(tiff) = tiff::offset_payload(bytes) {
                            seen_exif = visit_tiff(tiff, limit, &mut |kind, bytes| {
                                emit(Field::Text(kind, bytes))
                            })?;
                        }
                    }
                    MetadataKind::Xmp => {
                        xmp::visit(bytes, limit, &mut |kind, bytes| {
                            emit(Field::Text(kind, bytes))
                        })?;
                    }
                }
            }
            _ => {}
        }
    }
    codestream.finish_container(&mut input, emit)
}

enum MetadataKind {
    Exif,
    Xmp,
}

struct CompressedBox<'a> {
    kind: MetadataKind,
    bytes: &'a [u8],
}

impl<'a> CompressedBox<'a> {
    fn read<E>(
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
        seen_exif: bool,
    ) -> Result<Option<Self>, E> {
        let Some(length) = span
            .len()
            .checked_sub(4)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return Ok(None);
        };
        let kind = match input.range(span.data, 4)? {
            Some(b"Exif") if !seen_exif => MetadataKind::Exif,
            Some(b"xml ") => MetadataKind::Xmp,
            _ => return Ok(None),
        };
        Ok(input
            .range(span.data + 4, length)?
            .map(|bytes| Self { kind, bytes }))
    }
}

enum Stage {
    Header {
        bytes: [u8; header::MAX_BYTES],
        len: usize,
        profile: Option<profile::Probe>,
    },
    Profile(profile::Probe),
    Done,
}

struct CodestreamPrefix {
    stage: Stage,
    next_part: u32,
    indexed: Option<IndexedFragments>,
    deferred: Option<DeferredProfile>,
}

impl CodestreamPrefix {
    fn new(profile: Option<profile::Probe>) -> Self {
        Self {
            stage: Stage::Header {
                bytes: [0; header::MAX_BYTES],
                len: 0,
                profile,
            },
            next_part: 0,
            indexed: None,
            deferred: None,
        }
    }

    fn is_finished(&self) -> bool {
        matches!(self.stage, Stage::Done)
            || self
                .deferred
                .as_ref()
                .is_some_and(|profile| profile.complete)
    }

    fn part<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        span: &BoxSpan,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(length) = span.len().checked_sub(4) else {
            self.stage = Stage::Done;
            return Ok(());
        };
        let Some(&[a, b, c, d]) = input.range(span.data, 4)? else {
            self.stage = Stage::Done;
            return Ok(());
        };
        let value = u32::from_be_bytes([a, b, c, d]);
        let index = value & 0x7fff_ffff;
        let fragment = Fragment {
            offset: span.data + 4,
            length,
            last: value & 0x8000_0000 != 0,
        };
        let ready = index == self.next_part;
        if index < self.next_part
            || !match &mut self.indexed {
                Some(fragments) => fragments.observe(index, fragment, ready),
                None => ready,
            }
        {
            self.stage = Stage::Done;
            return Ok(());
        }
        if !ready {
            return Ok(());
        }
        let mut fragment = fragment;
        loop {
            self.next_part += 1;
            self.append(input, fragment.offset, fragment.length, fragment.last, emit)?;
            if self.is_finished() {
                self.indexed = None;
                return Ok(());
            }
            let Some(next) = self
                .indexed
                .as_mut()
                .and_then(|index| index.pending.remove(&self.next_part))
            else {
                return Ok(());
            };
            fragment = next;
        }
    }

    fn append<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        mut offset: u64,
        mut length: u64,
        last: bool,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        while length != 0 {
            let needed = match &self.stage {
                Stage::Header { bytes, len, .. } => bytes.len() - len,
                Stage::Profile(probe) => {
                    if let Some(deferred) = &mut self.deferred {
                        deferred.add(offset, length, last, probe.unbuffered());
                        return Ok(());
                    }
                    probe.remaining()
                }
                Stage::Done => return Ok(()),
            };
            let cached = (input.prefix.len() as u64).saturating_sub(offset);
            let available = if cached == 0 {
                input.unread_bytes() as u64
            } else {
                cached
            };
            let count = (needed as u64).min(length).min(available) as usize;
            if count == 0 {
                return self.finish(emit);
            }
            let Some(bytes) = input.range(offset, count)? else {
                return self.finish(emit);
            };
            offset += count as u64;
            length -= count as u64;
            self.push(bytes, last && length == 0, emit)?;
        }
        if last {
            match (&self.stage, &mut self.deferred) {
                (Stage::Profile(_), Some(deferred)) => deferred.complete = true,
                _ => self.finish(emit)?,
            }
        }
        Ok(())
    }

    fn finish_container<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(deferred) = self.deferred.take() {
            for (offset, length) in deferred.ranges {
                self.append(input, offset, length, false, emit)?;
                if self.is_finished() {
                    break;
                }
            }
        }
        self.finish(emit)
    }

    fn push<E>(
        &mut self,
        chunk: &[u8],
        last: bool,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        match &mut self.stage {
            Stage::Header {
                bytes,
                len,
                profile,
            } => {
                let end = *len + chunk.len();
                bytes[*len..end].copy_from_slice(chunk);
                *len = end;
                if let Some(Prefix::Complete(header)) = Header::parse(&bytes[..end]) {
                    header.emit(&mut |kind, bytes| emit(Field::Text(kind, bytes)))?;
                    self.stage = match profile.take().filter(|_| header.may_have_icc) {
                        Some(mut probe) => {
                            if probe.push(&bytes[..end]).is_some() && !probe.advance(last, emit)? {
                                Stage::Profile(probe)
                            } else {
                                Stage::Done
                            }
                        }
                        _ => Stage::Done,
                    };
                }
            }
            Stage::Profile(probe) => {
                if probe.push(chunk).is_none() || probe.advance(last, emit)? {
                    self.stage = Stage::Done;
                }
            }
            Stage::Done => {}
        }
        Ok(())
    }

    fn finish<E>(&mut self, emit: &mut impl FnMut(Field<'_>) -> Result<(), E>) -> Result<(), E> {
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Header { bytes, len, .. } => {
                if let Some(Prefix::Complete(header) | Prefix::IntrinsicPending(header)) =
                    Header::parse(&bytes[..len])
                {
                    header.emit(&mut |kind, bytes| emit(Field::Text(kind, bytes)))?;
                }
            }
            Stage::Profile(mut probe) => {
                probe.advance(true, emit)?;
            }
            Stage::Done => {}
        }
        Ok(())
    }
}

#[derive(Default)]
struct DeferredProfile {
    // Keep box metadata reads ahead of optional ICC payload reads.
    ranges: Vec<(u64, u64)>,
    bytes: u64,
    complete: bool,
}

impl DeferredProfile {
    fn add(&mut self, offset: u64, length: u64, last: bool, limit: usize) {
        let available = (limit as u64).saturating_sub(self.bytes);
        let length = length.min(available);
        if length != 0 {
            if self.ranges.try_reserve(1).is_err() {
                self.complete = true;
                return;
            }
            self.ranges.push((offset, length));
            self.bytes += length;
        }
        self.complete = last || length == available;
    }
}

#[derive(Clone, Copy)]
struct Fragment {
    offset: u64,
    length: u64,
    last: bool,
}

#[derive(Default)]
struct IndexedFragments {
    // These ranges contain no payload and are bounded by the box reads.
    pending: HashMap<u32, Fragment>,
    greatest: u32,
    last: Option<u32>,
}

impl IndexedFragments {
    fn observe(&mut self, index: u32, fragment: Fragment, ready: bool) -> bool {
        if self.last.is_some_and(|last| index > last || fragment.last)
            || (fragment.last && index < self.greatest)
            || self.pending.contains_key(&index)
        {
            return false;
        }
        self.greatest = self.greatest.max(index);
        if fragment.last {
            self.last = Some(index);
        }
        if !ready {
            if self.pending.try_reserve(1).is_err() {
                return false;
            }
            self.pending.insert(index, fragment);
        }
        true
    }
}

fn visit_exif<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    if span.len() < 4 {
        return Ok(false);
    }
    let Some(&[a, b, c, d]) = input.range(span.data, 4)? else {
        return Ok(false);
    };
    let offset = 4 + u64::from(u32::from_be_bytes([a, b, c, d]));
    let Some(length) = span.len().checked_sub(offset) else {
        return Ok(false);
    };
    let Ok(length) = usize::try_from(length) else {
        return Ok(false);
    };
    let Some(tiff) = input.range(span.data + offset, length)? else {
        return Ok(false);
    };
    visit_tiff(tiff, limit, emit)
}

fn visit_tiff<E>(
    bytes: &[u8],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let mut emitted = false;
    tiff::visit_exif(bytes, limit, &mut |kind, value| {
        // Orientation belongs to the codestream.
        if kind != IMAGE_ORIENTATION {
            emit(kind, value)?;
            emitted = true;
        }
        Ok(())
    })?;
    Ok(emitted)
}

#[cfg(test)]
mod tests {
    use super::super::compression::XMP_BROTLI;
    use super::*;
    use std::convert::Infallible;

    fn visit<E>(
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        super::visit(
            input,
            FieldLimits::text_only(limit),
            &mut super::super::text_only(emit),
        )
    }

    const FILE_TYPE: &[u8; 20] = b"\0\0\0\x14ftypjxl \0\0\0\0jxl ";
    const CONTAINER_HEADER_BYTES: usize = SIGNATURE.len() + FILE_TYPE.len();
    // Non-small SizeHeader 800×600, independent width, and orientation 8.
    const IMAGE_HEADER: &[u8] = b"\xff\x0a\xba\x12\xe8\x63\x78";

    #[test]
    fn reads_bounded_metadata_after_the_positioned_codestream() {
        const CODESTREAM_LEN: u64 = 64 * 1024;
        const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Paris"/></r:RDF>"#;
        const TIFF: &[u8] = b"II*\0\x08\0\0\0\x02\0\
            \x0f\x01\x02\0\x04\0\0\0Cam\0\
            \x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0";
        let prefix = [SIGNATURE.as_slice(), FILE_TYPE].concat();
        assert!(is_jxl(&prefix));
        assert!(is_jxl(CODESTREAM));
        assert!(!is_jxl(SIGNATURE));
        let mut codestream_header = (CODESTREAM_LEN as u32).to_be_bytes().to_vec();
        codestream_header.extend_from_slice(b"jxlc");
        let metadata_at = prefix.len() as u64 + CODESTREAM_LEN;

        // The first Exif box points outside itself and must not read the next box.
        let mut metadata = b"\0\0\0\x0cExif\xff\xff\xff\xff".to_vec();
        metadata.extend_from_slice(b"\0\0\0\x01Exif");
        metadata.extend_from_slice(&(16 + 4 + 3 + TIFF.len() as u64).to_be_bytes());
        metadata.extend_from_slice(b"\0\0\0\x03pad");
        metadata.extend_from_slice(TIFF);
        metadata.extend_from_slice(b"\0\0\0\0xml ");
        metadata.extend_from_slice(XMP);
        let extent = metadata_at + metadata.len() as u64;
        let mut scratch = [0; 512];
        let input = Input::new(
            &prefix,
            extent,
            &mut scratch,
            |offset, output: &mut [u8]| {
                if offset == CONTAINER_HEADER_BYTES as u64 {
                    output.copy_from_slice(&codestream_header);
                } else if offset == CONTAINER_HEADER_BYTES as u64 + 8 {
                    let mut header = [0; header::MAX_BYTES];
                    header[..IMAGE_HEADER.len()].copy_from_slice(IMAGE_HEADER);
                    output.copy_from_slice(&header[..output.len()]);
                } else {
                    assert!(offset >= metadata_at);
                    let start = (offset - metadata_at) as usize;
                    output.copy_from_slice(&metadata[start..start + output.len()]);
                }
                Ok::<(), Infallible>(())
            },
        );
        let mut fields = Vec::new();
        let Ok(()) = visit(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        });
        assert_eq!(
            fields,
            [
                (112, b"800x600".to_vec()),
                (110, b"left, bottom".to_vec()),
                (95, b"Cam".to_vec()),
                (41, b"Paris".to_vec())
            ]
        );
    }

    #[test]
    fn reads_bare_and_fragmented_headers_without_crossing_missing_parts() {
        let first = b"\0\0\0\x0ejxlp\0\0\0\0\xff\x0a";
        let separator = b"\0\0\0\x08free";
        let second = b"\0\0\0\x11jxlp\x80\0\0\x01\xba\x12\xe8\x63\x78";
        let fragmented = [SIGNATURE.as_slice(), FILE_TYPE, first, separator, second].concat();
        let mut missing = fragmented.clone();
        missing[CONTAINER_HEADER_BYTES + first.len() + separator.len() + 11] = 2;
        for (data, split, complete) in [
            (IMAGE_HEADER, 3, true),
            (&fragmented, CONTAINER_HEADER_BYTES, true),
            (&missing, CONTAINER_HEADER_BYTES, false),
        ] {
            let (prefix, tail) = data.split_at(split);
            let mut arena = vec![0; tail.len()];
            let input = Input::new(prefix, data.len() as u64, &mut arena, |offset, output| {
                assert!(offset >= split as u64);
                let start = offset as usize;
                output.copy_from_slice(&data[start..start + output.len()]);
                Ok::<(), Infallible>(())
            });
            let mut fields = Vec::new();
            let Ok(()) = visit(input, 32, &mut |kind, value| {
                fields.push((kind, value.to_vec()));
                Ok(())
            });
            if complete {
                assert_eq!(
                    fields,
                    [(112, b"800x600".to_vec()), (110, b"left, bottom".to_vec())]
                );
            } else {
                assert!(fields.is_empty());
            }
        }
    }

    #[test]
    fn prefers_intrinsic_size_after_the_full_prefix_is_available() {
        // Coded size 800×600, orientation 8, and intrinsic height 1200 at 4:3.
        const INTRINSIC: &[u8] = b"\xff\x0a\xba\x12\xe8\x63\xf8\x7a\x25\x03";
        let split = IMAGE_HEADER.len();
        let mut fragmented = [SIGNATURE.as_slice(), FILE_TYPE].concat();
        append_fragment(&mut fragmented, 0, &INTRINSIC[..split]);
        append_fragment(&mut fragmented, 0x8000_0001, &INTRINSIC[split..]);
        let mut truncated = [SIGNATURE.as_slice(), FILE_TYPE].concat();
        append_fragment(&mut truncated, 0x8000_0000, &INTRINSIC[..split]);
        let mut without_last = [SIGNATURE.as_slice(), FILE_TYPE].concat();
        append_fragment(&mut without_last, 0, &INTRINSIC[..split]);

        for (bytes, extent, dimensions) in [
            (INTRINSIC, INTRINSIC.len(), b"1600x1200".as_slice()),
            (&INTRINSIC[..split], INTRINSIC.len(), b"800x600"),
            (fragmented.as_slice(), fragmented.len(), b"1600x1200"),
            (truncated.as_slice(), truncated.len(), b"800x600"),
            (without_last.as_slice(), without_last.len(), b"800x600"),
        ] {
            let input = Input::new(bytes, extent as u64, &mut [], |_, _: &mut [u8]| {
                Err("unexpected read beyond the cached prefix")
            });
            let mut fields = Vec::new();
            let result = visit(input, 32, &mut |kind, value| {
                fields.push((kind, value.to_vec()));
                Ok(())
            });
            assert_eq!(result, Ok(()));
            assert_eq!(
                fields,
                [(112, dimensions.to_vec()), (110, b"left, bottom".to_vec())]
            );
        }
    }

    #[test]
    fn version_one_reorders_ranges_and_stops_at_an_invalid_index() {
        const EXTENDED_FILE_TYPE: &[u8] = b"\0\0\0\x01ftyp\0\0\0\0\0\0\0\x20jxl \0\0\0\x01jxl abcd";
        for (file_type, far_index, counters, complete) in [
            (EXTENDED_FILE_TYPE, 0x8000_0002, [1, 0], true),
            (EXTENDED_FILE_TYPE, 0x8000_0002, [1, 1], false),
            (EXTENDED_FILE_TYPE, 0x0000_0002, [0x8000_0001, 0], false),
            (EXTENDED_FILE_TYPE, 0x7fff_ffff, [2, 0], false),
            (FILE_TYPE.as_slice(), 0x8000_0002, [1, 0], false),
        ] {
            let mut file = [SIGNATURE.as_slice(), file_type].concat();
            let prefix_end = file.len();
            assert!(is_jxl(&file[..HEADER_BYTES.min(prefix_end)]));
            let far_header = file.len();
            append_fragment(&mut file, far_index, &[0x55; 512]);
            let far_data = far_header + 12..file.len();
            append_fragment(&mut file, counters[0], &IMAGE_HEADER[2..]);
            append_fragment(&mut file, counters[1], &IMAGE_HEADER[..2]);
            let mut scratch = [0; 64];
            let input = Input::new(
                &file[..prefix_end],
                file.len() as u64,
                &mut scratch,
                |offset, output: &mut [u8]| {
                    let at = offset as usize;
                    assert!(at + output.len() <= far_data.start || at >= far_data.end);
                    output.copy_from_slice(&file[at..at + output.len()]);
                    Ok::<(), Infallible>(())
                },
            );
            let mut fields = Vec::new();
            let Ok(()) = visit(input, 32, &mut |kind, value| {
                fields.push((kind, value.to_vec()));
                Ok(())
            });
            if complete {
                assert_eq!(
                    fields,
                    [(112, b"800x600".to_vec()), (110, b"left, bottom".to_vec())]
                );
            } else {
                assert!(fields.is_empty());
            }
        }
    }

    #[test]
    fn reads_brotli_exif_and_xmp_without_using_the_boxed_orientation() {
        const EXIF_BROTLI: &[u8] = b"\
            \x1f\x2c\x00\x00\x84\x87\xf7\xd6\xfb\x98\x69\x36\x25\x6a\x08\x51\
            \x52\xe2\xad\x5f\x88\x14\xc0\x22\xaf\x7d\xde\x9b\x1a\x92\x1e\x49\
            \xc1\xfd\x7e\x23\xb2\x40\x05\x00";
        let mut file = [SIGNATURE.as_slice(), FILE_TYPE].concat();
        for (kind, packet) in [
            (b"jumb", &[0][..]),
            (b"Exif", EXIF_BROTLI),
            (b"xml ", XMP_BROTLI),
        ] {
            file.extend_from_slice(&(12 + packet.len() as u32).to_be_bytes());
            file.extend_from_slice(b"brob");
            file.extend_from_slice(kind);
            file.extend_from_slice(packet);
        }
        let input = Input::new(&file, file.len() as u64, &mut [], |_, _: &mut [u8]| {
            Ok::<(), Infallible>(())
        });
        let mut fields = Vec::new();
        let Ok(()) = visit(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        });
        assert_eq!(fields, [(95, b"Cam".to_vec()), (41, b"Paris".to_vec())]);
    }

    #[test]
    fn visits_each_plain_and_brotli_xml_box() {
        const EMPTY_XMP: &[u8] =
            br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>"#;
        const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:Country="France"/></r:RDF>"#;
        let compressed = [b"xml ".as_slice(), XMP_BROTLI].concat();
        let mut file = [SIGNATURE.as_slice(), FILE_TYPE].concat();
        for (kind, payload) in [
            (b"jxlc", IMAGE_HEADER),
            (b"xml ", EMPTY_XMP),
            (b"brob", compressed.as_slice()),
            (b"xml ", XMP),
        ] {
            file.extend_from_slice(&(8 + payload.len() as u32).to_be_bytes());
            file.extend_from_slice(kind);
            file.extend_from_slice(payload);
        }
        let (prefix, tail) = file.split_at(CONTAINER_HEADER_BYTES);
        let mut scratch = vec![0; tail.len()];
        let input = Input::new(prefix, file.len() as u64, &mut scratch, |offset, output| {
            let start = offset as usize - CONTAINER_HEADER_BYTES;
            output.copy_from_slice(&tail[start..start + output.len()]);
            Ok::<(), Infallible>(())
        });
        let mut fields = Vec::new();
        let Ok(()) = visit(input, 32, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        });
        assert_eq!(
            fields,
            [
                (112, b"800x600".to_vec()),
                (110, b"left, bottom".to_vec()),
                (41, b"Paris".to_vec()),
                (43, b"France".to_vec())
            ]
        );
    }

    fn append_fragment(file: &mut Vec<u8>, index: u32, contents: &[u8]) {
        file.extend_from_slice(&(12 + contents.len() as u32).to_be_bytes());
        file.extend_from_slice(b"jxlp");
        file.extend_from_slice(&index.to_be_bytes());
        file.extend_from_slice(contents);
    }
}
