//! Canon Timed MetaData in indexed movie samples.

use super::super::{
    Input,
    boxes::{
        BoxSpan,
        samples::{MediaData, MovieFragments, SampleTable, track_id},
    },
    camera::{APERTURE, EXPOSURE, FOCAL_LENGTH, ISO_SPEED, Rational},
    tiff::CanonDirectory,
};

const DESCRIPTION: [u8; 4] = *b"CTMD";
const CREATION_DATE: u32 = 58;
const FRAME_HEADER_BYTES: usize = 12;

pub(super) fn visit<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    movie: &BoxSpan,
    tracks: &[BoxSpan],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    // A fixed-size table can advance without a positioned read.
    let mut samples_left =
        input.prefix.len().saturating_add(input.unread_bytes()) / FRAME_HEADER_BYTES;
    let mut payloads = None;
    for track in tracks {
        let Some(media) = track_media(input, track)? else {
            continue;
        };
        let Some(table) = SampleTable::read(input, &media)? else {
            continue;
        };
        if !table.descriptions().any(|entry| entry.kind == DESCRIPTION) {
            continue;
        }
        let (media, fragments) = match &mut payloads {
            Some(payloads) => payloads,
            vacant @ None => {
                vacant.insert((MediaData::read(input)?, MovieFragments::read(input, movie)?))
            }
        };
        let fragmented_track = if fragments.is_empty() {
            None
        } else {
            track_id(input, track)?.filter(|&id| fragments.has_track(id))
        };
        let mut samples = table.samples_with_fragments(media, fragments, fragmented_track);
        while samples_left > 0
            && let Some(sample) = samples.next(input)?
        {
            samples_left -= 1;
            if sample.description.kind == DESCRIPTION
                && let Some(frame) = input.section(sample.start, sample.length)
            {
                visit_frame(frame, limit, emit)?;
            }
        }
        if samples_left == 0 {
            break;
        }
    }
    Ok(())
}

fn track_media<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    track: &BoxSpan,
) -> Result<Option<BoxSpan>, E> {
    let mut movie_media = None;
    let mut at = track.data;
    while at < track.end {
        let Some(span) = BoxSpan::read(input, at, track.end)? else {
            return Ok(None);
        };
        at = span.end;
        if span.kind == *b"mdia" && movie_media.replace(span).is_some() {
            return Ok(None);
        }
    }
    Ok(movie_media)
}

fn visit_frame<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut at = 0;
    let end = input.extent;
    while let Some(record) = Record::next(&mut input, &mut at, end, Header::Frame)? {
        match record.tag {
            1 => {
                if let Some(fields) = record.read_prefix::<10, _>(&mut input)?
                    && let Some(date) = timestamp(fields)
                {
                    emit_text(CREATION_DATE, &date, limit, emit)?;
                }
            }
            4 => {
                if let Some(fields) = record.read_prefix::<4, _>(&mut input)?
                    && let Some(length) = rational(fields).and_then(Rational::focal_length)
                {
                    emit_text(FOCAL_LENGTH, &length, limit, emit)?;
                }
            }
            5 => {
                if let Some(fields) = record.read_prefix::<12, _>(&mut input)? {
                    visit_exposure(fields, limit, emit)?;
                }
            }
            7..=9 => visit_exif(&mut input, record, limit, emit)?,
            _ => {}
        }
    }
    Ok(())
}

fn visit_exif<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    parent: Record,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut at = parent.start;
    while let Some(record) = Record::next(input, &mut at, parent.end, Header::Exif)? {
        let role = match record.tag {
            0x8769 => CanonDirectory::Photo,
            0x927c => CanonDirectory::Maker,
            _ => continue,
        };
        if let Some(section) = input.section(record.start, record.end - record.start) {
            role.visit(section, limit, emit)?;
        }
    }
    Ok(())
}

fn visit_exposure<E>(
    payload: [u8; 12],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let ([aperture, time, iso], _) = payload.as_chunks::<4>() else {
        return Ok(());
    };
    if let Some(aperture) = rational(*aperture).and_then(Rational::aperture) {
        emit_text(APERTURE, &aperture, limit, emit)?;
    }
    if let Some(time) = rational(*time).and_then(Rational::exposure) {
        emit_text(EXPOSURE, &time, limit, emit)?;
    }
    let iso = u32::from_le_bytes(*iso) & 0x7fff_ffff;
    if iso != 0 {
        emit_text(ISO_SPEED, &iso.to_string(), limit, emit)?;
    }
    Ok(())
}

fn emit_text<E>(
    kind: u32,
    value: &str,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if value.len() <= limit {
        emit(kind, value.as_bytes())?;
    }
    Ok(())
}

fn timestamp(fields: [u8; 10]) -> Option<String> {
    let [_, _, lo, hi, month, day, hour, minute, second, fraction] = fields;
    let year = u16::from_le_bytes([lo, hi]);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return None,
    };
    if !(1..=9999).contains(&year)
        || !(1..=days).contains(&day)
        || hour >= 24
        || minute >= 60
        || second > 60
        || fraction >= 100
    {
        return None;
    }
    Some(format!(
        "{year:04}:{month:02}:{day:02} {hour:02}:{minute:02}:{second:02}.{fraction:02}"
    ))
}

fn rational([a, b, c, d]: [u8; 4]) -> Option<Rational> {
    Rational::new(
        i64::from(u16::from_le_bytes([a, b])),
        i64::from(u16::from_le_bytes([c, d])),
    )
}

enum Header {
    Frame,
    Exif,
}

struct Record {
    tag: u32,
    start: u64,
    end: u64,
}

impl Record {
    fn next<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        at: &mut u64,
        bound: u64,
        header: Header,
    ) -> Result<Option<Self>, E> {
        let header_bytes = match header {
            Header::Frame => FRAME_HEADER_BYTES,
            Header::Exif => 8,
        };
        let Some(start) = at
            .checked_add(header_bytes as u64)
            .filter(|&start| start <= bound)
        else {
            return Ok(None);
        };
        let Some([a, b, c, d, lo, hi, e, f, ..]) = input.range(*at, header_bytes)? else {
            return Ok(None);
        };
        let length = u64::from(u32::from_le_bytes([*a, *b, *c, *d]));
        let Some(end) = at
            .checked_add(length)
            .filter(|&end| (start..=bound).contains(&end))
        else {
            return Ok(None);
        };
        let tag = match header {
            Header::Frame => u32::from(u16::from_le_bytes([*lo, *hi])),
            Header::Exif => u32::from_le_bytes([*lo, *hi, *e, *f]),
        };
        *at = end;
        Ok(Some(Self { tag, start, end }))
    }

    fn read_prefix<const N: usize, E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<[u8; N]>, E> {
        if self.end - self.start < N as u64 {
            return Ok(None);
        }
        Ok(input
            .range(self.start, N)?
            .and_then(<[u8]>::first_chunk)
            .copied())
    }
}
