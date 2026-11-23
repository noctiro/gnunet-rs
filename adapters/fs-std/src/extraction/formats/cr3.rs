//! Canon CR3 camera directories, timed metadata, and Adobe XMP.

mod ctmd;

use std::collections::BTreeSet;

use super::{
    Input,
    boxes::{BoxSpan, file_type},
    tiff::CanonDirectory,
    xmp,
};

const BRAND: [u8; 4] = *b"crx ";
const CANON_UUID: [u8; 16] = [
    0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48,
];
const UUID_BYTES: u64 = CANON_UUID.len() as u64;

pub(super) fn detect(prefix: &[u8]) -> bool {
    file_type(prefix).is_some_and(|file_type| file_type.major == BRAND)
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
    if file_type.kind != *b"ftyp"
        || file_type.len() < 8
        || !file_type.len().is_multiple_of(4)
        || input.range(file_type.data, BRAND.len())? != Some(BRAND.as_slice())
    {
        return Ok(());
    }

    let mut movie = None;
    let mut packet = None;
    let mut at = file_type.end;
    while let Some(span) = BoxSpan::read(&mut input, at, extent)? {
        at = span.end;
        match &span.kind {
            b"moov" if movie.is_none() => {
                movie = Movie::read(&mut input, &span)?;
            }
            b"uuid"
                if packet.is_none()
                    && span.len() > UUID_BYTES
                    && matches_uuid(&mut input, &span, &xmp::UUID)? =>
            {
                packet = Some(span);
            }
            _ => {}
        }
        if movie.is_some() && packet.is_some() {
            break;
        }
    }

    let mut kinds = BTreeSet::new();
    {
        let mut collect = |kind, value: &[u8]| {
            kinds.insert(kind);
            emit(kind, value)
        };
        if let Some(directories) = movie.as_mut().and_then(|movie| movie.directories.take()) {
            directories.visit(&mut input, limit, &mut collect)?;
        }
        if let Some(span) = packet
            && let Ok(length) = usize::try_from(span.len() - UUID_BYTES)
            && let Some(bytes) = input.range(span.data + UUID_BYTES, length)?
        {
            xmp::visit(bytes, limit, &mut collect)?;
        }
    }
    if let Some(movie) = movie {
        ctmd::visit(
            &mut input,
            &movie.span,
            &movie.tracks,
            limit,
            &mut |kind, value| {
                if kinds.insert(kind) {
                    emit(kind, value)?;
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

fn matches_uuid<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
    uuid: &[u8; 16],
) -> Result<bool, E> {
    Ok(span.len() >= UUID_BYTES && input.range(span.data, uuid.len())? == Some(uuid.as_slice()))
}

struct Movie {
    span: BoxSpan,
    directories: Option<Directories>,
    tracks: Vec<BoxSpan>,
}

impl Movie {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        movie: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        let mut at = movie.data;
        let mut directories = None;
        let mut tracks = Vec::new();
        let mut seen_canon = false;
        while at < movie.end {
            let Some(span) = BoxSpan::read(input, at, movie.end)? else {
                return Ok(None);
            };
            at = span.end;
            match &span.kind {
                b"uuid" if matches_uuid(input, &span, &CANON_UUID)? => {
                    directories = if seen_canon {
                        None
                    } else {
                        Directories::read(input, &span)?
                    };
                    seen_canon = true;
                }
                b"trak" => {
                    if tracks.try_reserve(1).is_err() {
                        return Ok(None);
                    }
                    tracks.push(span);
                }
                _ => {}
            }
        }
        Ok(Some(Self {
            span: *movie,
            directories,
            tracks,
        }))
    }
}

#[derive(Default)]
struct Directories {
    image: Option<BoxSpan>,
    photo: Option<BoxSpan>,
    maker: Option<BoxSpan>,
    gps: Option<BoxSpan>,
}

impl Directories {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        canon: &BoxSpan,
    ) -> Result<Option<Self>, E> {
        let mut directories = Self::default();
        let mut at = canon.data + UUID_BYTES;
        while at < canon.end {
            let Some(span) = BoxSpan::read(input, at, canon.end)? else {
                return Ok(None);
            };
            at = span.end;
            let directory = match &span.kind {
                b"CMT1" => &mut directories.image,
                b"CMT2" => &mut directories.photo,
                b"CMT3" => &mut directories.maker,
                b"CMT4" => &mut directories.gps,
                _ => continue,
            };
            if directory.replace(span).is_some() {
                return Ok(None);
            }
        }
        Ok(Some(directories))
    }

    fn visit<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for (role, span) in [
            (CanonDirectory::Image, self.image),
            (CanonDirectory::Photo, self.photo),
            (CanonDirectory::Maker, self.maker),
            (CanonDirectory::Gps, self.gps),
        ] {
            if let Some(span) = span
                && let Some(directory) = input.section(span.data, span.len())
            {
                role.visit(directory, limit, emit)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
