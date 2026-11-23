//! Bounded built-in metadata extraction from an original file observation.

mod boxes;
mod camera;
mod compression;
mod cr3;
mod crw;
mod gif;
mod heif;
pub(super) mod icc;
mod id3;
mod iptc;
mod jp2;
mod jpeg;
mod jxl;
mod mrw;
mod pdf;
mod pgf;
mod photoshop;
mod png;
mod projected;
mod psd;
mod raf;
mod tiff;
mod webp;
mod x3f;
mod xmp;

use super::{PdfRecipientAuthorization, pdf_streams::DocumentStreams};
use std::num::NonZeroU32;

const IMAGE_DIMENSIONS: u32 = 112;
const MIME_TYPE: u32 = 1;
const IMAGE_ORIENTATION: u32 = 110;
const ORIENTATION_LABELS: &[&str] = &[
    "top, left",
    "top, right",
    "bottom, right",
    "bottom, left",
    "left, top",
    "right, top",
    "right, bottom",
    "left, bottom",
];

pub(super) struct Input<'a, Read> {
    prefix: &'a [u8],
    base: u64,
    extent: u64,
    scratch: &'a mut [u8],
    allowance: Allowance<'a>,
    projected: Option<projected::Projected<'a>>,
    pdf_streams: Option<DocumentStreams<'a>>,
    pdf_recipient: Option<&'a PdfRecipientAuthorization>,
    read_exact_at: Read,
}

enum Allowance<'a> {
    Owned(usize),
    Borrowed(&'a mut usize),
}

impl Allowance<'_> {
    fn remaining(&mut self) -> &mut usize {
        match self {
            Self::Owned(remaining) => remaining,
            Self::Borrowed(remaining) => remaining,
        }
    }
}

impl<'a, E, Read: FnMut(u64, &mut [u8]) -> Result<(), E>> Input<'a, Read> {
    pub(super) fn new(
        prefix: &'a [u8],
        extent: u64,
        scratch: &'a mut [u8],
        read_exact_at: Read,
    ) -> Self {
        Self {
            prefix,
            base: 0,
            extent,
            allowance: Allowance::Owned(scratch.len()),
            projected: None,
            pdf_streams: None,
            pdf_recipient: None,
            scratch,
            read_exact_at,
        }
    }

    pub(super) fn with_pdf_authorization(
        mut self,
        streams: Option<DocumentStreams<'a>>,
        recipient: Option<&'a PdfRecipientAuthorization>,
    ) -> Self {
        self.pdf_streams = streams;
        self.pdf_recipient = recipient;
        self
    }

    fn charge_unread(&mut self, bytes: usize) -> Option<()> {
        let remaining = self.allowance.remaining();
        *remaining = remaining.checked_sub(bytes)?;
        Some(())
    }

    fn range(&mut self, offset: u64, len: usize) -> Result<Option<&[u8]>, E> {
        let Some(end) = offset
            .checked_add(len as u64)
            .filter(|&end| end <= self.extent)
        else {
            return Ok(None);
        };
        if end <= self.prefix.len() as u64 {
            return Ok(self.prefix.get(offset as usize..end as usize));
        }
        if let Some(projected) = self.projected {
            return projected.read(
                self.base + offset,
                len,
                self.scratch,
                self.allowance.remaining(),
                &mut self.read_exact_at,
            );
        }
        let unread = self.allowance.remaining();
        if len > *unread {
            return Ok(None);
        }
        let Some(bytes) = self.scratch.get_mut(..len) else {
            return Ok(None);
        };
        (self.read_exact_at)(self.base + offset, bytes)?;
        *unread -= len;
        Ok(Some(bytes))
    }

    fn section(&mut self, start: u64, length: u64) -> Option<Input<'_, &mut Read>> {
        let end = start
            .checked_add(length)
            .filter(|&end| end <= self.extent)?;
        let prefix_len = self.prefix.len() as u64;
        Some(Input {
            prefix: &self.prefix[start.min(prefix_len) as usize..end.min(prefix_len) as usize],
            base: self.base + start,
            extent: length,
            scratch: self.scratch,
            allowance: Allowance::Borrowed(self.allowance.remaining()),
            projected: self.projected,
            pdf_streams: None,
            pdf_recipient: None,
            read_exact_at: &mut self.read_exact_at,
        })
    }

    fn projected<'view>(
        &'view mut self,
        map: &'view boxes::compressed::Projection,
    ) -> Option<Input<'view, &'view mut Read>> {
        if self.projected.is_some() {
            return None;
        }
        let unchanged = self
            .prefix
            .len()
            .min(usize::try_from(map.unchanged_prefix_len()).unwrap_or(usize::MAX));
        Some(Input {
            prefix: &self.prefix[..unchanged],
            base: 0,
            extent: map.extent(),
            scratch: self.scratch,
            allowance: Allowance::Borrowed(self.allowance.remaining()),
            projected: Some(projected::Projected {
                map,
                original_prefix: self.prefix,
                origin: self.base,
            }),
            pdf_streams: None,
            pdf_recipient: None,
            read_exact_at: &mut self.read_exact_at,
        })
    }

    fn probe(&mut self, cache: &'a mut [u8]) -> Result<Option<Format>, E> {
        let limit = self.extent.min(cache.len() as u64) as usize;
        let initial = limit.min(8);
        let cached = self.prefix.len().min(limit);
        cache[..cached].copy_from_slice(&self.prefix[..cached]);
        if cached < initial {
            let Some(bytes) = self.range(cached as u64, initial - cached)? else {
                return Ok(None);
            };
            cache[cached..initial].copy_from_slice(bytes);
        }
        let mut filled = cached.max(initial);
        loop {
            let length = Format::identification_len(&cache[..filled], limit);
            if length <= filled {
                break;
            }
            let Some(bytes) = self.range(filled as u64, length - filled)? else {
                return Ok(None);
            };
            cache[filled..length].copy_from_slice(bytes);
            filled = length;
        }
        if filled <= cached {
            return Ok(Format::detect(self.prefix));
        }
        self.prefix = &cache[..filled];
        Ok(Format::detect(self.prefix))
    }

    fn unread_bytes(&self) -> usize {
        match &self.allowance {
            Allowance::Owned(remaining) => *remaining,
            Allowance::Borrowed(remaining) => **remaining,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Format {
    Png,
    Jpeg,
    Exv,
    Jpeg2000(jp2::Brand),
    JpegXl,
    CompressedBmff,
    Cr3,
    Crw,
    Heif(heif::Brand),
    Tiff(tiff::Container),
    Raf,
    Mrw,
    X3f,
    Psd,
    Pdf,
    Pgf,
    WebP,
    Gif,
    Id3,
}

#[derive(Clone, Copy)]
pub(super) struct FieldLimits {
    pub(super) text: usize,
    pub(super) icc: usize,
}

pub(super) enum Field<'a> {
    Text(u32, &'a [u8]),
    ColorProfile(icc::Profile<'a>),
}

#[cfg(test)]
pub(super) fn text_only<E>(
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> impl FnMut(Field<'_>) -> Result<(), E> {
    |field| match field {
        Field::Text(kind, bytes) => emit(kind, bytes),
        Field::ColorProfile(_) => Ok(()),
    }
}

#[cfg(test)]
impl FieldLimits {
    const fn text_only(text: usize) -> Self {
        Self { text, icc: 0 }
    }
}

impl Format {
    pub(super) fn identification_len(prefix: &[u8], limit: usize) -> usize {
        if prefix.starts_with(&jp2::SIGNATURE[..8]) {
            // Read the signature and the brand, allowing an extended box header.
            prefix.len().max(limit.min(jp2::IDENTIFICATION_BYTES))
        } else if prefix.starts_with(&jxl::SIGNATURE[..8]) {
            prefix.len().max(limit.min(jxl::HEADER_BYTES))
        } else if prefix.get(4..8) == Some(b"ftyp") {
            prefix.len().max(limit.min(boxes::file_type_probe_len(
                prefix,
                heif::IDENTIFICATION_BYTES,
            )))
        } else if prefix.starts_with(&raf::SIGNATURE[..8]) {
            prefix.len().max(limit.min(raf::SIGNATURE.len()))
        } else if let Some(bytes) = tiff::identification_bytes(prefix) {
            prefix.len().max(limit.min(bytes))
        } else if crw::is_candidate(prefix) {
            prefix.len().max(limit.min(crw::IDENTIFICATION_BYTES))
        } else if prefix.starts_with(b"RIFF") {
            prefix.len().max(limit.min(webp::HEADER_BYTES))
        } else {
            match Self::detect(prefix) {
                Some(Self::Gif) => prefix.len().max(limit.min(gif::HEADER_BYTES)),
                Some(format) if format.uses_positioned_reads() => prefix.len(),
                _ => limit,
            }
        }
    }

    pub(super) fn detect(prefix: &[u8]) -> Option<Self> {
        if prefix.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if prefix.starts_with(b"\xff\xd8\xff") {
            Some(Self::Jpeg)
        } else if prefix.starts_with(jpeg::EXV_SIGNATURE) {
            Some(Self::Exv)
        } else if let Some(brand) = jp2::brand(prefix) {
            Some(Self::Jpeg2000(brand))
        } else if jxl::is_jxl(prefix) {
            Some(Self::JpegXl)
        } else if boxes::file_type(prefix)
            .is_some_and(|kind| kind.major == *b"comp" || kind.compatible.contains(b"comp"))
        {
            Some(Self::CompressedBmff)
        } else if cr3::detect(prefix) {
            Some(Self::Cr3)
        } else if crw::detect(prefix) {
            Some(Self::Crw)
        } else if let Some(brand) = heif::Brand::detect(prefix) {
            Some(Self::Heif(brand))
        } else if webp::is_webp(prefix) {
            Some(Self::WebP)
        } else if let Some(container) = tiff::Container::detect(prefix) {
            Some(Self::Tiff(container))
        } else if prefix.starts_with(raf::SIGNATURE) {
            Some(Self::Raf)
        } else if prefix.starts_with(mrw::SIGNATURE) {
            Some(Self::Mrw)
        } else if prefix.starts_with(x3f::SIGNATURE) {
            Some(Self::X3f)
        } else if matches!(prefix.first_chunk(), Some(b"8BPS\0\x01" | b"8BPS\0\x02")) {
            Some(Self::Psd)
        } else if prefix.starts_with(b"%PDF-") {
            Some(Self::Pdf)
        } else if prefix.starts_with(pgf::SIGNATURE) {
            Some(Self::Pgf)
        } else if prefix.starts_with(b"GIF87a") || prefix.starts_with(b"GIF89a") {
            Some(Self::Gif)
        } else if prefix.starts_with(b"ID3") {
            Some(Self::Id3)
        } else {
            None
        }
    }

    pub(super) const fn mime(self) -> &'static [u8] {
        match self {
            Self::Png => b"image/png",
            Self::Jpeg => b"image/jpeg",
            Self::Exv => b"image/x-exv",
            Self::Jpeg2000(brand) => brand.mime(),
            Self::JpegXl => b"image/jxl",
            Self::CompressedBmff => b"application/mp4",
            Self::Cr3 => b"image/x-canon-cr3",
            Self::Crw => b"image/x-canon-crw",
            Self::Heif(brand) => brand.mime(),
            Self::Tiff(container) => container.mime(),
            Self::Raf => b"image/x-fuji-raf",
            Self::Mrw => b"image/x-minolta-mrw",
            Self::X3f => b"image/x-sigma-x3f",
            Self::Psd => b"image/vnd.adobe.photoshop",
            Self::Pdf => b"application/pdf",
            Self::Pgf => b"image/pgf",
            Self::WebP => b"image/webp",
            Self::Gif => b"image/gif",
            Self::Id3 => b"audio/mpeg",
        }
    }

    const fn uses_positioned_reads(self) -> bool {
        matches!(
            self,
            Self::Png
                | Self::Jpeg
                | Self::Exv
                | Self::Jpeg2000(_)
                | Self::JpegXl
                | Self::CompressedBmff
                | Self::Cr3
                | Self::Crw
                | Self::Heif(_)
                | Self::Tiff(_)
                | Self::Raf
                | Self::Mrw
                | Self::X3f
                | Self::Psd
                | Self::Pdf
                | Self::Pgf
                | Self::WebP
        )
    }

    pub(super) fn visit<E>(
        self,
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limits: FieldLimits,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        if !matches!(self, Self::Tiff(_) | Self::CompressedBmff) {
            emit(Field::Text(MIME_TYPE, self.mime()))?;
        }
        if matches!(self, Self::Pgf) {
            return pgf::visit(input, limits, emit);
        }
        self.visit_leaf(input, limits, emit)
    }

    #[cfg(test)]
    fn visit_text<E>(
        self,
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.visit(input, FieldLimits::text_only(limit), &mut text_only(emit))
    }

    fn visit_leaf<E>(
        self,
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limits: FieldLimits,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        match self {
            Self::Png => return png::visit(input, limits, emit),
            Self::WebP => return webp::visit(input, limits, emit),
            Self::JpegXl => return jxl::visit(input, limits, emit),
            _ => {}
        }
        let max_text_bytes = limits.text;
        let emit = &mut |kind, bytes: &[u8]| emit(Field::Text(kind, bytes));
        match self {
            Self::Jpeg => jpeg::visit(input, max_text_bytes, emit),
            Self::Exv => jpeg::visit_exv(input, max_text_bytes, jpeg::Profiles::All, emit),
            Self::Jpeg2000(_) => jp2::visit(input, max_text_bytes, emit),
            Self::CompressedBmff => visit_compressed(input, max_text_bytes, emit),
            Self::Cr3 => cr3::visit(input, max_text_bytes, emit),
            Self::Crw => crw::visit(input, max_text_bytes, emit),
            Self::Heif(_) => heif::visit(input, max_text_bytes, emit),
            Self::Tiff(container) => container.visit(input, max_text_bytes, emit),
            Self::Raf => raf::visit(input, max_text_bytes, emit),
            Self::Mrw => mrw::visit(input, max_text_bytes, emit),
            Self::X3f => x3f::visit(input, max_text_bytes, emit),
            Self::Psd => psd::visit(input, max_text_bytes, emit),
            Self::Pdf => pdf::visit(input, max_text_bytes, emit),
            Self::Png | Self::Pgf | Self::WebP | Self::JpegXl => Ok(()),
            Self::Gif => gif::visit(input, max_text_bytes, emit),
            Self::Id3 => id3::visit(input.prefix, max_text_bytes, emit),
        }
    }
}

fn visit_compressed<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(map) = boxes::compressed::read(&mut input)? else {
        return Ok(());
    };
    let Some(mut view) = input.projected(&map) else {
        return Ok(());
    };
    let Some(header) = boxes::BoxSpan::read(&mut view, 0, map.extent())? else {
        return Ok(());
    };
    if header.kind != *b"ftyp" {
        return Ok(());
    }
    let Ok(size) = usize::try_from(header.end) else {
        return Ok(());
    };
    let Some(file_type) = view.range(0, size)? else {
        return Ok(());
    };
    if cr3::detect(file_type) {
        emit(MIME_TYPE, Format::Cr3.mime())?;
        return cr3::visit(view, limit, emit);
    }
    if let Some(brand) = heif::Brand::detect(file_type) {
        emit(MIME_TYPE, brand.mime())?;
        return heif::visit(view, limit, emit);
    }
    Ok(())
}

struct Dimensions {
    width: NonZeroU32,
    height: NonZeroU32,
}

impl Dimensions {
    fn new(width: u32, height: u32) -> Option<Self> {
        Some(Self {
            width: NonZeroU32::new(width)?,
            height: NonZeroU32::new(height)?,
        })
    }

    fn emit<E>(&self, emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>) -> Result<(), E> {
        let mut bytes = [0; 21];
        let mut start = decimal(self.height.get(), &mut bytes, 21);
        start -= 1;
        bytes[start] = b'x';
        start = decimal(self.width.get(), &mut bytes, start);
        emit(IMAGE_DIMENSIONS, &bytes[start..])
    }
}

fn decimal(mut number: u32, bytes: &mut [u8], mut end: usize) -> usize {
    loop {
        end -= 1;
        bytes[end] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            return end;
        }
    }
}
