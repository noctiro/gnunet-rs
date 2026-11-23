//! RAW image identities carried by classic TIFF headers and image directories.

use std::num::NonZeroU64;

use super::{
    LinkedPhoto, Selection,
    maker::{self, sony},
    reader::{Kind, Tiff},
};

mod compression;
mod hasselblad;
mod leaf;
pub(super) mod mamiya;
pub(super) mod nikon;
pub(super) mod samsung;

pub(super) use compression::Compression;

pub(super) const CR2_HEADER_BYTES: usize = 16;
const DNG_VERSION: u16 = 0xc612;

/// An ordinary TIFF can carry its first directory at byte 8. Only request
/// a CR2 extension if the directory leaves enough room for the extra header.
pub(super) fn cr2_prefix_candidate(prefix: &[u8]) -> bool {
    first_ifd(prefix).is_some_and(valid_cr2_offset)
}

#[derive(Clone, Copy)]
pub(super) struct Cr2Header {
    raw_ifd: Option<NonZeroU64>,
}

impl Cr2Header {
    pub(super) fn parse(prefix: &[u8]) -> Option<Self> {
        let header = prefix.first_chunk::<CR2_HEADER_BYTES>()?;
        if !cr2_prefix_candidate(header) || &header[8..12] != b"CR\x02\0" {
            return None;
        }
        let offset = tiff_u32(header, header.last_chunk()?)?;
        Some(Self {
            raw_ifd: NonZeroU64::new(u64::from(offset)).filter(|_| valid_cr2_offset(offset)),
        })
    }

    pub(super) fn raw_ifd(self) -> Option<u64> {
        self.raw_ifd.map(NonZeroU64::get)
    }
}

fn first_ifd(prefix: &[u8]) -> Option<u32> {
    let header = prefix.first_chunk::<8>()?;
    match header.first_chunk::<4>()? {
        b"II*\0" | b"MM\0*" => tiff_u32(header, header.last_chunk()?),
        _ => None,
    }
}

fn tiff_u32(prefix: &[u8], bytes: &[u8; 4]) -> Option<u32> {
    Some(match prefix.first_chunk()? {
        b"II" => u32::from_le_bytes(*bytes),
        b"MM" => u32::from_be_bytes(*bytes),
        _ => return None,
    })
}

fn valid_cr2_offset(offset: u32) -> bool {
    offset >= CR2_HEADER_BYTES as u32 && offset.is_multiple_of(2)
}

pub(super) const fn is_identity_tag(tag: u16) -> bool {
    matches!(tag, Compression::TAG | DNG_VERSION)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Subtype {
    Cr2,
    Dng,
    Arw,
    Arw1,
    Sr2,
    Srf,
    Erf,
    Srw,
    Nef,
    Nrw,
    Dcr,
    Kdc,
    Pef,
    Hasselblad3fr,
    Mos,
    Mef,
}

impl Subtype {
    pub(super) const fn mime(self) -> &'static [u8] {
        match self {
            Self::Cr2 => b"image/x-canon-cr2",
            Self::Dng => b"image/x-adobe-dng",
            Self::Arw | Self::Arw1 => b"image/x-sony-arw",
            Self::Sr2 => b"image/x-sony-sr2",
            Self::Srf => b"image/x-sony-srf",
            Self::Erf => b"image/x-epson-erf",
            Self::Srw => b"image/x-samsung-srw",
            Self::Nef => b"image/x-nikon-nef",
            Self::Nrw => b"image/x-nikon-nrw",
            Self::Dcr => b"image/x-kodak-dcr",
            Self::Kdc => b"image/x-kodak-kdc",
            Self::Pef => b"image/x-pentax-pef",
            Self::Hasselblad3fr => b"image/x-hasselblad-3fr",
            Self::Mos => b"image/x-leaf-mos",
            Self::Mef => b"image/x-mamiya-mef",
        }
    }

    /// The required DNGVersion is a four-byte version in IFD0.
    pub(super) fn dng<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(field) = root.find(DNG_VERSION).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Byte && field.row.count() == 4
        }) else {
            return Ok(None);
        };
        Ok(tiff
            .read_field(&field.row)?
            .is_some_and(|version| version.bytes().starts_with(&[1]))
            .then_some(Self::Dng))
    }

    pub(super) fn sony<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
        photo: Option<&LinkedPhoto>,
    ) -> Result<Option<Self>, E> {
        let Some(note) = photo
            .and_then(|photo| photo.fields.find(maker::TAG))
            .filter(|note| !note.duplicate)
        else {
            return Ok(None);
        };
        Ok(
            sony::raw_format(tiff, image, note.row)?.map(|format| match format {
                sony::RawFormat::Srf => Self::Srf,
                sony::RawFormat::Sr2 => Self::Sr2,
                sony::RawFormat::Arw1 => Self::Arw1,
                sony::RawFormat::Arw => Self::Arw,
            }),
        )
    }
}

pub(super) enum PrivateMetadata {
    Kodak(maker::kodak::Kdc),
    Leaf(leaf::Metadata),
    Hasselblad(hasselblad::Metadata),
}

impl PrivateMetadata {
    pub(super) const fn accepts_root_tag(tag: u16) -> bool {
        matches!(
            tag,
            maker::kodak::KDC_IFD | leaf::TAG | hasselblad::ROOT_TAG
        )
    }

    pub(super) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
        identified: Option<Subtype>,
    ) -> Result<Option<Self>, E> {
        if matches!(identified, None | Some(Subtype::Kdc))
            && let Some(kdc) = maker::kodak::Kdc::read(tiff, image)?
        {
            return Ok(Some(Self::Kodak(kdc)));
        }
        if identified.is_some() {
            return Ok(None);
        }
        if let Some(leaf) = leaf::Metadata::read(tiff, image)? {
            return Ok(Some(Self::Leaf(leaf)));
        }
        Ok(hasselblad::Metadata::read(tiff, image)?.map(Self::Hasselblad))
    }

    pub(super) const fn subtype(&self) -> Subtype {
        match self {
            Self::Kodak(_) => Subtype::Kdc,
            Self::Leaf(_) => Subtype::Mos,
            Self::Hasselblad(_) => Subtype::Hasselblad3fr,
        }
    }

    pub(super) fn emit<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        match self {
            Self::Kodak(kdc) => kdc.emit(limit, emit),
            Self::Leaf(mos) => mos.emit(tiff, limit, emit),
            Self::Hasselblad(three_fr) => three_fr.emit(tiff, limit, emit),
        }
    }
}

pub(super) fn is_sony<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
) -> Result<bool, E> {
    let Some(make) = image
        .find(maker::MAKE)
        .filter(|make| !make.duplicate && make.row.kind() == Kind::Ascii && make.row.len() <= 32)
    else {
        return Ok(false);
    };
    Ok(tiff
        .read_field(&make.row)?
        .and_then(|entry| entry.string())
        .is_some_and(|make| make.trim_ascii_end() == "SONY"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::{
        Input,
        tiff::{Container, ProfileKind},
    };
    use std::convert::Infallible;

    const DNG: &[u8; 12] = b"\x12\xc6\x01\0\x04\0\0\0\x01\x07\x01\0";
    const DNG_WRONG_TYPE: &[u8; 12] = b"\x12\xc6\x07\0\x04\0\0\0\x01\x07\x01\0";
    const NEF: &[u8; 12] = b"\x03\x01\x03\0\x01\0\0\0\x99\x87\0\0";

    #[test]
    fn cr2_marker_requires_classic_tiff_header_room() {
        for prefix in [
            b"II*\0\x10\0\0\0CR\x02\0\x12\0\0\0",
            b"MM\0*\0\0\0\x10CR\x02\0\0\0\0\x12",
        ] {
            assert!(cr2_prefix_candidate(&prefix[..8]));
            assert_eq!(
                Cr2Header::parse(prefix).and_then(Cr2Header::raw_ifd),
                Some(18)
            );
            assert!(Cr2Header::parse(&prefix[..15]).is_none());
        }
        assert!(Cr2Header::parse(b"II*\0\x08\0\0\0CR\x02\0\x12\0\0\0").is_none());
        assert!(Cr2Header::parse(b"II+\0\x10\0\0\0CR\x02\0\x12\0\0\0").is_none());
        assert!(Cr2Header::parse(b"II*\0\x10\0\0\0CR\x03\0\x12\0\0\0").is_none());
        let without_raw_link = Cr2Header::parse(b"II*\0\x10\0\0\0CR\x02\0\0\0\0\0");
        assert!(without_raw_link.is_some());
        assert_eq!(without_raw_link.and_then(Cr2Header::raw_ifd), None);
    }

    #[test]
    fn ifd_identity_requires_unique_correctly_typed_fields() {
        assert_eq!(
            classify(&[DNG, NEF]),
            Some((Some(Subtype::Dng), Some(Subtype::Nef)))
        );
        assert_eq!(
            classify(&[DNG_WRONG_TYPE, NEF]),
            Some((None, Some(Subtype::Nef)))
        );
        assert_eq!(classify(&[DNG, NEF, DNG, NEF]), Some((None, None)));
    }

    fn classify(rows: &[&[u8; 12]]) -> Option<(Option<Subtype>, Option<Subtype>)> {
        let mut bytes = b"II*\0\x08\0\0\0".to_vec();
        bytes.extend_from_slice(&u16::try_from(rows.len()).ok()?.to_le_bytes());
        for row in rows {
            bytes.extend_from_slice(*row);
        }
        bytes.extend_from_slice(&[0; 4]);
        let input = Input::new(&bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| {
            Ok::<(), Infallible>(())
        });
        let mut tiff = Tiff::open(input, ProfileKind::Standalone(Container::Tiff)).ok()??;
        let first = tiff.first_offset();
        let root = Selection::read(&mut tiff, first, is_identity_tag).ok()??;
        let compression = Compression::read(&mut tiff, &root).ok()?;
        Some((
            Subtype::dng(&mut tiff, &root).ok()?,
            compression.subtype(&mut tiff, &root, &root).ok()?,
        ))
    }
}
