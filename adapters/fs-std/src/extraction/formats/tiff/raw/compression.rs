//! TIFF compression evidence for RAW identity and primary-image selection.

use super::{
    super::{maker, primary, reader::Kind},
    Selection, Subtype, Tiff, samsung,
};

const SONY_ARW: u16 = 32767;
const PACKED_RAW: u16 = 32769;
const SAMSUNG_SRW: u16 = 32770;
const SAMSUNG_SRW_2: u16 = 32772;
const PACKBITS: u16 = 32773;
const KODAK_KDC: u16 = 32867;
const NIKON_NEF: u16 = 34713;
const KODAK_DCR: u16 = 65000;
const PENTAX_PEF: u16 = 65535;

#[derive(Clone, Copy)]
pub(in crate::extraction::formats::tiff) struct Compression(Option<u16>);

impl Compression {
    pub(super) const TAG: u16 = 0x0103;

    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
    ) -> Result<Self, E> {
        Self::read_with(tiff, image, |kind| kind == Kind::Short)
    }

    pub(super) fn is_samsung<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
    ) -> Result<bool, E> {
        let compression =
            Self::read_with(tiff, image, |kind| matches!(kind, Kind::Short | Kind::Long))?;
        Ok(matches!(
            compression.0,
            Some(PACKED_RAW | SAMSUNG_SRW | SAMSUNG_SRW_2 | PACKBITS)
        ))
    }

    fn read_with<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
        accepts: impl FnOnce(Kind) -> bool,
    ) -> Result<Self, E> {
        let Some(field) = image.find(Self::TAG).filter(|field| {
            !field.duplicate && field.row.count() == 1 && accepts(field.row.kind())
        }) else {
            return Ok(Self(None));
        };
        Ok(Self(
            tiff.read_field(&field.row)?
                .and_then(|entry| entry.unsigned(0))
                .and_then(|value| u16::try_from(value).ok()),
        ))
    }

    pub(in crate::extraction::formats::tiff) const fn value(self) -> Option<u16> {
        self.0
    }

    pub(in crate::extraction::formats::tiff) const fn is_raw(self) -> bool {
        matches!(self.0, Some(PACKED_RAW)) || self.distinct_subtype().is_some()
    }

    pub(in crate::extraction::formats::tiff) fn subtype<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
        image: &Selection,
    ) -> Result<Option<Subtype>, E> {
        match self.0 {
            Some(PACKED_RAW) => Ok(match PackedMake::read(tiff, root)? {
                Some(PackedMake::Epson) => Some(Subtype::Erf),
                Some(PackedMake::Samsung) => Some(Subtype::Srw),
                None => None,
            }),
            // Samsung reuses the standard PackBits code. The image directory
            // must describe a sensor mosaic and belong to a Samsung file.
            Some(PACKBITS) if primary::photometric(tiff, image)? == Some(32803) => Ok(matches!(
                PackedMake::read(tiff, root)?,
                Some(PackedMake::Samsung)
            )
            .then_some(Subtype::Srw)),
            _ => Ok(self.distinct_subtype()),
        }
    }

    const fn distinct_subtype(self) -> Option<Subtype> {
        match self.0 {
            Some(SONY_ARW) => Some(Subtype::Arw),
            Some(SAMSUNG_SRW | SAMSUNG_SRW_2) => Some(Subtype::Srw),
            Some(KODAK_KDC) => Some(Subtype::Kdc),
            Some(NIKON_NEF) => Some(Subtype::Nef),
            Some(KODAK_DCR) => Some(Subtype::Dcr),
            Some(PENTAX_PEF) => Some(Subtype::Pef),
            _ => None,
        }
    }
}

enum PackedMake {
    Epson,
    Samsung,
}

impl PackedMake {
    fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(field) = root.find(maker::MAKE).filter(|field| {
            !field.duplicate
                && field.row.kind() == Kind::Ascii
                && field.row.len() <= samsung::MAKE_BYTES
        }) else {
            return Ok(None);
        };
        let Some(entry) = tiff.read_field(&field.row)? else {
            return Ok(None);
        };
        if samsung::make_token(entry).is_some() {
            return Ok(Some(Self::Samsung));
        }
        Ok(entry
            .string()
            .map(str::trim_ascii)
            .is_some_and(|make| {
                ["SEIKO EPSON CORP.", "SEIKO EPSON", "EPSON"]
                    .iter()
                    .any(|name| make.eq_ignore_ascii_case(name))
            })
            .then_some(Self::Epson))
    }
}
