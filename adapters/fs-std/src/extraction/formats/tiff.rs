//! TIFF image, Exif camera, GPS, IPTC and XMP fields in the GNU metadata registry.

mod fields;
mod jis;
mod maker;
mod overlay;
mod panasonic;
mod primary;
mod raw;
mod reader;

use super::{Dimensions, Input, MIME_TYPE, camera::ISO_SPEED, iptc, photoshop, xmp};
use fields::{Representation, UnicodeComment, gps_field, image_field, photo_field};
use reader::{Directory, Entry, Kind, Row, Signature, Tiff};

pub(super) use overlay::{ExifLayer, ExifOverlay};

const PHOTO_IFD: u16 = 0x8769;
const GPS_IFD: u16 = 0x8825;
const XMP: u16 = 700;
const IPTC_NAA: u16 = 33723;
const PHOTOSHOP_RESOURCES: u16 = 34377;
const EXIF_WIDTH: u16 = 0xa002;
const EXIF_HEIGHT: u16 = 0xa003;
const MAX_KNOWN_TAGS: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::extraction) enum Container {
    Tiff,
    Cr2,
    Orf,
    PanasonicRaw,
    Rw2,
}

impl Container {
    pub(super) fn detect(prefix: &[u8]) -> Option<Self> {
        Some(Signature::parse(prefix)?.container())
    }

    pub(super) const fn mime(self) -> &'static [u8] {
        match self {
            Self::Tiff => b"image/tiff",
            Self::Cr2 => raw::Subtype::Cr2.mime(),
            Self::Orf => b"image/x-olympus-orf",
            Self::PanasonicRaw => b"image/x-panasonic-raw",
            Self::Rw2 => b"image/x-panasonic-rw2",
        }
    }

    pub(super) fn visit<E>(
        self,
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let profile = ProfileKind::Standalone(self);
        if matches!(self, Self::PanasonicRaw | Self::Rw2) {
            emit(MIME_TYPE, self.mime())?;
            panasonic::visit(input, profile, limit, emit)
        } else {
            visit_profile(input, profile, limit, emit)
        }
    }
}

pub(super) fn identification_bytes(prefix: &[u8]) -> Option<usize> {
    raw::cr2_prefix_candidate(prefix)
        .then_some(raw::CR2_HEADER_BYTES)
        .or_else(|| panasonic::identification_bytes(prefix))
}

#[derive(Clone, Copy)]
enum ProfileKind {
    Embedded,
    RawTiff,
    Standalone(Container),
}

impl ProfileKind {
    const fn is_standalone(self) -> bool {
        matches!(self, Self::RawTiff | Self::Standalone(_))
    }

    fn emit_mime<E>(
        self,
        subtype: Option<raw::Subtype>,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Self::Standalone(container) = self {
            emit(
                MIME_TYPE,
                subtype.map_or(container.mime(), raw::Subtype::mime),
            )?;
        }
        Ok(())
    }
}

pub(super) fn visit_exif<E>(
    bytes: &[u8],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let input = Input::new(bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| Ok(()));
    visit_embedded(input, limit, emit)
}

fn visit_embedded<E>(
    input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let profile = ProfileKind::Embedded;
    let Some(mut tiff) = Tiff::open(input, profile)? else {
        return Ok(());
    };
    let Some(image) = read_image(&mut tiff, profile)? else {
        return Ok(());
    };
    image.emit(&mut tiff, limit, |tag| image_field(tag, profile), emit)?;
    image.emit_children(&mut tiff, profile, limit, emit)?;
    if let Some(shooting) = maker::kodak::Shooting::read(&mut tiff, &image)? {
        shooting.emit(&mut tiff, limit, emit)?;
    }
    Ok(())
}

/// Extracts the TIFF payload from a HEIF or JPEG XL Exif item.
pub(super) fn offset_payload(bytes: &[u8]) -> Option<&[u8]> {
    let (offset, payload) = bytes.split_first_chunk()?;
    payload.get(usize::try_from(u32::from_be_bytes(*offset)).ok()?..)
}

pub(super) fn visit_raw_tiff<E>(
    input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    visit_profile(input, ProfileKind::RawTiff, limit, emit)
}

/// Classic TIFF root roles carried separately by Canon CR3 CMT boxes.
pub(super) enum CanonDirectory {
    Image,
    Photo,
    Maker,
    Gps,
}

impl CanonDirectory {
    pub(super) fn visit<E>(
        self,
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(mut tiff) = Tiff::open(input, ProfileKind::Embedded)? else {
            return Ok(());
        };
        let root = tiff.first_offset();
        match self {
            Self::Image => {
                let field = |tag| image_field(tag, ProfileKind::Embedded);
                if let Some(image) = Selection::read(&mut tiff, root, |tag| {
                    matches!(tag, XMP | IPTC_NAA | PHOTOSHOP_RESOURCES) || field(tag).is_some()
                })? {
                    image.emit(&mut tiff, limit, field, emit)?;
                    image.emit_profiles(&mut tiff, limit, emit)?;
                }
            }
            Self::Photo => {
                if let Some(photo) = Selection::read(&mut tiff, root, |tag| {
                    matches!(tag, EXIF_WIDTH | EXIF_HEIGHT) || is_photo_field(tag)
                })? {
                    if let Some(dimensions) =
                        photo.dimensions(&mut tiff, EXIF_WIDTH, EXIF_HEIGHT)?
                    {
                        dimensions.emit(emit)?;
                    }
                    photo.emit_photo(&mut tiff, limit, emit)?;
                }
            }
            Self::Maker => {
                if let Some(directory) = tiff.directory(root)? {
                    maker::canon::visit_directory(&mut tiff, directory, limit, emit)?;
                }
            }
            Self::Gps => {
                if let Some(gps) = Selection::read(&mut tiff, root, |tag| gps_field(tag).is_some())?
                {
                    gps.emit(&mut tiff, limit, gps_field, emit)?;
                }
            }
        }
        Ok(())
    }
}

fn read_image<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    profile: ProfileKind,
) -> Result<Option<Selection>, E> {
    Selection::read(tiff, tiff.first_offset(), |tag| {
        matches!(tag, PHOTO_IFD | GPS_IFD | maker::kodak::IFD)
            || profile.is_standalone()
                && (matches!(tag, XMP | IPTC_NAA | PHOTOSHOP_RESOURCES)
                    || raw::PrivateMetadata::accepts_root_tag(tag)
                    || primary::is_image_tag(tag))
            || image_field(tag, profile).is_some()
    })
}

fn visit_profile<E>(
    input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    profile_kind: ProfileKind,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(mut tiff) = Tiff::open(input, profile_kind)? else {
        return profile_kind.emit_mime(None, emit);
    };
    let Some(image) = read_image(&mut tiff, profile_kind)? else {
        return profile_kind.emit_mime(None, emit);
    };

    let cr2 = tiff.cr2_header();
    let kodak = maker::kodak::Shooting::read(&mut tiff, &image)?;
    let mut subtype = None;
    let mut photo = None;
    let mut primary = match profile_kind {
        ProfileKind::Standalone(Container::Tiff) => {
            subtype = raw::Subtype::dng(&mut tiff, &image)?;
            if subtype.is_none()
                && image.find(PHOTO_IFD).is_some()
                && raw::is_sony(&mut tiff, &image)?
            {
                let linked = image.read_photo(&mut tiff, profile_kind)?;
                subtype = raw::Subtype::sony(&mut tiff, &image, linked.as_ref())?;
                photo = Some(linked);
            }
            let nikon = if subtype.is_none() && image.find(PHOTO_IFD).is_some() {
                raw::nikon::Camera::read(&mut tiff, &image)?
            } else {
                None
            };
            let family = if subtype == Some(raw::Subtype::Dng) {
                primary::Family::Dng
            } else {
                nikon.map_or(primary::Family::Tiff, raw::nikon::Camera::family)
            };
            // The first ARW version assigns SubIFDs to the raster start.
            let selected = if subtype == Some(raw::Subtype::Arw1) {
                None
            } else {
                primary::select(&mut tiff, &image, family)?
            };
            if subtype.is_none() {
                let candidate = selected.as_ref().map_or(&image, primary::Alternate::image);
                subtype = selected.as_ref().and_then(primary::Alternate::subtype);
                if subtype.is_none() {
                    let compression = raw::Compression::read(&mut tiff, candidate)?;
                    subtype = compression.subtype(&mut tiff, &image, candidate)?;
                    if subtype.is_none()
                        && let (Some(shooting), Some(sensor)) = (&kodak, &selected)
                        && shooting.is_dc120_raw(&mut tiff, &image, sensor.image(), compression)?
                    {
                        subtype = Some(raw::Subtype::Kdc);
                    }
                    if matches!(subtype, None | Some(raw::Subtype::Nef))
                        && let Some(nikon) = nikon
                        && nikon.candidate(&mut tiff, candidate, compression)?
                    {
                        let linked = image.read_photo(&mut tiff, profile_kind)?;
                        subtype =
                            raw::nikon::subtype(&mut tiff, &image, linked.as_ref(), compression)?
                                .or(subtype);
                        photo = Some(linked);
                    }
                    if subtype.is_none()
                        && raw::mamiya::is_zd(&mut tiff, &image, candidate, compression)?
                    {
                        subtype = Some(raw::Subtype::Mef);
                    }
                }
            }
            selected
        }
        _ => None,
    };
    let private = if matches!(profile_kind, ProfileKind::Standalone(Container::Tiff)) {
        raw::PrivateMetadata::read(&mut tiff, &image, subtype)?
    } else {
        None
    };
    if let Some(metadata) = &private {
        subtype = Some(metadata.subtype());
    }
    profile_kind.emit_mime(subtype, emit)?;

    if profile_kind.is_standalone() {
        let mut dimensions = None;
        if cr2.is_some() {
            let linked = image.read_photo(&mut tiff, profile_kind)?;
            if let Some(linked) = &linked {
                dimensions = linked
                    .fields
                    .dimensions(&mut tiff, EXIF_WIDTH, EXIF_HEIGHT)?;
            }
            photo = Some(linked);
        }
        if dimensions.is_none()
            && let Some(header) = cr2
        {
            primary = primary::select(&mut tiff, &image, primary::Family::Cr2(header))?;
        }
        if dimensions.is_none() {
            dimensions = primary
                .as_ref()
                .map_or(&image, primary::Alternate::image)
                .dimensions(&mut tiff, 256, 257)?;
        }
        if let Some(dimensions) = dimensions {
            dimensions.emit(emit)?;
        }
    }
    image.emit(&mut tiff, limit, |tag| image_field(tag, profile_kind), emit)?;
    if let Some(photo) = photo {
        image.emit_linked(&mut tiff, profile_kind, photo, limit, emit)?;
    } else {
        image.emit_children(&mut tiff, profile_kind, limit, emit)?;
    }
    if let Some(shooting) = kodak {
        shooting.emit(&mut tiff, limit, emit)?;
    }
    if let Some(metadata) = private {
        metadata.emit(&mut tiff, limit, emit)?;
    }
    if profile_kind.is_standalone() {
        image.emit_profiles(&mut tiff, limit, emit)?;
    }
    Ok(())
}

fn is_photo_field(tag: u16) -> bool {
    matches!(tag, 0x9000 | 0x8827 | 0x8833 | maker::TAG)
        || photo_field(tag, UnicodeComment::LegacyUtf16).is_some()
}

#[derive(Clone, Copy)]
struct Selected {
    row: Row,
    duplicate: bool,
}

// Each role has a fixed set of fields. Retain descriptors in one pass so that
// linked offsets and EXIF versions can be resolved before reading values.
struct Selection {
    rows: [Option<Selected>; MAX_KNOWN_TAGS],
}

struct LinkedPhoto {
    offset: u64,
    fields: Selection,
}

impl Selection {
    fn read_photo<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        profile_kind: ProfileKind,
    ) -> Result<Option<LinkedPhoto>, E> {
        let root = tiff.first_offset();
        let Some(offset) = self
            .child(tiff, PHOTO_IFD, profile_kind)?
            .filter(|&offset| offset != root)
        else {
            return Ok(None);
        };
        let fields = Self::read(tiff, offset, |tag| {
            matches!(tag, EXIF_WIDTH | EXIF_HEIGHT) || is_photo_field(tag)
        })?;
        Ok(fields.map(|fields| LinkedPhoto { offset, fields }))
    }

    fn emit_children<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        profile_kind: ProfileKind,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let photo = self.read_photo(tiff, profile_kind)?;
        self.emit_linked(tiff, profile_kind, photo, limit, emit)
    }

    fn emit_linked<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        profile_kind: ProfileKind,
        photo: Option<LinkedPhoto>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let root = tiff.first_offset();
        let photo_offset = photo.as_ref().map(|photo| photo.offset);
        let gps = self
            .child(tiff, GPS_IFD, profile_kind)?
            .filter(|&offset| offset != root && Some(offset) != photo_offset);
        if let Some(photo) = photo {
            let mut observed = maker::CaptureFields::default();
            photo.fields.emit_photo(tiff, limit, &mut |kind, value| {
                observed.observe(kind);
                emit(kind, value)
            })?;
            if let Some(note) = photo.fields.find(maker::TAG).filter(|note| !note.duplicate)
                && let Some(vendor) = maker::Vendor::read(tiff, self)?
            {
                maker::visit(tiff, note.row, vendor, observed, limit, emit)?;
            }
        }
        if let Some(offset) = gps
            && let Some(gps) = Self::read(tiff, offset, |tag| gps_field(tag).is_some())?
        {
            gps.emit(tiff, limit, gps_field, emit)?;
        }
        Ok(())
    }

    fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        offset: u64,
        accepts: impl Fn(u16) -> bool,
    ) -> Result<Option<Self>, E> {
        let Some(directory) = tiff.directory(offset)? else {
            return Ok(None);
        };
        Self::read_directory(tiff, directory, accepts)
    }

    fn read_directory<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        mut directory: Directory,
        accepts: impl Fn(u16) -> bool,
    ) -> Result<Option<Self>, E> {
        let mut rows = [None::<Selected>; MAX_KNOWN_TAGS];
        while let Some(row) = tiff.next(&mut directory)? {
            let tag = row.tag();
            if !accepts(tag) {
                continue;
            }
            let Some(slot) = rows
                .iter_mut()
                .find(|entry| entry.is_none_or(|s| s.row.tag() == tag))
            else {
                return Ok(None);
            };
            match slot {
                Some(previous) => previous.duplicate = true,
                None => {
                    *slot = Some(Selected {
                        row,
                        duplicate: false,
                    })
                }
            }
        }
        Ok(Some(Self { rows }))
    }

    fn find(&self, tag: u16) -> Option<&Selected> {
        self.rows
            .iter()
            .flatten()
            .find(|field| field.row.tag() == tag)
    }

    fn child<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        tag: u16,
        profile_kind: ProfileKind,
    ) -> Result<Option<u64>, E> {
        let Some(field) = self.find(tag) else {
            return Ok(None);
        };
        let valid = match field.row.kind() {
            Kind::Long => true,
            Kind::Ifd | Kind::Long8 | Kind::Ifd8 => profile_kind.is_standalone(),
            _ => false,
        };
        if field.duplicate || !valid || field.row.count() != 1 {
            return Ok(None);
        }
        Ok(tiff
            .read_field(&field.row)?
            .and_then(|entry| entry.unsigned(0))
            .filter(|&offset| offset != 0))
    }

    fn dimension<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        tag: u16,
    ) -> Result<Option<u32>, E> {
        let Some(field) = self.find(tag) else {
            return Ok(None);
        };
        if field.duplicate
            || field.row.count() != 1
            || !matches!(field.row.kind(), Kind::Short | Kind::Long | Kind::Long8)
        {
            return Ok(None);
        }
        let value = tiff
            .read_field(&field.row)?
            .and_then(|entry| entry.unsigned(0));
        Ok(value.and_then(|size| u32::try_from(size).ok()))
    }

    fn dimensions<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        width_tag: u16,
        height_tag: u16,
    ) -> Result<Option<Dimensions>, E> {
        let Some(width) = self.dimension(tiff, width_tag)? else {
            return Ok(None);
        };
        Ok(self
            .dimension(tiff, height_tag)?
            .and_then(|height| Dimensions::new(width, height)))
    }

    fn emit<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        field: impl Fn(u16) -> Option<(u32, Representation)>,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for selected in self.rows.iter().flatten() {
            let Some((kind, representation)) = field(selected.row.tag()) else {
                continue;
            };
            if selected.row.len() <= representation.byte_limit(limit)
                && let Some(entry) = tiff.read_field(&selected.row)?
            {
                emit_entry(entry, kind, representation, limit, emit)?;
            }
        }
        Ok(())
    }

    fn emit_photo<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let encoding = read_comment_encoding(tiff, self)?;
        self.emit(tiff, limit, |tag| photo_field(tag, encoding), emit)?;
        if let Some(iso) = sensitivity(tiff, self)? {
            let value = iso.to_string();
            if value.len() <= limit {
                emit(ISO_SPEED, value.as_bytes())?;
            }
        }
        Ok(())
    }

    fn emit_profiles<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.emit_iptc(tiff, limit, emit)?;
        if let Some(field) = self.find(XMP).filter(|field| !field.duplicate)
            && matches!(field.row.kind(), Kind::Byte | Kind::Undefined)
            && let Some(entry) = tiff.read_field(&field.row)?
        {
            xmp::visit(entry.bytes(), limit, emit)?;
        }
        Ok(())
    }

    fn emit_iptc<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(field) = self.find(IPTC_NAA).filter(|field| !field.duplicate)
            && matches!(field.row.kind(), Kind::Byte | Kind::Undefined | Kind::Long)
            && let Some(entry) = tiff.read_field(&field.row)?
            && emit_iptc_field(entry.bytes(), entry.kind(), limit, emit)?
        {
            return Ok(());
        }
        let Some(field) = self
            .find(PHOTOSHOP_RESOURCES)
            .filter(|field| !field.duplicate)
        else {
            return Ok(());
        };
        if !matches!(field.row.kind(), Kind::Byte | Kind::Undefined) {
            return Ok(());
        }
        let Some(span) = photoshop::resource(
            field.row.len(),
            photoshop::IPTC_IIM,
            |start, target| -> Result<bool, E> {
                let Some(bytes) = tiff.read_field_range(&field.row, start, target.len())? else {
                    return Ok(false);
                };
                target.copy_from_slice(bytes);
                Ok(true)
            },
        )?
        else {
            return Ok(());
        };
        if let Some(bytes) = tiff.read_field_range(&field.row, span.start, span.len())?
            && let Some(profile) = iptc::Profile::parse(bytes, 0)
        {
            profile.emit(limit, emit)?;
        }
        Ok(())
    }
}

/// RichTIFFIPTC LONG values may contain literal IIM bytes or reversed words.
fn emit_iptc_field<E>(
    bytes: &[u8],
    kind: Kind,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let word_packed = kind == Kind::Long;
    if let Some(profile) = iptc::Profile::parse(bytes, if word_packed { 3 } else { 0 }) {
        profile.emit(limit, emit)?;
        return Ok(true);
    }
    if word_packed && bytes.get(3) == Some(&0x1c) {
        let mut reversed = Vec::new();
        if reversed.try_reserve_exact(bytes.len()).is_ok() {
            reversed.extend_from_slice(bytes);
            for word in reversed.as_chunks_mut::<4>().0 {
                word.reverse();
            }
            if let Some(profile) = iptc::Profile::parse(&reversed, 3) {
                profile.emit(limit, emit)?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn read_comment_encoding<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    photo: &Selection,
) -> Result<UnicodeComment, E> {
    let version = if let Some(field) = photo.find(0x9000)
        && !field.duplicate
        && field.row.kind() == Kind::Undefined
        && field.row.count() == 4
    {
        tiff.read_field(&field.row)?
    } else {
        None
    };
    Ok(UnicodeComment::from_version(version))
}

fn emit_entry<E>(
    entry: Entry<'_>,
    kind: u32,
    representation: Representation,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(value) = representation.decode(entry, limit)
        && !value.is_empty()
        && value.len() <= limit
    {
        emit(kind, value.as_bytes())?;
    }
    Ok(())
}

fn legacy_sensitivity(entry: Entry<'_>) -> Option<u64> {
    if entry.kind() != Kind::Short {
        return None;
    }
    entry
        .unsigned(0)
        .filter(|value| (1..65_535).contains(value))
}

fn extended_sensitivity(entry: Entry<'_>) -> Option<u64> {
    if entry.kind() != Kind::Long || entry.count() != 1 {
        return None;
    }
    entry.unsigned(0).filter(|&value| value != 0)
}

fn sensitivity<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    fields: &Selection,
) -> Result<Option<u64>, E> {
    if let Some(legacy) = fields.find(0x8827)
        && legacy.row.kind() == Kind::Short
        && let Some(value) = tiff.read_field(&legacy.row)?.and_then(legacy_sensitivity)
    {
        return Ok(Some(value));
    }
    let Some(extended) = fields.find(0x8833) else {
        return Ok(None);
    };
    if extended.row.kind() != Kind::Long || extended.row.count() != 1 {
        return Ok(None);
    }
    Ok(tiff
        .read_field(&extended.row)?
        .and_then(extended_sensitivity))
}

#[cfg(test)]
mod tests;
