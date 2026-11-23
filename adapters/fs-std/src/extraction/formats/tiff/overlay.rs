//! EXIF profile union over independent TIFF sources.

use super::{
    Entry, GPS_IFD, ISO_SPEED, Input, Kind, MAX_KNOWN_TAGS, PHOTO_IFD, ProfileKind, Selected,
    Selection, Tiff, UnicodeComment, emit_entry, extended_sensitivity, gps_field, image_field,
    legacy_sensitivity, maker, offset_payload, photo_field,
};
use crate::extraction::formats::IMAGE_ORIENTATION;
use std::{convert::Infallible, rc::Rc};

type SliceTiff<'a, E> = Tiff<'a, fn(u64, &mut [u8]) -> Result<(), E>>;

fn open<E>(bytes: &[u8]) -> Result<Option<SliceTiff<'_, E>>, E> {
    let read: fn(u64, &mut [u8]) -> Result<(), E> = |_, _| Ok(());
    Tiff::open(
        Input::new(bytes, bytes.len() as u64, &mut [], read),
        ProfileKind::Embedded,
    )
}

struct Source {
    bytes: Vec<u8>,
    maker: Option<maker::Vendor>,
}

/// One validated ExifDataBlock with offsets relative to its original TIFF.
pub(in crate::extraction::formats) struct ExifLayer {
    source: Source,
    cost: usize,
    image: Selection,
    photo: Option<Selection>,
    gps: Option<Selection>,
}

impl ExifLayer {
    pub(in crate::extraction::formats) fn read(block: &[u8], allowance: usize) -> Option<Self> {
        let cost = block.len();
        if cost > allowance {
            return None;
        }
        let bytes = offset_payload(block)?;
        let mut tiff = open::<Infallible>(bytes).ok()??;
        let root = tiff.first_offset();
        let profile = ProfileKind::Embedded;
        let image = Selection::read(&mut tiff, root, |tag| {
            matches!(tag, PHOTO_IFD | GPS_IFD) || image_field(tag, profile).is_some()
        })
        .ok()??;
        let photo = image.read_photo(&mut tiff, profile).ok()?;
        let maker = if photo
            .as_ref()
            .and_then(|directory| directory.fields.find(maker::TAG))
            .is_some_and(|note| !note.duplicate)
        {
            maker::Vendor::read(&mut tiff, &image).ok()?
        } else {
            None
        };
        let photo_offset = photo.as_ref().map(|directory| directory.offset);
        let gps = match image
            .child(&mut tiff, GPS_IFD, profile)
            .ok()?
            .filter(|&offset| offset != root && Some(offset) != photo_offset)
        {
            Some(offset) => {
                Selection::read(&mut tiff, offset, |tag| gps_field(tag).is_some()).ok()?
            }
            None => None,
        };
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).ok()?;
        owned.extend_from_slice(bytes);
        Some(Self {
            source: Source {
                bytes: owned,
                maker,
            },
            cost,
            image,
            photo: photo.map(|directory| directory.fields),
            gps,
        })
    }

    pub(in crate::extraction::formats) const fn cost(&self) -> usize {
        self.cost
    }
}

struct Field {
    selected: Selected,
    source: Rc<Source>,
}

impl Field {
    fn entry(&self) -> Option<Entry<'_>> {
        self.selected.row.embedded_entry(&self.source.bytes)
    }
}

#[derive(Default)]
struct DirectoryFields {
    fields: [Option<Field>; MAX_KNOWN_TAGS],
}

impl DirectoryFields {
    fn get(&self, tag: u16) -> Option<&Field> {
        self.fields
            .iter()
            .flatten()
            .find(|field| field.selected.row.tag() == tag)
    }

    fn add(&mut self, selection: Selection, source: &Rc<Source>) {
        for selected in selection.rows.into_iter().flatten() {
            let tag = selected.row.tag();
            // Directory offsets describe the original layer and are not metadata values.
            if matches!(tag, PHOTO_IFD | GPS_IFD) {
                continue;
            }
            if let Some(slot) = self.fields.iter_mut().find(|field| {
                field
                    .as_ref()
                    .is_none_or(|field| field.selected.row.tag() == tag)
            }) {
                *slot = Some(Field {
                    selected,
                    source: Rc::clone(source),
                });
            }
        }
    }

    fn emit<E>(
        &self,
        limit: usize,
        field: impl Fn(u16) -> Option<(u32, super::Representation)>,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for original in self.fields.iter().flatten() {
            let Some((kind, representation)) = field(original.selected.row.tag()) else {
                continue;
            };
            if kind != IMAGE_ORIENTATION
                && original.selected.row.len() <= representation.byte_limit(limit)
                && let Some(entry) = original.entry()
            {
                emit_entry(entry, kind, representation, limit, emit)?;
            }
        }
        Ok(())
    }
}

/// The effective fields for one HEIF image, keyed by IFD role and TIFF tag.
pub(in crate::extraction::formats) struct ExifOverlay {
    remaining: usize,
    image: DirectoryFields,
    photo: DirectoryFields,
    gps: DirectoryFields,
}

impl ExifOverlay {
    pub(in crate::extraction::formats) fn new(bytes: usize) -> Self {
        Self {
            remaining: bytes,
            image: DirectoryFields::default(),
            photo: DirectoryFields::default(),
            gps: DirectoryFields::default(),
        }
    }

    pub(in crate::extraction::formats) const fn remaining_bytes(&self) -> usize {
        self.remaining
    }

    pub(in crate::extraction::formats) fn add_block(&mut self, block: &[u8]) -> bool {
        let Some(layer) = ExifLayer::read(block, self.remaining) else {
            return false;
        };
        self.add_sample(None, layer)
    }

    /// Apply an EXIF sample only after all required layers have been collected.
    pub(in crate::extraction::formats) fn add_sample(
        &mut self,
        sync: Option<ExifLayer>,
        sample: ExifLayer,
    ) -> bool {
        let Some(remaining) = self
            .remaining
            .checked_sub(sync.as_ref().map_or(0, ExifLayer::cost))
            .and_then(|remaining| remaining.checked_sub(sample.cost()))
        else {
            return false;
        };
        self.remaining = remaining;
        if let Some(sync) = sync {
            self.add(sync);
        }
        self.add(sample);
        true
    }

    fn add(&mut self, layer: ExifLayer) {
        let source = Rc::new(layer.source);
        self.image.add(layer.image, &source);
        if let Some(photo) = layer.photo {
            self.photo.add(photo, &source);
        }
        if let Some(gps) = layer.gps {
            self.gps.add(gps, &source);
        }
    }

    pub(in crate::extraction::formats) fn visit<E>(
        &self,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.image
            .emit(limit, |tag| image_field(tag, ProfileKind::Embedded), emit)?;
        let version = self
            .photo
            .get(0x9000)
            .filter(|field| !field.selected.duplicate)
            .and_then(Field::entry)
            .filter(|entry| entry.kind() == Kind::Undefined && entry.count() == 4);
        let encoding = UnicodeComment::from_version(version);
        let mut observed = maker::CaptureFields::default();
        let mut emit_photo = |kind, value: &[u8]| {
            observed.observe(kind);
            emit(kind, value)
        };
        self.photo
            .emit(limit, |tag| photo_field(tag, encoding), &mut emit_photo)?;
        let sensitivity = self
            .photo
            .get(0x8827)
            .and_then(Field::entry)
            .and_then(legacy_sensitivity)
            .or_else(|| {
                self.photo
                    .get(0x8833)
                    .and_then(Field::entry)
                    .and_then(extended_sensitivity)
            });
        if let Some(iso) = sensitivity {
            let value = iso.to_string();
            if value.len() <= limit {
                emit_photo(ISO_SPEED, value.as_bytes())?;
            }
        }
        if let Some(note) = self
            .photo
            .get(maker::TAG)
            .filter(|note| !note.selected.duplicate)
            && let Some(vendor) = note.source.maker
            && let Some(mut tiff) = open(&note.source.bytes)?
        {
            maker::visit(&mut tiff, note.selected.row, vendor, observed, limit, emit)?;
        }
        self.gps.emit(limit, gps_field, emit)
    }
}
