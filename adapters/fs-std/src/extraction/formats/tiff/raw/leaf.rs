//! Creo Leaf MOS metadata in a bounded tree of PKTS records.

use super::super::{Kind, Row, Selection, Tiff, maker, reader::ByteOrder};
use crate::extraction::formats::{IMAGE_DIMENSIONS, IMAGE_ORIENTATION, Input, camera, jpeg};
use std::{num::NonZeroU32, ops::Range};

pub(in crate::extraction::formats::tiff) const TAG: u16 = 0x8606;

const MAKE: u32 = 95;
const MODEL: u32 = 96;
const PACKET_HEADER_BYTES: usize = 52;
const MAX_NUMBER_BYTES: usize = 24;

// Decimal ShootObj_back_type identifiers documented by LibRaw.
const BACKS: &[&str] = &[
    "",
    "DCB2",
    "Volare",
    "Cantare",
    "CMost",
    "Valeo 6",
    "Valeo 11",
    "Valeo 22",
    "Valeo 11p",
    "Valeo 17",
    "",
    "Aptus 17",
    "Aptus 22",
    "Aptus 75",
    "Aptus 65",
    "Aptus 54S",
    "Aptus 65S",
    "Aptus 75S",
    "AFi 5",
    "AFi 6",
    "AFi 7",
    "AFi-II 7",
    "Aptus-II 7",
    "",
    "Aptus-II 6",
    "AFi-II 10",
    "",
    "Aptus-II 10",
    "Aptus-II 5",
    "",
    "DM33",
    "",
    "",
    "Aptus-II 10R",
    "Aptus-II 8",
    "",
    "Aptus-II 12",
    "",
    "AFi-II 12",
];

pub(in crate::extraction::formats::tiff) struct Metadata {
    owner: Row,
    has_make: bool,
    has_model: bool,
    fields: Fields,
}

impl Metadata {
    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(field) = root.find(TAG).filter(|field| {
            !field.duplicate && matches!(field.row.kind(), Kind::Byte | Kind::Undefined)
        }) else {
            return Ok(None);
        };
        let order = tiff.byte_order();
        let Some(mut packets) = tiff.section_for_field(field.row) else {
            return Ok(None);
        };
        let mut fields = Fields::default();
        let extent = packets.extent;
        if !fields.read(&mut packets, order, Directory::Root, 0..extent)? {
            return Ok(None);
        }
        Ok(Some(Self {
            owner: field.row,
            has_make: root.find(maker::MAKE).is_some_and(|field| !field.duplicate),
            has_model: root
                .find(maker::MODEL)
                .is_some_and(|field| !field.duplicate),
            fields,
        }))
    }

    pub(in crate::extraction::formats::tiff) fn emit<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let back = self.fields.back.filter(|back| back.len() <= limit);
        let iso = self
            .fields
            .iso
            .map(|iso| iso.to_string())
            .filter(|text| text.len() <= limit);
        let leaf_make = (!self.has_make && b"Leaf".len() <= limit).then_some(b"Leaf".as_slice());
        let leaf_model = back.filter(|_| !self.has_model);
        if let Some(make) = leaf_make {
            emit(MAKE, make)?;
        }
        if let Some(model) = leaf_model {
            emit(MODEL, model.as_bytes())?;
        }
        if let Some(iso) = &iso {
            emit(camera::ISO_SPEED, iso.as_bytes())?;
        }
        if let Some(preview) = self.fields.preview
            && let Some(mut packets) = tiff.section_for_field(self.owner)
            && let Some(jpeg) = packets.section(preview.start, preview.end - preview.start)
        {
            jpeg::visit_preview(
                jpeg,
                limit,
                jpeg::Profiles::Metadata,
                &mut |kind, bytes| match kind {
                    IMAGE_DIMENSIONS | IMAGE_ORIENTATION => Ok(()),
                    MAKE if self.has_make || leaf_make.is_some() => Ok(()),
                    MODEL if self.has_model || leaf_model.is_some() => Ok(()),
                    camera::ISO_SPEED if iso.is_some() => Ok(()),
                    _ => emit(kind, bytes),
                },
            )?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Fields {
    back: Option<&'static str>,
    iso: Option<NonZeroU32>,
    preview: Option<Range<u64>>,
}

impl Fields {
    fn read<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        order: ByteOrder,
        directory: Directory,
        range: Range<u64>,
    ) -> Result<bool, E> {
        let mut cursor = range.start;
        let mut found = false;
        while range.end - cursor >= PACKET_HEADER_BYTES as u64 {
            let Some(header) = input.range(cursor, PACKET_HEADER_BYTES)? else {
                break;
            };
            let Some(packet) = Packet::parse(header, order, cursor, range.end) else {
                break;
            };
            cursor = packet.payload.end;
            found = true;
            match (directory, packet.name()) {
                (Directory::Root, b"JPEG_preview_data") if self.preview.is_none() => {
                    self.preview = Some(packet.payload);
                }
                (Directory::Shoot, b"ShootObj_back_type") if self.back.is_none() => {
                    self.back = number(input, packet.payload)?
                        .and_then(|number| usize::try_from(number).ok())
                        .and_then(|index| BACKS.get(index))
                        .copied()
                        .filter(|label| !label.is_empty());
                }
                (Directory::CameraSetup, b"CameraObj_ISO_speed") if self.iso.is_none() => {
                    self.iso = number(input, packet.payload)?.and_then(NonZeroU32::new);
                }
                (_, name) => {
                    if let Some(child) = directory.child(name) {
                        self.read(input, order, child, packet.payload)?;
                    }
                }
            }
        }
        Ok(found)
    }
}

#[derive(Clone, Copy)]
enum Directory {
    Root,
    Camera,
    Image,
    Shoot,
    CameraSetup,
}

impl Directory {
    fn child(self, packet: &[u8]) -> Option<Self> {
        Some(match (self, packet) {
            (Self::Root, b"camera_profile") => Self::Camera,
            (Self::Camera, b"CamProf_image_profile") => Self::Image,
            (Self::Image, b"ImgProf_shoot_setup") => Self::Shoot,
            (Self::Shoot, b"ShootObj_camera_setup") => Self::CameraSetup,
            _ => return None,
        })
    }
}

struct Packet {
    name: [u8; 40],
    payload: Range<u64>,
}

impl Packet {
    fn parse(header: &[u8], order: ByteOrder, cursor: u64, directory_end: u64) -> Option<Self> {
        let header = header.first_chunk::<PACKET_HEADER_BYTES>()?;
        if !header.starts_with(b"PKTS") {
            return None;
        }
        let size = *header.last_chunk::<4>()?;
        let size = match order {
            ByteOrder::Little => u32::from_le_bytes(size),
            ByteOrder::Big => u32::from_be_bytes(size),
        };
        let start = cursor + PACKET_HEADER_BYTES as u64;
        let end = start
            .checked_add(u64::from(size))
            .filter(|&end| end <= directory_end)?;
        let name = *header.get(8..48)?.first_chunk::<40>()?;
        Some(Self {
            name,
            payload: start..end,
        })
    }

    fn name(&self) -> &[u8] {
        self.name
            .split(|&byte| byte == 0)
            .next()
            .unwrap_or_default()
    }
}

fn number<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    range: Range<u64>,
) -> Result<Option<u32>, E> {
    let length = range.end - range.start;
    if !(1..=MAX_NUMBER_BYTES as u64).contains(&length) {
        return Ok(None);
    }
    Ok(input
        .range(range.start, length as usize)?
        .and_then(|bytes| {
            let number = str::from_utf8(bytes)
                .ok()?
                .trim_matches(|ch: char| ch.is_ascii_whitespace() || ch == '\0');
            number.parse().ok()
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::{Format, MIME_TYPE};

    const AT: u32 = 4096;

    #[test]
    fn leaf_projects_sparse_packets_and_positioned_jpeg_metadata() {
        let unknown_size = 1_000_000_u32;
        let unknown = header(b"private_binary", unknown_size);
        let camera = packet(
            b"camera_profile",
            &packet(
                b"CamProf_image_profile",
                &packet(
                    b"ImgProf_shoot_setup",
                    &[
                        packet(b"ShootObj_back_type", b"12\0"),
                        packet(
                            b"ShootObj_camera_setup",
                            &packet(b"CameraObj_ISO_speed", b"80\n"),
                        ),
                    ]
                    .concat(),
                ),
            ),
        );

        const TIFF: &[u8] = b"II*\0\x08\0\0\0\x01\0\x3b\x01\x02\0\x04\0\0\0Sam\0\0\0\0\0";
        let mut jpeg = b"\xff\xd8\xff\xe1".to_vec();
        jpeg.extend_from_slice(&u16::to_be_bytes((TIFF.len() + 8) as u16));
        jpeg.extend_from_slice(b"Exif\0\0");
        jpeg.extend_from_slice(TIFF);
        jpeg.extend_from_slice(b"\xff\xda\0\x08");
        let scan_size = 65536;
        let preview = header(b"JPEG_preview_data", jpeg.len() as u32 + scan_size);
        let observed = [camera.as_slice(), &preview, &jpeg].concat();
        let later = u64::from(AT) + PACKET_HEADER_BYTES as u64 + u64::from(unknown_size);
        let extent = later + observed.len() as u64 + u64::from(scan_size);
        let tiff = tiff(7, (extent - u64::from(AT)) as u32);
        let regions = [(u64::from(AT), unknown.as_slice()), (later, &observed)];
        let read = |offset: u64, output: &mut [u8]| {
            let bytes = regions.iter().find_map(|(start, bytes)| {
                let relative = usize::try_from(offset.checked_sub(*start)?).ok()?;
                bytes.get(relative..relative.checked_add(output.len())?)
            });
            output.copy_from_slice(bytes.ok_or("read escaped metadata")?);
            Ok::<_, &'static str>(())
        };
        let mut scratch = [0; 1024];
        let fields = extract(Input::new(&tiff, extent, &mut scratch, read));

        assert_eq!(
            fields,
            [
                (MIME_TYPE, b"image/x-leaf-mos".to_vec()),
                (IMAGE_DIMENSIONS, b"4080x2720".to_vec()),
                (MAKE, b"Leaf".to_vec()),
                (MODEL, b"Aptus 22".to_vec()),
                (camera::ISO_SPEED, b"80".to_vec()),
                (130, b"Sam".to_vec()),
            ]
        );
    }

    #[test]
    fn private_tag_does_not_identify_an_unowned_or_unframed_packet() {
        let mut broken = header(b"camera_profile", 128).to_vec();
        broken.extend_from_slice(b"unterminated packet");
        for (kind, packets) in [
            (7, broken.as_slice()),
            (7, b"not a Leaf PKTS stream"),
            (2, &packet(b"camera_profile", b"")),
        ] {
            let mut tiff = tiff(kind, packets.len() as u32);
            tiff.resize(AT as usize, 0);
            tiff.extend_from_slice(packets);
            let fields = extract(Input::new(&tiff, tiff.len() as u64, &mut [], |_, _| {
                Err("unexpected positioned read")
            }));
            assert_eq!(
                fields,
                [
                    (MIME_TYPE, b"image/tiff".to_vec()),
                    (IMAGE_DIMENSIONS, b"4080x2720".to_vec()),
                ]
            );
        }
    }

    fn tiff(kind: u16, length: u32) -> Vec<u8> {
        let mut tiff = b"II*\0\x08\0\0\0\x03\0".to_vec();
        for (tag, kind, count, value) in [
            (256_u16, 4_u16, 1_u32, 4080_u32),
            (257, 4, 1, 2720),
            (TAG, kind, length, AT),
        ] {
            tiff.extend_from_slice(&tag.to_le_bytes());
            tiff.extend_from_slice(&kind.to_le_bytes());
            tiff.extend_from_slice(&count.to_le_bytes());
            tiff.extend_from_slice(&value.to_le_bytes());
        }
        tiff.extend_from_slice(&[0; 4]);
        tiff
    }

    fn header(name: &[u8], length: u32) -> [u8; PACKET_HEADER_BYTES] {
        let mut header = [0; PACKET_HEADER_BYTES];
        header[..8].copy_from_slice(b"PKTS\x01\0\0\0");
        header[8..8 + name.len()].copy_from_slice(name);
        header[48..].copy_from_slice(&length.to_le_bytes());
        header
    }

    fn packet(name: &[u8], body: &[u8]) -> Vec<u8> {
        [header(name, body.len() as u32).as_slice(), body].concat()
    }

    fn extract(
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), &'static str>>,
    ) -> Vec<(u32, Vec<u8>)> {
        let mut fields = Vec::new();
        if let Some(format) = Format::detect(input.prefix) {
            let result = format.visit_text(input, 128, &mut |kind, bytes| {
                fields.push((kind, bytes.to_vec()));
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        fields
    }
}
