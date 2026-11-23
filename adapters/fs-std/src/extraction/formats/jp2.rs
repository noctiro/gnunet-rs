//! JPEG 2000 image brands and top-level metadata UUID boxes.

use std::ops::Range;

use super::{
    Dimensions, Input,
    boxes::{BoxSpan, EXTENDED_BOX_BYTES, file_type},
    iptc, xmp,
};

pub(super) const SIGNATURE: &[u8; 12] = b"\0\0\0\x0cjP  \r\n\x87\n";
pub(super) const IDENTIFICATION_BYTES: usize = SIGNATURE.len() + EXTENDED_BOX_BYTES + 4;
const IPTC_UUID: [u8; 16] = [
    0x33, 0xc7, 0xa4, 0xd2, 0xb8, 0x1d, 0x47, 0x23, 0xa0, 0xba, 0xf1, 0xa3, 0xe0, 0x97, 0xad, 0x38,
];

#[derive(Clone, Copy)]
pub(in crate::extraction) enum Brand {
    Jp2,
    Jpx,
    Jpm,
    Jph,
}

impl Brand {
    fn from_box(contents: &[u8], len: u64) -> Option<Self> {
        if len < 12 || !len.is_multiple_of(4) {
            return None;
        }
        Some(match contents.first_chunk()? {
            b"jp2 " => Self::Jp2,
            b"jpx " => Self::Jpx,
            b"jpm " => Self::Jpm,
            b"jph " => Self::Jph,
            _ => return None,
        })
    }

    pub(super) const fn mime(self) -> &'static [u8] {
        match self {
            Self::Jp2 => b"image/jp2",
            Self::Jpx => b"image/jpx",
            Self::Jpm => b"image/jpm",
            Self::Jph => b"image/jph",
        }
    }
}

pub(super) fn brand(prefix: &[u8]) -> Option<Brand> {
    let file_type = file_type(prefix.strip_prefix(SIGNATURE)?)?;
    Brand::from_box(&file_type.major, file_type.payload_bytes)
}

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if input.range(0, SIGNATURE.len())? != Some(SIGNATURE.as_slice()) {
        return Ok(());
    }
    let extent = input.extent;
    let Some(file_type) = BoxSpan::read(&mut input, SIGNATURE.len() as u64, extent)? else {
        return Ok(());
    };
    if file_type.kind != *b"ftyp" || file_type.len() < 12 {
        return Ok(());
    }
    let Some(brand) = input
        .range(file_type.data, 4)?
        .and_then(|bytes| Brand::from_box(bytes, file_type.len()))
    else {
        return Ok(());
    };

    let mut at = file_type.end;
    let mut find_dimensions = matches!(brand, Brand::Jp2 | Brand::Jph);
    let mut packets = [
        (PacketKind::Iptc, Packet::Missing),
        (PacketKind::Xmp, Packet::Missing),
    ];
    while find_dimensions
        || packets
            .iter()
            .any(|(_, packet)| !matches!(packet, Packet::Emitted))
    {
        let Some(span) = BoxSpan::read(&mut input, at, extent)? else {
            break;
        };
        match &span.kind {
            b"jp2h" if find_dimensions => {
                find_dimensions = false;
                if let Some(dimensions) = image_dimensions(&mut input, &span)? {
                    dimensions.emit(emit)?;
                }
                for (kind, packet) in &mut packets {
                    packet.emit(*kind, &mut input, limit, emit)?;
                }
            }
            b"uuid" => {
                if let Some((kind, data)) = metadata_packet(&mut input, &span)?
                    && let Some((_, packet)) = packets.iter_mut().find(|(wanted, packet)| {
                        *wanted == kind && matches!(packet, Packet::Missing)
                    })
                {
                    *packet = Packet::Pending(data);
                    if !find_dimensions {
                        packet.emit(kind, &mut input, limit, emit)?;
                    }
                }
            }
            _ => {}
        }
        at = span.end;
    }
    for (kind, packet) in &mut packets {
        packet.emit(*kind, &mut input, limit, emit)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PacketKind {
    Iptc,
    Xmp,
}

enum Packet {
    Missing,
    Pending(Range<u64>),
    Emitted,
}

impl Packet {
    fn emit<E>(
        &mut self,
        kind: PacketKind,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let Self::Pending(data) = self else {
            return Ok(());
        };
        let emitted = if let Ok(length) = usize::try_from(data.end - data.start)
            && let Some(bytes) = input.range(data.start, length)?
        {
            match kind {
                PacketKind::Iptc => {
                    if let Some(profile) = iptc::Profile::parse(bytes, 0) {
                        profile.emit(limit, emit)?;
                        true
                    } else {
                        false
                    }
                }
                PacketKind::Xmp => xmp::visit(bytes, limit, emit)?,
            }
        } else {
            false
        };
        *self = if emitted {
            Self::Emitted
        } else {
            Self::Missing
        };
        Ok(())
    }
}

fn metadata_packet<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    span: &BoxSpan,
) -> Result<Option<(PacketKind, Range<u64>)>, E> {
    if span.len() <= IPTC_UUID.len() as u64 {
        return Ok(None);
    }
    let kind = match input.range(span.data, IPTC_UUID.len())? {
        Some(uuid) if uuid == IPTC_UUID => PacketKind::Iptc,
        Some(uuid) if uuid == xmp::UUID => PacketKind::Xmp,
        _ => return Ok(None),
    };
    Ok(Some((kind, span.data + IPTC_UUID.len() as u64..span.end)))
}

fn image_dimensions<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    header: &BoxSpan,
) -> Result<Option<Dimensions>, E> {
    let Some(image) = BoxSpan::read(input, header.data, header.end)? else {
        return Ok(None);
    };
    if image.kind != *b"ihdr" || image.len() != 14 {
        return Ok(None);
    }
    let Some(bytes) = input.range(image.data, 14)? else {
        return Ok(None);
    };
    if bytes[8..10] == [0; 2] || bytes[11] != 7 || bytes[12] > 1 || bytes[13] > 1 {
        return Ok(None);
    }
    let height = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let width = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Ok(Dimensions::new(width, height))
}
