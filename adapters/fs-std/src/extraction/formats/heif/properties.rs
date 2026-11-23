//! Properties associated with the primary picture through ipma.

mod geometry;

use super::super::Dimensions;
use super::{BoxSpan, Input, ItemId, Reader, read_body};
use geometry::{Aperture, Scaling};

pub(super) struct Properties {
    pub(super) dimensions: Option<Dimensions>,
    /// Equivalent TIFF orientation when the container specifies rotation or mirroring.
    pub(super) orientation: Option<u8>,
}

pub(super) fn read<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    properties: &BoxSpan,
    primary: ItemId,
) -> Result<Option<Properties>, E> {
    let Some(definitions) = BoxSpan::read(input, properties.data, properties.end)? else {
        return Ok(None);
    };
    if definitions.kind != *b"ipco" {
        return Ok(None);
    }
    let mut indexes = Vec::new();
    let mut cursor = definitions.end;
    while cursor < properties.end {
        let Some(span) = BoxSpan::read(input, cursor, properties.end)? else {
            return Ok(None);
        };
        cursor = span.end;
        if span.kind == *b"ipma" {
            let Some(bytes) = read_body(input, &span)? else {
                return Ok(None);
            };
            if associations(bytes, primary, &mut indexes).is_none() {
                return Ok(None);
            }
        }
    }
    indexes.sort_unstable_by_key(|association| association.index);
    let Some(last) = indexes.last().map(|association| association.index) else {
        return Ok(None);
    };
    let mut selected = indexes.into_iter().peekable();
    let mut dimensions = None;
    let mut orientation = DisplayOrientation::default();
    let mut aperture = None;
    let mut scaling = None;
    let mut cursor = definitions.data;
    for index in 1..=last {
        let Some(property) = BoxSpan::read(input, cursor, definitions.end)? else {
            return Ok(None);
        };
        cursor = property.end;
        let Some(association) = selected.next_if(|association| association.index == index) else {
            continue;
        };
        if selected.peek().is_some_and(|next| next.index == index) {
            return Ok(None);
        }
        match &property.kind {
            b"ispe" => {
                if dimensions.is_some() || property.len() != 12 {
                    return Ok(None);
                }
                let Some(&[0, 0, 0, 0, w0, w1, w2, w3, h0, h1, h2, h3]) =
                    input.range(property.data, 12)?
                else {
                    return Ok(None);
                };
                dimensions = Dimensions::new(
                    u32::from_be_bytes([w0, w1, w2, w3]),
                    u32::from_be_bytes([h0, h1, h2, h3]),
                );
                if dimensions.is_none() {
                    return Ok(None);
                }
            }
            b"irot" | b"imir" => {
                if property.len() != 1 {
                    return Ok(None);
                }
                let Some(&[value]) = input.range(property.data, 1)? else {
                    return Ok(None);
                };
                if orientation
                    .insert(&property.kind, association.position, value)
                    .is_none()
                {
                    return Ok(None);
                }
            }
            b"clap" => {
                if aperture.is_some() || property.len() != 32 {
                    return Ok(None);
                }
                let Some(crop) = input.range(property.data, 32)?.and_then(Aperture::parse) else {
                    return Ok(None);
                };
                aperture = Some((association.position, Change::Crop(crop)));
            }
            b"iscl" => {
                if scaling.is_some() || property.len() != 12 {
                    return Ok(None);
                }
                let Some(scale) = input.range(property.data, 12)?.and_then(Scaling::parse) else {
                    return Ok(None);
                };
                scaling = Some((association.position, Change::Scale(scale)));
            }
            _ => {}
        }
    }
    if aperture.is_some() || scaling.is_some() {
        let transpose = orientation
            .rotation
            .filter(|(_, rotation)| rotation.transposes())
            .map(|(position, _)| (position, Change::Transpose));
        let Some(projected) =
            dimensions.and_then(|coded| project_dimensions(coded, [aperture, scaling, transpose]))
        else {
            return Ok(None);
        };
        dimensions = Some(projected);
    }
    Ok(Some(Properties {
        dimensions,
        orientation: orientation.as_tiff(),
    }))
}

enum Change {
    Crop(Aperture),
    Scale(Scaling),
    Transpose,
}

fn project_dimensions(
    mut size: Dimensions,
    mut changes: [Option<(usize, Change)>; 3],
) -> Option<Dimensions> {
    changes.sort_unstable_by_key(|change| change.as_ref().map(|(position, _)| *position));
    let mut transposed = false;
    for (_, change) in changes.into_iter().flatten() {
        size = match change {
            Change::Crop(aperture) => aperture.apply(size)?,
            Change::Scale(scaling) => scaling.apply(size)?,
            Change::Transpose => {
                transposed = true;
                Dimensions {
                    width: size.height,
                    height: size.width,
                }
            }
        };
    }
    // Keep the extent in the frame to which the emitted orientation applies.
    if transposed {
        std::mem::swap(&mut size.width, &mut size.height);
    }
    Some(size)
}

struct Association {
    index: u16,
    position: usize,
}

fn associations(bytes: &[u8], primary: ItemId, indexes: &mut Vec<Association>) -> Option<()> {
    let (&[version, 0, 0, flags], rest) = bytes.split_first_chunk()? else {
        return None;
    };
    let id_width = match version {
        0 => 2,
        1 => 4,
        _ => return None,
    };
    let (property_width, index_mask) = match flags {
        0 => (1, 0x7f),
        1 => (2, 0x7fff),
        _ => return None,
    };
    let mut reader = Reader::new(rest);
    let count = reader.integer(4)?;
    for _ in 0..count {
        let item = reader.item_id(id_width)?;
        let associations = reader.integer(1)?;
        for _ in 0..associations {
            let index = (reader.integer(property_width)? as u16) & index_mask;
            if item == primary && index != 0 {
                indexes.try_reserve(1).ok()?;
                indexes.push(Association {
                    index,
                    position: indexes.len(),
                });
            }
        }
    }
    reader.is_empty().then_some(())
}

#[derive(Default)]
struct DisplayOrientation {
    rotation: Option<(usize, Rotation)>,
    mirror: Option<(usize, Mirror)>,
}

impl DisplayOrientation {
    fn insert(&mut self, kind: &[u8; 4], position: usize, value: u8) -> Option<()> {
        match (kind, value) {
            (b"irot", angle) => self
                .rotation
                .replace((position, Rotation::parse(angle)?))
                .is_none()
                .then_some(()),
            (b"imir", 0 | 1) => self
                .mirror
                .replace((
                    position,
                    if value == 0 {
                        Mirror::TopBottom
                    } else {
                        Mirror::LeftRight
                    },
                ))
                .is_none()
                .then_some(()),
            _ => None,
        }
    }

    fn as_tiff(&self) -> Option<u8> {
        let (rotation, mirror) = match (self.rotation, self.mirror) {
            (None, None) => return None,
            // HEIF applies transforms in ipma order. A mirror before a rotation
            // equals the inverse rotation followed by the same mirror.
            (Some((rotate_at, rotation)), Some((mirror_at, mirror))) if mirror_at < rotate_at => {
                (rotation.inverse(), Some(mirror))
            }
            (rotation, mirror) => (
                rotation.map_or(Rotation::Identity, |(_, rotation)| rotation),
                mirror.map(|(_, mirror)| mirror),
            ),
        };
        // TIFF orientation values for a counterclockwise rotation followed by the mirror.
        let values = match mirror {
            None => [1, 8, 3, 6],
            Some(Mirror::TopBottom) => [4, 5, 2, 7],
            Some(Mirror::LeftRight) => [2, 7, 4, 5],
        };
        Some(values[rotation as usize])
    }
}

#[derive(Clone, Copy)]
enum Mirror {
    TopBottom,
    LeftRight,
}

#[derive(Clone, Copy)]
enum Rotation {
    Identity = 0,
    Counterclockwise90 = 1,
    Counterclockwise180 = 2,
    Counterclockwise270 = 3,
}

impl Rotation {
    fn parse(quarters: u8) -> Option<Self> {
        Some(match quarters {
            0 => Self::Identity,
            1 => Self::Counterclockwise90,
            2 => Self::Counterclockwise180,
            3 => Self::Counterclockwise270,
            _ => return None,
        })
    }

    const fn transposes(self) -> bool {
        matches!(self, Self::Counterclockwise90 | Self::Counterclockwise270)
    }

    fn inverse(self) -> Self {
        match self {
            Self::Counterclockwise90 => Self::Counterclockwise270,
            Self::Counterclockwise270 => Self::Counterclockwise90,
            rotation => rotation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_primary_association_order_instead_of_box_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let primary = Reader::new(&[0, 1])
            .item_id(2)
            .ok_or("invalid test item ID")?;
        let definitions = b"\0\0\0\x1aipco\0\0\0\x09irot\x01\0\0\0\x09imir\0";
        for (indexes, expected) in [([0x81, 0x82], 5), ([0x82, 0x81], 7)] {
            let mut bytes = definitions.to_vec();
            bytes.extend_from_slice(b"\0\0\0\x15ipma\0\0\0\0\0\0\0\x01\0\x01\x02");
            bytes.extend_from_slice(&indexes);
            let end = bytes.len() as u64;
            let mut input = Input::new(&bytes, end, &mut [], |_, _: &mut [u8]| {
                Ok::<_, std::convert::Infallible>(())
            });
            let span = BoxSpan {
                kind: *b"iprp",
                data: 0,
                end,
            };
            let orientation =
                read(&mut input, &span, primary)?.and_then(|properties| properties.orientation);
            if orientation != Some(expected) {
                return Err("unexpected primary orientation".into());
            }
        }
        Ok(())
    }

    #[test]
    fn projects_aperture_and_scaling_in_the_associated_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        let primary = Reader::new(&[0, 1])
            .item_id(2)
            .ok_or("invalid test item ID")?;
        let mut definitions = b"\0\0\0\x61ipco\0\0\0\x14ispe\0\0\0\0\0\0\0\x0c\0\0\0\x08".to_vec();
        definitions.extend_from_slice(b"\0\0\0\x28clap");
        // A 6.5 × 5 aperture with a negative, fractional horizontal offset.
        for value in [13_i32, 2, 5, 1, -3, 2, 1, 1] {
            definitions.extend_from_slice(&value.to_be_bytes());
        }
        definitions.extend_from_slice(b"\0\0\0\x09irot\x01");
        definitions.extend_from_slice(b"\0\0\0\x14iscl\0\0\0\0\0\x01\0\x02\0\x03\0\x02");

        for (indexes, expected) in [
            ([0x81, 0x82, 0x83, 0x84], Some((11, 3))),
            ([0x81, 0x82, 0x84, 0x83], Some((4, 8))),
            ([0x81, 0x83, 0x82, 0x84], None),
        ] {
            let mut bytes = definitions.clone();
            bytes.extend_from_slice(b"\0\0\0\x17ipma\0\0\0\0\0\0\0\x01\0\x01\x04");
            bytes.extend_from_slice(&indexes);
            let end = bytes.len() as u64;
            let mut input = Input::new(&bytes, end, &mut [], |_, _: &mut [u8]| {
                Ok::<_, std::convert::Infallible>(())
            });
            let span = BoxSpan {
                kind: *b"iprp",
                data: 0,
                end,
            };
            let properties = read(&mut input, &span, primary)?;
            let size = properties
                .as_ref()
                .and_then(|properties| properties.dimensions.as_ref())
                .map(|size| (size.width.get(), size.height.get()));
            if size != expected
                || properties.and_then(|properties| properties.orientation) != expected.map(|_| 8)
            {
                return Err("unexpected projected clean aperture and scale".into());
            }
        }
        Ok(())
    }
}
