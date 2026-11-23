//! Canon CRW metadata in role-specific CIFF heaps.

mod fields;

use std::ops::Range;

use super::Input;

pub(super) const IDENTIFICATION_BYTES: usize = 14;
const SIGNATURE: &[u8; 8] = b"HEAPCCDR";
const RECORD_BYTES: usize = 10;

const IMAGE_PROPERTIES: u16 = 0x300a;
const CAMERA_OBJECT: u16 = 0x2807;
const EXIF_INFORMATION: u16 = 0x300b;

pub(super) fn is_candidate(prefix: &[u8]) -> bool {
    Order::parse(prefix).is_some() && prefix.get(6..8) == Some(&SIGNATURE[..2])
}

pub(super) fn detect(prefix: &[u8]) -> bool {
    header(prefix).is_some()
}

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some((order, start)) = input.range(0, IDENTIFICATION_BYTES)?.and_then(header) else {
        return Ok(());
    };
    let root = Heap {
        bounds: start..input.extent,
        order,
    };
    let Some([Some(Value::Positioned(image))]) = root.records(&mut input, [IMAGE_PROPERTIES])?
    else {
        return Ok(());
    };
    let image = Heap {
        bounds: image,
        order,
    };
    let Some([comment, captured, geometry, camera, exif]) = image.records(
        &mut input,
        [0x0805, 0x180e, 0x1810, CAMERA_OBJECT, EXIF_INFORMATION],
    )?
    else {
        return Ok(());
    };
    if let Some(value) = geometry
        && let Some(bytes) = value.read(&mut input, 28)?
    {
        fields::geometry(bytes, order, limit, emit)?;
    }
    if let Some(value) = camera {
        visit_camera(&mut input, order, value, limit, emit)?;
    }
    if let Some(value) = captured
        && let Some(bytes) = value.read(&mut input, 12)?
    {
        fields::date(bytes, order, limit, emit)?;
    }
    if let Some(value) = comment
        && let Some(bytes) = value.read(&mut input, limit.saturating_add(1))?
    {
        fields::text(bytes, 3, limit, emit)?;
    }
    if let Some(value) = exif {
        visit_settings(&mut input, order, value, limit, emit)?;
    }
    Ok(())
}

fn visit_camera<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    order: Order,
    value: Value,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Value::Positioned(bounds) = value else {
        return Ok(());
    };
    let heap = Heap { bounds, order };
    if let Some([Some(make_model)]) = heap.records(input, [0x080a])?
        && let Some(bytes) = make_model.read(input, limit.saturating_add(1).saturating_mul(2))?
    {
        fields::make_model(bytes, limit, emit)?;
    }
    Ok(())
}

fn visit_settings<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    order: Order,
    value: Value,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Value::Positioned(bounds) = value else {
        return Ok(());
    };
    let heap = Heap { bounds, order };
    let Some([settings, shot]) = heap.records(input, [0x102d, 0x102a])? else {
        return Ok(());
    };
    if let Some(value) = settings
        && let Some(bytes) = value.read_words(input, 21)?
    {
        fields::camera_settings(bytes, order, limit, emit)?;
    }
    if let Some(value) = shot
        && let Some(bytes) = value.read_words(input, 23)?
    {
        fields::shot_info(bytes, order, limit, emit)?;
    }
    Ok(())
}

fn header(bytes: &[u8]) -> Option<(Order, u64)> {
    if bytes.get(6..IDENTIFICATION_BYTES)? != SIGNATURE {
        return None;
    }
    let order = Order::parse(bytes)?;
    let start = u64::from(order.long(bytes.get(2..6)?)?);
    (start >= IDENTIFICATION_BYTES as u64).then_some((order, start))
}

struct Heap {
    bounds: Range<u64>,
    order: Order,
}

impl Heap {
    fn records<E, const N: usize>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        tags: [u16; N],
    ) -> Result<Option<[Option<Value>; N]>, E> {
        let Some(trailer) = self.bounds.end.checked_sub(4) else {
            return Ok(None);
        };
        if self.bounds.start > trailer || trailer - self.bounds.start < 2 {
            return Ok(None);
        }
        let Some(pointer) = input
            .range(trailer, 4)?
            .and_then(|data| self.order.long(data))
        else {
            return Ok(None);
        };
        let Some(table) = self
            .bounds
            .start
            .checked_add(u64::from(pointer))
            .filter(|&at| at <= trailer - 2)
        else {
            return Ok(None);
        };
        let Some(count) = input
            .range(table, 2)?
            .and_then(|data| self.order.short(data))
        else {
            return Ok(None);
        };
        let bytes = usize::from(count) * RECORD_BYTES;
        if bytes as u64 > trailer - (table + 2) {
            return Ok(None);
        }
        let Some(records) = input.range(table + 2, bytes)? else {
            return Ok(None);
        };
        let mut selected = [const { None }; N];
        let mut seen = [false; N];
        for record in records.as_chunks::<RECORD_BYTES>().0 {
            let Some(code) = self.order.short(record) else {
                continue;
            };
            let Some(index) = tags.iter().position(|&tag| tag == code & 0x3fff) else {
                continue;
            };
            // The selected fields are unique within their designated CIFF role.
            selected[index] = if std::mem::replace(&mut seen[index], true) {
                None
            } else {
                self.value(record, code, table)
            };
        }
        Ok(Some(selected))
    }

    fn value(&self, record: &[u8; RECORD_BYTES], code: u16, table: u64) -> Option<Value> {
        match code & 0xc000 {
            0 => {
                let length = u64::from(self.order.long(&record[2..6])?);
                let offset = u64::from(self.order.long(&record[6..])?);
                let start = self.bounds.start.checked_add(offset)?;
                let end = start.checked_add(length)?;
                // Value data is separate from the records and trailing heap pointer.
                (end <= table).then_some(Value::Positioned(start..end))
            }
            0x4000 => Some(Value::Inline(*record.last_chunk()?)),
            _ => None,
        }
    }
}

enum Value {
    Inline([u8; 8]),
    Positioned(Range<u64>),
}

impl Value {
    fn len(&self) -> u64 {
        match self {
            Self::Inline(bytes) => bytes.len() as u64,
            Self::Positioned(bounds) => bounds.end - bounds.start,
        }
    }

    fn read<'a, E>(
        &'a self,
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
    ) -> Result<Option<&'a [u8]>, E> {
        let len = self.len().min(limit as u64) as usize;
        match self {
            Self::Inline(bytes) => Ok(bytes.get(..len)),
            Self::Positioned(bounds) => input.range(bounds.start, len),
        }
    }

    fn read_words<'a, E>(
        &'a self,
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        max_words: usize,
    ) -> Result<Option<&'a [u8]>, E> {
        if !self.len().is_multiple_of(2) {
            return Ok(None);
        }
        self.read(input, max_words * 2)
    }
}

#[derive(Clone, Copy)]
enum Order {
    Little,
    Big,
}

impl Order {
    fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes.first_chunk()? {
            b"II" => Some(Self::Little),
            b"MM" => Some(Self::Big),
            _ => None,
        }
    }

    fn short(self, bytes: &[u8]) -> Option<u16> {
        let bytes = *bytes.first_chunk()?;
        Some(match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        })
    }

    fn long(self, bytes: &[u8]) -> Option<u32> {
        let bytes = *bytes.first_chunk()?;
        Some(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }
}

#[cfg(test)]
mod tests;
