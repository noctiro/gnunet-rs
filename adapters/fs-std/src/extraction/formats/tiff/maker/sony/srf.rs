//! Layered Sony SRF MakerNote IFDs, confined to their metadata area.

use super::{Row, Tiff, WHITE_BALANCE};

const CLEAR_DIRECTORY: &[u8; 14] = b"\x01\0\x03\0\x04\0\x01\0\0\0\0\0\0\x01";
pub(super) const HEADER_BYTES: usize = CLEAR_DIRECTORY.len() + size_of::<u32>();
const KEY_MARKER: usize = 0x8ddc;
const WORD_BYTES: usize = size_of::<u32>();
const ROW_BYTES: usize = 12;

pub(super) fn has_signature(header: &[u8]) -> bool {
    header.starts_with(CLEAR_DIRECTORY)
}

pub(super) fn first_encrypted_link(header: &[u8], note: Row) -> Option<usize> {
    let absolute = header.strip_prefix(CLEAR_DIRECTORY)?.first_chunk()?;
    let relative = u64::from(u32::from_le_bytes(*absolute)).checked_sub(note.external_offset()?)?;
    let relative = usize::try_from(relative).ok()?;
    (relative.is_multiple_of(2)
        && relative >= HEADER_BYTES
        && relative.checked_add(2)? <= note.len())
    .then_some(relative)
}

pub(in super::super) fn visit<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    note: Row,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(owner) = note.external_offset() else {
        return Ok(());
    };
    if note.len() < KEY_MARKER + WORD_BYTES {
        return Ok(());
    }
    let Some(header) = tiff.read_field_range(&note, 0, HEADER_BYTES)? else {
        return Ok(());
    };
    let Some(first) = first_encrypted_link(header, note).filter(|&first| first < KEY_MARKER) else {
        return Ok(());
    };
    let Some(start) = owner.checked_add(first as u64) else {
        return Ok(());
    };
    let Some(index) = tiff
        .read_field_range(&note, KEY_MARKER, 1)?
        .and_then(|bytes| bytes.first().copied())
    else {
        return Ok(());
    };
    let key_at = KEY_MARKER + usize::from(index) * WORD_BYTES;
    let Some(key) = tiff
        .read_field_range(&note, key_at, WORD_BYTES)?
        .and_then(<[u8]>::first_chunk)
        .map(|bytes| u32::from_be_bytes(*bytes))
    else {
        return Ok(());
    };
    // Only the encrypted IFD area precedes the key marker. The full MakerNote
    // also includes an embedded preview and can be much larger.
    let Some(encrypted) = tiff.read_field_range(&note, first, KEY_MARKER - first)? else {
        return Ok(());
    };
    let mut metadata = Vec::new();
    if metadata.try_reserve_exact(encrypted.len()).is_err() {
        return Ok(());
    }
    metadata.extend_from_slice(encrypted);
    if let Some([red, green, blue]) = recover(&mut metadata, start, key) {
        // Stored camera coefficients in red:green:blue order. Their ratio,
        // with green as the reference, expresses the relative gain.
        let value = format!("As-shot RGB gains {red}:{green}:{blue}");
        if value.len() <= limit {
            emit(WHITE_BALANCE, value.as_bytes())?;
        }
    }
    Ok(())
}

fn recover(area: &mut [u8], start: u64, key: u32) -> Option<[u16; 3]> {
    decipher(area, key);
    let key_directory = Directory::read(area, start, 0)?;
    let settings_key = u32::from_le_bytes(*key_directory.inline_scalar(0, ScalarType::Long)?);
    let mut at = key_directory.next?;
    decipher(area.get_mut(at..)?, settings_key);

    // SRF2 supplies the primary sensor gains. SRF3 through SRF5 and the
    // terminating preview IFD must still form a forward chain in this area.
    let sensor = Directory::read(area, start, at)?;
    let gains = [
        sensor.short(0x00d0)?,
        sensor.short(0x00d1)?,
        sensor.short(0x00d2)?,
    ];
    at = sensor.next?;
    for _ in 3..=5 {
        at = Directory::read(area, start, at)?.next?;
    }
    let preview = Directory::read(area, start, at)?;
    (preview.next.is_none() && gains.into_iter().all(|value| value != 0)).then_some(gains)
}

struct Directory<'a> {
    rows: &'a [[u8; ROW_BYTES]],
    next: Option<usize>,
}

#[derive(Clone, Copy)]
#[repr(u16)]
enum ScalarType {
    Short = 3,
    Long = 4,
}

impl<'a> Directory<'a> {
    fn read(area: &'a [u8], start: u64, at: usize) -> Option<Self> {
        let (count, tail) = area.get(at..)?.split_first_chunk::<2>()?;
        let count = usize::from(u16::from_le_bytes(*count));
        if count == 0 {
            return None;
        }
        let rows_bytes = count * ROW_BYTES;
        let (rows, link) = tail.split_at_checked(rows_bytes)?;
        let (rows, []) = rows.as_chunks() else {
            return None;
        };
        let link = u32::from_le_bytes(*link.first_chunk()?);
        let next = if link == 0 {
            None
        } else {
            let next = usize::try_from(u64::from(link).checked_sub(start)?).ok()?;
            let encoded_end = at + 2 + rows_bytes + WORD_BYTES;
            if next < encoded_end || !next.is_multiple_of(2) || next >= area.len() {
                return None;
            }
            Some(next)
        };
        Some(Self { rows, next })
    }

    fn short(&self, tag: u16) -> Option<u16> {
        let value = self.inline_scalar(tag, ScalarType::Short)?;
        Some(u16::from_le_bytes(*value.first_chunk()?))
    }

    fn inline_scalar(&self, tag: u16, kind: ScalarType) -> Option<&[u8; WORD_BYTES]> {
        let mut matching = self.rows.iter().filter(|row| row[..2] == tag.to_le_bytes());
        let row = matching.next()?;
        if matching.next().is_some()
            || row[2..4] != (kind as u16).to_le_bytes()
            || row[4..8] != [1, 0, 0, 0]
        {
            return None;
        }
        row.last_chunk()
    }
}

// Published Sony word-stream recurrence, also used by LibRaw's parseSonySRF.
fn decipher(area: &mut [u8], mut key: u32) {
    const REGISTER: usize = 128;
    let mut pad = [0_u32; REGISTER];
    for word in &mut pad[..4] {
        key = key.wrapping_mul(48_828_125).wrapping_add(1);
        *word = key;
    }
    pad[3] = (pad[3] << 1) | ((pad[0] ^ pad[2]) >> 31);
    for index in 4..REGISTER - 1 {
        let previous = pad[index - 4] ^ pad[index - 2];
        let high = (pad[index - 3] ^ pad[index - 1]) >> 31;
        pad[index] = (previous << 1) | high;
    }
    for (index, bytes) in area.as_chunks_mut::<WORD_BYTES>().0.iter_mut().enumerate() {
        let mask = pad[index % REGISTER] ^ pad[(index + 64) % REGISTER];
        pad[(index + REGISTER - 1) % REGISTER] = mask;
        *bytes = (u32::from_be_bytes(*bytes) ^ mask).to_be_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decipher_matches_public_srf1_ifd_prefix() {
        // First two encrypted words of the RAWsamples DSC-F828 SRF1 IFD.
        let mut bytes = [6, 207, 92, 161, 65, 51, 153, 19];
        decipher(&mut bytes, 0x2bdc_c388);
        assert_eq!(bytes, [2, 0, 0, 0, 4, 0, 1, 0]);
    }

    #[test]
    fn as_shot_gains_require_owned_chain_and_unique_inline_shorts() {
        const START: u32 = 20;
        const MASTER: u32 = 0x2bdc_c388;
        const SECOND: u32 = 0x7b85_bd55;
        let fixture = |green_tag, following| {
            let mut area = [0; 256];
            let mut directory = |at: usize, values: &[(u16, u16, u32)], next: u32| {
                let tail = at + 2;
                area[at..tail].copy_from_slice(&(values.len() as u16).to_le_bytes());
                let (rows, link) = area[tail..].split_at_mut(values.len() * ROW_BYTES);
                for (row, &(tag, kind, value)) in
                    rows.as_chunks_mut::<ROW_BYTES>().0.iter_mut().zip(values)
                {
                    row[..2].copy_from_slice(&tag.to_le_bytes());
                    row[2..4].copy_from_slice(&kind.to_le_bytes());
                    row[4..8].copy_from_slice(&1_u32.to_le_bytes());
                    row[8..].copy_from_slice(&value.to_le_bytes());
                }
                link[..WORD_BYTES].copy_from_slice(&next.to_le_bytes());
            };
            directory(0, &[(0, 4, SECOND)], START + 20);
            directory(
                20,
                &[(0xd0, 3, 405), (green_tag, 3, 256), (0xd2, 3, 742)],
                following,
            );
            directory(80, &[(0, 4, 42)], START + 112);
            directory(112, &[(0, 4, 42)], START + 144);
            directory(144, &[(0, 4, 42)], START + 176);
            directory(176, &[(0, 4, 42)], 0);
            decipher(&mut area[20..], SECOND);
            decipher(&mut area, MASTER);
            area
        };
        assert_eq!(
            recover(&mut fixture(0xd1, START + 80), u64::from(START), MASTER),
            Some([405, 256, 742])
        );
        assert_eq!(
            recover(&mut fixture(0xd0, START + 80), u64::from(START), MASTER),
            None
        );
        assert_eq!(
            recover(&mut fixture(0xd1, START + 12), u64::from(START), MASTER),
            None
        );
        assert_eq!(
            recover(&mut fixture(0xd1, START + 256), u64::from(START), MASTER),
            None
        );
    }
}
