use crate::helpers::{Writer, cstr};
use crate::{Error, Profile, RecordType};
use gnunet_gnsrecord::decode_base32;
use gnunet_wire::official::messenger::records::Record;
const ENTRY: &[(usize, usize)] = &[(32, 64), (0, 32)];
const EPOCH: &[(usize, usize)] = &[
    (232, 4),
    (200, 32),
    (184, 16),
    (160, 24),
    (128, 32),
    (64, 64),
    (0, 64),
];
const ENCRYPTION: &[(usize, usize)] = &[(108, 516), (104, 4), (88, 16), (64, 24), (0, 64)];
pub(crate) fn supported(kind: RecordType) -> bool {
    matches!(
        kind,
        RecordType::MESSENGER_ROOM_ENTRY
            | RecordType::MESSENGER_ROOM_DETAILS
            | RecordType::MESSENGER_ROOM_EPOCH_KEY
            | RecordType::MESSENGER_ENCRYPTION_KEY
    )
}
struct Layout {
    bytes: usize,
    fields: &'static [(usize, usize)],
}
fn layout(kind: RecordType) -> Result<Layout, Error> {
    match kind {
        RecordType::MESSENGER_ROOM_ENTRY => Ok(Layout {
            bytes: 96,
            fields: ENTRY,
        }),
        RecordType::MESSENGER_ROOM_EPOCH_KEY => Ok(Layout {
            bytes: 236,
            fields: EPOCH,
        }),
        RecordType::MESSENGER_ENCRYPTION_KEY => Ok(Layout {
            bytes: 624,
            fields: ENCRYPTION,
        }),
        _ => Err(Error::Unsupported),
    }
}
fn component(text: &str, output: &mut [u8]) -> Result<(), Error> {
    if decode_base32(text.as_bytes(), output)? != output.len() {
        return Err(Error::Malformed);
    }
    Ok(())
}
pub(crate) fn parse(
    kind: RecordType,
    text: &str,
    out: &mut Writer<'_>,
    profile: Profile,
) -> Result<(), Error> {
    if kind == RecordType::MESSENGER_ROOM_DETAILS {
        let (flags, name) = text.split_once('-').ok_or(Error::Malformed)?;
        if name.len() > 256 {
            return Err(Error::TooLarge);
        }
        let record = out.fixed(260)?;
        component(flags, &mut record[256..260])?;
        record[..name.len()].copy_from_slice(name.as_bytes());
        Record::decode(kind, record, profile)?;
    } else {
        let layout = layout(kind)?;
        let record = out.fixed(layout.bytes)?;
        let mut pieces = text.split('-');
        for (offset, len) in layout.fields {
            let piece = pieces.next().ok_or(Error::Malformed)?;
            component(piece, &mut record[*offset..*offset + *len])?;
        }
        if pieces.next().is_some() {
            return Err(Error::Malformed);
        }
        Record::decode(kind, record, profile)?;
    }
    Ok(())
}
pub(crate) fn format(
    kind: RecordType,
    data: &[u8],
    out: &mut Writer<'_>,
    profile: Profile,
) -> Result<(), Error> {
    Record::decode(kind, data, profile)?;
    if kind == RecordType::MESSENGER_ROOM_DETAILS {
        out.b32(&data[256..260])?;
        out.byte(b'-')?;
        out.bytes(cstr(&data[..256]))?;
    } else {
        let layout = layout(kind)?;
        for (i, (offset, len)) in layout.fields.iter().enumerate() {
            if i > 0 {
                out.byte(b'-')?;
            }
            out.b32(&data[*offset..*offset + *len])?;
        }
    }
    Ok(())
}
