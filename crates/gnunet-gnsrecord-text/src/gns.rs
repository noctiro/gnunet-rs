use crate::helpers::{Fields, Writer, cstr, terminated, u16_at, u32_at};
use crate::{Error, RecordType};
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType, decode_base32};
pub(crate) fn parse_boxes<'a>(
    mut kind: RecordType,
    mut text: &'a str,
    out: &mut Writer<'_>,
    maximum: usize,
) -> Result<(RecordType, &'a str), Error> {
    let mut depth = 0;
    while kind == RecordType::BOX || kind == RecordType::SBOX {
        if depth >= maximum {
            return Err(Error::Capacity);
        }
        depth += 1;
        let mut fields = Fields::new(text);
        if kind == RecordType::BOX {
            let protocol = fields.u16()?;
            let service = fields.u16()?;
            let inner = fields.u32()?;
            out.bytes(&protocol.to_be_bytes())?;
            out.bytes(&service.to_be_bytes())?;
            out.bytes(&inner.to_be_bytes())?;
            kind = RecordType::new(inner);
        } else {
            let prefix = fields.next()?;
            let inner = fields.u32()?;
            if !prefix
                .rsplit('.')
                .next()
                .is_some_and(|s| s.starts_with('_'))
            {
                return Err(Error::Malformed);
            }
            out.bytes(&inner.to_be_bytes())?;
            out.bytes(prefix.as_bytes())?;
            out.byte(0)?;
            kind = RecordType::new(inner);
        }
        text = fields.rest();
    }
    Ok((kind, text))
}
pub(crate) fn format_boxes<'a>(
    mut kind: RecordType,
    mut data: &'a [u8],
    out: &mut Writer<'_>,
    maximum: usize,
) -> Result<(RecordType, &'a [u8]), Error> {
    let mut depth = 0;
    while kind == RecordType::BOX || kind == RecordType::SBOX {
        if depth >= maximum {
            return Err(Error::Capacity);
        }
        depth += 1;
        let inner;
        if kind == RecordType::BOX {
            out.number(u16_at(data, 0)?.into())?;
            out.byte(b' ')?;
            out.number(u16_at(data, 2)?.into())?;
            out.byte(b' ')?;
            inner = u32_at(data, 4)?;
            out.number(inner.into())?;
            out.byte(b' ')?;
            data = data.get(8..).ok_or(Error::Truncated)?;
        } else {
            inner = u32_at(data, 0)?;
            let (prefix, tail) = terminated(data.get(4..).ok_or(Error::Truncated)?)?;
            out.bytes(prefix)?;
            out.byte(b' ')?;
            out.number(inner.into())?;
            out.byte(b' ')?;
            data = tail;
        }
        kind = RecordType::new(inner);
    }
    Ok((kind, data))
}
pub(crate) fn parse(kind: RecordType, text: &str, out: &mut Writer<'_>) -> Result<(), Error> {
    match kind {
        RecordType::PKEY | RecordType::EDKEY => {
            let key = ZoneKey::from_ztld(text)?;
            if key.kind().record_type() != kind {
                return Err(Error::Malformed);
            }
            out.bytes(key.key())
        }
        RecordType::TXT
        | RecordType::NICK
        | RecordType::REDIRECT
        | RecordType::LEHO
        | RecordType::RECLAIM_TICKET
        | RecordType::RECLAIM_OIDC_CLIENT
        | RecordType::RECLAIM_OIDC_REDIRECT => out.bytes(text.as_bytes()),
        RecordType::GNS2DNS => {
            let (name, server) = text.split_once('@').ok_or(Error::Malformed)?;
            out.bytes(name.as_bytes())?;
            out.byte(0)?;
            out.bytes(server.as_bytes())?;
            out.byte(0)
        }
        RecordType::VPN => {
            let mut fields = Fields::new(text);
            let proto = fields.u16()?;
            let peer = fields.next()?;
            let service = fields.next()?;
            fields.end()?;
            if service.len() > 253 {
                return Err(Error::TooLarge);
            }
            let mut bytes = [0; 32];
            let n = decode_base32(peer.as_bytes(), &mut bytes)?;
            if n != 32 {
                return Err(Error::Malformed);
            }
            out.bytes(&bytes)?;
            out.bytes(&proto.to_be_bytes())?;
            out.bytes(service.as_bytes())?;
            out.byte(0)
        }
        RecordType::RECLAIM_ATTRIBUTE
        | RecordType::RECLAIM_ATTRIBUTE_REF
        | RecordType::RECLAIM_CREDENTIAL
        | RecordType::RECLAIM_PRESENTATION => {
            let n = decode_base32(text.as_bytes(), out.tail())?;
            out.advance(n)
        }
        RecordType::TOMBSTONE => Ok(()),
        _ => Err(Error::Unsupported),
    }
}
pub(crate) fn format(kind: RecordType, data: &[u8], out: &mut Writer<'_>) -> Result<(), Error> {
    match kind {
        RecordType::PKEY | RecordType::EDKEY => {
            let bytes: [u8; 32] = data.try_into().map_err(|_| Error::Malformed)?;
            let key = ZoneKey::new(ZoneKeyType::from_record_type(kind)?, bytes);
            let n = key.write_ztld(out.tail())?.len();
            out.advance(n)
        }
        RecordType::TXT
        | RecordType::NICK
        | RecordType::REDIRECT
        | RecordType::LEHO
        | RecordType::RECLAIM_TICKET
        | RecordType::RECLAIM_OIDC_CLIENT
        | RecordType::RECLAIM_OIDC_REDIRECT => out.bytes(cstr(data)),
        RecordType::GNS2DNS => {
            let (name, rest) = terminated(data)?;
            let (server, tail) = terminated(rest)?;
            if !tail.is_empty() {
                return Err(Error::Malformed);
            }
            out.bytes(name)?;
            out.byte(b'@')?;
            out.bytes(server)
        }
        RecordType::VPN => {
            let peer = data.get(..32).ok_or(Error::Truncated)?;
            let proto = u16_at(data, 32)?;
            let (service, tail) = terminated(data.get(34..).ok_or(Error::Truncated)?)?;
            if !tail.is_empty() {
                return Err(Error::Malformed);
            }
            out.number(proto.into())?;
            out.byte(b' ')?;
            out.b32(peer)?;
            out.byte(b' ')?;
            out.bytes(service)
        }
        RecordType::RECLAIM_ATTRIBUTE
        | RecordType::RECLAIM_ATTRIBUTE_REF
        | RecordType::RECLAIM_CREDENTIAL
        | RecordType::RECLAIM_PRESENTATION => out.b32(data),
        RecordType::TOMBSTONE => {
            out.bytes(b"This is a memento of an older block for internal maintenance.")
        }
        _ => Err(Error::Unsupported),
    }
}
