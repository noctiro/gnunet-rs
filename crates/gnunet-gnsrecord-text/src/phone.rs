//! Actual conditional CONVERSATION PHONE text. No key/source/call authority.
use crate::{Error, helpers::Writer};
use gnunet_gnsrecord::decode_base32;
use gnunet_wire::official::conversation::PhoneRecord;
pub(crate) fn parse(text: &str, output: &mut Writer<'_>) -> Result<(), Error> {
    // Fixed standard Base32 widths:512 bits ->103 chars,256 bits ->52 chars.
    let bytes = text.as_bytes();
    if bytes.len() != 156 || bytes[103] != b'-' {
        return Err(Error::Malformed);
    }
    let mut port = [0; 64];
    let mut peer = [0; 32];
    if decode_base32(&bytes[..103], &mut port)? != port.len()
        || decode_base32(&bytes[104..], &mut peer)? != peer.len()
    {
        return Err(Error::Malformed);
    }
    let n = PhoneRecord::v1(peer, port).encode(output.tail())?;
    output.advance(n)
}
pub(crate) fn format(data: &[u8], output: &mut Writer<'_>) -> Result<(), Error> {
    let value = PhoneRecord::decode(data)?;
    // The v1 public grammar carries neither version nor reserved. Never silently
    // rewrite unsupported/irreversible binary values to the current profile.
    if value.version != 1 || value.reserved != 0 {
        return Err(Error::Unsupported);
    }
    output.b32(&value.port)?;
    output.byte(b'-')?;
    output.b32(&value.peer)
}
