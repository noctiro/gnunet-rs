//! Actual DEL/ATTR text used by the installed ABD command/library. The contrib
//! C record plugin itself is not in active Meson; this is a shared Rust grammar,
//! not a claim that an unbuilt plugin was installed. Parsing authenticates none
//! of the signature, GNS source, expiration, delegation or authorization.
use crate::{
    AbdLayout, Error, RecordType,
    helpers::{Fields, Writer, decode_b64, encode_b64, number},
};
use gnunet_gnsrecord::decode_base32;
use gnunet_wire::official::abd::{Delegate, Key, Policy, SignedDelegate, Term};

pub(crate) fn supported(kind: RecordType) -> bool {
    matches!(kind, RecordType::DELEGATE | RecordType::ATTRIBUTE)
}
fn trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_ascii_whitespace())
}
fn key(text: &str) -> Result<[u8; 36], Error> {
    if text.len() != 58 {
        return Err(Error::Malformed);
    }
    let mut out = [0; 36];
    if decode_base32(text.as_bytes(), &mut out)? != out.len() {
        return Err(Error::Malformed);
    }
    Key::new(&out)?;
    Ok(out)
}
fn role(text: &str, required: bool) -> Result<([u8; 36], Option<&[u8]>), Error> {
    let head = text.get(..58).ok_or(Error::Malformed)?;
    let rest = text.get(58..).ok_or(Error::Malformed)?;
    let key = key(head)?;
    let attr = if rest.is_empty() && !required {
        None
    } else {
        let value = rest
            .strip_prefix('.')
            .filter(|a| !a.is_empty())
            .ok_or(Error::Malformed)?;
        Some(value.as_bytes())
    };
    Ok((key, attr))
}
fn text_attribute(bytes: &[u8], policy: bool) -> Result<(), Error> {
    // No escape grammar exists in these public text formats. Reject an
    // unrepresentable value rather than changing its original signed bytes.
    if bytes.is_empty()
        || bytes
            .iter()
            .any(|b| *b == 0 || b.is_ascii_whitespace() || (policy && *b == b','))
    {
        return Err(Error::Unsupported);
    }
    core::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
    Ok(())
}
fn del_parse(text: &str, out: &mut Writer<'_>) -> Result<(), Error> {
    // Only the last two bars separate signature and expiration. An original
    // attribute can itself contain a bar; it remains in the signed claim.
    let mut parts = text.rsplitn(3, '|');
    let expiration = number(trim(parts.next().ok_or(Error::Malformed)?), u64::MAX)?;
    let signature_text = trim(parts.next().ok_or(Error::Malformed)?);
    let claim = parts.next().ok_or(Error::Malformed)?;
    let mut fields = Fields::new(claim);
    let issuer_text = fields.next()?;
    if fields.next()? != "->" {
        return Err(Error::Malformed);
    }
    let subject_text = fields.next()?;
    fields.end()?;
    let (issuer, issuer_attribute) = role(issuer_text, true)?;
    let (subject, subject_attribute) = role(subject_text, false)?;
    let mut signature = [0; 68];
    {
        let mut signature_out = Writer::new(&mut signature);
        decode_b64(signature_text, &mut signature_out)?;
        if signature_out.len() != 68 {
            return Err(Error::Malformed);
        }
    }
    let value = Delegate {
        signature: &signature,
        issuer: Key::new(&issuer)?,
        subject: Key::new(&subject)?,
        expiration_us: expiration,
        issuer_attribute: issuer_attribute.ok_or(Error::Malformed)?,
        subject_attribute,
    };
    let n = value.encode_record(out.tail())?;
    out.advance(n)
}
fn term(text: &str) -> Result<([u8; 36], Option<&[u8]>), Error> {
    let mut fields = Fields::new(text);
    let subject = key(fields.next()?)?;
    let attribute = if fields.rest().is_empty() {
        None
    } else {
        let value = fields.next()?.as_bytes();
        text_attribute(value, true)?;
        Some(value)
    };
    fields.end()?;
    Ok((subject, attribute))
}
fn attr_parse(text: &str, out: &mut Writer<'_>, layout: AbdLayout) -> Result<(), Error> {
    layout.validate()?;
    let prefix = if layout.align64 == 8 { 16usize } else { 12 };
    let mut count = 0u32;
    let mut total = prefix;
    for part in text.split(',') {
        let (key, attribute) = term(part)?;
        let len = Term {
            subject: Key::new(&key)?,
            attribute,
        }
        .encoded_len()?;
        total = total.checked_add(len).ok_or(Error::Overflow)?;
        count = count.checked_add(1).ok_or(Error::TooLarge)?;
    }
    let data_size = u64::try_from(total - prefix).map_err(|_| Error::TooLarge)?;
    let bytes = out.fixed(total)?;
    bytes[..4].copy_from_slice(&count.to_be_bytes());
    bytes[prefix - 8..prefix].copy_from_slice(&data_size.to_be_bytes());
    let mut at = prefix;
    for part in text.split(',') {
        let (key, attribute) = term(part)?;
        at += Term {
            subject: Key::new(&key)?,
            attribute,
        }
        .encode(&mut bytes[at..])?;
    }
    Ok(())
}
pub(crate) fn parse(
    kind: RecordType,
    text: &str,
    out: &mut Writer<'_>,
    layout: AbdLayout,
) -> Result<(), Error> {
    match kind {
        RecordType::DELEGATE => del_parse(text, out),
        RecordType::ATTRIBUTE => attr_parse(text, out, layout),
        _ => Err(Error::Unsupported),
    }
}
fn del_format(data: &[u8], out: &mut Writer<'_>) -> Result<(), Error> {
    let value = SignedDelegate::decode(data)?.delegate();
    text_attribute(value.issuer_attribute, false)?;
    if let Some(attr) = value.subject_attribute {
        text_attribute(attr, false)?;
    }
    out.b32(value.issuer.bytes())?;
    out.byte(b'.')?;
    out.bytes(value.issuer_attribute)?;
    out.bytes(b" -> ")?;
    out.b32(value.subject.bytes())?;
    if let Some(attr) = value.subject_attribute {
        out.byte(b'.')?;
        out.bytes(attr)?;
    }
    out.bytes(b" | ")?;
    encode_b64(value.signature, out)?;
    out.bytes(b" | ")?;
    out.number(value.expiration_us)
}
fn attr_format(data: &[u8], out: &mut Writer<'_>, layout: AbdLayout) -> Result<(), Error> {
    let value = Policy::decode(data, layout)?;
    if value.count() == 0 {
        return Err(Error::Unsupported);
    }
    for (index, part) in value.iter().enumerate() {
        let term = part;
        if let Some(attr) = term.attribute {
            text_attribute(attr, true)?;
        }
        if index != 0 {
            out.byte(b',')?;
        }
        out.b32(term.subject.bytes())?;
        if let Some(attr) = term.attribute {
            out.byte(b' ')?;
            out.bytes(attr)?;
        }
    }
    Ok(())
}
pub(crate) fn format(
    kind: RecordType,
    data: &[u8],
    out: &mut Writer<'_>,
    layout: AbdLayout,
) -> Result<(), Error> {
    match kind {
        RecordType::DELEGATE => del_format(data, out),
        RecordType::ATTRIBUTE => attr_format(data, out, layout),
        _ => Err(Error::Unsupported),
    }
}
