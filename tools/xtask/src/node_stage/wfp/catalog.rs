//! Bounded CMS envelope inspection for an existing Windows catalog.
use std::io::{self, Read, Seek, SeekFrom};

struct Element {
    tag: u8,
    body: u64,
    end: u64,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "WFP catalog must contain a CMS SignedData envelope with a nonempty signature",
    )
}

fn element(file: &mut (impl Read + Seek), parent: u64) -> io::Result<Element> {
    let start = file.stream_position()?;
    if parent.checked_sub(start).is_none_or(|left| left < 2) {
        return Err(invalid());
    }
    let mut header = [0u8; 2];
    file.read_exact(&mut header)?;
    let tag = header[0];
    let encoded = header[1];
    let length = if encoded & 0x80 == 0 {
        u64::from(encoded)
    } else {
        let count = usize::from(encoded & 0x7f);
        if !(1..=4).contains(&count) || count as u64 + 2 > parent - start {
            return Err(invalid());
        }
        let mut raw = [0u8; 8];
        file.read_exact(&mut raw[8 - count..])?;
        let length = u64::from_be_bytes(raw);
        if raw[8 - count] == 0 || length < 128 {
            return Err(invalid());
        }
        length
    };
    let body = file.stream_position()?;
    let end = body
        .checked_add(length)
        .filter(|end| *end <= parent)
        .ok_or_else(invalid)?;
    Ok(Element { tag, body, end })
}

fn expect(file: &mut (impl Read + Seek), parent: u64, tag: u8) -> io::Result<Element> {
    let item = element(file, parent)?;
    if item.tag != tag || item.body == item.end {
        return Err(invalid());
    }
    Ok(item)
}

fn skip(file: &mut (impl Read + Seek), item: Element) -> io::Result<()> {
    file.seek(SeekFrom::Start(item.end))?;
    Ok(())
}

pub(super) fn signed_data(file: &mut (impl Read + Seek), bytes: u64) -> io::Result<()> {
    const SIGNED_DATA: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2];
    file.rewind()?;
    let envelope = expect(file, bytes, 0x30)?;
    let oid = expect(file, envelope.end, 6)?;
    if envelope.end != bytes || oid.end - oid.body != SIGNED_DATA.len() as u64 {
        return Err(invalid());
    }
    let mut identifier = [0u8; SIGNED_DATA.len()];
    file.read_exact(&mut identifier)?;
    if identifier != SIGNED_DATA {
        return Err(invalid());
    }
    let explicit = expect(file, envelope.end, 0xa0)?;
    let signed = expect(file, explicit.end, 0x30)?;
    if signed.end != explicit.end || explicit.end != envelope.end {
        return Err(invalid());
    }
    for tag in [2, 0x31, 0x30] {
        let field = expect(file, signed.end, tag)?;
        skip(file, field)?;
    }
    let mut signers = element(file, signed.end)?;
    for optional in [0xa0, 0xa1] {
        if signers.tag == optional {
            skip(file, signers)?;
            signers = element(file, signed.end)?;
        }
    }
    if signers.tag != 0x31 || signers.end != signed.end || signers.body == signers.end {
        return Err(invalid());
    }
    let first = expect(file, signers.end, 0x30)?;
    let version = expect(file, first.end, 2)?;
    skip(file, version)?;
    let signer = element(file, first.end)?;
    if !matches!(signer.tag, 0x30 | 0x80) || signer.body == signer.end {
        return Err(invalid());
    }
    skip(file, signer)?;
    let digest = expect(file, first.end, 0x30)?;
    skip(file, digest)?;
    let mut signature_algorithm = element(file, first.end)?;
    if signature_algorithm.tag == 0xa0 {
        skip(file, signature_algorithm)?;
        signature_algorithm = element(file, first.end)?;
    }
    if signature_algorithm.tag != 0x30 || signature_algorithm.body == signature_algorithm.end {
        return Err(invalid());
    }
    skip(file, signature_algorithm)?;
    let _signature = expect(file, first.end, 4)?;
    Ok(())
}
