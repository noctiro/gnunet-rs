//! Shared official GNUnet peer-identity text conversion at the CLI boundary.
use std::{error::Error, ffi::OsStr};

pub(super) fn parse(value: &OsStr) -> Result<[u8; 32], Box<dyn Error>> {
    let text = value
        .to_str()
        .ok_or("peer identity must be ASCII")?
        .as_bytes();
    let mut peer = [0; 32];
    if text.len() == 64 {
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        for (output, pair) in peer.iter_mut().zip(text.as_chunks::<2>().0) {
            *output = hex(pair[0]).ok_or("invalid hex peer identity")? << 4
                | hex(pair[1]).ok_or("invalid hex peer identity")?;
        }
    } else if text.len() == 52 {
        let mut accumulator = 0_u16;
        let mut available = 0;
        let mut at = 0;
        for byte in text {
            let canonical = match byte.to_ascii_uppercase() {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                b'U' => b'V',
                byte => byte,
            };
            let digit = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
                .iter()
                .position(|byte| *byte == canonical)
                .ok_or("invalid GNUnet peer identity")?;
            accumulator = ((accumulator & ((1 << available) - 1)) << 5) | digit as u16;
            available += 5;
            if available >= 8 {
                available -= 8;
                *peer.get_mut(at).ok_or("invalid peer identity length")? =
                    (accumulator >> available) as u8;
                at += 1;
            }
        }
    } else {
        return Err("expected a 52-character GNUnet peer identity or 64 hex digits".into());
    }
    Ok(peer)
}

pub(super) fn hexadecimal(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 15)]));
    }
    output
}
