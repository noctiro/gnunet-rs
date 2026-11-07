//! Explicit standard private material boundary. No key files, RNG or services.
use super::{Result, SecretKey, ipc};
use gnunet::{gnsrecord, types::Error as Fault};
use serde_json::Value;
use std::{ffi::OsString, io::Write, os::unix::ffi::OsStrExt};
use zeroize::Zeroizing;

// 36 bytes: official BE32 key type followed by the original32 secret bytes.
const TEXT_LEN: usize = 58;
pub(super) struct Imported {
    pub at: usize,
    pub width: usize,
    pub key: SecretKey,
}
struct Argument {
    at: usize,
    width: usize,
    start: usize,
    bytes: Zeroizing<Vec<u8>>,
}
/// Take every explicitly identified private argument before any ordinary parse
/// can fail. The original CLI-owned OsString is replaced, never copied into a
/// String, Value, Debug or error. OS argv visibility remains inherent to -P.
pub(super) fn extract(args: &mut [OsString]) -> Result<Option<Imported>> {
    let mut first = None;
    let mut duplicate = false;
    let mut missing = false;
    let mut at = match args.first().and_then(|value| value.to_str()) {
        Some("list" | "monitor") => 2,
        Some("lookup" | "lookup-suffix" | "export" | "create" | "delete") => 3,
        Some("rename" | "decrypt") => 4,
        Some("encrypt") => 3,
        // An invalid action has no valid positional contract. Erase explicitly
        // marked option material before the later generic parse error.
        _ => 0,
    };
    while at < args.len() {
        let option = args[at].as_os_str().as_bytes();
        let separate = matches!(option, b"--private-key" | b"--privkey" | b"-P");
        let prefix = [b"--private-key=".as_slice(), b"--privkey=".as_slice()]
            .iter()
            .find(|prefix| option.starts_with(prefix))
            .map(|prefix| prefix.len());
        let argument = if separate {
            if at + 1 == args.len() {
                missing = true;
                at += 1;
                continue;
            }
            let bytes = Zeroizing::new(std::mem::take(&mut args[at + 1]).into_encoded_bytes());
            Some(Argument {
                at,
                width: 2,
                start: 0,
                bytes,
            })
        } else if let Some(start) = prefix {
            let bytes = Zeroizing::new(std::mem::take(&mut args[at]).into_encoded_bytes());
            Some(Argument {
                at,
                width: 1,
                start,
                bytes,
            })
        } else {
            None
        };
        if let Some(argument) = argument {
            at += argument.width;
            if first.is_some() {
                duplicate = true;
                drop(argument);
            } else {
                first = Some(argument);
            }
        } else {
            at += 1;
        }
    }
    if duplicate {
        return Err("private key supplied more than once".into());
    }
    if missing {
        return Err("missing private key option value".into());
    }
    let Some(argument) = first else {
        return Ok(None);
    };
    let encoded = &argument.bytes[argument.start..];
    if encoded.len() != TEXT_LEN {
        return Err("private key must be one58-character official typed Base32GNS value".into());
    }
    let mut raw = Zeroizing::new([0; ipc::KEY_LEN]);
    let used = gnsrecord::decode_base32(encoded, &mut raw[..])?;
    if used != ipc::KEY_LEN {
        return Err(Fault::Malformed.into());
    }
    let key = SecretKey::from_serialized(&raw[..])?;
    Ok(Some(Imported {
        at: argument.at,
        width: argument.width,
        key,
    }))
}
fn encoded(key: &SecretKey) -> Result<Zeroizing<[u8; TEXT_LEN]>> {
    let mut bytes = Zeroizing::new([0; TEXT_LEN]);
    let used = gnsrecord::encode_base32(key.expose_serialized(), &mut bytes[..])?;
    if used != TEXT_LEN {
        return Err(Fault::Malformed.into());
    }
    Ok(bytes)
}
/// Exact official text, one newline and no metadata rows. This function is only
/// reached through the explicit export action, after the real lookup result.
pub(super) fn line(out: &mut impl Write, key: &SecretKey) -> Result<()> {
    let bytes = encoded(key)?;
    out.write_all(&bytes[..])?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
/// The prefix contains only public metadata. Secret ASCII is streamed directly
/// from an erased fixed buffer, never inserted into an owned JSON Value/String.
pub(super) fn row(out: &mut impl Write, public: &Value, key: &SecretKey) -> Result<()> {
    if public.as_object().is_none_or(|object| object.is_empty()) {
        return Err(Fault::InvalidInput.into());
    }
    let bytes = encoded(key)?;
    let mut prefix = serde_json::to_vec(public)?;
    if prefix.pop() != Some(b'}') {
        return Err(Fault::InvalidInput.into());
    }
    out.write_all(&prefix)?;
    out.write_all(b",\"private_key\":\"")?;
    out.write_all(&bytes[..])?;
    out.write_all(b"\"}\n")?;
    out.flush()?;
    Ok(())
}
