//! Offline test adapter: hex URI input and exact artifact observations, no I/O ports.
use gnunet_crypto::EddsaPrivateKey;
use gnunet_fs::{Limits, Location, Uri};
use gnunet_wire::official::AbsoluteTime;
use std::{
    error::Error,
    fmt::Write as _,
    io::{self, BufRead, Write as _},
};
fn decode(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("hex length".into());
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(Into::into))
        .collect()
}
fn hex(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut out = String::new();
    for b in bytes {
        write!(out, "{b:02x}")?;
    }
    Ok(out)
}
fn describe(uri: Uri<'_>) -> Result<String, Box<dyn Error>> {
    let mut buffer = vec![0; uri.encoded_len()?];
    uri.encode(&mut buffer)?;
    let kind = match uri {
        Uri::Content(_) => "chk",
        Uri::Namespace(_) => "sks",
        Uri::Keywords(_) => "ksk",
        Uri::Location(_) => "loc",
    };
    let mut out = format!("OK {kind} {}", hex(&buffer)?);
    if let Uri::Keywords(words) = uri {
        for term in words.iter() {
            write!(
                out,
                " {}:{}",
                u8::from(term.mandatory()),
                hex(&term.bytes().collect::<Vec<_>>())?
            )?;
        }
    }
    Ok(out)
}
fn main() -> Result<(), Box<dyn Error>> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        let mut fields = line.split_ascii_whitespace();
        let mode = fields.next().ok_or("mode")?;
        let bytes = decode(fields.next().ok_or("hex URI")?)?;
        let parsed = Uri::parse(&bytes, Limits::default());
        let result = match mode {
            "P" => parsed,
            "S" => {
                let seed: [u8; 32] = decode(fields.next().ok_or("seed")?)?
                    .try_into()
                    .map_err(|_| "seed32")?;
                let expiry = fields.next().ok_or("expiry")?.parse::<u64>()?;
                match parsed {
                    Ok(Uri::Content(c)) => Location::sign(
                        c,
                        &EddsaPrivateKey::from_seed(seed),
                        AbsoluteTime::from_micros(expiry),
                    )
                    .map(Uri::Location),
                    Ok(_) => Err(gnunet_types::Error::InvalidInput),
                    Err(e) => Err(e),
                }
            }
            _ => return Err("mode".into()),
        };
        if fields.next().is_some() {
            return Err("extra input".into());
        }
        let output = match result {
            Ok(uri) => describe(uri)?,
            Err(_) => "ERR".into(),
        };
        writeln!(io::stdout().lock(), "{output}")?;
    }
    Ok(())
}
