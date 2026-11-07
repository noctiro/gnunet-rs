//! Public deterministic Elligator primitive observer, not a daemon.
use gnunet_session_crypto::{
    elligator::{self, Representative, Secret},
    exchange::{EcdhePublic, EcdheSecret},
};
use std::{
    fmt::Write as _,
    io::{self, BufRead, Write as _},
};
fn hex(data: &[u8]) -> Result<String, std::fmt::Error> {
    let mut s = String::new();
    for b in data {
        write!(&mut s, "{b:02x}")?;
    }
    Ok(s)
}
fn parse(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if s.len() != 64 {
        return Err("hex length".into());
    }
    let mut b = [0; 32];
    for (i, p) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        b[i] = u8::from_str_radix(std::str::from_utf8(p)?, 16)?;
    }
    Ok(b)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let p: Vec<_> = line.split_ascii_whitespace().collect();
        if p.len() != 3 {
            return Err("MODE HEX TWEAK".into());
        }
        let bytes = parse(p[1])?;
        let tweak = p[2].parse::<u8>()?;
        match p[0] {
            "D" => {
                let d = elligator::decode(Representative::from_bytes(bytes));
                writeln!(
                    out,
                    "{{\"point\":\"{}\",\"high\":{}}}",
                    hex(d.public.as_bytes())?,
                    d.high_y
                )?;
            }
            "E" => match elligator::encode(EcdhePublic::from_bytes(bytes), tweak) {
                Ok(r) => writeln!(out, "{{\"representative\":\"{}\"}}", hex(r.as_bytes())?)?,
                Err(_) => writeln!(out, "{{\"error\":true}}")?,
            },
            "S" => {
                let secret = Secret::from_bytes(bytes);
                match secret.public(tweak) {
                    Err(_) => writeln!(out, "{{\"error\":true}}")?,
                    Ok((point, repr)) => {
                        let rec = EcdheSecret::from_bytes([9; 32]);
                        let (enc, shared) =
                            elligator::encapsulate(rec.public_key(), &secret, tweak)?;
                        if enc != repr {
                            return Err("repr mismatch".into());
                        }
                        let other = elligator::decapsulate(&rec, enc)?;
                        let mut proof = [0; 32];
                        let mut opposite = [0; 32];
                        shared.expand(&[b"test-component"], &mut proof)?;
                        other.expand(&[b"test-component"], &mut opposite)?;
                        if proof != opposite {
                            return Err("shared mismatch".into());
                        }
                        writeln!(
                            out,
                            "{{\"point\":\"{}\",\"representative\":\"{}\",\"derived\":\"{}\"}}",
                            hex(point.as_bytes())?,
                            hex(repr.as_bytes())?,
                            hex(&proof)?
                        )?;
                    }
                }
            }
            _ => return Err("mode".into()),
        }
    }
    Ok(())
}
