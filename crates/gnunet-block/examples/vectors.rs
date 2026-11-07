//! Test-only signed plugin vectors, produced using actual pure Rust signers.
use gnunet_crypto::{
    EddsaPrivateKey,
    gns::{EdkeySecret, PkeySecret},
};
use gnunet_hello::{AbsoluteTime, HelloBuilder, Limits, SignatureProfile};
use std::{
    error::Error,
    io::{self, Write},
};
fn emit(name: &str, kind: u32, bytes: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    write!(out, "{name} {kind} ")?;
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    writeln!(out)
}
fn main() -> Result<(), Box<dyn Error>> {
    let timestamp = std::env::args()
        .nth(1)
        .ok_or("missing UTC timestamp")?
        .parse::<u64>()?;
    let profile = match std::env::args().nth(2).as_deref() {
        Some("normal") => SignatureProfile::Gnunet029,
        Some("deterministic") => SignatureProfile::DeterministicPidDerivation,
        _ => return Err("missing explicit HELLO compilation profile".into()),
    };
    let ed = EddsaPrivateKey::from_seed([42; 32]);
    let public = ed.public_key();
    for n in [0usize, 1, 64, 4096] {
        let mut b = vec![0; 104 + n];
        b[64..68].copy_from_slice(&((40 + n) as u32).to_be_bytes());
        b[68..72].copy_from_slice(&17u32.to_be_bytes());
        b[72..104].copy_from_slice(public.as_bytes());
        for (i, v) in b[104..].iter_mut().enumerate() {
            *v = i as u8;
        }
        let sig = ed.sign(17, &b[64..])?;
        b[..64].copy_from_slice(sig.as_bytes());
        emit(&format!("fs-{n}"), 9, &b)?;
    }
    for expiry in [0, u64::MAX] {
        let mut b = vec![0; 112];
        b[64..68].copy_from_slice(&48u32.to_be_bytes());
        b[68..72].copy_from_slice(&11u32.to_be_bytes());
        b[72..80].copy_from_slice(&expiry.to_be_bytes());
        b[80..].copy_from_slice(public.as_bytes());
        let sig = ed.sign(11, &b[64..])?;
        b[..64].copy_from_slice(sig.as_bytes());
        emit(&format!("dns-{expiry}"), 10, &b)?;
        let mut b = vec![0; 176];
        b[..4].copy_from_slice(&80u32.to_be_bytes());
        b[4..8].copy_from_slice(&18u32.to_be_bytes());
        b[8..16].copy_from_slice(&expiry.to_be_bytes());
        b[16..80].fill(93);
        b[80..112].copy_from_slice(public.as_bytes());
        let sig = ed.sign(18, &b[..80])?;
        b[112..].copy_from_slice(sig.as_bytes());
        emit(&format!("regex-accept-{expiry}"), 23, &b)?;
    }
    let limits = Limits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 65535,
        maximum_addresses: 1024,
    };
    for expiry in [1, u64::MAX] {
        let mut storage = [0; 1024];
        let mut builder = HelloBuilder::new(&mut storage, limits);
        builder.add_address(b"tcp://127.0.0.1:1234")?;
        builder.add_address(b"udp://[::1]:9876")?;
        let hello = builder.sign(&ed, AbsoluteTime::from_micros(expiry), profile)?;
        let mut out = vec![0; hello.block_len()?];
        hello.encode_block(&mut out)?;
        emit(&format!("hello-{expiry}"), 13, &out)?;
    }
    let p = PkeySecret::from_bytes([7; 32])?.derive("block", "gns")?;
    let e = EdkeySecret::from_seed([7; 32]).derive("block", "gns")?;
    for n in [0usize, 1, 16, 65, 65535] {
        for kind in [65536u32, 65556] {
            let mut b = vec![0; 112 + n];
            b[..4].copy_from_slice(&((112 + n) as u32).to_be_bytes());
            b[4..8].copy_from_slice(&kind.to_be_bytes());
            let public = if kind == 65536 {
                p.public_key()
            } else {
                e.public_key()
            };
            b[8..40].copy_from_slice(&public);
            b[104..112].copy_from_slice(&u64::MAX.to_be_bytes());
            for (i, v) in b[112..].iter_mut().enumerate() {
                *v = i as u8;
            }
            let mut region = Vec::with_capacity(16 + n);
            region.extend_from_slice(&((16 + n) as u32).to_be_bytes());
            region.extend_from_slice(&15u32.to_be_bytes());
            region.extend_from_slice(&b[104..]);
            let sig = if kind == 65536 {
                p.sign(15, &[&region])?
            } else {
                e.sign(15, &[&region])?
            };
            b[40..104].copy_from_slice(&sig);
            emit(&format!("gns-{kind}-{n}"), 11, &b)?;
        }
    }
    for kind in [65536u32, 65556] {
        let mut b = vec![0; 380];
        b[4..8].copy_from_slice(&372u32.to_be_bytes());
        b[8..16].copy_from_slice(&timestamp.to_be_bytes());
        b[16..24].copy_from_slice(&123u64.to_be_bytes());
        for i in 0..32 {
            b[24 + i * 8..32 + i * 8].copy_from_slice(&(i as u64).to_be_bytes());
        }
        b[280..284].copy_from_slice(&kind.to_be_bytes());
        let public = if kind == 65536 {
            p.public_key()
        } else {
            e.public_key()
        };
        b[284..316].copy_from_slice(&public);
        let mut region = vec![0; 52];
        region[..4].copy_from_slice(&52u32.to_be_bytes());
        region[4..8].copy_from_slice(&3u32.to_be_bytes());
        region[8..16].copy_from_slice(&timestamp.to_be_bytes());
        region[16..52].copy_from_slice(&b[280..316]);
        let sig = if kind == 65536 {
            p.sign(3, &[&region])?
        } else {
            e.sign(3, &[&region])?
        };
        b[316..380].copy_from_slice(&sig);
        emit(&format!("revocation-{kind}"), 12, &b)?;
    }
    Ok(())
}
