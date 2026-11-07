//! Finite stdin numeric/crypto observer for independent original-C expression vectors.
use gnunet_crypto::{hash512, pow};
use gnunet_nse::{
    crypto::{self, ReferenceEndian},
    history,
};
use std::{
    error::Error,
    io::{self, BufRead, Write},
};
fn hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("hex length".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let s = std::str::from_utf8(p)?;
            Ok(u8::from_str_radix(s, 16)?)
        })
        .collect()
}
fn print_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() -> Result<(), Box<dyn Error>> {
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let mut out = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let f: Vec<_> = line.split_whitespace().collect();
        match f.first().copied() {
            Some("W") => {
                let count: usize = f[1].parse()?;
                let values: Result<Vec<u32>, _> = f[2..].iter().map(|v| v.parse()).collect();
                let result = history::summarize(&values?, count)?;
                writeln!(
                    out,
                    "W {:016x} {:016x} {:016x}",
                    result.mean.to_bits(),
                    result.deviation.to_bits(),
                    result.log2_size.to_bits()
                )?;
            }
            Some("D") => {
                let result = history::matching_delay(f[1].parse()?, f[2].parse()?, f[3].parse()?)?;
                writeln!(out, "D {:016x} {}", result.to_bits(), result as u64)?;
            }
            Some("T") => {
                let time = u64::from_str_radix(f[1], 16)?;
                let key: [u8; 32] = hex(f[2])?.try_into().map_err(|_| "key length")?;
                writeln!(
                    out,
                    "T {} {} {} {} {}",
                    print_hex(&hash512(&ReferenceEndian::native().timestamp(time))),
                    print_hex(&hash512(&ReferenceEndian::Little.timestamp(time))),
                    print_hex(&hash512(&ReferenceEndian::Big.timestamp(time))),
                    print_hex(&hash512(&key)),
                    crypto::matching_bits(time, &key, ReferenceEndian::native())
                )?;
            }
            Some("P") => {
                let key: [u8; 32] = hex(f[1])?.try_into().map_err(|_| "key length")?;
                let proof: [u8; 8] = hex(f[2])?.try_into().map_err(|_| "proof length")?;
                let hash = crypto::proof_hash(&key, &proof, &mut memory)?;
                writeln!(
                    out,
                    "P {} {}",
                    print_hex(&hash),
                    crypto::leading_zeros(&hash)
                )?;
            }
            _ => return Err("unknown finite fixture command".into()),
        }
    }
    Ok(())
}
