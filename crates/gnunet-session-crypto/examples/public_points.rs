//! Generate public prime-subgroup/torsion fixtures, never keys or secret material.
#![forbid(unsafe_code)]
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
    scalar::Scalar,
};
use std::io::{self, Write};
fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    for n in 0_u64..32 {
        let base = ED25519_BASEPOINT_POINT * Scalar::from(n);
        for (torsion, point) in EIGHT_TORSION.iter().enumerate() {
            let bytes = (base + point).compress().to_bytes();
            write!(out, "{n} {torsion} ")?;
            for byte in bytes {
                write!(out, "{byte:02x}")?;
            }
            writeln!(out)?;
        }
    }
    Ok(())
}
