//! Bounded actual default15 proof mining for a normal PILS-derived public identity.
use gnunet_crypto::pow;
use gnunet_nse::crypto::{WorkBits, valid_proof};
use gnunet_pils::{MasterKey, Profile};
use std::{
    error::Error,
    io::{self, Write},
};
fn main() -> Result<(), Box<dyn Error>> {
    let key = MasterKey::from_seed([17; 32])
        .derive(&gnunet_crypto::hash512(&[]), Profile::Reference029)?
        .public_key();
    let mut memory = Vec::new();
    memory.try_reserve_exact(pow::MEMORY_BLOCKS)?;
    for _ in 0..pow::MEMORY_BLOCKS {
        memory.push(pow::Block::default());
    }
    for counter in 0..262144_u64 {
        let proof = counter.to_be_bytes();
        if valid_proof(WorkBits::default(), key.as_bytes(), &proof, &mut memory)? {
            let key: String = key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            let raw: String = proof.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(
                io::stdout().lock(),
                "{{\"key32\":\"{key}\",\"raw8\":\"{raw}\",\"candidates\":{},\"workbits\":15}}",
                counter + 1
            )?;
            return Ok(());
        }
    }
    Err("explicit bounded default15 search exhausted".into())
}
