//! Bounded test-fixture search for a second PILS identity sharing a valid raw15 proof.
use gnunet_crypto::{hash512, pow};
use gnunet_nse::crypto::{WorkBits, valid_proof};
use gnunet_pils::{MasterKey, Profile};
use std::{
    error::Error,
    io::{self, Write},
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() -> Result<(), Box<dyn Error>> {
    let proof = 32508_u64.to_be_bytes();
    let context = hash512(&[]);
    let mut memory = Vec::new();
    memory.try_reserve_exact(pow::MEMORY_BLOCKS)?;
    for _ in 0..pow::MEMORY_BLOCKS {
        memory.push(pow::Block::default());
    }
    for counter in 0..262144_u64 {
        let mut ikm = [0x61; 32];
        ikm[..8].copy_from_slice(&counter.to_be_bytes());
        let key = MasterKey::from_seed(ikm)
            .derive(&context, Profile::Reference029)?
            .public_key();
        if valid_proof(WorkBits::default(), key.as_bytes(), &proof, &mut memory)? {
            writeln!(
                io::stdout().lock(),
                "{{\"kind\":\"synthetic-PILS-rotation15-fixture\",\"fixture_ikm32\":\"{}\",\"peer32\":\"{}\",\"raw8\":\"{}\",\"candidates\":{},\"workbits\":15}}",
                hex(&ikm),
                hex(key.as_bytes()),
                hex(&proof),
                counter + 1
            )?;
            return Ok(());
        }
    }
    Err("explicit bounded rotation fixture search exhausted".into())
}
