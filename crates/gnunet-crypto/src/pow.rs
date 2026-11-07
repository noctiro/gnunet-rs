//! Exact GNUnet Argon2id13 PoW primitive with caller-owned1MiB memory.
/// One aligned1024-byte Argon2 memory block; exactly1024 are required.
pub use argon2::Block;
use gnunet_types::Error;
/// Fixed GNUnet PoW memory block count.
pub const MEMORY_BLOCKS: usize = 1024;
/// GNUnet's64-byte Argon2id13 output, t3/m1024KiB/p1. Scratch is reusable public
/// work memory and may change on error; output remains unchanged on any error.
/// Salt is exactly16 bytes. No implicit entropy, allocation or OS call exists.
pub fn hash(
    salt: &[u8; 16],
    input: &[u8],
    output: &mut [u8; 64],
    memory: &mut [Block],
) -> Result<(), Error> {
    if memory.len() < MEMORY_BLOCKS {
        return Err(Error::Capacity);
    }
    let params = argon2::Params::new(1024, 3, 1, Some(64)).map_err(|_| Error::InvalidInput)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut temporary = [0; 64];
    let result = argon.hash_password_into_with_memory(
        input,
        salt,
        &mut temporary,
        &mut memory[..MEMORY_BLOCKS],
    );
    if result.is_err() {
        crate::erase(&mut temporary);
        return Err(Error::InvalidInput);
    }
    output.copy_from_slice(&temporary);
    crate::erase(&mut temporary);
    Ok(())
}
