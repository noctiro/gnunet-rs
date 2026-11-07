//! The normal public C primitive's twelve existing BLOCK-corpus vectors.
#![cfg(feature = "pow")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check exact external vectors and caller-storage boundaries."
)]
use gnunet_crypto::pow;
use gnunet_types::Error;

fn hex(text: &str) -> Result<Vec<u8>, Error> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return Err(Error::InvalidInput);
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |c| match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(Error::InvalidInput),
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

#[test]
fn normal_c_pow_vectors_and_reusable_caller_storage() -> Result<(), Error> {
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS + 1];
    memory[pow::MEMORY_BLOCKS].as_mut().fill(u64::MAX);
    let mut count = 0;
    for line in include_str!("fixtures/pow-normal-C.txt").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 {
            return Err(Error::InvalidInput);
        }
        let salt = hex(fields[0])?;
        let salt: &[u8; 16] = salt
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidInput)?;
        let input = hex(fields[1])?;
        let expected = hex(fields[2])?;
        let mut output = [0xa5; 64];
        pow::hash(salt, &input, &mut output, &mut memory)?;
        assert_eq!(output.as_slice(), expected);
        assert_eq!(memory[pow::MEMORY_BLOCKS].as_ref(), &[u64::MAX; 128]);
        count += 1;
    }
    assert_eq!(count, 12);
    Ok(())
}

#[test]
fn short_scratch_preserves_output_and_work_memory() {
    assert_eq!(core::mem::size_of::<pow::Block>(), 1024);
    assert_eq!(
        pow::MEMORY_BLOCKS * core::mem::size_of::<pow::Block>(),
        1024 * 1024
    );
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS - 1];
    let mut output = [0xa5; 64];
    for block in &mut memory {
        block.as_mut().fill(u64::MAX);
    }
    assert_eq!(
        pow::hash(&[0; 16], b"input", &mut output, &mut memory),
        Err(Error::Capacity)
    );
    assert_eq!(output, [0xa5; 64]);
    assert!(memory.iter().all(|block| block.as_ref() == [u64::MAX; 128]));
    assert_eq!(
        pow::hash(&[0; 16], b"", &mut output, &mut []),
        Err(Error::Capacity)
    );
    assert_eq!(output, [0xa5; 64]);
}
