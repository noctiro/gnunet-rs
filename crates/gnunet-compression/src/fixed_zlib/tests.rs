use super::*;

#[test]
fn exact_member_accepts_overlap_and_rejects_nonmembers() -> Result<(), Error> {
    const EMPTY: [u8; 8] = [0x78, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];
    let mut codec = FixedZlib::new();
    let mut raw = [0; 768];
    for pattern in raw.as_chunks_mut::<3>().0 {
        *pattern = *b"xyz";
    }
    let mut encoded = [0; 64];
    let len = codec.compress(&raw, &mut encoded)?;
    let mut decoded = [0; 768];
    if len >= 32
        || codec.decompress(&encoded[..len], &mut decoded)? != raw.len()
        || decoded != raw
        || codec.decompress(&encoded[..len], &mut decoded[..767]) != Err(Error::Capacity)
        || codec.decompress(&encoded[..len - 1], &mut decoded) != Err(Error::Truncated)
        || codec.decompress(&encoded[..len + 1], &mut decoded) != Err(Error::Malformed)
    {
        return Err(Error::Conflict);
    }
    encoded[len - 1] ^= 1;
    if codec.decompress(&encoded[..len], &mut decoded) != Err(Error::Malformed) {
        return Err(Error::Conflict);
    }
    let len = codec.compress(&[], &mut encoded)?;
    if encoded[..len] != EMPTY
        || codec.decompress(&encoded[..len], &mut [])? != 0
        || codec.compress(b"x", &mut encoded[..5]) != Err(Error::Capacity)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn decodes_independent_dynamic_huffman_member() -> Result<(), Error> {
    // This compressed member was produced by zlib's dynamic-Huffman encoder.
    let compressed = [
        0x78, 0x9c, 0xed, 0xcb, 0xab, 0x11, 0x80, 0x30, 0x10, 0x05, 0x40, 0x4f, 0x15, 0x57, 0x01,
        0x05, 0xe0, 0x99, 0x38, 0x0c, 0xa4, 0x80, 0x83, 0x79, 0x8a, 0x90, 0x81, 0xfb, 0xf4, 0x0f,
        0x7d, 0xf0, 0xd4, 0xaa, 0x2d, 0x4b, 0xed, 0x08, 0x59, 0xe7, 0xad, 0x8a, 0x87, 0x69, 0xe8,
        0x24, 0x78, 0x52, 0x9b, 0xa0, 0xe1, 0x42, 0x0f, 0x17, 0x43, 0x3a, 0xc4, 0x6f, 0xb5, 0x8f,
        0x3d, 0x8f, 0x13, 0xe1, 0xe3, 0x50, 0x18, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19,
        0x19, 0x19, 0x19, 0x19, 0xff, 0x14, 0x5f, 0x9d, 0x4f, 0x1b, 0x0c,
    ];
    let line = b"GNUnet SETU strata: equal elements reuse sparse buckets.\n";
    let mut decoded = [0; 64 * 57];
    let len = FixedZlib::new().decompress(&compressed, &mut decoded)?;
    if len != 64 * line.len() || !decoded.chunks_exact(line.len()).all(|entry| entry == line) {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn visits_exact_member_across_history_wrap() -> Result<(), Error> {
    use crate::INFLATE_WINDOW_BYTES as WINDOW;
    let mut codec = FixedZlib::new();
    let mut raw = [0; 2 * WINDOW + 129];
    for (position, value) in raw.iter_mut().enumerate() {
        *value = (position % 193) as u8;
    }
    let mut encoded = [0; 2048];
    let len = codec.compress(&raw, &mut encoded)?;
    let mut history = [0; WINDOW];
    let mut offset = 0;
    let count =
        codec.visit_decompressed(&encoded[..len], &mut history, raw.len(), &mut |chunk| {
            if raw.get(offset..offset + chunk.len()) != Some(chunk) {
                return Err(Error::Conflict);
            }
            offset += chunk.len();
            Ok(())
        })?;
    if offset != raw.len()
        || count != raw.len()
        || codec.visit_decompressed(
            &encoded[..len + 1],
            &mut history,
            raw.len(),
            &mut |_| Ok(()),
        ) != Err(Error::Malformed)
        || codec.visit_decompressed(
            &encoded[..len],
            &mut history,
            raw.len() - 1,
            &mut |_| Ok(()),
        ) != Err(Error::Capacity)
    {
        return Err(Error::Conflict);
    }
    encoded[len - 1] ^= 1;
    if codec.visit_decompressed(&encoded[..len], &mut history, raw.len(), &mut |_| Ok(()))
        != Err(Error::Malformed)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[test]
fn keeps_hash_sparse_setu_strata_inside_cadet_capacity() -> Result<(), Error> {
    const BUCKETS: usize = 79;
    const STRIDE: usize = 20 * BUCKETS;
    let mut strata = [0_u8; 32 * STRIDE];
    let mut generator = 0x8214_756a_3019_6cf3_u64;
    for _ in 0..64 {
        generator = next(generator);
        let key = generator.to_le_bytes();
        let checksum = next(generator).to_le_bytes();
        let layers = generator.trailing_ones().min(32) as usize;
        for layer in strata.as_chunks_mut::<STRIDE>().0.iter_mut().take(layers) {
            let first = (generator % BUCKETS as u64) as usize;
            for index in 0..3 {
                let slot = (first + index * 23) % BUCKETS;
                let key_start = slot * 8;
                for (stored, value) in layer[key_start..key_start + 8].iter_mut().zip(key) {
                    *stored ^= value;
                }
                let check_start = 8 * BUCKETS + slot * 4;
                for (stored, value) in layer[check_start..check_start + 4].iter_mut().zip(checksum)
                {
                    *stored ^= value;
                }
                layer[12 * BUCKETS + slot] += 1;
            }
        }
    }
    let mut codec = FixedZlib::new();
    let mut compressed = [0; 2000];
    let len = codec.compress(&strata, &mut compressed)?;
    let mut decoded = [0; 32 * STRIDE];
    if codec.decompress(&compressed[..len], &mut decoded)? != strata.len() || decoded != strata {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn next(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^ (state << 17)
}
