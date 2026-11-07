//! Variable-width pooled storage; all backing data is caller-owned, no I/O.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Pool ownership tests assert exact bytes, generation refusal and unchanged errors."
)]
use gnunet_resolver_service_core::pool::{BlobSlot, BytePool};
use gnunet_types::Error;
#[test]
fn one_full_dns_width_does_not_preallocate_that_width_for_every_metadata_slot() -> Result<(), Error>
{
    let mut slots = vec![BlobSlot::EMPTY; 4096];
    let mut bytes = vec![0; 70_000];
    let mut p = BytePool::new(&mut slots, &mut bytes, 1)?;
    let input = vec![0xa5; 65_535];
    let big = p.copy(&input)?;
    assert_eq!(p.get(big)?, input);
    assert_eq!(p.live_bytes(), 65_535);
    assert_eq!(p.slot_capacity(), 4096);
    assert_eq!(p.capacity(), 70_000);
    let tiny = p.copy(b"small")?;
    assert_eq!(p.get(tiny)?, b"small");
    assert_eq!(p.live_objects(), 2);
    Ok(())
}
#[test]
fn shared_pin_keeps_payload_and_old_generation_cannot_release_replacement() -> Result<(), Error> {
    let mut slots = [BlobSlot::EMPTY; 4];
    let mut bytes = [0; 32];
    let mut p = BytePool::new(&mut slots, &mut bytes, 1)?;
    let old = p.copy(b"retained output")?;
    p.retain(old)?;
    assert!(matches!(p.unique_mut(old), Err(Error::Conflict)));
    p.release(old)?;
    assert_eq!(p.get(old)?, b"retained output");
    p.release(old)?;
    let new = p.copy(b"new payload")?;
    assert_ne!(old, new);
    assert_eq!(p.release(old), Err(Error::StaleGeneration));
    assert_eq!(p.get(new)?, b"new payload");
    Ok(())
}
#[test]
fn fragmentation_compacts_live_payloads_and_zero_length_spans_safely() -> Result<(), Error> {
    let mut slots = [BlobSlot::EMPTY; 8];
    let mut bytes = [0; 16];
    let mut p = BytePool::new(&mut slots, &mut bytes, 1)?;
    let a = p.copy(b"aaaa")?;
    let zero = p.copy(b"")?;
    let b = p.copy(b"bbbb")?;
    let c = p.copy(b"cccc")?;
    let zero2 = p.copy(b"")?;
    p.release(a)?;
    p.release(c)?;
    let d = p.copy(b"12345678")?;
    assert_eq!(p.get(b)?, b"bbbb");
    assert_eq!(p.get(zero)?, b"");
    assert_eq!(p.get(zero2)?, b"");
    assert_eq!(p.get(d)?, b"12345678");
    assert_eq!(p.live_bytes(), 12);
    Ok(())
}
#[test]
fn capacity_refusals_do_not_reclaim_or_consume_original_generation() -> Result<(), Error> {
    let mut slots = [BlobSlot::EMPTY; 2];
    let mut bytes = [0; 8];
    let mut p = BytePool::new(&mut slots, &mut bytes, 1)?;
    let a = p.copy(b"aaaa")?;
    assert_eq!(p.copy(b"123456789"), Err(Error::Capacity));
    let b = p.copy(b"bbbb")?;
    assert_eq!(p.allocate(0), Err(Error::Capacity));
    assert_eq!(p.get(a)?, b"aaaa");
    assert_eq!(p.get(b)?, b"bbbb");
    p.release(a)?;
    let c = p.copy(b"c")?;
    assert_eq!(p.release(a), Err(Error::StaleGeneration));
    assert_eq!(p.get(c)?, b"c");
    Ok(())
}
#[test]
fn foreign_pool_token_cannot_release_same_index_generation_in_another_pool() -> Result<(), Error> {
    let mut sa = [BlobSlot::EMPTY; 1];
    let mut ba = [0; 8];
    let mut sb = [BlobSlot::EMPTY; 1];
    let mut bb = [0; 8];
    let mut a = BytePool::new(&mut sa, &mut ba, 1)?;
    let mut b = BytePool::new(&mut sb, &mut bb, 1)?;
    let old = a.copy(b"a")?;
    let new = b.copy(b"b")?;
    assert_eq!(b.release(old), Err(Error::StaleGeneration));
    assert_eq!(b.get(new)?, b"b");
    Ok(())
}
