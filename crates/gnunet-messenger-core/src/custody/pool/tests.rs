#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert erasure and live handle invariants after fallible writes"
)]

use super::*;

#[test]
fn compaction_keeps_live_handles_and_erases_moved_copies() -> Result<(), Error> {
    let mut bytes = [0xa5; 12];
    let mut slots = [OriginalSlot::EMPTY; 3];
    let mut instance = OriginalPoolInstance::new();
    {
        let mut pool = OriginalPool::new(&mut instance, &mut slots, &mut bytes);
        let first = pool.copy_from(b"abcd")?;
        let middle = pool.copy_from(b"efg")?;
        let last = pool.copy_from(b"hijkl")?;
        assert_eq!(pool.used_bytes(), 12);

        pool.remove(first)?;
        assert_eq!(&pool.bytes[..4], &[0; 4]);
        let reused = pool.copy_from(b"mn")?;
        assert_eq!(first.index.get(), reused.index.get());
        assert_ne!(first, reused);
        assert!(matches!(
            pool.expose(first),
            Err(Error::Protocol(Fault::StaleGeneration))
        ));
        assert_eq!(pool.expose(middle)?, b"efg");
        assert_eq!(pool.expose(last)?, b"hijkl");
        assert_eq!(pool.expose(reused)?, b"mn");
        assert_eq!(pool.used_bytes(), 10);
        assert_eq!(&pool.bytes[10..], &[0; 2]);
    }
    assert_eq!(bytes, [0; 12]);
    Ok(())
}

#[test]
fn writer_failure_erases_partial_output_without_publishing_a_record() -> Result<(), Error> {
    let mut bytes = [0xa5; 8];
    let mut slots = [OriginalSlot::EMPTY; 2];
    let mut instance = OriginalPoolInstance::new();
    let mut pool = OriginalPool::new(&mut instance, &mut slots, &mut bytes);
    let existing = pool.copy_from(b"keep")?;

    assert!(matches!(
        pool.write(5, |_| Err(Fault::Malformed.into())),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert!(matches!(
        pool.write(4, |out| {
            out.fill(0xa5);
            Err(Fault::Malformed.into())
        }),
        Err(Error::Protocol(Fault::Malformed))
    ));
    assert_eq!(pool.used_bytes(), 4);
    assert_eq!(pool.expose(existing)?, b"keep");
    let empty_bytes = pool.write(4, |_| Ok(()))?;
    assert_eq!(pool.expose(empty_bytes)?, &[0; 4]);
    assert!(matches!(
        pool.write(0, |_| Err(Fault::Malformed.into())),
        Err(Error::Protocol(Fault::Capacity))
    ));
    Ok(())
}

#[test]
fn empty_originals_take_metadata_and_cannot_cross_pools() -> Result<(), Error> {
    let mut left_instance = OriginalPoolInstance::new();
    let mut right_instance = OriginalPoolInstance::new();
    let mut left_slots = [OriginalSlot::EMPTY; 1];
    let mut right_slots = [OriginalSlot::EMPTY; 1];
    let mut left_bytes = [];
    let mut right_bytes = [];
    let mut left = OriginalPool::new(&mut left_instance, &mut left_slots, &mut left_bytes);
    let mut right = OriginalPool::new(&mut right_instance, &mut right_slots, &mut right_bytes);
    let left_id = left.copy_from(b"")?;
    let right_id = right.copy_from(b"")?;

    assert_eq!(left.used_bytes(), 0);
    assert!(left.expose(left_id)?.is_empty());
    assert_ne!(left_id, right_id);
    #[cfg(feature = "alloc")]
    {
        assert_eq!(left.bind_local(left_id.local()), Ok(left_id));
        assert_eq!(
            left.bind_local(right_id.local()),
            Err(Fault::StaleGeneration.into())
        );
    }
    assert!(matches!(
        left.remove(right_id),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(matches!(
        left.copy_from(b""),
        Err(Error::Protocol(Fault::Capacity))
    ));

    left.remove(left_id)?;
    let replacement = left.copy_from(b"")?;
    assert_ne!(left_id, replacement);
    assert!(left.expose(replacement)?.is_empty());
    #[cfg(feature = "alloc")]
    assert_eq!(
        left.expose(left.bind_local(left_id.local())?),
        Err(Fault::StaleGeneration.into())
    );
    Ok(())
}

#[test]
fn replacement_uses_net_bytes_and_keeps_the_old_generation_on_capacity() -> Result<(), Error> {
    let mut instance = OriginalPoolInstance::new();
    let mut slots = [OriginalSlot::EMPTY; 2];
    let mut bytes = [0; 12];
    let mut pool = OriginalPool::new(&mut instance, &mut slots, &mut bytes);
    let old = pool.copy_from(b"old")?;
    let unrelated = pool.copy_from(b"keep")?;

    assert!(matches!(
        pool.replace_from_slice(old, b"too large"),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert_eq!(pool.expose(old)?, b"old");
    assert_eq!(pool.used_bytes(), 7);

    let replaced = pool.replace_from_slice(old, b"new data")?;
    assert_eq!(pool.used_bytes(), 12);
    assert!(matches!(
        pool.expose(old),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert_eq!(pool.expose(replaced)?, b"new data");
    assert_eq!(pool.expose(unrelated)?, b"keep");

    let shortened = pool.replace_from_slice(replaced, b"ok")?;
    assert_ne!(shortened, replaced);
    assert_eq!(pool.expose(shortened)?, b"ok");
    assert_eq!(&pool.bytes[6..], &[0; 6]);
    Ok(())
}

#[test]
fn last_generation_requires_a_different_free_slot_before_erasure() -> Result<(), Error> {
    let mut instance = OriginalPoolInstance::new();
    let mut slots = [OriginalSlot::EMPTY; 2];
    let mut bytes = [0; 5];
    let mut pool = OriginalPool::new(&mut instance, &mut slots, &mut bytes);
    let old = pool.copy_from(b"old")?;
    let other = pool.copy_from(b"ob")?;
    pool.slots[old.index.get()].generation = NonZeroU64::MAX;
    let old = OriginalId {
        generation: NonZeroU64::MAX,
        ..old
    };

    assert!(matches!(
        pool.replace_from_slice(old, b"new"),
        Err(Error::Protocol(Fault::Capacity))
    ));
    assert_eq!(pool.expose(old)?, b"old");
    pool.remove(other)?;
    let replaced = pool.replace_from_slice(old, b"new")?;
    assert_eq!(replaced.index.get(), other.index.get());
    assert_eq!(pool.expose(replaced)?, b"new");
    assert!(matches!(
        pool.expose(old),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(matches!(
        pool.copy_from(b""),
        Err(Error::Protocol(Fault::Capacity))
    ));
    Ok(())
}
