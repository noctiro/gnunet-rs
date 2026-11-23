#![expect(
    clippy::panic_in_result_fn,
    reason = "Custody tests check ownership and erasure after fallible writes"
)]

use super::*;

#[test]
fn disjoint_slots_keep_independent_originals_and_return_erased_storage() -> Result<(), Error> {
    let mut backing = [0xa5; 16];
    {
        let (left, right) = backing.split_at_mut(8);
        let left = ByteSlot::new(left);
        let right = ByteSlot::new(right);
        let first = left.copy_from(b"first")?;
        let second = right.copy_from(b"second")?;

        assert!(matches!(
            left.copy_from(b"other"),
            Err(Error::Protocol(Fault::Capacity))
        ));
        assert_eq!(first.expose(), b"first");
        assert_eq!(first.capacity(), 8);
        assert_eq!(second.expose(), b"second");

        drop(first);
        let reused = left.write(8, |out| {
            if out.iter().any(|&byte| byte != 0) {
                return Err(Fault::Conflict.into());
            }
            out.fill(0x31);
            Ok(())
        })?;
        assert_eq!(reused.expose(), &[0x31; 8]);
        assert_eq!(second.expose(), b"second");
    }
    assert_eq!(backing, [0; 16]);
    Ok(())
}

#[test]
fn failed_write_erases_partial_output_and_releases_slot() -> Result<(), Error> {
    let mut storage = [0; 8];
    let slot = ByteSlot::new(&mut storage);
    assert!(matches!(
        slot.write(5, |output| {
            output.fill(0xe4);
            Err(Fault::Malformed.into())
        }),
        Err(Error::Protocol(Fault::Malformed))
    ));
    assert!(matches!(
        slot.copy_from(b"too long!"),
        Err(Error::Protocol(Fault::Capacity))
    ));
    let reused = slot.write(8, |_| Ok(()))?;
    assert_eq!(reused.expose(), &[0; 8]);
    Ok(())
}

#[cfg(feature = "alloc")]
#[test]
fn heap_custody_adopts_original_without_copy() -> Result<(), Error> {
    let mut storage = Zeroizing::new(Vec::new());
    storage.try_reserve_exact(32).map_err(|_| Fault::Capacity)?;
    storage.extend_from_slice(b"original");
    let pointer = storage.as_ptr();
    let capacity = storage.capacity();

    let owned = OwnedBytes::new(storage);
    assert_eq!(owned.expose(), b"original");
    assert_eq!(owned.expose().as_ptr(), pointer);
    assert_eq!(owned.capacity(), capacity);
    Ok(())
}
