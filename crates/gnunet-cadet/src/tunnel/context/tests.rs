//! Reusable fixed-row capability models; no native/C interoperability claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible fixed-row models assert exact revocation, unique allocation and atomic checked exhaustion"
)]
use super::*;
use crate::tunnel::identity_dh;

#[test]
fn one_context_row_reuses_while_old_scopes_live_and_exhaustion_is_atomic() -> Result<(), Error> {
    let domain = Instance::new();
    let mut rows = [const { Slot::new() }; 1];
    let mut registry = Registry::new(&domain, &mut rows)?;
    let mut retired = [None; 8];
    for (index, previous) in retired.iter_mut().enumerate() {
        let peer = [u8::try_from(index + 1).map_err(|_| Error::Overflow)?; 32];
        let lease = registry.allocate([0; 32], peer)?;
        let scope = lease.scope();
        assert!(scope.is_live());
        assert_eq!(scope.peer(), peer);
        assert_eq!(registry.available(), 0);
        *previous = Some(scope);
        drop(lease);
        assert!(!scope.is_live());
        assert_eq!(registry.available(), 1);
    }
    // The dynamic owner is closed but still exists. Its later Drop/second close
    // must not revoke a replacement lease occupying that same physical row.
    let mut old = registry.allocate([0; 32], [20; 32])?;
    let old_scope = old.scope();
    old.close();
    let replacement = registry.allocate([0; 32], [21; 32])?;
    let current = replacement.scope();
    assert_ne!(old_scope, current);
    assert!(!old_scope.is_live());
    old.close();
    drop(old);
    assert!(current.is_live());
    for (index, scope) in retired.into_iter().enumerate() {
        let scope = scope.ok_or(Error::NotReady)?;
        assert!(!scope.is_live());
        assert_ne!(scope, current);
        assert_eq!(
            scope.peer(),
            [u8::try_from(index + 1).map_err(|_| Error::Overflow)?; 32]
        );
    }
    drop(replacement);
    assert!(!current.is_live());
    assert_eq!(registry.available(), 1);

    // Context-child visibility deliberately exercises the checked boundary.
    // The final valid ID is usable; subsequent refusal changes neither row nor
    // counter and never wraps to a previously issued allocation.
    domain.next.set(u64::MAX - 1);
    let last = registry.allocate([0; 32], [22; 32])?;
    let last_scope = last.scope();
    assert_eq!(last_scope.allocation(), u64::MAX);
    assert_eq!(registry.available(), 0);
    drop(last);
    assert!(!last_scope.is_live());
    assert!(matches!(
        registry.allocate([0; 32], [23; 32]),
        Err(Error::Overflow)
    ));
    assert_eq!(domain.next.get(), u64::MAX);
    assert_eq!(registry.available(), 1);
    assert_eq!(registry.slots[0].live.get().allocation, 0);
    assert!(!old_scope.is_live());
    Ok(())
}

#[test]
fn one_source_row_rebinds_same_local_epoch_without_reviving_copied_sources() -> Result<(), Error> {
    let domain = identity_dh::Instance::new();
    let mut rows = [const { identity_dh::Slot::new() }; 1];
    let mut registry = identity_dh::Registry::new(&domain, &mut rows)?;
    let mut old = registry.bind([7; 32], 9)?;
    let original = old.source();
    assert!(original.is_live());
    assert_eq!(registry.available(), 0);
    old.close();
    assert!(!original.is_live());
    for _ in 0..8 {
        let replacement = registry.bind([7; 32], 9)?;
        let source = replacement.source();
        assert_eq!(source.local(), original.local());
        assert_eq!(source.epoch(), original.epoch());
        assert_ne!(source, original);
        assert!(source.allocation() > original.allocation());
        assert!(source.is_live());
        assert!(!original.is_live());
        old.close();
        assert!(source.is_live());
        drop(replacement);
        assert!(!source.is_live());
        assert_eq!(registry.available(), 1);
    }
    drop(old);
    let last = registry.bind([7; 32], 9)?;
    assert!(last.source().is_live());
    assert!(!original.is_live());
    Ok(())
}
