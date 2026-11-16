//! Read-only Windows interface identity checks; no driver, route or device changes.
#![cfg(windows)]
use gnunet_native::interfaces::{self, Identity};
use std::io;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Read-only native identity qualification asserts original interface matching and rejects zero-index selection"
)]
fn original_loopback_identity_revalidates_without_name_selection() -> io::Result<()> {
    let rows = interfaces::snapshot(interfaces::Limits::default())?;
    let loopback = rows
        .iter()
        .find(|row| row.index != 0 && row.is_loopback())
        .ok_or_else(|| io::Error::other("Windows loopback interface absent"))?;
    let observed = Identity::from_index(loopback.index)?;
    assert_eq!(observed.index(), loopback.index);
    assert_ne!(observed.luid(), 0);
    observed.check()?;
    let repeated = Identity::from_index(loopback.index)?;
    assert_eq!(observed, repeated);
    let error = Identity::from_index(0)
        .err()
        .ok_or_else(|| io::Error::other("zero interface index accepted"))?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}
