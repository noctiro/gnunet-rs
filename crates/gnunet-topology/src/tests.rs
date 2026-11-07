//! One pure public metadata model; no HELLO signature/hash/native/store work.
use super::*;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public policy assertions with fallible bounded setup"
)]
fn unchanged_strength_does_not_issue_a_new_transport_intent() -> Result<(), Error> {
    let mut core = Engine::new(Limits::default(), 10)?;
    assert_eq!(core.suppression_bytes(), 512);
    core.set_local([1; 32], 10);
    let node = core.connected([2; 32], 10)?;
    let first = core.control(10)?.ok_or(Error::NotReady)?;
    assert_eq!(first.before(), 0);
    assert_eq!(first.after(), 2);
    // Mock provider receipts exercise only the pure caller contract. They are not
    // evidence of any native write, connection, store or signature operation.
    core.control_queued(&first)?;
    core.control_written(&first)?;
    assert!(core.control(10)?.is_none());
    assert!(core.control(60_000_010)?.is_none());
    core.disconnected(&node, 60_000_011)?;
    let changed = core.control(60_000_011)?.ok_or(Error::NotReady)?;
    assert_eq!(changed.before(), 2);
    assert_eq!(changed.after(), 1);
    core.control_queued(&changed)?;
    core.control_written(&changed)?;
    assert!(core.control(60_000_011)?.is_none());
    core.controls_retired();
    let fresh = core.control(60_000_012)?.ok_or(Error::NotReady)?;
    assert_ne!(fresh, changed);
    assert_eq!(fresh.before(), 0);
    assert_eq!(fresh.after(), 1);
    Ok(())
}
