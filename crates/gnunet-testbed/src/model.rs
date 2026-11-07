//! Public integer ownership model only. No sockets/files/processes/keys/crypto.
use super::*;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "This pure integer ownership model reports assertions through the test harness while propagating state errors."
)]
fn original_probe_release_path_and_replacement_scope() -> Result<(), Error> {
    let domain = Instance::new();
    let mut slots = [PortSlot::empty(), PortSlot::empty()];
    let old;
    {
        let mut system = System::new(&domain, &mut slots, 12000, 12003, 0)?;
        let busy = system.probe()?;
        assert_eq!(busy.port(), 12000);
        assert!(system.probed(busy, Availability::Busy)?.is_none());
        let first = system.probe()?;
        assert_eq!(first.port(), 12001);
        let first = system
            .probed(first, Availability::Free)?
            .ok_or(Error::Conflict)?;
        old = first;
        system.release(first)?;
        let next = system.probe()?;
        assert_eq!(next.port(), 12002);
        let next = system
            .probed(next, Availability::Free)?
            .ok_or(Error::Conflict)?;
        assert_eq!(system.release(first), Err(Error::StaleGeneration));
        system.reserved(next)?;
        let path = system.allocate_path()?;
        assert_eq!(path.number(), 0);
        assert_eq!(system.path_high_water(), 1);
        system.check_path(path)?;
        system.close();
        assert_eq!(system.reserved(next), Err(Error::Closed));
    }
    let mut replacement = System::new(&domain, &mut slots, 12000, 12003, 1)?;
    assert_eq!(replacement.release(old), Err(Error::StaleGeneration));
    let probe = replacement.probe()?;
    replacement.cancel_probe(probe)?;
    assert_eq!(
        replacement.probed(probe, Availability::Free),
        Err(Error::StaleGeneration)
    );
    assert_eq!(replacement.allocate_path()?.number(), 1);
    Ok(())
}
