//! Pure provider model: no native interface or route operation is executed.
use crate::*;
use gnunet_types::Error;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Checks ownership, stale generations and provider receipt ordering across modeled session replacement"
)]
fn retained_owned_routes_require_fresh_verification() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut requests = [RequestSlot::new(); 1];
    let mut leases = [LeaseSlot::new(); 1];
    let mut flows = [FlowSlot::new(); 1];
    let mut backing = [0u8; 2048];
    let mut packets = [PacketSlot::new(&mut backing)];
    let mut engine = Engine::new(
        &mut instance,
        Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        Limits {
            packet_bytes: 1280,
            ipv4: Some(Prefix {
                network: Address::V4([192, 0, 2, 0]),
                bits: 29,
                interface: Address::V4([192, 0, 2, 1]),
            }),
            ..Limits::default()
        },
    )?;
    let original = engine.attach_tun()?;
    let pending = engine.routing_request(original)?.routing;
    engine.routing_queued(pending)?;
    engine.tun_lost(original, Error::Io)?;
    assert_eq!(engine.can_rebind_tun(original), Err(Error::WouldBlock));
    engine.retire_routing(pending)?;
    let replacement = engine.rebind_tun_same_interface(original)?;
    assert_ne!(original, replacement);
    assert_eq!(engine.route_state(original), Err(Error::StaleGeneration));
    assert_eq!(engine.route_applied(pending), Err(Error::StaleGeneration));
    assert_eq!(engine.route_state(replacement)?, RouteState::Unknown);
    assert!(!engine.tun_ready(replacement)?);
    assert_eq!(
        engine.release_borrowed_routes(replacement),
        Err(Error::PermissionDenied)
    );
    let verification = engine.routing_verification_request(replacement)?;
    assert_eq!(verification.action, RouteAction::Verify);
    assert_eq!(
        engine.route_reverified(verification.routing),
        Err(Error::NotReady)
    );
    assert_eq!(
        engine.routing_borrowed_queued(verification.routing),
        Err(Error::Conflict)
    );
    engine.routing_queued(verification.routing)?;
    assert_eq!(
        engine.route_applied(verification.routing),
        Err(Error::Conflict)
    );
    engine.route_reverified(verification.routing)?;
    assert!(engine.tun_ready(replacement)?);
    assert_eq!(engine.route_state(replacement)?, RouteState::Present);

    engine.tun_lost(replacement, Error::Io)?;
    let replacement = engine.rebind_tun_same_interface(replacement)?;
    let restoration = engine.routing_restoration_request(replacement)?;
    assert_eq!(restoration.action, RouteAction::Restore);
    assert_eq!(
        engine.route_restored(restoration.routing),
        Err(Error::NotReady)
    );
    engine.routing_queued(restoration.routing)?;
    assert_eq!(
        engine.route_reverified(restoration.routing),
        Err(Error::PermissionDenied)
    );
    assert!(!engine.tun_ready(replacement)?);
    engine.route_restored(restoration.routing)?;
    assert!(engine.tun_ready(replacement)?);
    assert_eq!(engine.route_state(replacement)?, RouteState::Present);

    let cleanup = engine.route_cleanup_request(replacement)?;
    engine.routing_queued(cleanup.routing)?;
    engine.route_removed(cleanup.routing)?;
    assert_eq!(engine.route_state(replacement)?, RouteState::Absent);
    let interrupted = engine.routing_request(replacement)?.routing;
    engine.routing_queued(interrupted)?;
    engine.tun_lost(replacement, Error::Io)?;
    assert_eq!(engine.can_retire_tun(replacement), Err(Error::WouldBlock));
    assert_eq!(
        engine.confirm_routes_absent(replacement),
        Err(Error::WouldBlock)
    );
    // Modeled original provider quiescence and native absence are independent
    // ports. No Windows table, interface or route operation runs in this test.
    engine.retire_routing(interrupted)?;
    assert_eq!(engine.route_state(replacement)?, RouteState::Unknown);
    assert_eq!(engine.can_retire_tun(replacement), Err(Error::WouldBlock));
    engine.confirm_routes_absent(replacement)?;
    engine.can_retire_tun(replacement)?;
    engine.retire_tun(replacement)?;
    let physical = engine.attach_tun()?;
    assert_ne!(physical, replacement);
    assert_eq!(engine.route_state(replacement), Err(Error::StaleGeneration));
    assert!(!engine.tun_ready(physical)?);
    let borrowed = engine.routing_request(physical)?.routing;
    engine.routing_borrowed_queued(borrowed)?;
    engine.route_borrowed_verified(borrowed)?;
    assert!(engine.tun_ready(physical)?);
    assert_eq!(engine.route_state(physical)?, RouteState::BorrowedVerified);
    assert_eq!(
        engine.route_cleanup_request(physical).err(),
        Some(Error::PermissionDenied)
    );
    Ok(())
}
