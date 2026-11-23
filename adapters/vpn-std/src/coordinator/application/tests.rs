use super::*;
use crate::coordinator::provider::Application;
use gnunet_vpn::{Address, Prefix};
use tokio::time::Instant;

fn route(id: RequestId, action: RouteAction) -> RouteRequest {
    RouteRequest {
        id,
        action,
        ipv4: Some(Prefix {
            network: Address::V4([10, 1, 2, 0]),
            bits: 24,
            interface: Address::V4([10, 1, 2, 1]),
        }),
        ipv6: None,
        mtu: 1280,
        deadline: Instant::now() + Duration::from_secs(1),
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact native application handoff states"
)]
fn installed_route_controls_packet_admission_and_revocation() -> io::Result<()> {
    let budget = NonZeroU16::new(1280).ok_or(io::ErrorKind::InvalidInput)?;
    let (control, source) = channel(budget, NonZeroU16::MIN)?;
    let mut source = Application::new(source)?;
    let mut context = Context::from_waker(Waker::noop());
    let id = source.issue()?;
    let mut bytes = [0; 20];
    bytes[0] = 0x45;
    bytes[3] = 20;
    assert_eq!(
        control.receive(&bytes).err().map(|e| e.kind()),
        Some(io::ErrorKind::NotConnected)
    );

    let original = route(id, RouteAction::Install);
    let oversized = RouteRequest {
        mtu: 1281,
        ..original
    };
    assert_eq!(
        source.driver.begin_route(oversized).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert!(control.next(Duration::ZERO).is_none());
    source.driver.begin_route(original)?;
    assert!(matches!(control.next(Duration::ZERO), Some(Command::Route(r)) if r.id == id));
    control.complete_route(RouteCompletion {
        id,
        outcome: RouteOutcome::Installed,
    })?;
    assert!(control.receive(&bytes).is_err());
    assert!(matches!(
        source.driver.poll_route(&mut context),
        Poll::Ready(RouteCompletion { id: original, outcome: RouteOutcome::Installed }) if original == id
    ));

    control.receive(&bytes)?;
    assert_eq!(
        control.receive(&bytes).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert!(matches!(
        source.driver.poll_read(&mut context, 1280),
        Poll::Ready(Ok(Some(packet))) if packet == bytes
    ));

    let packet_id = source.issue()?;
    let request = PacketRequest {
        id: packet_id,
        deadline: Instant::now() + Duration::from_secs(1),
    };
    source.driver.begin_write(request, &bytes)?;
    assert!(matches!(
        control.next(Duration::ZERO),
        Some(Command::Write(packet)) if packet.request().id == packet_id && packet.bytes() == bytes
    ));
    assert!(matches!(
        source.driver.cancel_write(packet_id),
        PacketOutcome::Unknown { exposed: true, .. }
    ));
    control.complete_write(PacketCompletion {
        id: packet_id,
        outcome: PacketOutcome::Written { bytes: bytes.len() },
    })?;
    assert!(source.driver.poll_write(&mut context).is_pending());

    control.receive(&bytes)?;
    let queued = PacketRequest {
        id: source.issue()?,
        ..request
    };
    source.driver.begin_write(queued, &bytes)?;
    control.fence_packets();
    control.fence_packets();
    assert!(control.next(Duration::ZERO).is_none());
    assert_eq!(
        control.receive(&bytes).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    let later = PacketRequest {
        id: source.issue()?,
        ..request
    };
    assert_eq!(
        source
            .driver
            .begin_write(later, &bytes)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert!(source.driver.poll_read(&mut context, 1280).is_pending());
    assert!(source.driver.poll_route(&mut context).is_pending());
    assert!(matches!(
        source.driver.poll_write(&mut context),
        Poll::Ready(PacketCompletion { id, outcome: PacketOutcome::Unsent { error } })
            if id == queued.id && error.kind() == io::ErrorKind::Interrupted
    ));

    control.revoke(CloseOutcome {
        routes_absent: true,
        error: None,
    });
    assert!(matches!(
        source.driver.poll_route(&mut context),
        Poll::Ready(RouteCompletion { id: original, outcome: RouteOutcome::Removed }) if original == id
    ));
    assert!(matches!(
        source.driver.poll_read(&mut context, 1280),
        Poll::Ready(Ok(None))
    ));
    assert!(source.close().is_some_and(|outcome| outcome.routes_absent));
    assert!(matches!(
        control.next(Duration::ZERO),
        Some(Command::Closed)
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert the late route remains fenced until its receipt"
)]
fn cancelled_claim_cannot_be_overtaken_by_removal() -> io::Result<()> {
    let budget = NonZeroU16::new(1280).ok_or(io::ErrorKind::InvalidInput)?;
    let (control, source) = channel(budget, NonZeroU16::MIN)?;
    let mut source = Application::new(source)?;
    let install = source.issue()?;
    let remove = route(source.issue()?, RouteAction::Remove);
    source
        .driver
        .begin_route(route(install, RouteAction::Install))?;
    assert!(matches!(control.next(Duration::ZERO), Some(Command::Route(r)) if r.id == install));
    control.fence_packets();
    assert!(matches!(
        source.driver.cancel_route(install),
        RouteOutcome::Failed {
            routes_absent: false,
            ..
        }
    ));
    assert_eq!(
        source.driver.begin_route(remove).err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    control.complete_route(RouteCompletion {
        id: install,
        outcome: RouteOutcome::Installed,
    })?;
    source.driver.begin_route(remove)?;
    assert!(matches!(control.next(Duration::ZERO), Some(Command::Route(r)) if r.id == remove.id));
    control.complete_route(RouteCompletion {
        id: remove.id,
        outcome: RouteOutcome::Removed,
    })?;
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        source.driver.poll_route(&mut context),
        Poll::Ready(RouteCompletion { id, outcome: RouteOutcome::Removed }) if id == remove.id
    ));
    assert!(source.close().is_some_and(|outcome| outcome.routes_absent));
    Ok(())
}
