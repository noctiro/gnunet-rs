use super::*;
use crate::coordinator::provider::Application;
use std::{future::poll_fn, os::fd::AsFd, os::unix::net::UnixDatagram, task::Waker};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert original packet, fd, and route identities"
)]
fn original_descriptor_is_admitted_by_its_route_and_fenced_by_revocation() -> io::Result<()> {
    fn assert_send<T: Send>(_: &T) {}

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let maximum = NonZeroU16::new(68).ok_or(io::ErrorKind::InvalidInput)?;
            let (controller, mailbox) = channel(maximum)?;
            assert_send(&mailbox);
            let mut source = Application::new(mailbox)?;
            let (borrowed, platform) = UnixDatagram::pair()?;
            borrowed.set_nonblocking(true)?;
            platform.set_nonblocking(true)?;
            let id = source.issue()?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let route = RouteRequest {
                id,
                action: RouteAction::Install,
                ipv4: None,
                ipv6: None,
                mtu: u32::from(maximum.get()),
                deadline,
            };
            source.driver.begin_route(route)?;
            assert!(controller.installed(id, borrowed.as_fd()).is_err());
            assert!(matches!(controller.next(Duration::ZERO), Some(Command::Route(request)) if request.id == id));
            assert!(controller.installed(source.issue()?, borrowed.as_fd()).is_err());
            controller.installed(id, borrowed.as_fd())?;
            drop(borrowed);

            let mut cx = Context::from_waker(Waker::noop());
            assert!(source.driver.poll_read(&mut cx, 68).is_pending());
            assert!(matches!(
                source.driver.poll_route(&mut cx),
                Poll::Ready(RouteCompletion { id: original, outcome: RouteOutcome::Installed }) if original == id
            ));
            let mut overlong = [0; 69];
            overlong[0] = 0x45;
            overlong[3] = 68;
            assert_eq!(platform.send(&overlong)?, overlong.len());
            let rejected = tokio::time::timeout(
                Duration::from_secs(1),
                poll_fn(|cx| source.driver.poll_read(cx, 68)),
            ).await?;
            assert!(matches!(rejected, Err(error) if error.kind() == io::ErrorKind::InvalidData));

            let mut packet = [0; 20];
            packet[0] = 0x45;
            packet[3] = 20;
            assert_eq!(platform.send(&packet)?, packet.len());
            let delivered = tokio::time::timeout(
                Duration::from_secs(1),
                poll_fn(|cx| source.driver.poll_read(cx, 68)),
            ).await??;
            assert_eq!(delivered.as_deref(), Some(packet.as_slice()));

            let sent = source.issue()?;
            source.driver.begin_write(PacketRequest { id: sent, deadline }, &packet)?;
            let receipt = tokio::time::timeout(Duration::from_secs(1), poll_fn(|cx| {
                source.driver.poll_write(cx)
            })).await?;
            assert!(matches!(receipt, PacketCompletion {id, outcome: PacketOutcome::Written { bytes }} if id == sent && bytes == 20));
            let mut received = [0; 20];
            assert_eq!(platform.recv(&mut received)?, packet.len());
            assert_eq!(received, packet);

            let fenced = source.issue()?;
            source.driver.begin_write(PacketRequest { id: fenced, deadline }, &packet)?;
            controller.fence_packets();
            assert!(matches!(
                source.driver.poll_write(&mut cx),
                Poll::Ready(PacketCompletion { id, outcome: PacketOutcome::Unsent { error } })
                    if id == fenced && error.kind() == io::ErrorKind::Interrupted
            ));
            assert!(matches!(platform.recv(&mut received), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            assert_eq!(platform.send(&packet)?, packet.len());
            assert!(source.driver.poll_read(&mut cx, 68).is_pending());
            assert!(source.driver.poll_route(&mut cx).is_pending());

            let removal = RouteRequest {
                id: source.issue()?,
                action: RouteAction::Remove,
                ..route
            };
            source.driver.begin_route(removal)?;
            assert!(matches!(controller.next(Duration::ZERO), Some(Command::Route(request)) if request.id == removal.id));
            controller.complete_route(RouteCompletion {
                id: removal.id,
                outcome: RouteOutcome::Removed,
            })?;
            assert!(matches!(
                source.driver.poll_route(&mut cx),
                Poll::Ready(RouteCompletion { id, outcome: RouteOutcome::Removed }) if id == removal.id
            ));
            assert!(source.close().is_some_and(|outcome| outcome.routes_absent));
            Ok(())
        })
}

#[test]
fn partial_write_reports_exposure_without_a_suffix() {
    assert!(matches!(
        write_outcome(7, 20),
        PacketOutcome::Unknown { exposed: true, .. }
    ));
}
