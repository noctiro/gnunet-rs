//! Private loopback owners; fixture announcements are never submitted natively.
use super::*;
use crate::discovery::{Interface, Operation, Pending};

fn retain(
    owner: &mut Communicator<'_>,
    target: SocketAddr,
    serial: u64,
    hard: Instant,
) -> Result<Interface, Box<dyn std::error::Error>> {
    let source = owner.sockets[0].local_address();
    // Directly exercise the retained-send owner below the public LAN snapshot
    // validator. This intentionally uses loopback and is no interface evidence.
    let interface = Interface {
        source,
        index: 1,
        broadcast: Some(std::net::Ipv4Addr::LOCALHOST),
    };
    owner.sockets[0].queue_discovery(source, 1, target, serial, [0; 96], hard)?;
    owner.discovery.as_mut().ok_or(Error::Stale)?.pending[0] = Some(Pending {
        operation: serial,
        interface,
        target,
    });
    Ok(interface)
}
#[tokio::test(flavor = "current_thread")]
async fn expiry_and_snapshot_revocation_retire_only_the_original_announcement() -> Test {
    let local = Identity::from_seed([3; 32]);
    let (mut owner, _service) = owner(&local).await?;
    owner.enable_discovery(Default::default())?;
    let target = UdpSocket::bind("127.0.0.1:0").await?;
    let destination = target.local_addr()?;
    let original_socket = owner.sockets[0].local_address();
    let generation = owner.transport_generation();
    let hard = Instant::now() + Duration::from_millis(10);
    let interface = retain(&mut owner, destination, 1, hard)?;
    tokio::time::sleep_until(hard.into()).await;
    poll_fn(|cx| {
        check(owner.poll_native_guard(cx).is_none())?;
        Poll::Ready(Ok::<_, Box<dyn std::error::Error>>(()))
    })
    .await?;
    check(!owner.sockets[0].has_pending_send())?;
    let event = poll_fn(|cx| Poll::Ready(owner.discovery_step(cx, &local, 100))).await?;
    check(matches!(event, Some(Activity::DiscoveryFailed {
        socket: 0,
        operation: Operation::Send { interface: original, target: intended },
        error: SocketError::Core(Error::Deadline),
    }) if original == interface && intended == destination))?;

    retain(
        &mut owner,
        destination,
        2,
        Instant::now() + Duration::from_secs(1),
    )?;
    // A dependent address projection may refuse this prepared replacement.
    // Dropping its guard must not cancel the original retained announcement.
    drop(owner.prepare_interfaces(&[])?);
    check(
        owner.sockets[0].has_pending_send()
            && owner.discovery.as_ref().ok_or(Error::Stale)?.pending[0].is_some(),
    )?;
    owner.update_interfaces(&[])?;
    check(!owner.sockets[0].has_pending_send())?;
    let event = poll_fn(|cx| Poll::Ready(owner.discovery_step(cx, &local, 100))).await?;
    check(matches!(event, Some(Activity::DiscoveryFailed {
        socket: 0,
        operation: Operation::Send { interface: original, target: intended },
        error: SocketError::Core(Error::StaleGeneration),
    }) if original == interface && intended == destination))?;
    check(
        owner.discovery.as_ref().ok_or(Error::Stale)?.failures[0].is_none()
            && owner.sockets[0].local_address() == original_socket
            && owner.transport_generation() == generation
            && owner.transport_attached(),
    )?;
    let mut bytes = [0; 128];
    check(
        matches!(target.try_recv(&mut bytes), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
    )?;
    owner.close();
    Ok(())
}
