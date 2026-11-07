//! Independent raw UDP owner, retry, endpoint and lifetime contracts.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite owner-state regressions fail on incorrect effects or authority."
)]
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use gnunet_dnsstub::{
    Action, Admission, DEFAULT_RETRY, DnsStub, DropReason, Family, RequestId, SocketId,
};
use gnunet_types::{Duration, Error, MonoInstant};

type Core = DnsStub<2, 64, 4>;
fn endpoint(n: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)), 5300 + u16::from(n))
}
fn v6() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5306)
}
fn admit<const R: usize, const N: usize, const S: usize>(
    c: &mut DnsStub<R, N, S>,
    bytes: &[u8],
    slot: u32,
    now: u64,
) -> Result<Admission, Error> {
    c.resolve(bytes, MonoInstant(now), |_| Ok(slot))
}
fn send<const R: usize, const N: usize, const S: usize>(
    c: &mut DnsStub<R, N, S>,
    now: u64,
) -> Result<(RequestId, SocketId, SocketAddr), Error> {
    let mut action = c.next_action(MonoInstant(now))?.ok_or(Error::NotReady)?;
    if let Action::OpenSocket { socket } = action {
        c.socket_opened(socket, true)?;
        action = c.next_action(MonoInstant(now))?.ok_or(Error::NotReady)?;
    }
    let Action::Send {
        attempt,
        request,
        socket,
        destination,
        len,
    } = action
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(c.query(request)?.len(), len);
    c.sent(attempt)?;
    Ok((request, socket, destination))
}
#[test]
fn start_admission_and_refusals_are_lazy_and_leave_existing_state() -> Result<(), Error> {
    assert!(matches!(Core::start(0), Err(Error::Capacity)));
    assert!(matches!(Core::start(3), Err(Error::Capacity)));
    let mut c = Core::start(1)?;
    assert_eq!(c.retry(), DEFAULT_RETRY);
    assert_eq!(c.slot_count(), 1);
    assert!(matches!(admit(&mut c, b"a", 0, 0), Err(Error::Unavailable)));
    c.add_dns_sa(endpoint(1))?;
    let id = admit(&mut c, b"original", 0, 10)?.request;
    assert_eq!(c.next_wakeup(), Some(MonoInstant(10)));
    assert_eq!(c.readable_sockets().count(), 0);
    assert!(matches!(
        admit(&mut c, &[0; 65], 0, 10),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        admit(&mut c, b"bad rng", 1, 10),
        Err(Error::InvalidInput)
    ));
    assert_eq!(c.pending_requests(), 1);
    assert_eq!(c.query(id)?, b"original");
    let (_, socket, server) = send(&mut c, 10)?;
    assert_eq!(server, endpoint(1));
    assert_eq!(c.readable_socket_at(0, Family::V4), Some(socket));
    assert_eq!(c.readable_socket_at(1, Family::V4), None);
    Ok(())
}
#[test]
fn servers_insert_at_head_and_existing_cursor_survives_new_insert() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    let a = admit(&mut c, b"a", 0, 0)?.request;
    c.add_dns_sa(endpoint(2))?;
    assert_eq!(send(&mut c, 0)?.2, endpoint(1));
    assert_eq!(send(&mut c, 250_000)?.2, endpoint(2));
    assert_eq!(send(&mut c, 500_000)?.2, endpoint(1));
    c.resolve_cancel(a)?;
    assert!(admit(&mut c, b"b", 0, 750_000)?.evicted.is_none());
    assert_eq!(send(&mut c, 750_000)?.2, endpoint(2));
    assert_eq!(send(&mut c, 1_000_000)?.2, endpoint(1));
    Ok(())
}
#[test]
fn exactly_256_occupied_random_choices_evict_only_the_last_with_failure_token() -> Result<(), Error>
{
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    let a = admit(&mut c, b"a", 0, 0)?.request;
    let b = admit(&mut c, b"b", 1, 0)?.request;
    let mut draws = 0;
    let replaced = c.resolve(b"new", MonoInstant(1), |bound| {
        assert_eq!(bound, 2);
        draws += 1;
        Ok(if draws == 256 { 1 } else { 0 })
    })?;
    assert_eq!(draws, 256);
    assert_eq!(replaced.evicted, Some(b));
    assert!(c.owns_request(a));
    assert!(!c.owns_request(b));
    assert_ne!(replaced.request, b);
    assert_eq!(c.query(replaced.request)?, b"new");
    assert_eq!(c.query(a)?, b"a");
    assert_eq!(c.resolve_cancel(b), Err(Error::StaleGeneration));
    Ok(())
}
#[test]
fn query_copy_repeated_unverified_results_and_retry_continue_until_cancel() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    let mut bytes = [0xab; 12];
    let id = admit(&mut c, &bytes, 0, 0)?.request;
    bytes.fill(0);
    assert_eq!(c.query(id)?, &[0xab; 12]);
    let (_, socket, _) = send(&mut c, 0)?;
    for idbytes in [[0, 0], [255, 255]] {
        let mut packet = [0; 12];
        packet[..2].copy_from_slice(&idbytes);
        let event = c
            .receive(socket, endpoint(1), &packet)
            .map_err(|_| Error::Malformed)?;
        assert_eq!(event.request, id);
        assert_eq!(event.bytes, &packet);
        assert_eq!(event.bytes[2] & 0x80, 0); // QR0 is not authority at this raw layer.
    }
    assert_eq!(c.pending_requests(), 1);
    assert_eq!(send(&mut c, 250_000)?.1, socket);
    c.resolve_cancel(id)?;
    assert_eq!(
        c.receive(socket, endpoint(1), &[0; 12]),
        Err(DropReason::Cancelled)
    );
    assert_eq!(c.next_wakeup(), None);
    assert_eq!(c.next_action(MonoInstant(10_000_000))?, None);
    Ok(())
}
#[test]
fn receive_filters_peer_port_minimum_header_and_actual_socket_interest() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    c.add_dns_sa(endpoint(2))?;
    assert!(admit(&mut c, b"q", 0, 0)?.evicted.is_none());
    let Some(Action::OpenSocket { socket }) = c.next_action(MonoInstant(0))? else {
        return Err(Error::NotReady);
    };
    assert_eq!(
        c.receive(socket, endpoint(1), &[0; 12]),
        Err(DropReason::NotReading)
    );
    c.socket_opened(socket, true)?;
    let Some(Action::Send { attempt, .. }) = c.next_action(MonoInstant(0))? else {
        return Err(Error::NotReady);
    };
    assert_eq!(
        c.receive(socket, endpoint(1), &[0; 12]),
        Err(DropReason::NotReading)
    );
    c.sent(attempt)?;
    assert!(c.receive(socket, endpoint(1), &[0; 12]).is_ok()); // configured even if not yet queried
    assert_eq!(
        c.receive(socket, endpoint(3), &[0; 12]),
        Err(DropReason::UnknownPeer)
    );
    assert_eq!(
        c.receive(socket, SocketAddr::new(endpoint(1).ip(), 42), &[0; 12]),
        Err(DropReason::UnknownPeer)
    );
    assert_eq!(
        c.receive(socket, endpoint(1), &[0; 11]),
        Err(DropReason::ShortPacket)
    );
    assert_eq!(
        c.receive(socket, v6(), &[0; 12]),
        Err(DropReason::WrongFamily)
    );
    Ok(())
}
#[test]
fn retry_changes_only_subsequent_period_and_forever_has_no_fake_timeout() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    let id = admit(&mut c, b"q", 0, 0)?.request;
    let (_, socket, _) = send(&mut c, 0)?;
    c.set_retry(Duration(10))?;
    assert_eq!(c.next_wakeup(), Some(MonoInstant(250_000)));
    assert_eq!(c.next_action(MonoInstant(249_999))?, None);
    send(&mut c, 250_000)?;
    assert_eq!(c.next_wakeup(), Some(MonoInstant(250_010)));
    c.set_retry(Duration(u64::MAX))?;
    send(&mut c, 250_010)?;
    assert_eq!(c.next_wakeup(), None);
    assert!(c.owns_request(id));
    assert!(c.receive(socket, endpoint(1), &[0; 12]).is_ok());
    c.set_retry(Duration(1))?;
    assert_eq!(c.next_action(MonoInstant(1_000_000))?, None);
    Ok(())
}
#[test]
fn canceled_slot_reuses_real_cached_sockets_but_old_request_tokens_are_stale() -> Result<(), Error>
{
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    let a = admit(&mut c, b"a", 0, 0)?.request;
    let (_, socket, _) = send(&mut c, 0)?;
    c.resolve_cancel(a)?;
    let b = admit(&mut c, b"b", 0, 1)?.request;
    assert_eq!(c.readable_sockets().count(), 0);
    let Some(Action::Send {
        attempt,
        socket: cached,
        request,
        ..
    }) = c.next_action(MonoInstant(1))?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(cached, socket);
    assert_eq!(request, b);
    c.sent(attempt)?;
    // The socket cannot attribute a late raw datagram to the old DNS ID.
    assert_eq!(
        c.receive(socket, endpoint(1), &[0; 12])
            .map_err(|_| Error::Malformed)?
            .request,
        b
    );
    assert_eq!(c.query(a), Err(Error::StaleGeneration));
    Ok(())
}
#[test]
fn dual_family_cache_read_errors_and_late_effects_do_not_close_other_family() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    c.add_dns_sa(v6())?;
    let id = admit(&mut c, b"q", 0, 0)?.request;
    let (_, six, target) = send(&mut c, 0)?;
    assert_eq!(target, v6());
    let (_, four, target) = send(&mut c, 250_000)?;
    assert_eq!(target, endpoint(1));
    assert_eq!(c.readable_sockets().count(), 2);
    c.socket_failed(six)?;
    assert_eq!(c.readable_sockets().count(), 1);
    assert!(c.receive(four, endpoint(1), &[0; 12]).is_ok());
    assert_eq!(c.receive(six, v6(), &[0; 12]), Err(DropReason::StaleSocket));
    let Some(Action::OpenSocket { socket: new }) = c.next_action(MonoInstant(500_000))? else {
        return Err(Error::NotReady);
    };
    assert_ne!(new, six);
    assert_eq!(c.socket_opened(six, true), Err(Error::StaleGeneration));
    c.socket_opened(new, true)?;
    let Some(Action::Send {
        attempt, request, ..
    }) = c.next_action(MonoInstant(500_000))?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, id);
    c.sent(attempt)?;
    assert_eq!(c.readable_sockets().count(), 2);
    Ok(())
}
#[test]
fn failed_bind_advances_server_without_inventing_read_or_callback() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(endpoint(1))?;
    c.add_dns_sa(v6())?;
    let id = admit(&mut c, b"q", 0, 0)?.request;
    let Some(Action::OpenSocket { socket }) = c.next_action(MonoInstant(0))? else {
        return Err(Error::NotReady);
    };
    c.socket_opened(socket, false)?;
    assert_eq!(c.readable_sockets().count(), 0);
    assert!(c.owns_request(id));
    assert_eq!(c.next_wakeup(), Some(MonoInstant(250_000)));
    assert_eq!(send(&mut c, 250_000)?.2, endpoint(1));
    Ok(())
}
#[test]
fn stop_cancels_all_tokens_without_synthetic_result_or_retained_servers() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_ip("127.0.0.1")?;
    let id = admit(&mut c, b"", 0, 0)?.request;
    let (_, socket, target) = send(&mut c, 0)?;
    assert_eq!(target.port(), 53);
    let stopped = c.stop();
    assert_eq!(stopped.requests, 1);
    assert_eq!(stopped.socket_tokens, 1);
    assert!(!c.owns_request(id));
    assert_eq!(c.next_wakeup(), None);
    assert_eq!(c.readable_sockets().count(), 0);
    assert_eq!(c.next_action(MonoInstant(0)), Err(Error::Closed));
    assert_eq!(
        c.receive(socket, target, &[0; 12]),
        Err(DropReason::StaleSocket)
    );
    assert_eq!(c.stop().requests, 0);
    assert_eq!(c.add_dns_ip("invalid"), Err(Error::Closed));
    Ok(())
}
#[test]
fn ipv6_scope_and_flow_are_preserved_for_send_but_not_claimed_response_authority()
-> Result<(), Error> {
    let mut c = Core::new()?;
    let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 7, 11));
    c.add_dns_sa(target)?;
    assert!(admit(&mut c, b"q", 0, 0)?.evicted.is_none());
    let (_, socket, destination) = send(&mut c, 0)?;
    assert_eq!(destination, target);
    let other_metadata = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 99));
    assert!(c.receive(socket, other_metadata, &[0; 12]).is_ok());
    Ok(())
}

#[test]
fn newly_opened_second_family_is_not_readable_until_its_send_attempt() -> Result<(), Error> {
    let mut c = Core::new()?;
    c.add_dns_sa(v6())?;
    c.add_dns_sa(endpoint(1))?;
    let id = admit(&mut c, b"q", 0, 0)?.request;
    let (_, v4, _) = send(&mut c, 0)?;
    let Action::OpenSocket { socket: v6socket } = c
        .next_action(MonoInstant(250_000))?
        .ok_or(Error::NotReady)?
    else {
        return Err(Error::NotReady);
    };
    c.socket_opened(v6socket, true)?;
    assert_eq!(c.readable_sockets().collect::<Vec<_>>(), vec![v4]);
    assert_eq!(c.readable_socket_at(0, Family::V6), None);
    assert_eq!(
        c.receive(v6socket, v6(), &[0; 12]),
        Err(DropReason::NotReading)
    );
    let Action::Send {
        attempt, request, ..
    } = c
        .next_action(MonoInstant(250_000))?
        .ok_or(Error::NotReady)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, id);
    assert_eq!(
        c.receive(v6socket, v6(), &[0; 12]),
        Err(DropReason::NotReading)
    );
    c.sent(attempt)?;
    assert_eq!(c.readable_sockets().collect::<Vec<_>>(), vec![v4, v6socket]);
    assert_eq!(
        c.receive(v6socket, v6(), &[0; 12])
            .map_err(|_| Error::Malformed)?
            .request,
        id
    );
    Ok(())
}
