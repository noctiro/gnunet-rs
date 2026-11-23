//! Internal finite resource exhaustion and effect authority regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite owner-state regressions fail on incorrect effects or authority."
)]
use super::*;
use core::net::{Ipv4Addr, SocketAddrV4};
fn configured() -> Result<DnsStub<2, 16, 2>, Error> {
    let mut c = DnsStub::new()?;
    c.add_dns_sa(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5300)))?;
    Ok(c)
}
fn admit(c: &mut DnsStub<2, 16, 2>, slot: u32) -> Result<Admission, Error> {
    c.resolve(b"original", MonoInstant(0), |_| Ok(slot))
}
#[test]
fn pending_destination_tracks_only_the_original_active_open_attempt() -> Result<(), Error> {
    let mut core = configured()?;
    let destination: SocketAddr = "[fe80::53%7]:53".parse().map_err(|_| Error::Malformed)?;
    core.add_dns_sa(destination)?;
    let request = admit(&mut core, 0)?.request;
    let Action::OpenSocket { socket } = core.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    let due = core.next_wakeup();
    assert_eq!(core.pending_destination(socket)?, destination);
    assert_eq!(core.next_wakeup(), due);
    assert_eq!(core.query(request)?, b"original");
    let mut stale = socket;
    stale.generation += 1;
    assert_eq!(core.pending_destination(stale), Err(Error::StaleGeneration));
    core.socket_opened(socket, true)?;
    assert_eq!(core.pending_destination(socket), Err(Error::NotReady));
    core.resolve_cancel(request)?;
    assert_eq!(core.pending_destination(socket), Err(Error::NotReady));
    Ok(())
}

#[test]
fn response_must_match_configured_ipv6_zone_but_ignores_flow_label() -> Result<(), Error> {
    let mut owner = configured()?;
    let expected = "[fe80::53%7]:53".parse().map_err(|_| Error::Malformed)?;
    owner.add_dns_sa(expected)?;
    let request = admit(&mut owner, 0)?.request;
    let Action::OpenSocket { socket } =
        owner.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    owner.socket_opened(socket, true)?;
    let Action::Send {
        attempt,
        destination,
        ..
    } = owner.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(expected, destination);
    owner.sent(attempt)?;
    let SocketAddr::V6(expected) = expected else {
        return Err(Error::Conflict);
    };
    let mut received = expected;
    received.set_flowinfo(0x1234);
    let bytes = [0; MINIMUM_RESPONSE_LEN];
    assert_eq!(
        owner
            .receive(socket, received.into(), &bytes)
            .map(|response| response.request),
        Ok(request)
    );
    for scope in [0, 8] {
        received.set_scope_id(scope);
        assert!(matches!(
            owner.receive(socket, received.into(), &bytes),
            Err(DropReason::UnknownPeer)
        ));
    }
    Ok(())
}
#[test]
fn last_request_generation_remains_live_but_is_never_reassigned() -> Result<(), Error> {
    let mut c = configured()?;
    c.slots[0].next_generation = u32::MAX;
    let last = admit(&mut c, 0)?.request;
    assert_eq!(last.resource_id().generation, u32::MAX);
    assert_eq!(c.query(last)?, b"original");
    let mut draws = 0;
    assert_eq!(
        c.resolve(b"new", MonoInstant(1), |_| {
            draws += 1;
            Ok(0)
        }),
        Err(Error::Capacity)
    );
    assert_eq!(draws, SELECTION_ATTEMPTS);
    assert!(c.owns_request(last));
    c.resolve_cancel(last)?;
    assert_eq!(admit(&mut c, 0), Err(Error::Capacity));
    let second = admit(&mut c, 1)?.request;
    assert_ne!(last, second);
    assert_eq!(c.pending_requests(), 1);
    Ok(())
}
#[test]
fn exhausted_scheduler_or_socket_identity_refuses_before_retry_cursor_changes() -> Result<(), Error>
{
    let mut c = configured()?;
    let id = admit(&mut c, 0)?.request;
    let due = c.next_wakeup();
    let cursor = c.slots[0].next_server;
    let generation = c.slots[0].next_generation;
    c.order = u64::MAX;
    assert_eq!(admit(&mut c, 0), Err(Error::Overflow));
    assert_eq!(c.next_action(MonoInstant(0)), Err(Error::Overflow));
    assert_eq!(c.slots[0].next_generation, generation);
    assert_eq!(c.slots[0].next_server, cursor);
    assert_eq!(c.next_wakeup(), due);
    assert_eq!(c.query(id)?, b"original");
    c.order = 1;
    c.slots[0].sockets[0].generation = u64::MAX;
    assert_eq!(c.next_action(MonoInstant(0)), Err(Error::Overflow));
    assert_eq!(c.order, 1);
    assert_eq!(c.slots[0].next_server, cursor);
    assert_eq!(c.next_wakeup(), due);
    assert!(c.slots[0].pending.is_none());
    assert!(c.readable_sockets().next().is_none());
    Ok(())
}
#[test]
fn random_source_failure_after_occupied_probes_cannot_evict_or_consume_identity()
-> Result<(), Error> {
    let mut c = configured()?;
    let a = admit(&mut c, 0)?.request;
    let b = admit(&mut c, 1)?.request;
    let order = c.order;
    let mut draws = 0;
    assert_eq!(
        c.resolve(b"new", MonoInstant(1), |_| {
            draws += 1;
            if draws == SELECTION_ATTEMPTS {
                Err(Error::Io)
            } else {
                Ok(0)
            }
        }),
        Err(Error::Io)
    );
    assert_eq!(draws, SELECTION_ATTEMPTS);
    assert_eq!(c.order, order);
    assert_eq!(c.query(a)?, b"original");
    assert_eq!(c.query(b)?, b"original");
    assert_eq!(c.pending_requests(), 2);
    Ok(())
}
#[test]
fn zero_retry_yields_to_other_due_slots_and_old_send_result_has_no_authority() -> Result<(), Error>
{
    let mut c = configured()?;
    c.set_retry(Duration(0))?;
    let a = admit(&mut c, 0)?.request;
    let b = admit(&mut c, 1)?.request;
    let mut seen = [a; 4];
    let mut old = None;
    for item in &mut seen {
        let mut action = c.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?;
        if let Action::OpenSocket { socket } = action {
            c.socket_opened(socket, true)?;
            action = c.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?;
        }
        let Action::Send {
            attempt, request, ..
        } = action
        else {
            return Err(Error::NotReady);
        };
        *item = request;
        if let Some(old) = old {
            assert_eq!(c.sent(old), Err(Error::StaleGeneration));
        }
        c.sent(attempt)?;
        old = Some(attempt);
    }
    assert_eq!(seen, [a, b, a, b]);
    Ok(())
}
#[test]
fn pending_bind_belongs_to_cache_and_cannot_resurrect_canceled_query() -> Result<(), Error> {
    let mut c = configured()?;
    let old = admit(&mut c, 0)?.request;
    let Action::OpenSocket { socket } = c.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::NotReady);
    };
    c.resolve_cancel(old)?;
    assert!(c.next_action(MonoInstant(0))?.is_none());
    assert!(c.next_wakeup().is_none());
    let new = c.resolve(b"new", MonoInstant(1), |_| Ok(0))?.request;
    // The same actual in-progress socket is still useful to the replacement.
    assert!(c.next_action(MonoInstant(1))?.is_none());
    c.socket_opened(socket, true)?;
    let Action::Send {
        request, attempt, ..
    } = c.next_action(MonoInstant(1))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, new);
    assert_eq!(c.query(request)?, b"new");
    assert_eq!(c.query(old), Err(Error::StaleGeneration));
    c.sent(attempt)?;
    let stopped = c.stop();
    assert_eq!(stopped.socket_tokens, 1);
    assert!(c.is_stopped());
    assert_eq!(c.socket_opened(socket, true), Err(Error::StaleGeneration));
    assert_eq!(c.sent(attempt), Err(Error::Closed));
    assert_eq!(
        c.stop(),
        Stopped {
            requests: 0,
            socket_tokens: 0
        }
    );
    Ok(())
}

#[test]
fn replacing_upstreams_retires_original_effects_and_keeps_preference_order() -> Result<(), Error> {
    let mut core = configured()?;
    core.set_retry(Duration(10))?;
    let original = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5300));
    let first = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5301));
    let second = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5302));
    let response = [0; MINIMUM_RESPONSE_LEN];
    let old_request = admit(&mut core, 0)?.request;
    let Action::OpenSocket { socket: old_socket } =
        core.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    core.socket_opened(old_socket, true)?;
    let Action::Send { attempt, .. } = core.next_action(MonoInstant(0))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    core.sent(attempt)?;
    let old_opening_request = core.resolve(b"opening", MonoInstant(1), |_| Ok(1))?.request;
    let Action::OpenSocket {
        socket: old_opening,
    } = core.next_action(MonoInstant(1))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    let Action::Send {
        attempt: old_attempt,
        ..
    } = core.next_action(MonoInstant(10))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };

    assert_eq!(
        core.replace_servers(&[first, second, first]),
        Err(Error::Capacity)
    );
    assert_eq!(core.pending_destination(old_opening), Ok(original));
    assert_eq!(
        core.receive(old_socket, original, &response)
            .map(|value| value.request),
        Ok(old_request)
    );

    core.replace_servers(&[first, second])?;
    assert_eq!(core.pending_requests(), 0);
    assert_eq!(core.next_wakeup(), None);
    assert_eq!(core.retry(), Duration(10));
    assert_eq!(core.query(old_request), Err(Error::StaleGeneration));
    assert_eq!(core.query(old_opening_request), Err(Error::StaleGeneration));
    assert_eq!(
        core.socket_opened(old_opening, true),
        Err(Error::StaleGeneration)
    );
    assert_eq!(core.sent(old_attempt), Err(Error::StaleGeneration));
    assert!(matches!(
        core.receive(old_socket, original, &response),
        Err(DropReason::StaleSocket)
    ));

    let request = core.resolve(b"fresh", MonoInstant(11), |_| Ok(0))?.request;
    assert_ne!(request, old_request);
    let Action::OpenSocket { socket } =
        core.next_action(MonoInstant(11))?.ok_or(Error::NotReady)?
    else {
        return Err(Error::Conflict);
    };
    assert_ne!(socket, old_socket);
    core.socket_opened(socket, true)?;
    for (now, expected) in [(11, first), (21, second)] {
        let Action::Send {
            attempt,
            request: sent,
            destination,
            ..
        } = core.next_action(MonoInstant(now))?.ok_or(Error::NotReady)?
        else {
            return Err(Error::Conflict);
        };
        assert_ne!(attempt, old_attempt);
        assert_eq!(sent, request);
        assert_eq!(destination, expected);
        core.sent(attempt)?;
    }
    assert!(matches!(
        core.receive(socket, original, &response),
        Err(DropReason::UnknownPeer)
    ));

    core.replace_servers(&[])?;
    assert!(!core.is_stopped());
    assert_eq!(
        core.resolve(b"disabled", MonoInstant(21), |_| Ok(0)),
        Err(Error::Unavailable)
    );
    assert_eq!(core.next_action(MonoInstant(21))?, None);
    core.replace_servers(&[first])?;
    assert!(core.resolve(b"enabled", MonoInstant(21), |_| Ok(0)).is_ok());
    Ok(())
}
