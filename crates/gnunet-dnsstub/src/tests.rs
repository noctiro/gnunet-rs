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
