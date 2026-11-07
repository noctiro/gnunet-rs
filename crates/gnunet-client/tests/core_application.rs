//! Original CORE request/permit identity, immutable frame and peer lifecycle tests.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol tests assert operation/epoch resource invariants"
)]
use gnunet_client::core::{
    ClassOrder, ConnectionEpoch, CoreClient, Direction, Event, HEADER_OUTBOUND, Instance, KxState,
    Monitor, MonitorEvent, Peer, PeerClass, PeerId, Request, Response, SendOperation, SendOutcome,
    Traffic,
};
use gnunet_types::Error;
use gnunet_wire::official::{MessageHeader, message_type};
use std::{cell::Cell, rc::Rc};
const LOCAL: PeerId = PeerId([0x22; 32]);
const A: PeerId = PeerId([0x11; 32]);
const B: PeerId = PeerId([0x33; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
const ORDER: ClassOrder = ClassOrder::Little;
type Client<'a> = CoreClient<'a, 4, 8>;

#[test]
fn same_mq_disconnect_barrier_preserves_ordered_ready_generation_boundaries() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let old_peer = connect(&mut owner, epoch, A, &mut out)?;
    let (old, old_wire) = requested(&mut owner, old_peer, &mut out)?;
    // A previously queued READY arrives before the service's DISCONNECT barrier.
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: A,
                request_id: old_wire,
                size: 8
            },
            &mut out
        )?,
        Event::SendReady {
            send: old.id(),
            capacity: 8
        }
    );
    response(&mut owner, epoch, Response::Disconnected(A), &mut out)?;
    assert_eq!(
        owner
            .finish(old)
            .map_err(|rejected| rejected.reason)?
            .outcome,
        SendOutcome::PeerDisconnected
    );
    let new_peer = connect(&mut owner, epoch, A, &mut out)?;
    assert_ne!(old_peer, new_peer);
    assert_eq!(owner.request_available(old_peer), Err(Error::Stale));
    assert!(owner.request_available(new_peer)?);
    assert!(
        matches!(owner.request_send(old_peer, 0, 0, MESSAGE, &mut out), Err(rejected) if rejected.reason == Error::Stale)
    );
    let (new, new_wire) = requested(&mut owner, new_peer, &mut out)?;
    assert_eq!(old_wire, new_wire);
    assert!(matches!(
        owner.prepare_payload(&new, &mut out),
        Err(Error::NotReady)
    ));
    // This is the new original request's READY. Source cleanup/FIFO rules prohibit
    // synthesizing a delayed old generation here and calling it valid C traffic.
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: A,
                request_id: new_wire,
                size: 8
            },
            &mut out
        )?,
        Event::SendReady {
            send: new.id(),
            capacity: 8
        }
    );
    Ok(())
}
fn response<'a, 'frame>(
    owner: &mut Client<'a>,
    epoch: ConnectionEpoch<'_>,
    value: Response<'_>,
    bytes: &'frame mut [u8],
) -> Result<Event<'a, 'frame>, Error> {
    let n = value.encode(bytes, ORDER)?;
    owner.receive(epoch, &bytes[..n])
}
fn ready<'a>(
    owner: &mut Client<'a>,
    bytes: &mut [u8],
) -> Result<(ConnectionEpoch<'a>, Peer<'a>), Error> {
    let (epoch, _) = owner.begin(bytes)?;
    match response(
        owner,
        epoch,
        Response::InitReply {
            identity: LOCAL,
            class: PeerClass::SERVER,
        },
        bytes,
    )? {
        Event::Ready {
            local,
            previous_identity: None,
        } => Ok((epoch, local)),
        _ => Err(Error::Malformed),
    }
}
fn connect<'a>(
    owner: &mut Client<'a>,
    epoch: ConnectionEpoch<'_>,
    peer: PeerId,
    bytes: &mut [u8],
) -> Result<Peer<'a>, Error> {
    match response(
        owner,
        epoch,
        Response::Connected {
            peer,
            class: PeerClass::DESKTOP,
        },
        bytes,
    )? {
        Event::Connected(peer) => Ok(peer),
        _ => Err(Error::Malformed),
    }
}
fn request_id(bytes: &[u8]) -> Result<u16, Error> {
    match Request::decode(bytes)? {
        Request::SendRequest { request_id, .. } => Ok(request_id),
        _ => Err(Error::Malformed),
    }
}
fn requested<'a>(
    owner: &mut Client<'a>,
    peer: Peer<'a>,
    bytes: &mut [u8],
) -> Result<(SendOperation<'a, Vec<u8>>, u16), Error> {
    let (operation, n) = owner
        .request_send(peer, 0, 0, MESSAGE.to_vec(), bytes)
        .map_err(|rejected| rejected.reason)?;
    Ok((operation, request_id(&bytes[..n])?))
}

#[test]
fn init_reply_creates_real_loopback_and_complete_local_write_is_not_delivery_ack()
-> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, local) = ready(&mut owner, &mut out)?;
    assert_eq!(local.identity(), LOCAL);
    assert_eq!(local.class(), PeerClass::SERVER);
    let (op, wire) = requested(&mut owner, local, &mut out)?;
    assert_eq!(
        owner.payload_bytes_written(op.id(), 1),
        Err(Error::NotReady)
    );
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: LOCAL,
                request_id: wire,
                size: 8
            },
            &mut out
        )?,
        Event::SendReady {
            send: op.id(),
            capacity: 8
        }
    );
    let prepared = owner.prepare_payload(&op, &mut out)?;
    let len = prepared.bytes().len();
    assert_eq!(owner.payload_bytes_written(prepared.send(), 3)?, None);
    assert_eq!(
        owner.payload_bytes_written(prepared.send(), len - 3)?,
        Some(SendOutcome::Written)
    );
    let done = owner.finish(op).map_err(|rejected| rejected.reason)?;
    assert_eq!(done.outcome, SendOutcome::Written);
    assert_eq!(done.source, MESSAGE);
    Ok(())
}

#[test]
fn only_original_peer_request_ready_permits_the_retained_operation() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let a = connect(&mut owner, epoch, A, &mut out)?;
    let b = connect(&mut owner, epoch, B, &mut out)?;
    assert!(owner.request_available(a)?);
    assert!(owner.request_available(b)?);
    let (op_a, id_a) = requested(&mut owner, a, &mut out)?;
    assert!(!owner.request_available(a)?);
    assert!(owner.request_available(b)?);
    let (op_b, id_b) = requested(&mut owner, b, &mut out)?;
    assert!(!owner.request_available(b)?);
    assert_eq!(id_a, id_b);
    assert!(
        matches!(owner.request_send(a, 0, 0, MESSAGE, &mut out), Err(rejected) if rejected.reason == Error::WouldBlock)
    );
    assert!(matches!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: A,
                request_id: id_a + 1,
                size: 8
            },
            &mut out
        )?,
        Event::IgnoredReady { .. }
    ));
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: B,
                request_id: id_b,
                size: 8
            },
            &mut out
        )?,
        Event::SendReady {
            send: op_b.id(),
            capacity: 8
        }
    );
    assert!(matches!(
        owner.prepare_payload(&op_a, &mut out),
        Err(Error::NotReady)
    ));
    let prepared = owner.prepare_payload(&op_b, &mut out)?;
    owner.payload_bytes_written(prepared.send(), prepared.bytes().len())?;
    owner.finish(op_b).map_err(|rejected| rejected.reason)?;
    owner
        .cancel_unwritten(op_a)
        .map_err(|rejected| rejected.reason)?;
    Ok(())
}

#[test]
fn canceled_request_reply_cannot_release_the_next_original_payload() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, local) = ready(&mut owner, &mut out)?;
    let (old, old_wire) = requested(&mut owner, local, &mut out)?;
    let cancelled = owner
        .cancel_unwritten(old)
        .map_err(|rejected| rejected.reason)?;
    assert_eq!(cancelled.outcome, SendOutcome::CancelledBeforePayload);
    let (new, new_wire) = requested(&mut owner, local, &mut out)?;
    assert_ne!(old_wire, new_wire);
    assert!(matches!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: LOCAL,
                request_id: old_wire,
                size: 8
            },
            &mut out
        )?,
        Event::IgnoredReady { .. }
    ));
    assert!(matches!(
        owner.prepare_payload(&new, &mut out),
        Err(Error::NotReady)
    ));
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: LOCAL,
                request_id: new_wire,
                size: 8
            },
            &mut out
        )?,
        Event::SendReady {
            send: new.id(),
            capacity: 8
        }
    );
    Ok(())
}

#[test]
fn zero_ready_is_rejection_and_undersized_ready_retires_the_mq() -> Result<(), Error> {
    for permit in [0, 4] {
        let mut scope = Instance::new();
        let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
        let mut out = [0; 128];
        let (epoch, local) = ready(&mut owner, &mut out)?;
        let (op, wire) = requested(&mut owner, local, &mut out)?;
        let result = response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: LOCAL,
                request_id: wire,
                size: permit,
            },
            &mut out,
        );
        if permit == 0 {
            assert_eq!(result?, Event::Rejected(op.id()));
            assert!(matches!(
                owner.prepare_payload(&op, &mut out),
                Err(Error::Closed)
            ));
        } else {
            assert_eq!(result, Err(Error::Malformed));
        }
        let completion = owner.finish(op).map_err(|rejected| rejected.reason)?;
        assert_eq!(
            completion.outcome,
            if permit == 0 {
                SendOutcome::Rejected
            } else {
                SendOutcome::ConnectionLost
            }
        );
    }
    Ok(())
}

struct Dynamic {
    select: Rc<Cell<bool>>,
    views: Rc<Cell<usize>>,
}
impl AsRef<[u8]> for Dynamic {
    fn as_ref(&self) -> &[u8] {
        self.views.set(self.views.get() + 1);
        if self.select.get() {
            &[0, 8, 0, 0, 0, 0, 0, 2]
        } else {
            &MESSAGE
        }
    }
}
#[test]
fn safe_changing_asref_source_cannot_regenerate_an_admitted_partial_frame() -> Result<(), Error> {
    let select = Rc::new(Cell::new(false));
    let views = Rc::new(Cell::new(0));
    let source = Dynamic {
        select: select.clone(),
        views: views.clone(),
    };
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, local) = ready(&mut owner, &mut out)?;
    let (op, n) = owner
        .request_send(local, 0, 0, source, &mut out)
        .map_err(|rejected| rejected.reason)?;
    let wire = request_id(&out[..n])?;
    assert_eq!(views.get(), 1);
    select.set(true);
    response(
        &mut owner,
        epoch,
        Response::SendReady {
            peer: LOCAL,
            request_id: wire,
            size: 8,
        },
        &mut out,
    )?;
    let mut short = [0xa5; 55];
    assert!(matches!(
        owner.prepare_payload(&op, &mut short),
        Err(Error::Capacity)
    ));
    assert_eq!(views.get(), 1);
    let prepared = owner.prepare_payload(&op, &mut out)?;
    assert_eq!(views.get(), 2);
    assert_eq!(&prepared.bytes()[48..], &[0, 8, 0, 0, 0, 0, 0, 2]);
    select.set(false);
    assert!(matches!(
        owner.prepare_payload(&op, &mut [0; 128]),
        Err(Error::NotReady)
    ));
    owner.payload_bytes_written(prepared.send(), 7)?;
    assert_eq!(&prepared.bytes()[48..], &[0, 8, 0, 0, 0, 0, 0, 2]);
    owner.payload_bytes_written(prepared.send(), prepared.bytes().len() - 7)?;
    owner.finish(op).map_err(|rejected| rejected.reason)?;
    assert_eq!(views.get(), 2);
    Ok(())
}

#[test]
fn partial_cancel_requires_original_frame_drain_and_reports_uncertainty() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, local) = ready(&mut owner, &mut out)?;
    let (op, wire) = requested(&mut owner, local, &mut out)?;
    response(
        &mut owner,
        epoch,
        Response::SendReady {
            peer: LOCAL,
            request_id: wire,
            size: 8,
        },
        &mut out,
    )?;
    let prepared = owner.prepare_payload(&op, &mut out)?;
    owner.payload_bytes_written(prepared.send(), 2)?;
    let refused = match owner.cancel_unwritten(op) {
        Err(rejected) => rejected,
        Ok(_) => return Err(Error::InvalidInput),
    };
    assert_eq!(refused.reason, Error::Conflict);
    let op = refused.value;
    owner.cancel_started(op.id())?;
    owner.payload_bytes_written(prepared.send(), prepared.bytes().len() - 2)?;
    assert_eq!(
        owner
            .finish(op)
            .map_err(|rejected| rejected.reason)?
            .outcome,
        SendOutcome::CancelledAfterWrite
    );
    Ok(())
}

#[test]
fn foreign_tokens_and_moving_owner_preserve_instance_authority() -> Result<(), Error> {
    let (mut a_scope, mut b_scope) = (Instance::new(), Instance::new());
    let mut a = Client::new(&mut a_scope, ORDER, 0, &[0])?;
    let mut b = Client::new(&mut b_scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (ea, pa) = ready(&mut a, &mut out)?;
    let (eb, pb) = ready(&mut b, &mut out)?;
    assert_ne!(ea, eb);
    assert_ne!(pa, pb);
    assert_eq!(b.connection_lost(ea), Err(Error::Stale));
    assert!(
        matches!(b.request_send(pa, 0, 0, MESSAGE, &mut out), Err(rejected) if rejected.reason == Error::Stale)
    );
    let (op, wire) = requested(&mut a, pa, &mut out)?;
    assert!(matches!(
        b.prepare_payload(&op, &mut out),
        Err(Error::Stale)
    ));
    let mut moved = a;
    response(
        &mut moved,
        ea,
        Response::SendReady {
            peer: LOCAL,
            request_id: wire,
            size: 8,
        },
        &mut out,
    )?;
    let prepared = moved.prepare_payload(&op, &mut out)?;
    moved.payload_bytes_written(prepared.send(), prepared.bytes().len())?;
    assert_eq!(
        moved
            .finish(op)
            .map_err(|rejected| rejected.reason)?
            .outcome,
        SendOutcome::Written
    );
    Ok(())
}

#[test]
fn peer_disconnect_and_service_loss_retire_only_original_work() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let a = connect(&mut owner, epoch, A, &mut out)?;
    let b = connect(&mut owner, epoch, B, &mut out)?;
    let (op_a, _) = requested(&mut owner, a, &mut out)?;
    let (op_b, _) = requested(&mut owner, b, &mut out)?;
    assert_eq!(
        response(&mut owner, epoch, Response::Disconnected(A), &mut out)?,
        Event::Disconnected(a)
    );
    assert_eq!(
        owner
            .finish(op_a)
            .map_err(|rejected| rejected.reason)?
            .outcome,
        SendOutcome::PeerDisconnected
    );
    owner.connection_lost(epoch)?;
    assert_eq!(
        owner
            .finish(op_b)
            .map_err(|rejected| rejected.reason)?
            .outcome,
        SendOutcome::ConnectionLost
    );
    let mut notices = Vec::new();
    while let Some(peer) = owner.next_lost_peer() {
        notices.push(peer.identity());
    }
    assert_eq!(notices, vec![LOCAL, B]);
    let (new_epoch, _) = owner.begin(&mut out)?;
    assert_ne!(new_epoch, epoch);
    assert_eq!(owner.connection_lost(epoch), Err(Error::Stale));
    assert!(matches!(
        response(
            &mut owner,
            new_epoch,
            Response::InitReply {
                identity: A,
                class: PeerClass::MOBILE
            },
            &mut out
        )?,
        Event::Ready {
            previous_identity: Some(LOCAL),
            ..
        }
    ));
    Ok(())
}

#[test]
fn observational_header_preview_does_not_invent_full_payload_or_peer_membership()
-> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, HEADER_OUTBOUND, &[])?;
    let mut out = [0; 128];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let traffic = Traffic::Header(MessageHeader::new(message_type::TEST, 4)?);
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::Traffic {
                direction: Direction::Outbound,
                peer: A,
                traffic
            },
            &mut out
        )?,
        Event::Traffic {
            peer: A,
            connection: None,
            direction: Direction::Outbound,
            traffic
        }
    );
    assert_eq!(owner.peer(A), None);
    Ok(())
}

#[test]
fn native_preflight_does_not_consume_the_source_view_or_request_id() -> Result<(), Error> {
    let views = Rc::new(Cell::new(0));
    let source = Dynamic {
        select: Rc::new(Cell::new(false)),
        views: views.clone(),
    };
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (_, local) = ready(&mut owner, &mut out)?;
    let mut short = [0xa5; 55];
    assert!(owner.request_available(local)?);
    assert!(owner.request_available(local)?);
    assert_eq!(views.get(), 0);
    let rejected = match owner.request_send(local, 0, 0, source, &mut short) {
        Err(rejected) => rejected,
        Ok(_) => return Err(Error::InvalidInput),
    };
    assert_eq!(rejected.reason, Error::Capacity);
    assert_eq!(views.get(), 0);
    assert_eq!(short, [0xa5; 55]);
    let (_, n) = owner
        .request_send(local, 0, 0, rejected.value, &mut out)
        .map_err(|rejected| rejected.reason)?;
    assert_eq!(request_id(&out[..n])?, 1);
    Ok(())
}

#[test]
fn finite_wire_ids_wrap_under_progress_but_cancellation_backlog_never_aliases() -> Result<(), Error>
{
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, local) = ready(&mut owner, &mut out)?;
    for serial in 1..=u64::from(u16::MAX) {
        let (op, wire) = requested(&mut owner, local, &mut out)?;
        assert_eq!(u64::from(wire), serial);
        owner
            .cancel_unwritten(op)
            .map_err(|rejected| rejected.reason)?;
    }
    assert!(!owner.request_available(local)?);
    assert!(
        matches!(owner.request_send(local, 0, 0, MESSAGE, &mut out), Err(rejected) if rejected.reason == Error::WouldBlock)
    );
    assert!(matches!(
        response(
            &mut owner,
            epoch,
            Response::SendReady {
                peer: LOCAL,
                request_id: u16::MAX,
                size: 8
            },
            &mut out
        )?,
        Event::IgnoredReady { .. }
    ));
    assert!(owner.request_available(local)?);
    let (op, wire) = requested(&mut owner, local, &mut out)?;
    assert_eq!(wire, 0);
    response(
        &mut owner,
        epoch,
        Response::SendReady {
            peer: LOCAL,
            request_id: wire,
            size: 8,
        },
        &mut out,
    )?;
    let prepared = owner.prepare_payload(&op, &mut out)?;
    owner.payload_bytes_written(prepared.send(), prepared.bytes().len())?;
    owner.finish(op).map_err(|rejected| rejected.reason)?;
    let (_, wire) = requested(&mut owner, local, &mut out)?;
    assert_eq!(wire, 1);
    Ok(())
}

#[test]
fn monitor_snapshot_marker_does_not_end_continuous_updates_and_old_epochs_fail() -> Result<(), Error>
{
    let mut scope = Instance::new();
    let mut owner = Monitor::new(&mut scope);
    let mut out = [0; 64];
    let (epoch, n) = owner.begin(&mut out)?;
    assert_eq!(Request::decode(&out[..n])?, Request::Monitor);
    for state in [KxState(4), KxState::SNAPSHOT_FINISHED, KxState(7)] {
        let peer = if state == KxState::SNAPSHOT_FINISHED {
            PeerId([0; 32])
        } else {
            A
        };
        let timeout = if state == KxState::SNAPSHOT_FINISHED {
            u64::MAX
        } else {
            123
        };
        let n = Response::Monitor {
            peer,
            state,
            timeout,
        }
        .encode(&mut out, ORDER)?;
        let event = owner.receive(epoch, &out[..n])?;
        assert_eq!(
            event,
            if state == KxState::SNAPSHOT_FINISHED {
                MonitorEvent::SnapshotFinished
            } else {
                MonitorEvent::Update {
                    peer,
                    state,
                    timeout,
                }
            }
        );
    }
    assert_eq!(owner.connection_lost(epoch)?, MonitorEvent::ServiceLost);
    let (next, _) = owner.begin(&mut out)?;
    assert_ne!(next, epoch);
    assert_eq!(owner.connection_lost(epoch), Err(Error::Stale));
    Ok(())
}

#[test]
fn malformed_monitor_marker_and_app_traffic_before_init_reply_are_not_success() -> Result<(), Error>
{
    let mut scope = Instance::new();
    let mut owner = Monitor::new(&mut scope);
    let mut out = [0; 64];
    let (epoch, _) = owner.begin(&mut out)?;
    let n = Response::Monitor {
        peer: A,
        state: KxState::SNAPSHOT_FINISHED,
        timeout: u64::MAX,
    }
    .encode(&mut out, ORDER)?;
    assert_eq!(owner.receive(epoch, &out[..n]), Err(Error::Malformed));
    assert_eq!(owner.connection_lost(epoch), Err(Error::Closed));
    let mut scope = Instance::new();
    let mut client = Client::new(&mut scope, ORDER, 0, &[0])?;
    let (epoch, _) = client.begin(&mut out)?;
    let n = Response::Connected {
        peer: A,
        class: PeerClass::DESKTOP,
    }
    .encode(&mut out, ORDER)?;
    assert_eq!(client.receive(epoch, &out[..n]), Err(Error::Malformed));
    assert_eq!(client.connection_lost(epoch), Err(Error::Closed));
    Ok(())
}

fn sized_message(size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..2].copy_from_slice(&(size as u16).to_be_bytes());
    bytes
}
fn remote_aggregate() -> Vec<u8> {
    let mut bytes = sized_message(64_508);
    bytes.extend_from_slice(&[0, 4, 0, 0]);
    bytes
}
#[test]
fn remote_session_limits_are_distinct_from_the_larger_loopback_wire_envelope() -> Result<(), Error>
{
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0xa5; 128];
    let (epoch, local) = ready(&mut owner, &mut out)?;
    let remote = connect(&mut owner, epoch, A, &mut out)?;
    for body in [sized_message(64_512), sized_message(64_513)] {
        out.fill(0xa5);
        assert!(
            matches!(owner.request_send(remote, 0, 0, body, &mut out), Err(rejected) if rejected.reason == Error::TooLarge)
        );
        assert_eq!(out, [0xa5; 128]);
    }
    let (op, n) = owner
        .request_send(remote, 0, 0, remote_aggregate(), &mut out)
        .map_err(|rejected| rejected.reason)?;
    assert_eq!(request_id(&out[..n])?, 1);
    owner
        .cancel_unwritten(op)
        .map_err(|rejected| rejected.reason)?;
    let (op, n) = owner
        .request_send(local, 0, 0, sized_message(65_487), &mut out)
        .map_err(|rejected| rejected.reason)?;
    assert_eq!(request_id(&out[..n])?, 1);
    owner
        .cancel_unwritten(op)
        .map_err(|rejected| rejected.reason)?;
    Ok(())
}
struct BoundarySource {
    select: Rc<Cell<bool>>,
    safe: Vec<u8>,
    unsafe_single: Vec<u8>,
}
impl AsRef<[u8]> for BoundarySource {
    fn as_ref(&self) -> &[u8] {
        if self.select.get() {
            &self.unsafe_single
        } else {
            &self.safe
        }
    }
}
#[test]
fn deferred_body_is_rechecked_before_emitting_a_known_unsafe_remote_boundary() -> Result<(), Error>
{
    let select = Rc::new(Cell::new(false));
    let source = BoundarySource {
        select: select.clone(),
        safe: remote_aggregate(),
        unsafe_single: sized_message(64_512),
    };
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = vec![0xa5; 65_535];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let remote = connect(&mut owner, epoch, A, &mut out)?;
    let (op, n) = owner
        .request_send(remote, 0, 0, source, &mut out)
        .map_err(|rejected| rejected.reason)?;
    let id = request_id(&out[..n])?;
    response(
        &mut owner,
        epoch,
        Response::SendReady {
            peer: A,
            request_id: id,
            size: 64_512,
        },
        &mut out,
    )?;
    select.set(true);
    out.fill(0xa5);
    assert!(matches!(
        owner.prepare_payload(&op, &mut out),
        Err(Error::TooLarge)
    ));
    assert!(out.iter().all(|byte| *byte == 0xa5));
    owner
        .cancel_unwritten(op)
        .map_err(|rejected| rejected.reason)?;
    Ok(())
}

#[test]
fn unsettled_same_mq_peer_frontiers_are_bounded_and_not_evicted() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let healthy = connect(&mut owner, epoch, B, &mut out)?;
    for byte in [0x51, 0x52] {
        let identity = PeerId([byte; 32]);
        let peer = connect(&mut owner, epoch, identity, &mut out)?;
        let (operation, _) = requested(&mut owner, peer, &mut out)?;
        response(
            &mut owner,
            epoch,
            Response::Disconnected(identity),
            &mut out,
        )?;
        assert_eq!(
            owner.finish(operation).map_err(|r| r.reason)?.outcome,
            SendOutcome::PeerDisconnected
        );
    }
    let new = Response::Connected {
        peer: A,
        class: PeerClass::ROUTER,
    };
    for _ in 0..3 {
        assert_eq!(
            response(&mut owner, epoch, new, &mut out),
            Err(Error::Capacity)
        );
        assert_eq!(owner.peer(B), Some(healthy));
        assert_eq!(owner.peer(A), None);
    }
    // The occupied unresolved-ID slots do not prevent unrelated live-peer sends.
    let (operation, _) = requested(&mut owner, healthy, &mut out)?;
    owner.cancel_unwritten(operation).map_err(|r| r.reason)?;
    owner.connection_lost(epoch)?;
    while owner.next_lost_peer().is_some() {}
    let (next, _) = owner.begin(&mut out)?;
    assert_ne!(next, epoch);
    assert!(matches!(
        response(
            &mut owner,
            next,
            Response::InitReply {
                identity: LOCAL,
                class: PeerClass::SERVER
            },
            &mut out
        )?,
        Event::Ready { .. }
    ));
    assert!(matches!(
        response(&mut owner, next, new, &mut out)?,
        Event::Connected(_)
    ));
    Ok(())
}

#[test]
fn disconnected_zero_written_payload_is_terminal_without_draining_to_new_peer() -> Result<(), Error>
{
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, ORDER, 0, &[0])?;
    let mut out = [0; 128];
    let (epoch, _) = ready(&mut owner, &mut out)?;
    let old_peer = connect(&mut owner, epoch, A, &mut out)?;
    let (operation, wire) = requested(&mut owner, old_peer, &mut out)?;
    response(
        &mut owner,
        epoch,
        Response::SendReady {
            peer: A,
            request_id: wire,
            size: 8,
        },
        &mut out,
    )?;
    let prepared = owner.prepare_payload(&operation, &mut out)?;
    assert_eq!(prepared.send(), operation.id());
    response(&mut owner, epoch, Response::Disconnected(A), &mut out)?;
    let new_peer = connect(&mut owner, epoch, A, &mut out)?;
    assert_ne!(old_peer, new_peer);
    // The native host removes the wholly unwritten immutable frame before return.
    assert_eq!(
        owner.finish(operation).map_err(|r| r.reason)?.outcome,
        SendOutcome::PeerDisconnected
    );
    Ok(())
}
