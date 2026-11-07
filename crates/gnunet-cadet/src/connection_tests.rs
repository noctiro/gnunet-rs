#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible bounded route models assert actual original wire effects, CORE-source direction and signature provenance"
)]
use super::*;
fn create<'path>(path: &'path [[u8; 32]], cid: [u8; 32]) -> PeerMessage<'path> {
    PeerMessage::ConnectionCreate {
        options_bytes: [2, 0, 0, 0],
        has_monotime_bytes: [0; 4],
        monotime: 0,
        monotime_signature: [0; 64],
        connection: cid,
        path: PathPeers::new(path),
    }
}
fn signed_create<'path>(
    path: &'path [[u8; 32]],
    cid: [u8; 32],
    monotime: u64,
    key: &gnunet_crypto::EddsaPrivateKey,
) -> Result<PeerMessage<'path>, Error> {
    let mut purpose = [0; 16];
    ConnectionInitiatorPurpose { monotime }.encode(&mut purpose)?;
    let signature = key.sign(CONNECTION_INITIATOR_PURPOSE, &purpose)?;
    Ok(PeerMessage::ConnectionCreate {
        options_bytes: [2, 0, 0, 0],
        has_monotime_bytes: [1, 0, 0, 0],
        monotime,
        monotime_signature: *signature.as_bytes(),
        connection: cid,
        path: PathPeers::new(path),
    })
}
fn emit<'id, const P: usize>(
    book: &mut Book<'id, '_, '_, P>,
    now: u64,
    output: &mut [u8],
) -> Result<(Neighbor<'id>, usize), Error> {
    let queued = book.next_frame().ok_or(Error::NotReady)?;
    let length = queued.bytes.len();
    // Model the containing native owner's final immutable allocation/copy before
    // any start consumes an actual CORE permission or original attempt identity.
    output
        .get_mut(..length)
        .ok_or(Error::Capacity)?
        .copy_from_slice(queued.bytes);
    let frame = queued.frame;
    let target = queued.neighbor;
    let attempt = book.start(frame)?;
    book.exposed(attempt)?;
    assert_eq!(
        book.settle(attempt, true, MonoInstant(now))?.outcome,
        Outcome::Written
    );
    book.release_frame(frame)?;
    // Explicit modeled original CORE availability callback, never settle itself.
    book.neighbor_ready(target, true)?;
    Ok((target, length))
}

#[test]
fn whole_path_forwarding_requires_actual_adjacent_sources_and_checks_broken_direction()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut neighbors = [NeighborSlot::new(); 4];
    let mut routes = [RouteSlot::<4>::new(); 4];
    let mut origins = [OriginSlot::new(); 2];
    let mut buffers = [[0; 512]; 8];
    let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut book = Book::new(
        &mut instance,
        [2; 32],
        &mut neighbors,
        &mut routes,
        &mut origins,
        &mut frames,
        MonoInstant(0),
        Limits {
            keepalive_micros: 10,
            ..Limits::default()
        },
    )?;
    let prev = book.neighbor_up([1; 32])?;
    let next = book.neighbor_up([3; 32])?;
    let stranger = book.neighbor_up([4; 32])?;
    for peer in [prev, next, stranger] {
        book.neighbor_ready(peer, true)?;
    }
    let looped = [[1; 32], [2; 32], [1; 32], [3; 32]];
    assert!(matches!(
        book.receive(prev, create(&looped, [9; 32]), MonoInstant(0)),
        Err(Error::Malformed)
    ));
    let missing = [[1; 32], [3; 32]];
    assert!(matches!(
        book.receive(prev, create(&missing, [9; 32]), MonoInstant(0)),
        Err(Error::Authentication)
    ));
    let path = [[1; 32], [2; 32], [3; 32]];
    assert!(matches!(
        book.receive(stranger, create(&path, [9; 32]), MonoInstant(0)),
        Err(Error::Authentication)
    ));
    assert!(book.next_frame().is_none());
    let missing_next = [[1; 32], [2; 32], [6; 32]];
    assert!(matches!(
        book.receive(prev, create(&missing_next, [8; 32]), MonoInstant(0))?,
        Event::Rejected { .. }
    ));
    let mut wire = [0; 512];
    let (target, length) = emit(&mut book, 0, &mut wire)?;
    assert_eq!(target, prev);
    assert_eq!(
        PeerMessage::decode(&wire[..length])?,
        PeerMessage::ConnectionBroken {
            reserved: 0,
            connection: [8; 32],
            peer1: [2; 32],
            peer2: [6; 32]
        }
    );
    let message = create(&path, [9; 32]);
    let Event::Created {
        route,
        reset: Reset::Absent,
    } = book.receive(prev, message, MonoInstant(0))?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(book.route_info(route)?.role, Role::Relay);
    let (target, length) = emit(&mut book, 0, &mut wire)?;
    assert_eq!(target, next);
    assert_eq!(PeerMessage::decode(&wire[..length])?, message);
    let ack = PeerMessage::ConnectionCreateAck {
        reserved: 0,
        connection: [9; 32],
    };
    assert!(matches!(
        book.receive(prev, ack, MonoInstant(0)),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        book.receive(next, ack, MonoInstant(0))?,
        Event::Forwarded { .. }
    ));
    let (target, length) = emit(&mut book, 0, &mut wire)?;
    assert_eq!(target, prev);
    assert_eq!(PeerMessage::decode(&wire[..length])?, ack);
    assert_eq!(book.route_info(route)?.phase, Phase::Ready);
    let broken = PeerMessage::ConnectionBroken {
        reserved: 0,
        connection: [9; 32],
        peer1: [2; 32],
        peer2: [3; 32],
    };
    assert!(matches!(
        book.receive(stranger, broken, MonoInstant(0)),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        book.receive(
            next,
            PeerMessage::ConnectionBroken {
                reserved: 0,
                connection: [9; 32],
                peer1: [1; 32],
                peer2: [2; 32]
            },
            MonoInstant(0)
        ),
        Err(Error::Authentication)
    ));
    assert_eq!(book.route_info(route)?.phase, Phase::Ready);
    assert!(matches!(
        book.receive(next, broken, MonoInstant(0))?,
        Event::Forwarded { .. }
    ));
    let (target, length) = emit(&mut book, 0, &mut wire)?;
    assert_eq!(target, prev);
    assert_eq!(PeerMessage::decode(&wire[..length])?, broken);
    assert_eq!(book.route_info(route)?.phase, Phase::Retired);
    book.release_route(route)?;

    // A separate real relay path expires after three actual keepalive periods.
    let Event::Created { route: timed, .. } =
        book.receive(prev, create(&path, [10; 32]), MonoInstant(0))?
    else {
        return Err(Error::Malformed);
    };
    let _create = emit(&mut book, 0, &mut wire)?;
    assert_eq!(book.tick(MonoInstant(29))?, 0);
    assert_eq!(book.tick(MonoInstant(30))?, 1);
    assert_eq!(book.retired_route(), Some(timed));
    for _ in 0..2 {
        let (_, length) = emit(&mut book, 30, &mut wire)?;
        assert_eq!(
            PeerMessage::decode(&wire[..length])?,
            PeerMessage::ConnectionBroken {
                reserved: 0,
                connection: [10; 32],
                peer1: [0; 32],
                peer2: [0; 32]
            }
        );
    }
    book.release_route(timed)?;
    Ok(())
}

#[test]
fn monotime_signature_verification_precedes_origin_observation_and_replay_cannot_reset()
-> Result<(), Error> {
    let key = gnunet_crypto::EddsaPrivateKey::from_seed([11; 32]);
    let origin = *key.public_key().as_bytes();
    let mut instance = Instance::new();
    let mut neighbors = [NeighborSlot::new(); 3];
    let mut routes = [RouteSlot::<4>::new(); 4];
    let mut origins = [OriginSlot::restored(origin, 10), OriginSlot::new()];
    let mut buffers = [[0; 512]; 8];
    let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut book = Book::new(
        &mut instance,
        [4; 32],
        &mut neighbors,
        &mut routes,
        &mut origins,
        &mut frames,
        MonoInstant(0),
        Limits::default(),
    )?;
    let previous = book.neighbor_up([3; 32])?;
    let other_previous = book.neighbor_up([5; 32])?;
    book.neighbor_ready(previous, true)?;
    book.neighbor_ready(other_previous, true)?;
    let path = [origin, [3; 32], [4; 32]];
    let forged = PeerMessage::ConnectionCreate {
        options_bytes: [2, 0, 0, 0],
        has_monotime_bytes: [1, 0, 0, 0],
        monotime: u64::MAX,
        monotime_signature: [0; 64],
        connection: [9; 32],
        path: PathPeers::new(&path),
    };
    assert!(matches!(
        book.receive(previous, forged, MonoInstant(0)),
        Err(Error::Authentication)
    ));
    assert_eq!(book.observed_monotime(origin), Some(10));
    assert!(book.next_frame().is_none());
    let valid = signed_create(&path, [9; 32], 11, &key)?;
    let Event::Created { route, reset } = book.receive(previous, valid, MonoInstant(0))? else {
        return Err(Error::Malformed);
    };
    let Reset::Fresh(proof) = reset else {
        return Err(Error::Authentication);
    };
    assert_eq!(proof.origin(), origin);
    assert_eq!(proof.monotime(), 11);
    assert_eq!(proof.authority(), book.reset_authority());
    assert_eq!(proof.authority().local(), [4; 32]);
    assert_eq!(book.observed_monotime(origin), Some(11));
    assert_eq!(book.route_info(route)?.phase, Phase::AckPending);
    let mut wire = [0; 512];
    let (target, length) = emit(&mut book, 0, &mut wire)?;
    assert_eq!(target, previous);
    assert_eq!(
        PeerMessage::decode(&wire[..length])?,
        PeerMessage::ConnectionCreateAck {
            reserved: 0,
            connection: [9; 32]
        }
    );
    assert_eq!(book.route_info(route)?.phase, Phase::Ready);
    let duplicate = signed_create(&path, [9; 32], 10, &key)?;
    assert!(matches!(
        book.receive(previous, duplicate, MonoInstant(0))?,
        Event::Duplicate {
            reset: Reset::Replayed,
            ..
        }
    ));
    assert_eq!(book.observed_monotime(origin), Some(11));
    let _ack = emit(&mut book, 0, &mut wire)?;
    let other_path = [origin, [5; 32], [4; 32]];
    let old = signed_create(&other_path, [10; 32], 9, &key)?;
    // A replayed timestamp is denied reset authority; normal route establishment
    // is separate, just as unsigned CREATE is legal in the current protocol.
    assert!(matches!(
        book.receive(other_previous, old, MonoInstant(0))?,
        Event::Created {
            reset: Reset::Replayed,
            ..
        }
    ));
    assert_eq!(book.observed_monotime(origin), Some(11));
    Ok(())
}

#[test]
fn async_pils_signature_completion_is_bound_to_original_identity_route_and_purpose()
-> Result<(), Error> {
    let key = gnunet_crypto::EddsaPrivateKey::from_seed([7; 32]);
    let local = *key.public_key().as_bytes();
    let mut instance = Instance::new();
    let mut neighbors = [NeighborSlot::new(); 2];
    let mut routes = [RouteSlot::<4>::new(); 2];
    let mut origins = [OriginSlot::new(); 2];
    let mut buffers = [[0; 512]; 4];
    let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut book = Book::new(
        &mut instance,
        local,
        &mut neighbors,
        &mut routes,
        &mut origins,
        &mut frames,
        MonoInstant(0),
        Limits::default(),
    )?;
    let next = book.neighbor_up([3; 32])?;
    book.neighbor_ready(next, true)?;
    let path = [local, [3; 32], [4; 32]];
    let opened = book.open(
        PathPeers::new(&path),
        [9; 32],
        Authentication::Monotime(42),
        MonoInstant(0),
    )?;
    let request = opened.sign.ok_or(Error::NotReady)?;
    assert_eq!(book.route_info(opened.route)?.phase, Phase::Signing);
    assert!(book.next_frame().is_none());
    let mut purpose = [0; 16];
    request.purpose(&mut purpose)?;
    assert_eq!(ConnectionInitiatorPurpose::decode(&purpose)?.monotime, 42);
    let signature = *key.sign(CONNECTION_INITIATOR_PURPOSE, &purpose)?.as_bytes();
    assert_eq!(
        book.signed(request, [9; 32], signature, MonoInstant(0)),
        Err(Error::Authentication)
    );
    let frame = book.signed(request, local, signature, MonoInstant(0))?;
    assert_eq!(
        book.signed(request, local, signature, MonoInstant(0)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(book.next_frame().ok_or(Error::NotReady)?.frame, frame);
    let mut wire = [0; 512];
    let (_, length) = emit(&mut book, 0, &mut wire)?;
    assert_eq!(
        PeerMessage::decode(&wire[..length])?,
        signed_create(&path, [9; 32], 42, &key)?
    );
    assert!(
        matches!(book.receive(next, PeerMessage::ConnectionCreateAck { reserved: 0, connection: [9; 32] }, MonoInstant(0))?, Event::Ready(route) if route == opened.route)
    );
    Ok(())
}

#[test]
fn actual_neighbor_loss_retires_original_attempt_and_late_sources_cannot_ready_reused_route_slot()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut neighbors = [NeighborSlot::new(); 2];
    let mut routes = [RouteSlot::<4>::new(); 2];
    let mut origins = [OriginSlot::new(); 2];
    let mut buffers = [[0; 512]; 4];
    let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut book = Book::new(
        &mut instance,
        [1; 32],
        &mut neighbors,
        &mut routes,
        &mut origins,
        &mut frames,
        MonoInstant(0),
        Limits::default(),
    )?;
    let old_neighbor = book.neighbor_up([2; 32])?;
    book.neighbor_ready(old_neighbor, true)?;
    let path = [[1; 32], [2; 32], [3; 32]];
    let old = book
        .open(
            PathPeers::new(&path),
            [9; 32],
            Authentication::Unsigned,
            MonoInstant(0),
        )?
        .route;
    let frame = book.next_frame().ok_or(Error::NotReady)?.frame;
    let pending = book.start(frame)?;
    book.exposed(pending)?;
    // Original native CORE owner is physically stopped before this callback.
    assert_eq!(book.neighbor_lost(old_neighbor, MonoInstant(0))?, 1);
    let completion = book.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.attempt, Some(pending));
    assert_eq!(completion.outcome, Outcome::Unknown);
    assert!(completion.exposed);
    assert_eq!(book.release_route(old), Err(Error::WouldBlock));
    book.release_frame(completion.frame)?;
    book.release_route(old)?;
    let current = book.neighbor_up([2; 32])?;
    book.neighbor_ready(current, true)?;
    assert_ne!(current, old_neighbor);
    let new = book
        .open(
            PathPeers::new(&path),
            [10; 32],
            Authentication::Unsigned,
            MonoInstant(0),
        )?
        .route;
    assert_ne!(new, old);
    assert_eq!(book.route_info(old), Err(Error::StaleGeneration));
    assert!(matches!(
        book.receive(
            old_neighbor,
            PeerMessage::ConnectionCreateAck {
                reserved: 0,
                connection: [10; 32]
            },
            MonoInstant(0)
        ),
        Err(Error::StaleGeneration)
    ));
    assert!(matches!(
        book.receive(
            current,
            PeerMessage::ConnectionCreateAck {
                reserved: 0,
                connection: [9; 32]
            },
            MonoInstant(0)
        )?,
        Event::Rejected { .. }
    ));
    assert!(matches!(
        book.receive(
            current,
            PeerMessage::ConnectionCreateAck {
                reserved: 0,
                connection: [10; 32]
            },
            MonoInstant(0)
        )?,
        Event::Ignored
    ));
    assert_eq!(book.route_info(new)?.phase, Phase::Opening);
    assert_eq!(
        book.settle(pending, false, MonoInstant(0)),
        Err(Error::StaleGeneration)
    );
    let mut wire = [0; 512];
    let (_, length) = emit(&mut book, 0, &mut wire)?;
    assert!(matches!(
        PeerMessage::decode(&wire[..length])?,
        PeerMessage::ConnectionCreate { connection, .. } if connection == [10; 32]
    ));
    let _old_ack_broken = emit(&mut book, 0, &mut wire)?;
    assert!(
        matches!(book.receive(current, PeerMessage::ConnectionCreateAck { reserved: 0, connection: [10; 32] }, MonoInstant(0))?, Event::Ready(route) if route == new)
    );
    assert_eq!(book.select([3; 32]), Some(new));
    Ok(())
}

#[test]
fn multipath_selection_requires_current_core_eligibility_and_preserves_other_route_on_loss()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut neighbors = [NeighborSlot::new(); 3];
    let mut routes = [RouteSlot::<4>::new(); 4];
    let mut origins = [OriginSlot::new(); 2];
    let mut buffers = [[0; 512]; 8];
    let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut book = Book::new(
        &mut instance,
        [1; 32],
        &mut neighbors,
        &mut routes,
        &mut origins,
        &mut frames,
        MonoInstant(0),
        Limits {
            keepalive_micros: 10,
            ..Limits::default()
        },
    )?;
    let first = book.neighbor_up([2; 32])?;
    let second = book.neighbor_up([3; 32])?;
    book.neighbor_ready(first, true)?;
    book.neighbor_ready(second, true)?;
    let path1 = [[1; 32], [2; 32], [4; 32]];
    let path2 = [[1; 32], [3; 32], [4; 32]];
    let route1 = book
        .open(
            PathPeers::new(&path1),
            [11; 32],
            Authentication::Unsigned,
            MonoInstant(0),
        )?
        .route;
    let route2 = book
        .open(
            PathPeers::new(&path2),
            [12; 32],
            Authentication::Unsigned,
            MonoInstant(0),
        )?
        .route;
    assert!(book.select([4; 32]).is_none());
    let mut wire = [0; 512];
    let _one = emit(&mut book, 0, &mut wire)?;
    let _two = emit(&mut book, 0, &mut wire)?;
    let _ready1 = book.receive(
        first,
        PeerMessage::ConnectionCreateAck {
            reserved: 0,
            connection: [11; 32],
        },
        MonoInstant(0),
    )?;
    let _ready2 = book.receive(
        second,
        PeerMessage::ConnectionCreateAck {
            reserved: 0,
            connection: [12; 32],
        },
        MonoInstant(0),
    )?;
    let incoming = PeerMessage::KeyExchange {
        flags: 1,
        connection: [12; 32],
        ephemeral_key: [7; 32],
        ratchet_key: [8; 32],
    };
    assert!(matches!(
        book.receive(first, incoming, MonoInstant(0)),
        Err(Error::Authentication)
    ));
    let Event::Endpoint(receipt) = book.receive(second, incoming, MonoInstant(0))? else {
        return Err(Error::Malformed);
    };
    assert_eq!(receipt.authority(), book.reset_authority());
    assert_eq!(receipt.route(), route2);
    assert_eq!(receipt.source(), second);
    assert_eq!(receipt.expected_peer(), [4; 32]);
    assert_eq!(receipt.message(), incoming);
    assert!(!receipt.implicit_ready());
    book.latency_observed(route1, 100)?;
    book.latency_observed(route2, 50)?;
    assert_eq!(book.select([4; 32]), Some(route2));
    book.neighbor_ready(second, false)?;
    assert_eq!(book.select([4; 32]), Some(route1));
    book.neighbor_ready(second, true)?;
    let packet = PeerMessage::KeyExchange {
        flags: 1,
        connection: [12; 32],
        ephemeral_key: [5; 32],
        ratchet_key: [6; 32],
    };
    let _retained = book.queue_payload(route2, packet, MonoInstant(0))?;
    assert_eq!(book.select([4; 32]), Some(route1));
    let (target, length) = emit(&mut book, 1, &mut wire)?;
    assert_eq!(target, second);
    assert_eq!(PeerMessage::decode(&wire[..length])?, packet);
    assert_eq!(book.neighbor_lost(second, MonoInstant(2))?, 1);
    assert_eq!(book.route_info(route1)?.phase, Phase::Ready);
    assert_eq!(book.route_info(route2)?.phase, Phase::Retired);
    assert_eq!(book.select([4; 32]), Some(route1));
    assert_eq!(book.keepalive_due(MonoInstant(10)), Some(route1));
    Ok(())
}
