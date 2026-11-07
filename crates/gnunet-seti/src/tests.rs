#![expect(
    clippy::panic_in_result_fn,
    reason = "Focused reconciliation and lifecycle models assert original provenance and results"
)]
use super::*;
use gnunet_crypto::Entropy;
use gnunet_wire::official::seti as wire;

struct Random(u32);
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        for byte in output {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}
struct Backing {
    members: [u8; 1],
    active: [u8; 1],
    reported: [u8; 1],
    bloom: [u8; 512],
    context: [u8; 32],
}
fn with_service(
    run: impl FnOnce(&mut Service<'_, '_, '_>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut domain = Instance::new();
    let mut clients = [ClientSlot::new(); 3];
    let mut sets = [SetSlot::new(); 2];
    let mut listeners = [ListenerSlot::new(); 1];
    let mut bodies = [[0; 16]; 8];
    let mut elements = bodies.each_mut().map(|b| ElementSlot::new(b));
    let mut backing = core::array::from_fn::<_, 3, _>(|_| Backing {
        members: [0; 1],
        active: [0; 1],
        reported: [0; 1],
        bloom: [0; 512],
        context: [0; 32],
    });
    let mut operations = backing.each_mut().map(|b| {
        OperationSlot::new(
            &mut b.members,
            &mut b.active,
            &mut b.reported,
            &mut b.bloom,
            &mut b.context,
        )
    });
    let mut service = Service::new(
        &mut domain,
        &mut clients,
        &mut sets,
        &mut listeners,
        &mut elements,
        &mut operations,
        Limits {
            bloom_bytes: 512,
            element_bytes: 16,
            ..Limits::default()
        },
    )?;
    run(&mut service)
}
fn settle<'id>(service: &mut Service<'id, '_, '_>, effect: Effect<'id>) -> Result<(), Error> {
    service.queued(effect)?;
    service.exposed(effect)?;
    service.written(effect)
}
fn credit<'id>(service: &mut Service<'id, '_, '_>, operation: Operation<'id>) -> Result<(), Error> {
    if let Some(delivery) = service.receive_ready(operation)? {
        service.receive_done(delivery)?;
    }
    Ok(())
}
fn peer_step<'a, 'b>(
    from: &mut Service<'a, '_, '_>,
    operation: Operation<'a>,
    to: &mut Service<'b, '_, '_>,
    source: PeerSource<'b>,
) -> Result<bool, Error> {
    let mut bytes = [0; 1024];
    let Some(prepared) = from.prepare_peer(operation, &mut bytes)? else {
        return Ok(false);
    };
    let effect = prepared.effect;
    let frame = prepared.bytes;
    settle(from, effect)?;
    to.receive_peer(source, frame, 2)?;
    credit(to, source.operation())?;
    Ok(true)
}
#[derive(Default)]
struct Results {
    added: u32,
    removed: u32,
    done: bool,
    current_size: u64,
}
fn result_step<'id>(
    service: &mut Service<'id, '_, '_>,
    client: Client<'id>,
    observed: &mut Results,
) -> Result<bool, Error> {
    let mut bytes = [0; 1024];
    let Some(prepared) = service.prepare_client(client, &mut bytes)? else {
        return Ok(false);
    };
    let effect = prepared.effect;
    let Response::Result {
        current_size,
        status,
        element_type,
        data,
        ..
    } = Response::decode(prepared.bytes)?
    else {
        return Err(Error::Conflict);
    };
    observed.current_size = current_size;
    if status == wire::DONE {
        assert!(data.is_empty());
        assert!(!observed.done);
        observed.done = true;
    } else {
        assert_eq!(data.len(), 1);
        assert_eq!(element_type, 0x1234);
        let bit = 1 << u32::from(data[0] - b'a');
        if status == wire::ADD_LOCAL {
            assert_eq!(observed.added & bit, 0);
            observed.added |= bit;
        } else {
            assert_eq!(status, wire::DEL_LOCAL);
            assert_eq!(observed.removed & bit, 0);
            observed.removed |= bit;
        }
    }
    settle(service, effect)?;
    Ok(true)
}
fn element(data: &[u8]) -> Element<'_> {
    Element {
        element_type: 0x1234,
        data,
    }
}

#[test]
fn official_roundtrip_snapshot_full_delta_and_empty_intersection() -> Result<(), Error> {
    // The C RESULT's unpacked u64 is an explicit local ABI choice, never guessed.
    let response = Response::Result {
        current_size: 0x0102_0304_0506_0708,
        request_id: 0x1122_3344,
        status: wire::ADD_LOCAL,
        element_type: 0x1234,
        data: b"x",
    };
    for layout in [wire::ResultLayout::Aligned24, wire::ResultLayout::Packed20] {
        let mut bytes = [0xa5; 25];
        let n = response.encode_with_layout(&mut bytes, layout)?;
        assert_eq!(n, layout.prefix() + 1);
        assert_eq!(Response::decode_with_layout(&bytes[..n], layout)?, response);
        assert_eq!(&bytes[n - 3..n - 1], &[0x12, 0x34]);
        if layout == wire::ResultLayout::Aligned24 {
            assert_eq!(&bytes[4..8], &[0; 4]);
            assert_eq!(&bytes[8..16], &0x0102_0304_0506_0708_u64.to_be_bytes());
        }
    }
    with_service(|a| {
        with_service(|b| {
            let ac = a.attach()?;
            let aset = a.create(ac)?;
            for value in [b"a", b"b", b"c"] {
                assert!(a.add(aset, element(value))?);
            }
            let bc = b.attach()?;
            let bset = b.create(bc)?;
            for value in [b"b", b"c", b"d", b"e"] {
                assert!(b.add(bset, element(value))?);
            }
            let listener_client = b.attach()?;
            let listener = b.listen(listener_client, [9; 64])?;
            let port = b.bind_listener(listener)?;
            let context = [0, 4, 0x12, 0x34];
            let ao = a.evaluate(
                aset,
                11,
                Evaluation {
                    peer: [2; 32],
                    app_id: [9; 64],
                    mode: ResultMode::Intersection,
                    context: Some(&context),
                    deadline: 1000,
                },
            )?;
            // Mutating the live set cannot alter the already captured operation.
            assert!(a.remove(aset, element(b"b"))?);
            assert!(a.add(aset, element(b"x"))?);
            assert_eq!(a.elements(aset)?.count(), 3);
            let asource = a.bind_peer(ao, [2; 32])?;
            let bsource = b.incoming(port, [1; 32], 0)?;
            let bo = bsource.operation();
            assert!(peer_step(a, ao, b, bsource)?);
            assert!(b.receive_ready(bo)?.is_none());
            let mut bytes = [0; 128];
            let suggestion = b
                .prepare_client(listener_client, &mut bytes)?
                .ok_or(Error::NotReady)?;
            let Response::Request {
                accept_id,
                peer,
                context: incoming_context,
            } = Response::decode(suggestion.bytes)?
            else {
                return Err(Error::Conflict);
            };
            assert_eq!(peer, [1; 32]);
            assert_eq!(incoming_context, Some(context.as_slice()));
            assert_eq!(b.suggested(accept_id), Some(bo));
            let effect = suggestion.effect;
            assert_eq!(
                b.accept(bset, bo, 22, ResultMode::Removed, 1000),
                Err(Error::NotReady)
            );
            settle(b, effect)?;
            b.accept(bset, bo, 22, ResultMode::Removed, 1000)?;
            credit(b, bo)?;
            let mut rng = Random(0x3245_6789);
            let mut ar = Results::default();
            let mut br = Results::default();
            for _ in 0..128 {
                a.progress_next(&mut rng)?;
                b.progress_next(&mut rng)?;
                peer_step(a, ao, b, bsource)?;
                peer_step(b, bo, a, asource)?;
                result_step(a, ac, &mut ar)?;
                result_step(b, bc, &mut br)?;
                if b.close_required() == Some(bsource) {
                    let loss = b.peer_lost(bsource, Error::Closed)?;
                    assert!(loss.expected);
                    let loss = a.peer_lost(asource, Error::Closed)?;
                    assert!(loss.expected);
                } else if a.close_required() == Some(asource) {
                    assert!(a.peer_lost(asource, Error::Closed)?.expected);
                    assert!(b.peer_lost(bsource, Error::Closed)?.expected);
                }
                if ar.done && br.done {
                    break;
                }
            }
            assert!(ar.done && br.done);
            assert_eq!(ar.added, (1 << 1) | (1 << 2)); // b and c from the snapshot.
            assert_eq!(ar.removed, 0);
            assert_eq!(br.removed, (1 << 3) | (1 << 4));
            assert_eq!(br.added, 0);
            assert_eq!((ar.current_size, br.current_size), (2, 2));
            a.retire(ao)?;
            b.retire(bo)?;
            assert_eq!(a.operation_info(ao).err(), Some(Error::StaleGeneration));
            // Empty sets use an ordinary all-zero Bloom, avoiding C's zero divide.
            a.release_set(aset)?;
            b.release_set(bset)?;
            let aset = a.create(ac)?;
            let bset = b.create(bc)?;
            let ao = a.evaluate(
                aset,
                33,
                Evaluation {
                    peer: [2; 32],
                    app_id: [9; 64],
                    mode: ResultMode::Intersection,
                    context: None,
                    deadline: 1000,
                },
            )?;
            let asource = a.bind_peer(ao, [2; 32])?;
            let bsource = b.incoming(port, [1; 32], 0)?;
            let bo = bsource.operation();
            peer_step(a, ao, b, bsource)?;
            let suggestion = b
                .prepare_client(listener_client, &mut bytes)?
                .ok_or(Error::NotReady)?;
            settle(b, suggestion.effect)?;
            b.accept(bset, bo, 44, ResultMode::Intersection, 1000)?;
            credit(b, bo)?;
            let mut ar = Results::default();
            let mut br = Results::default();
            for _ in 0..16 {
                a.progress_next(&mut rng)?;
                b.progress_next(&mut rng)?;
                peer_step(a, ao, b, bsource)?;
                peer_step(b, bo, a, asource)?;
                result_step(a, ac, &mut ar)?;
                result_step(b, bc, &mut br)?;
                if a.close_required() == Some(asource) || b.close_required() == Some(bsource) {
                    assert!(a.peer_lost(asource, Error::Closed)?.expected);
                    assert!(b.peer_lost(bsource, Error::Closed)?.expected);
                }
                if ar.done && br.done {
                    break;
                }
            }
            assert!(ar.done && br.done);
            assert_eq!((ar.added, br.added), (0, 0));
            a.retire(ao)?;
            b.retire(bo)
        })
    })
}

#[test]
fn original_effect_cancel_loss_port_rebind_and_bloom_fragment_validation() -> Result<(), Error> {
    with_service(|service| {
        let client = service.attach()?;
        let set = service.create(client)?;
        service.add(set, element(b"a"))?;
        let spec = Evaluation {
            peer: [2; 32],
            app_id: [9; 64],
            mode: ResultMode::Removed,
            context: None,
            deadline: 1000,
        };
        let first = service.evaluate(set, 1, spec)?;
        assert_eq!(
            service.bind_peer(first, [3; 32]),
            Err(Error::Authentication)
        );
        let source = service.bind_peer(first, [2; 32])?;
        let mut bytes = [0; 1024];
        let prepared = service
            .prepare_peer(first, &mut bytes)?
            .ok_or(Error::NotReady)?;
        let effect = prepared.effect;
        assert_eq!(service.written(effect), Err(Error::InvalidInput));
        service.cancel(first)?;
        assert_eq!(service.can_queue(effect), Err(Error::Closed));
        service.reject_prepared(effect)?;
        let loss = service.peer_lost(source, Error::Closed)?;
        assert!(loss.expected && !loss.exposed && loss.pending.is_none());
        service.retire(first)?;
        assert_eq!(service.queued(effect), Err(Error::StaleGeneration));
        let next = service.evaluate(set, 2, spec)?;
        let source = service.bind_peer(next, [2; 32])?;
        let prepared = service
            .prepare_peer(next, &mut bytes)?
            .ok_or(Error::NotReady)?;
        let effect = prepared.effect;
        service.queued(effect)?;
        service.exposed(effect)?;
        service.cancel(next)?;
        assert_eq!(service.reject_prepared(effect), Err(Error::WouldBlock));
        assert_eq!(service.unsent(effect), Err(Error::WouldBlock));
        let loss = service.peer_lost(source, Error::Io)?;
        assert_eq!(loss.pending, Some(effect));
        assert!(loss.queued && loss.exposed && loss.expected);
        assert_eq!(loss.reason, Error::Io);
        service.retire(next)?;
        assert_eq!(service.written(effect), Err(Error::StaleGeneration));
        let third = service.evaluate(set, 3, spec)?;
        let source = service.bind_peer(third, [2; 32])?;
        let prepared = service
            .prepare_peer(third, &mut bytes)?
            .ok_or(Error::NotReady)?;
        settle(service, prepared.effect)?;
        // Real split receive state retains the bytes and validates every header.
        let mut part = [0; 128];
        let len = PeerMessage::Bloom {
            element_count: 1,
            element_xor: [4; 64],
            mutator: 1,
            total_length: 8,
            bits_per_element: 1,
            data: &[0; 4],
        }
        .encode(&mut part)?;
        let delivery = service.receive_peer(source, &part[..len], 1)?;
        assert_eq!(service.receive_ready(third)?, Some(delivery));
        assert_eq!(
            service.receive_peer(source, &part[..len], 1),
            Err(Error::WouldBlock)
        );
        service.receive_done(delivery)?;
        let len = PeerMessage::Bloom {
            element_count: 1,
            element_xor: [5; 64], // Header substitution in the same filter.
            mutator: 1,
            total_length: 8,
            bits_per_element: 1,
            data: &[0; 4],
        }
        .encode(&mut part)?;
        assert_eq!(
            service.receive_peer(source, &part[..len], 1),
            Err(Error::Conflict)
        );
        assert_eq!(service.operation_info(third)?.phase, Phase::Failed);
        assert!(service.receive_ready(third)?.is_none());
        let output = service
            .prepare_client(client, &mut bytes)?
            .ok_or(Error::NotReady)?;
        assert!(matches!(
            Response::decode(output.bytes)?,
            Response::Result {
                request_id: 3,
                status: wire::FAILURE,
                ..
            }
        ));
        settle(service, output.effect)?;
        service.peer_lost(source, Error::Closed)?;
        service.retire(third)?;
        let listener_client = service.attach()?;
        let listener = service.listen(listener_client, [9; 64])?;
        let old_port = service.bind_listener(listener)?;
        service.unbind_listener(old_port)?;
        let port = service.bind_listener(listener)?;
        assert_ne!(old_port, port);
        assert_eq!(
            service.incoming(old_port, [2; 32], 0),
            Err(Error::StaleGeneration)
        );
        let source = service.incoming(port, [2; 32], 0)?;
        assert_eq!(service.expire(60_000_000), 1);
        assert_eq!(service.close_required(), Some(source));
        service.peer_lost(source, Error::Deadline)?;
        service.retire(source.operation())?;
        let Dispatch::Operation(unknown) = service.dispatch(
            client,
            Request::Accept {
                accept_id: 0xffff,
                request_id: 4,
                return_intersection: 1,
            },
            1000,
        )?
        else {
            return Err(Error::Conflict);
        };
        let prepared = service
            .prepare_client(client, &mut bytes)?
            .ok_or(Error::NotReady)?;
        assert!(matches!(
            Response::decode(prepared.bytes)?,
            Response::Result {
                request_id: 4,
                status: wire::FAILURE,
                ..
            }
        ));
        let effect = prepared.effect;
        service.queued(effect)?;
        service.exposed(effect)?;
        let loss = service.detach(client, Error::Io)?;
        assert_eq!(loss.pending, Some(effect));
        assert!(loss.queued && loss.exposed);
        service.retire(unknown)?;
        assert_eq!(service.written(effect), Err(Error::StaleGeneration));
        let replacement = service.attach()?;
        assert_ne!(replacement, client);
        assert_eq!(service.set(client), Err(Error::StaleGeneration));
        assert_eq!(service.close_listener(listener)?, Some(port));
        Ok(())
    })
}

// These are pure transition cases for the normal fixed-C message roles below.
// They do not run a C daemon, CADET, a native socket, a key or an entropy source.
fn settle_empty_bloom<'id>(
    service: &mut Service<'id, '_, '_>,
    operation: Operation<'id>,
) -> Result<(), Error> {
    let mut bytes = [0; 1024];
    let prepared = service
        .prepare_peer(operation, &mut bytes)?
        .ok_or(Error::NotReady)?;
    let PeerMessage::Bloom {
        element_count,
        element_xor,
        total_length,
        bits_per_element,
        data,
        ..
    } = PeerMessage::decode(prepared.bytes)?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(element_count, 0);
    assert_eq!(element_xor, [0; 64]);
    assert_eq!(total_length, 8);
    assert_eq!(bits_per_element, 1);
    assert_eq!(data, &[0; 8]);
    let effect = prepared.effect;
    settle(service, effect)
}

#[test]
fn empty_c_initiator_gets_standard_bloom_from_nonempty_acceptor() -> Result<(), Error> {
    for mode in [ResultMode::Intersection, ResultMode::Removed] {
        with_service(|service| {
            let client = service.attach()?;
            let set = service.create(client)?;
            service.add(set, element(b"a"))?;
            service.add(set, element(b"b"))?;
            let listener_client = service.attach()?;
            let listener = service.listen(listener_client, [9; 64])?;
            let port = service.bind_listener(listener)?;
            let source = service.incoming(port, [1; 32], 0)?;
            let operation = source.operation();
            // Fixed C's empty set sends count0 and enters PHASE_COUNT_SENT.
            let mut bytes = [0; 1024];
            let n = PeerMessage::OperationRequest {
                element_count: 0,
                app_id: [0; 64],
                context: None,
            }
            .encode(&mut bytes)?;
            service.receive_peer(source, &bytes[..n], 1)?;
            let prepared = service
                .prepare_client(listener_client, &mut bytes)?
                .ok_or(Error::NotReady)?;
            assert!(matches!(
                Response::decode(prepared.bytes)?,
                Response::Request { .. }
            ));
            let effect = prepared.effect;
            settle(service, effect)?;
            service.accept(set, operation, 41, mode, 1000)?;
            credit(service, operation)?;
            // Live mutations do not replace the original a/b snapshot.
            assert!(service.remove(set, element(b"a"))?);
            assert!(service.add(set, element(b"c"))?);
            assert_eq!(service.elements(set)?.count(), 2);
            assert!(service.progress(operation, &mut Random(0x1234_5678))?);
            settle_empty_bloom(service, operation)?;
            let mut observed = Results::default();
            for _ in 0..4 {
                if !result_step(service, client, &mut observed)? {
                    break;
                }
            }
            assert!(!observed.done);
            assert_eq!(observed.added, 0);
            assert_eq!(
                observed.removed,
                if mode == ResultMode::Removed { 3 } else { 0 }
            );
            // The normal C BF receiver now returns agreement, not ELEMENT_INFO.
            let n = PeerMessage::Done {
                element_count: 0,
                element_xor: [0; 64],
            }
            .encode(&mut bytes)?;
            service.receive_peer(source, &bytes[..n], 2)?;
            credit(service, operation)?;
            assert!(service.peer_lost(source, Error::Closed)?.expected);
            for _ in 0..4 {
                if !result_step(service, client, &mut observed)? {
                    break;
                }
            }
            assert!(observed.done);
            assert_eq!(observed.current_size, 0);
            assert_eq!(observed.added, 0);
            assert_eq!(
                observed.removed,
                if mode == ResultMode::Removed { 3 } else { 0 }
            );
            assert_eq!(service.elements(set)?.count(), 2);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn empty_rust_initiator_accepts_nonempty_c_count_then_agreement() -> Result<(), Error> {
    for mode in [ResultMode::Intersection, ResultMode::Removed] {
        with_service(|service| {
            let client = service.attach()?;
            let set = service.create(client)?;
            let operation = service.evaluate(
                set,
                42,
                Evaluation {
                    peer: [2; 32],
                    app_id: [9; 64],
                    mode,
                    context: None,
                    deadline: 1000,
                },
            )?;
            // A later local insertion cannot change the original empty query.
            service.add(set, element(b"a"))?;
            let source = service.bind_peer(operation, [2; 32])?;
            let mut bytes = [0; 1024];
            let prepared = service
                .prepare_peer(operation, &mut bytes)?
                .ok_or(Error::NotReady)?;
            assert!(matches!(
                PeerMessage::decode(prepared.bytes)?,
                PeerMessage::OperationRequest {
                    element_count: 0,
                    ..
                }
            ));
            let effect = prepared.effect;
            settle(service, effect)?;
            // Fixed C's larger acceptor replies with ELEMENT_INFO first.
            let n = PeerMessage::ElementInfo { element_count: 2 }.encode(&mut bytes)?;
            service.receive_peer(source, &bytes[..n], 1)?;
            credit(service, operation)?;
            assert!(service.progress(operation, &mut Random(0x8765_4321))?);
            settle_empty_bloom(service, operation)?;
            let mut observed = Results::default();
            assert!(!result_step(service, client, &mut observed)?);
            assert!(!observed.done);
            let n = PeerMessage::Done {
                element_count: 0,
                element_xor: [0; 64],
            }
            .encode(&mut bytes)?;
            service.receive_peer(source, &bytes[..n], 2)?;
            credit(service, operation)?;
            assert!(service.peer_lost(source, Error::Closed)?.expected);
            for _ in 0..2 {
                if !result_step(service, client, &mut observed)? {
                    break;
                }
            }
            assert!(observed.done);
            assert_eq!(observed.current_size, 0);
            assert_eq!(observed.added, 0);
            assert_eq!(observed.removed, 0);
            assert_eq!(service.elements(set)?.count(), 1);
            Ok(())
        })?;
    }
    Ok(())
}
