#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible application service models assert exact official bytes, actual credit effects and original source ownership"
)]
use super::*;
use gnunet_types::MonoInstant;
use gnunet_wire::official::cadet_peer::ChannelMessage;
const PORT: [u8; 64] = [3; 64];
const BATCH: [u8; 8] = [0, 4, 0x12, 0x34, 0, 4, 0x12, 0x35];
fn emit<'id>(
    service: &mut Service<'id, '_, '_>,
    client: Client<'id>,
    output: &mut [u8],
) -> Result<(Output<'id>, usize), Error> {
    let needed = service.next_output_len(client)?.ok_or(Error::NotReady)?;
    assert!(output.len() >= needed);
    let prepared = service
        .prepare_output(client, output)?
        .ok_or(Error::NotReady)?;
    let token = prepared.output();
    let length = prepared.bytes().len();
    service.exposed(token)?;
    service.written(token)?;
    Ok((token, length))
}
fn peer_emit<'id>(
    owner: &mut peer::ChannelOwner<'id, '_, '_>,
    output: &mut [u8],
) -> Result<(), Error> {
    let prepared = owner
        .prepare_next(MonoInstant(0), output)?
        .ok_or(Error::NotReady)?;
    let attempt = prepared.attempt();
    owner.exposed(attempt)?;
    owner.settle(
        attempt,
        peer::Emission::Sent {
            connection: [7; 32],
        },
        MonoInstant(0),
    )?;
    Ok(())
}

#[test]
fn loopback_complete_batches_actual_credit_and_application_receive_done_are_distinct()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 2];
    let mut ports = [PortSlot::new(); 2];
    let mut channels = [ChannelSlot::new(); 2];
    let mut buffers = [[0; 16]; 10];
    let mut messages = buffers.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
            ..Limits::default()
        },
    )?;
    let creator = service.attach()?;
    let listener = service.attach()?;
    let Event::PortOpened(port) = service.receive(listener, Request::PortOpen { port: PORT })?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(
        service.receive(creator, Request::PortClose { port: PORT }),
        Err(Error::NotFound)
    );
    let Event::ChannelCreated(outgoing) = service.receive(
        creator,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [1; 32],
            port: PORT,
            options: u32::MAX,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(service.channel_info(outgoing)?.phase, Phase::Opening);
    let incoming = service.progress()?.ok_or(Error::NotReady)?;
    assert_eq!(incoming.wire_id(), 0);
    assert_eq!(service.channel_info(outgoing)?.allowance, 0);
    let mut wire = [0; 256];
    let (_, length) = emit(&mut service, listener, &mut wire)?;
    assert_eq!(
        Response::decode(&wire[..length])?,
        Response::ChannelCreate {
            channel: 0,
            peer: [1; 32],
            port: PORT,
            options: 0
        }
    );
    for _ in 0..4 {
        let (_, length) = emit(&mut service, creator, &mut wire)?;
        assert_eq!(
            Response::decode(&wire[..length])?,
            Response::Ack {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        );
    }
    for _ in 0..4 {
        let (_, length) = emit(&mut service, listener, &mut wire)?;
        assert_eq!(
            Response::decode(&wire[..length])?,
            Response::Ack { channel: 0 }
        );
    }
    assert_eq!(service.channel_info(outgoing)?.allowance, 4);
    service.receive(listener, Request::PortClose { port: PORT })?;
    assert_eq!(service.port_hash(port), Err(Error::StaleGeneration));
    assert_eq!(service.channel_info(incoming)?.phase, Phase::Ready);
    assert!(matches!(
        service.receive(
            creator,
            Request::Data {
                channel: CLIENT_CHANNEL_BOUNDARY,
                priority: 0xa1b2_c3d4,
                messages: &BATCH
            }
        )?,
        Event::DataQueued(_)
    ));
    assert_eq!(service.channel_info(outgoing)?.allowance, 3);
    assert!(service.next_output_len(creator)?.is_none());
    let prepared = service
        .prepare_output(listener, &mut wire)?
        .ok_or(Error::NotReady)?;
    assert_eq!(
        Response::decode(prepared.bytes())?,
        Response::Data {
            channel: 0,
            priority: 0xa1b2_c3d4,
            messages: &BATCH
        }
    );
    let data = prepared.output();
    assert_eq!(
        service.receive(listener, Request::Ack { channel: 0 })?,
        Event::Ignored
    );
    assert!(service.next_output_len(creator)?.is_none());
    service.exposed(data)?;
    service.written(data)?;
    assert!(service.channel_info(incoming)?.receive_pending);
    let prepared = service
        .prepare_output(creator, &mut wire)?
        .ok_or(Error::NotReady)?;
    let credit = prepared.output();
    assert_eq!(
        Response::decode(prepared.bytes())?,
        Response::Ack {
            channel: CLIENT_CHANNEL_BOUNDARY
        }
    );
    assert_eq!(service.channel_info(outgoing)?.allowance, 3);
    service.exposed(credit)?;
    service.written(credit)?;
    assert_eq!(service.channel_info(outgoing)?.allowance, 4);
    assert!(
        matches!(service.receive(listener, Request::Ack { channel: 0 })?, Event::ReceiveDone(channel) if channel == incoming)
    );
    assert!(!service.channel_info(incoming)?.receive_pending);
    assert_eq!(
        service.receive(listener, Request::Ack { channel: 0 })?,
        Event::Ignored
    );
    // An already frozen old credit must settle before its high-half raw local
    // number can name a new endpoint on this very same still-live MQ.
    let _again = service.receive(
        creator,
        Request::Data {
            channel: CLIENT_CHANNEL_BOUNDARY,
            priority: 0,
            messages: &BATCH,
        },
    )?;
    let _data = emit(&mut service, listener, &mut wire)?;
    let old_credit = service
        .prepare_output(creator, &mut wire)?
        .ok_or(Error::NotReady)?
        .output();
    let _closed = service.receive(
        creator,
        Request::ChannelDestroy {
            channel: CLIENT_CHANNEL_BOUNDARY,
        },
    )?;
    let reused = Request::ChannelCreate {
        channel: CLIENT_CHANNEL_BOUNDARY,
        peer: [1; 32],
        port: PORT,
        options: 0,
    };
    assert_eq!(service.receive(creator, reused), Err(Error::WouldBlock));
    service.exposed(old_credit)?;
    service.written(old_credit)?;
    assert_eq!(service.channel_info(outgoing), Err(Error::StaleGeneration));
    assert!(matches!(
        service.receive(creator, reused)?,
        Event::ChannelCreated(_)
    ));
    Ok(())
}

#[test]
fn same_mq_dual_namespaces_progress_with_one_shared_baseline_slot_per_channel() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 2];
    let mut buffers = [[0; 16]; 3];
    let mut messages = buffers.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
            ..Limits::default()
        },
    )?;
    let client = service.attach()?;
    let _port = service.receive(client, Request::PortOpen { port: PORT })?;
    let Event::ChannelCreated(outgoing) = service.receive(
        client,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [1; 32],
            port: PORT,
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let incoming = service.progress()?.ok_or(Error::NotReady)?;
    let mut wire = [0; 256];
    let (_, length) = emit(&mut service, client, &mut wire)?;
    assert!(matches!(
        Response::decode(&wire[..length])?,
        Response::ChannelCreate { channel: 0, .. }
    ));
    let _outgoing_credit = emit(&mut service, client, &mut wire)?;
    let _incoming_credit = emit(&mut service, client, &mut wire)?;
    assert_eq!(service.channel_info(outgoing)?.allowance, 1);
    assert_eq!(service.channel_info(incoming)?.allowance, 1);
    assert!(service.next_output_len(client)?.is_none());
    for _ in 0..3 {
        let _accepted = service.receive(
            client,
            Request::Data {
                channel: CLIENT_CHANNEL_BOUNDARY,
                priority: 0,
                messages: &BATCH,
            },
        )?;
        let (_, length) = emit(&mut service, client, &mut wire)?;
        assert_eq!(
            Response::decode(&wire[..length])?,
            Response::Data {
                channel: 0,
                priority: 0,
                messages: &BATCH
            }
        );
        let _done = service.receive(client, Request::Ack { channel: 0 })?;
        let (_, length) = emit(&mut service, client, &mut wire)?;
        assert_eq!(
            Response::decode(&wire[..length])?,
            Response::Ack {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        );
        assert_eq!(service.channel_info(outgoing)?.allowance, 1);
    }
    // The reverse local endpoint uses the same real MQ with its low-half ID.
    let _reverse = service.receive(
        client,
        Request::Data {
            channel: 0,
            priority: 9,
            messages: &BATCH,
        },
    )?;
    let (_, length) = emit(&mut service, client, &mut wire)?;
    assert_eq!(
        Response::decode(&wire[..length])?,
        Response::Data {
            channel: CLIENT_CHANNEL_BOUNDARY,
            priority: 9,
            messages: &BATCH
        }
    );
    let _done = service.receive(
        client,
        Request::Ack {
            channel: CLIENT_CHANNEL_BOUNDARY,
        },
    )?;
    Ok(())
}

#[test]
fn accepted_source_loss_preserves_exposure_revokes_ports_and_never_reuses_incoming_wire_id()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 2];
    let mut ports = [PortSlot::new(); 2];
    let mut channels = [ChannelSlot::new(); 4];
    let mut buffers = [[0; 16]; 6];
    let mut messages = buffers.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            window: 1,
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
        },
    )?;
    let original = service.attach()?;
    let listener = service.attach()?;
    let _owned = service.receive(original, Request::PortOpen { port: [4; 64] })?;
    let _port = service.receive(listener, Request::PortOpen { port: PORT })?;
    let _outgoing = service.receive(
        original,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [1; 32],
            port: PORT,
            options: 0,
        },
    )?;
    let old_incoming = service.progress()?.ok_or(Error::NotReady)?;
    let mut wire = [0; 256];
    let _announce = emit(&mut service, listener, &mut wire)?;
    let pending = service
        .prepare_output(original, &mut wire)?
        .ok_or(Error::NotReady)?
        .output();
    service.exposed(pending)?;
    let loss = service.detach(original)?;
    assert_eq!(loss.pending, Some(pending));
    assert!(loss.exposed);
    assert_eq!(loss.channels, 1);
    let fresh = service.attach()?;
    assert_ne!(fresh, original);
    assert_eq!(service.written(pending), Err(Error::StaleGeneration));
    assert!(matches!(
        service.receive(original, Request::PortOpen { port: [8; 64] }),
        Err(Error::StaleGeneration)
    ));
    assert!(matches!(
        service.receive(fresh, Request::PortOpen { port: [4; 64] })?,
        Event::PortOpened(_)
    ));
    let (_, length) = emit(&mut service, listener, &mut wire)?;
    assert_eq!(
        Response::decode(&wire[..length])?,
        Response::ChannelDestroy { channel: 0 }
    );
    assert_eq!(
        service.channel_info(old_incoming),
        Err(Error::StaleGeneration)
    );
    let _outgoing = service.receive(
        fresh,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [1; 32],
            port: PORT,
            options: 0,
        },
    )?;
    let next = service.progress()?.ok_or(Error::NotReady)?;
    assert_eq!(next.wire_id(), 1);
    assert_eq!(
        service.receive(listener, Request::Ack { channel: 0 })?,
        Event::Ignored
    );
    assert!(!service.channel_info(next)?.receive_pending);
    Ok(())
}

#[test]
fn remote_effects_require_actual_peer_claim_send_acceptance_and_application_done()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 2];
    let mut buffers = [[0; 16]; 3];
    let mut messages = buffers.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            window: 1,
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
        },
    )?;
    let client = service.attach()?;
    let Event::ChannelCreated(channel) = service.receive(
        client,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [2; 32],
            port: PORT,
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let open = service.next_open().ok_or(Error::NotReady)?;
    assert!(service.next_output_len(client)?.is_none());
    let peer_instance = peer::Instance::new();
    let mut tx = [[0; 16]; 1];
    let mut rx = [[0; 16]; 3];
    let mut sends = tx.each_mut().map(|bytes| peer::SendSlot::new(bytes));
    let mut receives = rx.each_mut().map(|bytes| peer::ReceiveSlot::new(bytes));
    let address = peer::Address {
        channel: 0,
        local_peer: [1; 32],
        remote_peer: [2; 32],
        port: PORT,
    };
    let mut owner = peer::ChannelOwner::outbound(
        &peer_instance,
        address,
        &mut sends,
        &mut receives,
        MonoInstant(0),
        peer::Limits {
            window: 1,
            payload_bytes: 16,
            ..peer::Limits::default()
        },
    )?;
    assert!(matches!(
        service.peer_opened(open, &mut owner),
        Err(Error::NotReady)
    ));
    let mut wire = [0; 256];
    peer_emit(&mut owner, &mut wire)?;
    assert_eq!(
        owner.receive(
            owner.scope(),
            ChannelMessage::OpenAck {
                reserved: 0,
                channel: 0,
                port: PORT
            },
            [7; 32],
            MonoInstant(0)
        )?,
        peer::Event::Opened
    );
    let binding = service.peer_opened(open, &mut owner)?;
    assert_eq!(binding.channel(), channel);
    assert_eq!(service.rebind_local_peer([4; 32]), Err(Error::WouldBlock));
    assert_eq!(service.local_peer(), [1; 32]);
    assert_eq!(owner.claim_application(), Err(Error::Conflict));
    let _initial_credit = emit(&mut service, client, &mut wire)?;
    let _queued = service.receive(
        client,
        Request::Data {
            channel: CLIENT_CHANNEL_BOUNDARY,
            priority: 0,
            messages: &BATCH,
        },
    )?;
    let sending = service.next_send().ok_or(Error::NotReady)?;
    assert_eq!(sending.payload, BATCH);
    let effect = sending.effect;
    let actual_send = owner.queue_send(sending.payload, MonoInstant(0))?;
    let admitted = service.send_admitted(effect, binding, &owner, actual_send)?;
    assert!(matches!(
        service.send_completed(admitted, &owner),
        Err(Error::WouldBlock)
    ));
    peer_emit(&mut owner, &mut wire)?;
    assert!(matches!(
        service.send_completed(admitted, &owner),
        Err(Error::WouldBlock)
    ));
    assert!(service.next_output_len(client)?.is_none());
    let _actual_ack = owner.receive(
        owner.scope(),
        ChannelMessage::DataAck {
            channel: 0,
            mid: 2,
            futures: 0,
        },
        [7; 32],
        MonoInstant(0),
    )?;
    assert_eq!(
        service.send_completed(admitted, &owner)?,
        peer::Outcome::PeerAccepted
    );
    assert_eq!(
        service.send_completed(admitted, &owner),
        Err(Error::StaleGeneration)
    );
    owner.release_send(actual_send)?;
    let _actual_local_credit = emit(&mut service, client, &mut wire)?;
    let _received = owner.receive(
        owner.scope(),
        ChannelMessage::Data {
            channel: 0,
            mid: 1,
            payload: &BATCH,
        },
        [7; 32],
        MonoInstant(0),
    )?;
    let received = service.receive_peer(binding, &mut owner)?;
    assert!(service.next_receive_done().is_none());
    let (_, length) = emit(&mut service, client, &mut wire)?;
    assert_eq!(
        Response::decode(&wire[..length])?,
        Response::Data {
            channel: CLIENT_CHANNEL_BOUNDARY,
            priority: 0,
            messages: &BATCH
        }
    );
    assert!(service.next_receive_done().is_none());
    let _app_done = service.receive(
        client,
        Request::Ack {
            channel: CLIENT_CHANNEL_BOUNDARY,
        },
    )?;
    let done = service.next_receive_done().ok_or(Error::NotReady)?;
    service.peer_receive_done(done, received, &mut owner)?;
    assert_eq!(
        service.peer_receive_done(done, received, &mut owner),
        Err(Error::StaleGeneration)
    );
    assert!(service.next_receive_done().is_none());
    let _close = service.receive(
        client,
        Request::ChannelDestroy {
            channel: CLIENT_CHANNEL_BOUNDARY,
        },
    )?;
    let close = service.next_close().ok_or(Error::NotReady)?;
    assert_eq!(service.rebind_local_peer([4; 32]), Err(Error::WouldBlock));
    assert_eq!(
        service.peer_closed(close, binding, &owner),
        Err(Error::NotReady)
    );
    owner.close()?;
    peer_emit(&mut owner, &mut wire)?;
    service.peer_closed(close, binding, &owner)?;
    assert_eq!(service.channel_info(channel), Err(Error::StaleGeneration));
    service.rebind_local_peer([4; 32])?;
    assert_eq!(service.local_peer(), [4; 32]);
    Ok(())
}

#[test]
fn explicit_destroy_retains_original_remote_tx_until_real_ack_or_expiry() -> Result<(), Error> {
    // Pure transition source only: these cases are not native interoperability
    // or application-processing evidence, and have not been executed here.
    for disposition in 0..3 {
        let mut instance = Instance::new();
        let mut clients = [ClientSlot::new(); 1];
        let mut ports = [PortSlot::new(); 1];
        let mut channels = [ChannelSlot::new(); 2];
        let mut buffers = [[0; 16]; 3];
        let mut messages = buffers.each_mut().map(|bytes| MessageSlot::new(bytes));
        let mut service = Service::new(
            &mut instance,
            [1; 32],
            &mut clients,
            &mut ports,
            &mut channels,
            &mut messages,
            Limits {
                window: 1,
                loop_payload_bytes: 16,
                remote_payload_bytes: 16,
            },
        )?;
        let client = service.attach()?;
        let Event::ChannelCreated(channel) = service.receive(
            client,
            Request::ChannelCreate {
                channel: CLIENT_CHANNEL_BOUNDARY,
                peer: [2; 32],
                port: PORT,
                options: 0,
            },
        )?
        else {
            return Err(Error::Malformed);
        };
        let open = service.next_open().ok_or(Error::NotReady)?;
        assert!(service.next_output_len(client)?.is_none());
        let peer_instance = peer::Instance::new();
        let mut tx = [[0; 16]; 1];
        let mut rx = [[0; 16]; 3];
        let mut sends = tx.each_mut().map(|bytes| peer::SendSlot::new(bytes));
        let mut receives = rx.each_mut().map(|bytes| peer::ReceiveSlot::new(bytes));
        let address = peer::Address {
            channel: 0,
            local_peer: [1; 32],
            remote_peer: [2; 32],
            port: PORT,
        };
        let mut owner = peer::ChannelOwner::outbound(
            &peer_instance,
            address,
            &mut sends,
            &mut receives,
            MonoInstant(0),
            peer::Limits {
                window: 1,
                payload_bytes: 16,
                ..peer::Limits::default()
            },
        )?;
        let mut wire = [0; 256];
        peer_emit(&mut owner, &mut wire)?;
        assert_eq!(
            owner.receive(
                owner.scope(),
                ChannelMessage::OpenAck {
                    reserved: 0,
                    channel: 0,
                    port: PORT
                },
                [7; 32],
                MonoInstant(0)
            )?,
            peer::Event::Opened
        );
        let binding = service.peer_opened(open, &mut owner)?;
        assert_eq!(binding.channel(), channel);
        assert_eq!(owner.claim_application(), Err(Error::Conflict));
        let _initial_credit = emit(&mut service, client, &mut wire)?;

        service.receive(
            client,
            Request::Data {
                channel: CLIENT_CHANNEL_BOUNDARY,
                priority: 0,
                messages: &BATCH,
            },
        )?;
        assert_eq!(
            service.receive(
                client,
                Request::ChannelDestroy {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                }
            )?,
            Event::ChannelDraining(channel)
        );
        assert_eq!(
            service.receive(
                client,
                Request::ChannelDestroy {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                }
            )?,
            Event::Ignored
        );
        assert!(service.channel_info(channel)?.draining);
        assert_eq!(service.channel_info(channel)?.allowance, 0);
        assert!(service.next_close().is_none());
        assert_eq!(
            service.receive(
                client,
                Request::Data {
                    channel: CLIENT_CHANNEL_BOUNDARY,
                    priority: 0,
                    messages: &BATCH
                }
            )?,
            Event::Ignored
        );
        let reused = Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [2; 32],
            port: PORT,
            options: 0,
        };
        let Event::ChannelCreated(replacement) = service.receive(client, reused)? else {
            return Err(Error::Malformed);
        };
        assert_ne!(replacement, channel);
        assert_eq!(service.channel_info(replacement)?.phase, Phase::Opening);
        assert!(service.channel_info(channel)?.draining);
        assert_eq!(service.receive(client, reused), Err(Error::Conflict));
        let sending = service.next_send().ok_or(Error::NotReady)?;
        assert_eq!(sending.payload, BATCH);
        let effect = sending.effect;
        let send = owner.queue_send(sending.payload, MonoInstant(0))?;
        let admitted = service.send_admitted(effect, binding, &owner, send)?;
        assert!(service.next_send().is_none());
        assert!(service.next_close().is_none());
        peer_emit(&mut owner, &mut wire)?;
        assert_eq!(
            service.send_completed(admitted, &owner),
            Err(Error::WouldBlock)
        );
        if disposition == 1 {
            owner.receive(
                owner.scope(),
                ChannelMessage::DataAck {
                    channel: 0,
                    mid: 2,
                    futures: 0,
                },
                [7; 32],
                MonoInstant(0),
            )?;
            assert_eq!(
                service.send_completed(admitted, &owner)?,
                peer::Outcome::PeerAccepted
            );
            assert!(!service.channel_info(channel)?.draining);
            assert_eq!(service.channel_info(channel)?.phase, Phase::Closing);
            assert!(service.next_output_len(client)?.is_none());
            owner.release_send(send)?;
            owner.close()?;
            peer_emit(&mut owner, &mut wire)?;
        } else if disposition == 0 {
            service.expire_destroy(channel)?;
            assert_eq!(service.channel_info(channel)?.phase, Phase::Closing);
            owner.retire()?;
            assert_eq!(
                owner.completion_for(send)?.outcome,
                peer::Outcome::DeliveryUnknown
            );
            owner.release_send(send)?;
        } else {
            // A real terminal peer failure after local Destroy must not queue
            // an old raw Destroy against the replacement endpoint.
            owner.retire()?;
            assert_eq!(
                service.send_completed(admitted, &owner)?,
                peer::Outcome::DeliveryUnknown
            );
            assert_eq!(service.channel_info(channel)?.phase, Phase::Closing);
            owner.release_send(send)?;
        }
        let close = service.next_close().ok_or(Error::NotReady)?;
        service.peer_closed(close, binding, &owner)?;
        assert_eq!(service.channel_info(channel), Err(Error::StaleGeneration));
        assert_eq!(service.channel_info(replacement)?.phase, Phase::Opening);
        assert!(service.next_output_len(client)?.is_none());
        assert_eq!(
            service.next_open().ok_or(Error::NotReady)?.channel(),
            replacement
        );
    }
    Ok(())
}

#[test]
fn local_raw_ccn_reuse_keeps_original_open_retirement_and_cancels_unsent_close_notice()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 2];
    let mut buffers = [[0; 16]; 3];
    let mut messages = buffers.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            window: 1,
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
        },
    )?;
    let client = service.attach()?;
    let create = Request::ChannelCreate {
        channel: CLIENT_CHANNEL_BOUNDARY,
        peer: [2; 32],
        port: PORT,
        options: 0,
    };
    let Event::ChannelCreated(original) = service.receive(client, create)? else {
        return Err(Error::Malformed);
    };
    let old_open = service.next_open().ok_or(Error::NotReady)?;
    assert_eq!(old_open.channel(), original);
    assert_eq!(
        service.receive(
            client,
            Request::ChannelDestroy {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        )?,
        Event::ChannelClosed
    );
    assert_eq!(service.channel_info(original)?.phase, Phase::Closing);
    let Event::ChannelCreated(replacement) = service.receive(client, create)? else {
        return Err(Error::Malformed);
    };
    assert_ne!(replacement, original);
    assert_eq!(service.channel_info(replacement)?.phase, Phase::Opening);
    assert_eq!(service.receive(client, create), Err(Error::Conflict));
    assert_eq!(
        service.canceling_open().ok_or(Error::NotReady)?.channel(),
        original
    );
    // This source case explicitly supplies the original stopped-open receipt;
    // it is not native IO or peer authentication/acceptance evidence.
    service.open_failed(old_open)?;
    assert_eq!(service.channel_info(original), Err(Error::StaleGeneration));
    assert_eq!(service.channel_info(replacement)?.phase, Phase::Opening);
    assert_eq!(service.open_failed(old_open), Err(Error::StaleGeneration));
    assert!(service.next_output_len(client)?.is_none());
    let new_open = service.next_open().ok_or(Error::NotReady)?;
    assert_eq!(new_open.channel(), replacement);
    // A remote-open refusal has not yet exposed its local notification. A
    // concurrent explicit Destroy discards that intent, never issued output.
    service.open_failed(new_open)?;
    assert!(service.next_output_len(client)?.is_some());
    assert_eq!(service.receive(client, create), Err(Error::WouldBlock));
    assert_eq!(
        service.receive(
            client,
            Request::ChannelDestroy {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        )?,
        Event::ChannelClosed
    );
    assert!(service.next_output_len(client)?.is_none());
    let Event::ChannelCreated(third) = service.receive(client, create)? else {
        return Err(Error::Malformed);
    };
    assert_ne!(third, replacement);
    assert_eq!(service.channel_info(third)?.phase, Phase::Opening);
    Ok(())
}

#[path = "service/send_selection_tests.rs"]
mod send_selection_tests;
