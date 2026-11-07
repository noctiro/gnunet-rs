//! Actual pure Service/ChannelOwner transitions with explicit protocol inputs
//! and caller emission observations. No native WholeWrite, authenticated tunnel,
//! remote application delivery or interoperability receipt is manufactured.
use super::*;

const A1: [u8; 4] = [0, 4, 0x12, 1];
const A2: [u8; 4] = [0, 4, 0x12, 2];
const A3: [u8; 4] = [0, 4, 0x12, 3];
const B1: [u8; 4] = [0, 4, 0x13, 1];

fn ready<'app, 'peer, 'slots, 'bytes>(
    service: &mut Service<'app, '_, '_>,
    client: Client<'app>,
    wire: u32,
    remote: [u8; 32],
    domain: &'peer peer::Instance,
    buffers: peer::Buffers<'slots, 'bytes>,
    window: u8,
) -> Result<
    (
        Channel<'app>,
        Binding<'app, 'peer>,
        peer::ChannelOwner<'peer, 'slots, 'bytes>,
    ),
    Error,
> {
    let Event::ChannelCreated(channel) = service.receive(
        client,
        Request::ChannelCreate {
            channel: wire,
            peer: remote,
            port: PORT,
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let open = service.next_open().ok_or(Error::NotReady)?;
    let mut owner = peer::ChannelOwner::allocate(
        domain,
        peer::Address {
            channel: 0,
            local_peer: [1; 32],
            remote_peer: remote,
            port: PORT,
        },
        buffers,
        None,
        MonoInstant(0),
        peer::Limits {
            window,
            payload_bytes: 16,
            ..peer::Limits::default()
        },
    )
    .map_err(|refused| refused.reason)?;
    let mut output = [0; 256];
    peer_emit(&mut owner, &mut output)?;
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
    Ok((channel, binding, owner))
}

fn data_emitted(
    owner: &mut peer::ChannelOwner<'_, '_, '_>,
    send: peer::Send<'_>,
    payload: &[u8],
) -> Result<(), Error> {
    let mut output = [0; 256];
    let prepared = owner
        .prepare_next(MonoInstant(0), &mut output)?
        .ok_or(Error::NotReady)?;
    assert!(
        matches!(ChannelMessage::decode(prepared.bytes())?, ChannelMessage::Data { mid, payload: actual, .. } if mid == send.mid() && actual == payload)
    );
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

fn selection_case(window: u8) -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut ports = [PortSlot::new(); 1];
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
            window: 4,
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
        },
    )?;
    let client = service.attach()?;
    let domain = peer::Instance::new();
    let mut a_tx = [[0; 16]; 2];
    let mut a_rx = [[0; 16]; 3];
    let mut a_sends = a_tx.each_mut().map(|bytes| peer::SendSlot::new(bytes));
    let mut a_receives = a_rx.each_mut().map(|bytes| peer::ReceiveSlot::new(bytes));
    let (a, a_binding, mut a_owner) = ready(
        &mut service,
        client,
        CLIENT_CHANNEL_BOUNDARY,
        [2; 32],
        &domain,
        peer::Buffers {
            sends: &mut a_sends,
            receives: &mut a_receives,
        },
        window,
    )?;
    let mut b_tx = [[0; 16]; 2];
    let mut b_rx = [[0; 16]; 3];
    let mut b_sends = b_tx.each_mut().map(|bytes| peer::SendSlot::new(bytes));
    let mut b_receives = b_rx.each_mut().map(|bytes| peer::ReceiveSlot::new(bytes));
    let (b, b_binding, mut b_owner) = ready(
        &mut service,
        client,
        CLIENT_CHANNEL_BOUNDARY + 1,
        [3; 32],
        &domain,
        peer::Buffers {
            sends: &mut b_sends,
            receives: &mut b_receives,
        },
        window,
    )?;
    let mut output = [0; 256];
    for _ in 0..8 {
        emit(&mut service, client, &mut output)?;
    }
    assert_eq!(service.channel_info(a)?.allowance, 4);
    assert_eq!(service.channel_info(b)?.allowance, 4);
    service.receive(
        client,
        Request::Data {
            channel: a.wire_id(),
            priority: 0,
            messages: &A1,
        },
    )?;
    let first = service.next_send().ok_or(Error::NotReady)?;
    assert_eq!(first.payload, A1);
    let first_send = a_owner.queue_send(first.payload, MonoInstant(0))?;
    let first_admitted = service.send_admitted(first.effect, a_binding, &a_owner, first_send)?;
    for payload in [&A2, &A3] {
        service.receive(
            client,
            Request::Data {
                channel: a.wire_id(),
                priority: 0,
                messages: payload,
            },
        )?;
    }
    service.receive(
        client,
        Request::Data {
            channel: b.wire_id(),
            priority: 0,
            messages: &B1,
        },
    )?;
    // A3 must never reach a predicate while the older A2 is still queued,
    // even if that predicate would prefer A3's smaller/different payload.
    let mut examined_later_a = false;
    assert!(
        service
            .next_send_where(|sending| {
                examined_later_a |= sending.payload == A3;
                sending.payload == A3
            })
            .is_none()
    );
    assert!(!examined_later_a);
    let mut pipelined = None;
    if window == 2 {
        // A1 was really admitted, so its peer FIFO already owns its bytes.
        // A real second window slot permits A2 without waiting for A1's ACK.
        let second = service
            .next_send_where(|sending| {
                sending.effect.channel() == a && a_owner.available_send() != 0
            })
            .ok_or(Error::NotReady)?;
        assert_eq!(second.payload, A2);
        let send = a_owner.queue_send(second.payload, MonoInstant(0))?;
        let admitted = service.send_admitted(second.effect, a_binding, &a_owner, send)?;
        pipelined = Some((send, admitted));
    }
    assert_eq!(a_owner.available_send(), 0);
    let waiting = service.next_send().ok_or(Error::NotReady)?;
    let waiting_effect = waiting.effect;
    let waiting_payload = if window == 1 { A2 } else { A3 };
    assert_eq!(waiting.payload, waiting_payload);
    // The older blocked A candidate does not hide B's actual free owner.
    let selected = service
        .next_send_where(|sending| {
            (sending.effect.channel() == a && a_owner.available_send() != 0)
                || (sending.effect.channel() == b && b_owner.available_send() != 0)
        })
        .ok_or(Error::NotReady)?;
    assert_eq!(selected.effect.channel(), b);
    assert_eq!(selected.payload, B1);
    let b_send = b_owner.queue_send(selected.payload, MonoInstant(0))?;
    let b_admitted = service.send_admitted(selected.effect, b_binding, &b_owner, b_send)?;
    for _ in 0..16 {
        assert!(
            service
                .next_send_where(|sending| {
                    (sending.effect.channel() == a && a_owner.available_send() != 0)
                        || (sending.effect.channel() == b && b_owner.available_send() != 0)
                })
                .is_none()
        );
        // A blocked readonly query consumes no candidate, credit or new work.
        assert_eq!(
            service.next_send().ok_or(Error::NotReady)?.effect,
            waiting_effect
        );
        assert_eq!(service.channel_info(a)?.allowance, 1);
        assert_eq!(service.channel_info(b)?.allowance, 3);
    }
    data_emitted(&mut a_owner, first_send, &A1)?;
    if let Some((send, _)) = pipelined {
        data_emitted(&mut a_owner, send, &A2)?;
    }
    data_emitted(&mut b_owner, b_send, &B1)?;
    // Only the original actual ACK input can release A1's real peer window.
    assert_eq!(
        a_owner.receive(
            a_owner.scope(),
            ChannelMessage::DataAck {
                channel: 0,
                mid: first_send.mid().wrapping_add(1),
                futures: 0
            },
            [7; 32],
            MonoInstant(0)
        )?,
        peer::Event::Acknowledged { sends: 1 }
    );
    assert_eq!(
        service.send_completed(first_admitted, &a_owner)?,
        peer::Outcome::PeerAccepted
    );
    a_owner.release_send(first_send)?;
    let resumed = service
        .next_send_where(|sending| sending.effect.channel() == a && a_owner.available_send() != 0)
        .ok_or(Error::NotReady)?;
    assert_eq!(resumed.effect, waiting_effect);
    assert_eq!(resumed.payload, waiting_payload);
    let resumed_send = a_owner.queue_send(resumed.payload, MonoInstant(0))?;
    assert_eq!(resumed_send.mid(), if window == 1 { 2 } else { 3 });
    assert!(resumed_send.value() > first_send.value());
    let _resumed = service.send_admitted(resumed.effect, a_binding, &a_owner, resumed_send)?;
    data_emitted(&mut a_owner, resumed_send, &waiting_payload)?;
    assert_eq!(
        b_owner.receive(
            b_owner.scope(),
            ChannelMessage::DataAck {
                channel: 0,
                mid: b_send.mid().wrapping_add(1),
                futures: 0
            },
            [7; 32],
            MonoInstant(0)
        )?,
        peer::Event::Acknowledged { sends: 1 }
    );
    assert_eq!(
        service.send_completed(b_admitted, &b_owner)?,
        peer::Outcome::PeerAccepted
    );
    b_owner.release_send(b_send)?;
    Ok(())
}

#[test]
fn blocked_original_peer_window_does_not_hide_an_independent_ready_channel() -> Result<(), Error> {
    selection_case(1)
}

#[test]
fn an_admitted_head_keeps_real_two_slot_pipeline_and_queued_head_order() -> Result<(), Error> {
    selection_case(2)
}
