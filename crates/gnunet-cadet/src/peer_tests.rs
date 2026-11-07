#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible state models assert actual channel wire effects, retained payloads and original attempt ownership"
)]
use super::*;
const PAYLOAD: [u8; 8] = [0, 8, 0x12, 0x34, 1, 2, 3, 4];
fn address(channel: u32, listener: bool) -> Address {
    Address {
        channel,
        local_peer: [if listener { 2 } else { 1 }; 32],
        remote_peer: [if listener { 1 } else { 2 }; 32],
        port: [3; 64],
    }
}
fn emit<'id>(
    owner: &mut ChannelOwner<'id, '_, '_>,
    now: u64,
    output: &mut [u8],
) -> Result<(Attempt<'id>, usize), Error> {
    let prepared = owner
        .prepare_next(MonoInstant(now), output)?
        .ok_or(Error::NotReady)?;
    let attempt = prepared.attempt();
    let length = prepared.bytes().len();
    owner.exposed(attempt)?;
    owner.settle(
        attempt,
        Emission::Sent {
            connection: [7; 32],
        },
        MonoInstant(now),
    )?;
    Ok((attempt, length))
}

#[test]
fn dropped_first_data_retransmits_same_mid_while_sack_only_accepts_buffered_peers()
-> Result<(), Error> {
    let a_instance = Instance::new();
    let b_instance = Instance::new();
    let mut a_send_bytes = [[0; 16]; 4];
    let mut b_send_bytes = [[0; 16]; 4];
    let mut a_receive_bytes = [[0; 16]; 6];
    let mut b_receive_bytes = [[0; 16]; 6];
    let mut a_sends = a_send_bytes.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut b_sends = b_send_bytes.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut a_receives = a_receive_bytes
        .each_mut()
        .map(|bytes| ReceiveSlot::new(bytes));
    let mut b_receives = b_receive_bytes
        .each_mut()
        .map(|bytes| ReceiveSlot::new(bytes));
    let mut a = ChannelOwner::outbound(
        &a_instance,
        address(0, false),
        &mut a_sends,
        &mut a_receives,
        MonoInstant(0),
        Limits::default(),
    )?;
    let challenge = hash_port(&address(0, true).port, &address(0, true).local_peer);
    let mut b = ChannelOwner::incoming(
        &b_instance,
        address(0, true),
        challenge,
        &mut b_sends,
        &mut b_receives,
        MonoInstant(0),
        Limits::default(),
    )?;
    let mut wire = [0; 256];
    let (_, length) = emit(&mut a, 0, &mut wire)?;
    assert_eq!(
        ChannelMessage::decode(&wire[..length])?,
        ChannelMessage::Open {
            options_bytes: [2, 0, 0, 0],
            h_port: challenge,
            channel: 0
        }
    );
    assert_eq!(
        b.receive(
            b.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0)
        )?,
        Event::DuplicateOpen
    );
    let (_, length) = emit(&mut b, 0, &mut wire)?;
    assert_eq!(
        a.receive(
            a.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0)
        )?,
        Event::Opened
    );
    assert_eq!(a.available_send(), 4);
    let mut sends = [None; 4];
    for send in &mut sends {
        *send = Some(a.queue_send(&PAYLOAD, MonoInstant(0))?);
    }
    assert_eq!(a.available_send(), 0);
    for (index, send) in sends.iter().enumerate() {
        let (attempt, length) = emit(&mut a, 0, &mut wire)?;
        assert_eq!(attempt.send(), *send);
        if index != 0 {
            assert!(matches!(
                b.receive(
                    b.scope(),
                    ChannelMessage::decode(&wire[..length])?,
                    [7; 32],
                    MonoInstant(0)
                )?,
                Event::Buffered(_)
            ));
        }
    }
    assert!(b.peek_delivery().is_none());
    assert_eq!(b.ack(), (1, 7));
    let (_, length) = emit(&mut b, 0, &mut wire)?;
    assert_eq!(
        a.receive(
            a.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0)
        )?,
        Event::Acknowledged { sends: 3 }
    );
    let mut completed = 0;
    while let Some(completion) = a.completion() {
        assert_eq!(completion.outcome, Outcome::PeerAccepted);
        assert_ne!(Some(completion.send), sends[0]);
        assert_eq!(completion.payload, PAYLOAD);
        let send = completion.send;
        a.release_send(send)?;
        completed += 1;
    }
    assert_eq!(completed, 3);
    assert_eq!(a.available_send(), 3);
    assert!(a.prepare_next(MonoInstant(249_999), &mut wire)?.is_none());
    let (retry, length) = emit(&mut a, 250_000, &mut wire)?;
    assert_eq!(retry.send(), sends[0]);
    assert_eq!(
        ChannelMessage::decode(&wire[..length])?,
        ChannelMessage::Data {
            mid: 1,
            channel: 0,
            payload: &PAYLOAD
        }
    );
    let _buffered = b.receive(
        b.scope(),
        ChannelMessage::decode(&wire[..length])?,
        [7; 32],
        MonoInstant(250_000),
    )?;
    for mid in 1..=4 {
        let preview = b.peek_delivery().ok_or(Error::NotReady)?;
        assert_eq!(preview.received.mid(), mid);
        assert_eq!(preview.payload, PAYLOAD);
        let received = preview.received;
        let delivery = b.deliver(received)?;
        assert!(b.peek_delivery().is_none());
        b.receive_done(delivery)?;
    }
    assert_eq!(b.ack(), (5, 0));
    let (_, length) = emit(&mut b, 250_000, &mut wire)?;
    assert_eq!(
        a.receive(
            a.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(250_000)
        )?,
        Event::Acknowledged { sends: 1 }
    );
    let completion = a.completion().ok_or(Error::NotReady)?;
    assert_eq!(Some(completion.send), sends[0]);
    assert_eq!(completion.outcome, Outcome::PeerAccepted);
    assert!(completion.latency.is_none());
    let send = completion.send;
    a.release_send(send)?;
    assert_eq!(a.available_send(), 4);
    Ok(())
}

#[test]
fn application_credit_and_receive_capacity_cannot_ack_unowned_or_reused_bytes() -> Result<(), Error>
{
    let instance = Instance::new();
    let mut tx_bytes = [[0; 8]; 1];
    let mut rx_bytes = [[0; 8]; 2];
    let mut sends = tx_bytes.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut receives = rx_bytes.each_mut().map(|bytes| ReceiveSlot::new(bytes));
    let listener = address(0, true);
    let challenge = hash_port(&listener.port, &listener.local_peer);
    let mut owner = ChannelOwner::incoming(
        &instance,
        listener,
        challenge,
        &mut sends,
        &mut receives,
        MonoInstant(0),
        Limits {
            window: 1,
            payload_bytes: 8,
            ..Limits::default()
        },
    )?;
    let mut wire = [0; 256];
    let _opening = emit(&mut owner, 0, &mut wire)?;
    let data = |mid| ChannelMessage::Data {
        mid,
        channel: 0,
        payload: &PAYLOAD,
    };
    let Event::Buffered(first) = owner.receive(owner.scope(), data(1), [7; 32], MonoInstant(0))?
    else {
        return Err(Error::Malformed);
    };
    let first_delivery = owner.deliver(first)?;
    assert_eq!(owner.ack(), (2, 0));
    let Event::Buffered(second) = owner.receive(owner.scope(), data(2), [7; 32], MonoInstant(0))?
    else {
        return Err(Error::Malformed);
    };
    assert!(matches!(
        owner.receive(owner.scope(), data(3), [7; 32], MonoInstant(0)),
        Ok(Event::Dropped)
    ));
    assert_eq!(owner.ack(), (2, 0));
    assert_eq!(owner.deliver(second), Err(Error::WouldBlock));
    owner.receive_done(first_delivery)?;
    assert_eq!(
        owner.receive_done(first_delivery),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        owner.receive(owner.scope(), data(2), [7; 32], MonoInstant(0))?,
        Event::Dropped
    );
    let second_delivery = owner.deliver(second)?;
    owner.receive_done(second_delivery)?;
    let Event::Buffered(third) = owner.receive(owner.scope(), data(3), [7; 32], MonoInstant(0))?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(owner.deliver(first), Err(Error::StaleGeneration));
    assert_ne!(first.serial, third.serial);
    let last = owner.deliver(third)?;
    owner.close()?;
    assert_eq!(owner.receive_done(last), Err(Error::StaleGeneration));
    let (destroy, length) = emit(&mut owner, 0, &mut wire)?;
    assert_eq!(destroy.kind(), AttemptKind::Destroy);
    assert_eq!(
        ChannelMessage::decode(&wire[..length])?,
        ChannelMessage::Destroy {
            reserved: 0,
            channel: 0
        }
    );
    assert_eq!(owner.phase(), Phase::Closed);
    Ok(())
}

#[test]
fn wrapping_mids_and_ack_snapshot_revision_preserve_current_missing_base() -> Result<(), Error> {
    let instance = Instance::new();
    let mut tx_bytes = [[0; 8]; 2];
    let mut rx_bytes = [[0; 8]; 4];
    let mut sends = tx_bytes.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut receives = rx_bytes.each_mut().map(|bytes| ReceiveSlot::new(bytes));
    let mut owner = ChannelOwner::outbound(
        &instance,
        address(0, false),
        &mut sends,
        &mut receives,
        MonoInstant(0),
        Limits {
            window: 2,
            ..Limits::default()
        },
    )?;
    // Checkpoint a long-lived ready channel near the real u32 rollover.
    owner.phase = Phase::Ready;
    owner.next_send = u32::MAX - 1;
    let last = owner.queue_send(&PAYLOAD, MonoInstant(0))?;
    let zero = owner.queue_send(&PAYLOAD, MonoInstant(0))?;
    assert_eq!(last.mid(), u32::MAX);
    assert_eq!(zero.mid(), 0);
    let mut wire = [0; 256];
    let _first = emit(&mut owner, 0, &mut wire)?;
    let _second = emit(&mut owner, 0, &mut wire)?;
    assert_eq!(
        owner.receive(
            owner.scope(),
            ChannelMessage::DataAck {
                channel: 0,
                mid: u32::MAX,
                futures: 1
            },
            [7; 32],
            MonoInstant(1)
        )?,
        Event::Acknowledged { sends: 1 }
    );
    let completion = owner.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.send, zero);
    let sent = completion.send;
    owner.release_send(sent)?;
    assert_eq!(
        owner.receive(
            owner.scope(),
            ChannelMessage::DataAck {
                channel: 0,
                mid: 1,
                futures: 0
            },
            [7; 32],
            MonoInstant(2)
        )?,
        Event::Acknowledged { sends: 1 }
    );
    let completion = owner.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.send, last);
    assert_eq!(completion.latency.map(|latency| latency.micros), Some(2));
    let sent = completion.send;
    owner.release_send(sent)?;
    owner.next_receive = u32::MAX;
    let _future = owner.receive(
        owner.scope(),
        ChannelMessage::Data {
            channel: 0,
            mid: 0,
            payload: &PAYLOAD,
        },
        [7; 32],
        MonoInstant(2),
    )?;
    assert_eq!(owner.ack(), (u32::MAX, 1));
    let Event::Buffered(expected) = owner.receive(
        owner.scope(),
        ChannelMessage::Data {
            channel: 0,
            mid: u32::MAX,
            payload: &PAYLOAD,
        },
        [7; 32],
        MonoInstant(2),
    )?
    else {
        return Err(Error::Malformed);
    };
    let delivery = owner.deliver(expected)?;
    assert_eq!(owner.ack(), (0, 0));
    let prepared = owner
        .prepare_next(MonoInstant(2), &mut wire)?
        .ok_or(Error::NotReady)?;
    assert_eq!(
        ChannelMessage::decode(prepared.bytes())?,
        ChannelMessage::DataAck {
            channel: 0,
            mid: 0,
            futures: 0
        }
    );
    let original_ack = prepared.attempt();
    let _newer = owner.receive(
        owner.scope(),
        ChannelMessage::Data {
            channel: 0,
            mid: 1,
            payload: &PAYLOAD,
        },
        [7; 32],
        MonoInstant(2),
    )?;
    owner.exposed(original_ack)?;
    owner.settle(
        original_ack,
        Emission::Sent {
            connection: [7; 32],
        },
        MonoInstant(2),
    )?;
    let prepared = owner
        .prepare_next(MonoInstant(2), &mut wire)?
        .ok_or(Error::NotReady)?;
    assert_eq!(
        ChannelMessage::decode(prepared.bytes())?,
        ChannelMessage::DataAck {
            channel: 0,
            mid: 0,
            futures: 1
        }
    );
    let updated_ack = prepared.attempt();
    owner.discard_attempt(updated_ack)?;
    owner.receive_done(delivery)?;
    Ok(())
}

#[test]
fn ack_during_exposed_retry_cannot_reuse_original_slot_before_settlement() -> Result<(), Error> {
    let instance = Instance::new();
    let foreign_instance = Instance::new();
    let mut tx_bytes = [[0; 8]; 2];
    let mut rx_bytes = [[0; 8]; 2];
    let mut foreign_tx = [[0; 8]; 2];
    let mut foreign_rx = [[0; 8]; 2];
    let mut sends = tx_bytes.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut receives = rx_bytes.each_mut().map(|bytes| ReceiveSlot::new(bytes));
    let mut foreign_sends = foreign_tx.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut foreign_receives = foreign_rx.each_mut().map(|bytes| ReceiveSlot::new(bytes));
    let limits = Limits {
        window: 2,
        ..Limits::default()
    };
    let mut owner = ChannelOwner::outbound(
        &instance,
        address(0, false),
        &mut sends,
        &mut receives,
        MonoInstant(0),
        limits,
    )?;
    let foreign = ChannelOwner::outbound(
        &foreign_instance,
        address(0, false),
        &mut foreign_sends,
        &mut foreign_receives,
        MonoInstant(0),
        limits,
    )?;
    owner.phase = Phase::Ready;
    let send = owner.queue_send(&PAYLOAD, MonoInstant(0))?;
    let mut wire = [0; 256];
    let _first = emit(&mut owner, 0, &mut wire)?;
    let ack = ChannelMessage::DataAck {
        channel: 0,
        mid: 2,
        futures: 0,
    };
    assert_eq!(
        owner.receive(foreign.scope(), ack, [7; 32], MonoInstant(0)),
        Err(Error::StaleGeneration)
    );
    let prepared = owner
        .prepare_next(MonoInstant(250_000), &mut wire)?
        .ok_or(Error::NotReady)?;
    let retry = prepared.attempt();
    assert_eq!(retry.send(), Some(send));
    owner.exposed(retry)?;
    assert_eq!(
        owner.receive(owner.scope(), ack, [7; 32], MonoInstant(250_000))?,
        Event::Acknowledged { sends: 1 }
    );
    assert!(owner.completion().is_none());
    assert_eq!(owner.release_send(send), Err(Error::WouldBlock));
    assert_eq!(owner.discard_attempt(retry), Err(Error::OutcomeUnknown));
    owner.settle(retry, Emission::Failed, MonoInstant(250_000))?;
    let completion = owner.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.send, send);
    assert_eq!(completion.outcome, Outcome::PeerAccepted);
    assert!(completion.latency.is_none());
    owner.release_send(send)?;
    let exposed_send = owner.queue_send(&PAYLOAD, MonoInstant(250_000))?;
    let unsent = owner.queue_send(&PAYLOAD, MonoInstant(250_000))?;
    assert_eq!(owner.release_send(send), Err(Error::StaleGeneration));
    let original = owner
        .prepare_next(MonoInstant(250_000), &mut wire)?
        .ok_or(Error::NotReady)?
        .attempt();
    owner.exposed(original)?;
    assert_eq!(owner.retire(), Err(Error::WouldBlock));
    assert_eq!(
        owner.receive(
            owner.scope(),
            ChannelMessage::Destroy {
                reserved: 0,
                channel: 0
            },
            [7; 32],
            MonoInstant(250_000)
        )?,
        Event::Destroyed {
            pending: Some(original)
        }
    );
    let completion = owner.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.send, unsent);
    assert_eq!(completion.outcome, Outcome::RetiredUnsent);
    owner.release_send(unsent)?;
    assert!(owner.completion().is_none());
    owner.settle(original, Emission::Failed, MonoInstant(250_000))?;
    let completion = owner.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.send, exposed_send);
    assert_eq!(completion.outcome, Outcome::DeliveryUnknown);
    owner.release_send(exposed_send)?;
    assert_eq!(owner.exposed(original), Err(Error::StaleGeneration));
    owner.retire()?;
    let mut small = Numbers::new(&[1; 32], &[2; 32])?;
    let mut large = Numbers::new(&[2; 32], &[1; 32])?;
    assert_eq!(small.allocate()?, 0);
    assert_eq!(large.allocate()?, NUMBER_SIDE_BIT);
    Ok(())
}

#[test]
fn future_packets_preserve_largest_free_buffer_for_missing_base_progress() -> Result<(), Error> {
    let instance = Instance::new();
    let mut tx_bytes = [[0; 16]; 2];
    let mut small = [0; 8];
    let mut large = [0; 16];
    let mut sends = tx_bytes.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut receives = [ReceiveSlot::new(&mut small), ReceiveSlot::new(&mut large)];
    let listener = address(0, true);
    let challenge = hash_port(&listener.port, &listener.local_peer);
    let mut owner = ChannelOwner::incoming(
        &instance,
        listener,
        challenge,
        &mut sends,
        &mut receives,
        MonoInstant(0),
        Limits {
            window: 2,
            payload_bytes: 16,
            ..Limits::default()
        },
    )?;
    let future = ChannelMessage::Data {
        mid: 2,
        channel: 0,
        payload: &PAYLOAD,
    };
    assert!(matches!(
        owner.receive(owner.scope(), future, [7; 32], MonoInstant(0))?,
        Event::Buffered(_)
    ));
    assert_eq!(owner.ack(), (1, 1));
    assert!(matches!(
        owner.receive(
            owner.scope(),
            ChannelMessage::Data {
                mid: 3,
                channel: 0,
                payload: &PAYLOAD
            },
            [7; 32],
            MonoInstant(0)
        ),
        Ok(Event::Dropped)
    ));
    assert_eq!(owner.ack(), (1, 1));
    assert_eq!(owner.receive_capacity(), 16);
    let oversized_base = [0; 17];
    assert_eq!(
        owner.receive(
            owner.scope(),
            ChannelMessage::Data {
                mid: 1,
                channel: 0,
                payload: &oversized_base
            },
            [7; 32],
            MonoInstant(0)
        ),
        Err(Error::TooLarge)
    );
    assert_eq!(owner.ack(), (1, 1));
    let larger_base = [0xa5; 16];
    let Event::Buffered(base) = owner.receive(
        owner.scope(),
        ChannelMessage::Data {
            mid: 1,
            channel: 0,
            payload: &larger_base,
        },
        [7; 32],
        MonoInstant(0),
    )?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(
        owner.peek_delivery().ok_or(Error::NotReady)?.payload,
        larger_base
    );
    let delivery = owner.deliver(base)?;
    owner.receive_done(delivery)?;
    let preview = owner.peek_delivery().ok_or(Error::NotReady)?;
    assert_eq!(preview.received.mid(), 2);
    assert_eq!(preview.payload, PAYLOAD);
    let token = preview.received;
    let delivery = owner.deliver(token)?;
    owner.receive_done(delivery)?;
    assert_eq!(owner.ack(), (3, 0));

    // Also protect the *next* missing base when the current base is
    // already buffered in a smaller slot. The large slot stays reserved.
    let next_instance = Instance::new();
    let mut next_tx = [[0; 8]; 2];
    let mut next_small = [0; 4];
    let mut next_large = [0; 8];
    let mut next_sends = next_tx.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut next_receives = [
        ReceiveSlot::new(&mut next_small),
        ReceiveSlot::new(&mut next_large),
    ];
    let mut next_owner = ChannelOwner::incoming(
        &next_instance,
        listener,
        challenge,
        &mut next_sends,
        &mut next_receives,
        MonoInstant(0),
        Limits {
            window: 2,
            payload_bytes: 8,
            ..Limits::default()
        },
    )?;
    let smaller_base = [0, 4, 0, 9];
    let Event::Buffered(first) = next_owner.receive(
        next_owner.scope(),
        ChannelMessage::Data {
            mid: 1,
            channel: 0,
            payload: &smaller_base,
        },
        [7; 32],
        MonoInstant(0),
    )?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(
        next_owner.peek_delivery().ok_or(Error::NotReady)?.payload,
        smaller_base
    );
    let large_future = ChannelMessage::Data {
        mid: 3,
        channel: 0,
        payload: &PAYLOAD,
    };
    assert!(matches!(
        next_owner.receive(next_owner.scope(), large_future, [7; 32], MonoInstant(0)),
        Ok(Event::Dropped)
    ));
    assert_eq!(next_owner.ack(), (1, 0));
    let handoff = next_owner.deliver(first)?;
    next_owner.receive_done(handoff)?;
    let Event::Buffered(second) = next_owner.receive(
        next_owner.scope(),
        ChannelMessage::Data {
            mid: 2,
            channel: 0,
            payload: &PAYLOAD,
        },
        [7; 32],
        MonoInstant(0),
    )?
    else {
        return Err(Error::Malformed);
    };
    let handoff = next_owner.deliver(second)?;
    // The reserve is temporarily held by an actual application handoff;
    // the expected base waits for receive_done rather than being dropped.
    assert_eq!(
        next_owner.receive(next_owner.scope(), large_future, [7; 32], MonoInstant(0)),
        Err(Error::Capacity)
    );
    assert_eq!(next_owner.ack(), (3, 0));
    next_owner.receive_done(handoff)?;
    let Event::Buffered(third) =
        next_owner.receive(next_owner.scope(), large_future, [7; 32], MonoInstant(0))?
    else {
        return Err(Error::Malformed);
    };
    let handoff = next_owner.deliver(third)?;
    next_owner.receive_done(handoff)?;
    assert_eq!(next_owner.ack(), (4, 0));
    Ok(())
}

#[test]
fn later_cumulative_ack_accepts_old_exposed_mid_after_selective_credit_and_lost_acks()
-> Result<(), Error> {
    let a_instance = Instance::new();
    let b_instance = Instance::new();
    let mut a_tx = [[0; 16]; 4];
    let mut b_tx = [[0; 16]; 4];
    let mut a_rx = [[0; 16]; 6];
    let mut b_rx = [[0; 16]; 6];
    let mut a_sends = a_tx.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut b_sends = b_tx.each_mut().map(|bytes| SendSlot::new(bytes));
    let mut a_receives = a_rx.each_mut().map(|bytes| ReceiveSlot::new(bytes));
    let mut b_receives = b_rx.each_mut().map(|bytes| ReceiveSlot::new(bytes));
    let mut a = ChannelOwner::outbound(
        &a_instance,
        address(0, false),
        &mut a_sends,
        &mut a_receives,
        MonoInstant(0),
        Limits::default(),
    )?;
    let listener = address(0, true);
    let challenge = hash_port(&listener.port, &listener.local_peer);
    let mut b = ChannelOwner::incoming(
        &b_instance,
        listener,
        challenge,
        &mut b_sends,
        &mut b_receives,
        MonoInstant(0),
        Limits::default(),
    )?;
    a.phase = Phase::Ready;
    let mut wire = [0; 256];
    let _opening = emit(&mut b, 0, &mut wire)?;
    for _ in 0..4 {
        let _send = a.queue_send(&PAYLOAD, MonoInstant(0))?;
    }
    for _ in 0..4 {
        let (_, length) = emit(&mut a, 0, &mut wire)?;
        let _buffered = b.receive(
            b.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0),
        )?;
    }
    assert_eq!(b.ack(), (1, 7));
    let (_, length) = emit(&mut b, 0, &mut wire)?;
    assert_eq!(
        a.receive(
            a.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0)
        )?,
        Event::Acknowledged { sends: 3 }
    );
    while let Some(completion) = a.completion() {
        let send = completion.send;
        assert_ne!(send.mid(), 1);
        a.release_send(send)?;
    }
    for _ in 0..3 {
        let _send = a.queue_send(&PAYLOAD, MonoInstant(0))?;
    }
    for _ in 0..3 {
        let (_, length) = emit(&mut a, 0, &mut wire)?;
        let _event = b.receive(
            b.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0),
        )?;
    }
    assert_eq!(b.ack(), (1, 15));
    let (_, length) = emit(&mut b, 0, &mut wire)?;
    assert_eq!(
        a.receive(
            a.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(0)
        )?,
        Event::Acknowledged { sends: 1 }
    );
    let completion = a.completion().ok_or(Error::NotReady)?;
    assert_eq!(completion.send.mid(), 5);
    let send = completion.send;
    a.release_send(send)?;
    // The peer hands off 1..5, but every resulting cumulative ACK is lost.
    for mid in 1..=5 {
        let incoming = b.peek_delivery().ok_or(Error::NotReady)?;
        assert_eq!(incoming.received.mid(), mid);
        let token = incoming.received;
        let delivery = b.deliver(token)?;
        b.receive_done(delivery)?;
    }
    assert_eq!(b.ack(), (6, 0));
    // Original MID1 and rejected future MIDs6/7 now retry on the same channel.
    for _ in 0..3 {
        let (_, length) = emit(&mut a, 250_000, &mut wire)?;
        let _event = b.receive(
            b.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(250_000),
        )?;
    }
    for mid in 6..=7 {
        let incoming = b.peek_delivery().ok_or(Error::NotReady)?;
        assert_eq!(incoming.received.mid(), mid);
        let token = incoming.received;
        let delivery = b.deliver(token)?;
        b.receive_done(delivery)?;
    }
    assert_eq!(b.ack(), (8, 0));
    let (_, length) = emit(&mut b, 250_000, &mut wire)?;
    assert_eq!(
        a.receive(
            a.scope(),
            ChannelMessage::decode(&wire[..length])?,
            [7; 32],
            MonoInstant(250_000)
        )?,
        Event::Acknowledged { sends: 3 }
    );
    let mut original_accepted = false;
    while let Some(completion) = a.completion() {
        assert_eq!(completion.outcome, Outcome::PeerAccepted);
        original_accepted |= completion.send.mid() == 1;
        let send = completion.send;
        a.release_send(send)?;
    }
    assert!(original_accepted);
    assert_eq!(a.available_send(), 4);
    Ok(())
}
