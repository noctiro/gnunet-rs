//! Protocol framing, peer flow control and original-operation lifetime checks.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests assert protocol and original-operation resource invariants"
)]
use gnunet_client::transport::{
    ConnectionEpoch, Event, Instance, Peer, PeerId, Request, Response, SEND_WINDOW, SendOutcome,
    Start, TransportClient,
};
use gnunet_types::Error;

const A: PeerId = PeerId([0x11; 32]);
const B: PeerId = PeerId([0x22; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
type Client<'a> = TransportClient<'a, 2, 16, 8>;

fn connected<'a>(
    owner: &mut Client<'a>,
    epoch: ConnectionEpoch<'_>,
    id: PeerId,
) -> Result<Peer<'a>, Error> {
    let mut bytes = [0; 40];
    let len = Response::Connected(id).encode(&mut bytes)?;
    match owner.receive(epoch, &bytes[..len])? {
        Event::Connected(peer) => Ok(peer),
        _ => Err(Error::Malformed),
    }
}
fn response<'a, 'frame>(
    owner: &mut Client<'a>,
    epoch: ConnectionEpoch<'_>,
    value: Response<'_>,
    storage: &'frame mut [u8],
) -> Result<Event<'a, 'frame>, Error> {
    let len = value.encode(storage)?;
    owner.receive(epoch, &storage[..len])
}

#[test]
fn current_profile_round_trips_all_seven_messages_and_start_options() -> Result<(), Error> {
    let mut output = [0xa5; 128];
    for identity in [None, Some(A)] {
        for receive in [false, true] {
            let start = Start::new(identity, receive);
            assert_eq!(
                start.options,
                u32::from(identity.is_some()) | (u32::from(receive) << 1)
            );
            let request = Request::Start(start);
            let len = request.encode(&mut output)?;
            assert_eq!(len, 40);
            assert_eq!(&output[..4], &[0, 40, 1, 104]);
            assert_eq!(Request::decode(&output[..len])?, request);
        }
    }
    for request in [
        Request::Send {
            peer: A,
            priority: 0x0102_0304,
            message: &MESSAGE,
        },
        Request::ReceiveContinue {
            peer: A,
            increase: 7,
        },
    ] {
        let len = request.encode(&mut output)?;
        assert_eq!(Request::decode(&output[..len])?, request);
    }
    for value in [
        Response::Connected(A),
        Response::Disconnected(A),
        Response::SendCredit(A),
        Response::Received {
            peer: A,
            message: &MESSAGE,
        },
    ] {
        output.fill(0xa5);
        let len = value.encode(&mut output)?;
        assert_eq!(Response::decode(&output[..len])?, value);
        assert!(output[len..].iter().all(|byte| *byte == 0xa5));
    }
    Ok(())
}

#[test]
fn rejected_encodes_are_atomic_and_enforce_current_envelope_limit() -> Result<(), Error> {
    let mut output = [0xa5; 47];
    assert_eq!(
        Request::Send {
            peer: A,
            priority: 0,
            message: &MESSAGE
        }
        .encode(&mut output),
        Err(Error::Capacity)
    );
    assert_eq!(output, [0xa5; 47]);
    assert_eq!(
        Request::ReceiveContinue {
            peer: A,
            increase: 0
        }
        .encode(&mut output),
        Err(Error::InvalidInput)
    );
    assert_eq!(output, [0xa5; 47]);
    assert_eq!(
        Request::Start(Start {
            options: 4,
            identity: A
        })
        .encode(&mut output),
        Err(Error::Unsupported)
    );
    assert_eq!(output, [0xa5; 47]);
    assert!(
        Request::Send {
            peer: A,
            priority: 0,
            message: &[0, 5, 0, 0]
        }
        .encode(&mut output)
        .is_err()
    );
    assert_eq!(output, [0xa5; 47]);
    let mut huge = vec![0; 65_496];
    huge[..4].copy_from_slice(&[0xff, 0xd8, 0, 0]);
    let mut destination = vec![0xa5; 65_535];
    assert_eq!(
        Request::Send {
            peer: A,
            priority: 0,
            message: &huge
        }
        .encode(&mut destination),
        Err(Error::TooLarge)
    );
    assert!(destination.iter().all(|byte| *byte == 0xa5));
    huge.pop();
    huge[..2].copy_from_slice(&65_495u16.to_be_bytes());
    assert_eq!(
        Request::Send {
            peer: A,
            priority: 0,
            message: &huge
        }
        .encode(&mut destination)?,
        65_535
    );
    Ok(())
}

#[test]
fn truncation_unknown_reserved_trailing_and_nested_mismatch_are_rejected() -> Result<(), Error> {
    let mut buffer = [0; 64];
    for value in [
        Response::Connected(A),
        Response::Disconnected(A),
        Response::SendCredit(A),
        Response::Received {
            peer: A,
            message: &MESSAGE,
        },
    ] {
        let len = value.encode(&mut buffer)?;
        for cut in 0..len {
            assert!(Response::decode(&buffer[..cut]).is_err(), "cut {cut}");
        }
        assert!(Response::decode(&buffer[..len + 1]).is_err());
    }
    Response::Connected(A).encode(&mut buffer)?;
    buffer[7] = 1;
    assert_eq!(Response::decode(&buffer[..40]), Err(Error::Malformed));
    buffer[..4].copy_from_slice(&[0, 4, 0xff, 0xff]);
    assert_eq!(Response::decode(&buffer[..4]), Err(Error::Unsupported));
    let len = Response::Received {
        peer: A,
        message: &MESSAGE,
    }
    .encode(&mut buffer)?;
    buffer[37] = 7;
    assert!(Response::decode(&buffer[..len]).is_err());
    Ok(())
}

#[test]
fn send_windows_are_per_peer_and_actual_write_is_not_send_credit() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut owner = Client::new(&mut instance, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = owner.begin(&mut bytes)?;
    let a = connected(&mut owner, epoch, A)?;
    let b = connected(&mut owner, epoch, B)?;
    for _ in 0..SEND_WINDOW {
        let (send, len) = owner.prepare_send(a, 0, &MESSAGE, &mut bytes)?;
        assert_eq!(
            owner.send_bytes_written(send, len)?,
            Some(SendOutcome::Written)
        );
        assert_eq!(owner.take_send_result(send)?, SendOutcome::Written);
    }
    assert_eq!(owner.send_credit(a)?, 0);
    assert_eq!(
        owner.prepare_send(a, 0, &MESSAGE, &mut bytes),
        Err(Error::WouldBlock)
    );
    assert_eq!(owner.send_credit(b)?, SEND_WINDOW);
    let _other_send = owner.prepare_send(b, 0, &MESSAGE, &mut bytes)?;
    response(&mut owner, epoch, Response::SendCredit(A), &mut bytes)?;
    assert_eq!(owner.send_credit(a)?, 1);
    assert_eq!(owner.send_credit(b)?, SEND_WINDOW - 1);
    Ok(())
}

#[test]
fn foreign_instance_peer_epoch_send_and_receive_capabilities_are_rejected() -> Result<(), Error> {
    let (mut scope_a, mut scope_b) = (Instance::new(), Instance::new());
    let mut first = Client::new(&mut scope_a, Start::new(None, true))?;
    let mut second = Client::new(&mut scope_b, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch_a, _) = first.begin(&mut bytes)?;
    let (epoch_b, _) = second.begin(&mut bytes)?;
    let a = connected(&mut first, epoch_a, A)?;
    let b = connected(&mut second, epoch_b, A)?;
    assert_ne!(a, b);
    assert_ne!(epoch_a, epoch_b);
    assert_eq!(second.send_credit(a), Err(Error::Stale));
    assert_eq!(second.connection_lost(epoch_a), Err(Error::Stale));
    let (send_a, _) = first.prepare_send(a, 0, &MESSAGE, &mut bytes)?;
    let (send_b, _) = second.prepare_send(b, 0, &MESSAGE, &mut bytes)?;
    assert_ne!(send_a, send_b);
    assert_eq!(second.send_bytes_written(send_a, 1), Err(Error::Stale));
    let receive = match response(
        &mut first,
        epoch_a,
        Response::Received {
            peer: A,
            message: &MESSAGE,
        },
        &mut bytes,
    )? {
        Event::Received { receive, .. } => receive,
        _ => return Err(Error::Malformed),
    };
    assert_eq!(
        second.complete_receive(receive, &mut bytes),
        Err(Error::Stale)
    );
    assert_eq!(second.send_credit(b)?, 3);
    Ok(())
}

#[test]
fn moving_the_owner_preserves_original_tokens() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut original = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = original.begin(&mut bytes)?;
    let peer = connected(&mut original, epoch, A)?;
    let (send, len) = original.prepare_send(peer, 0, &MESSAGE, &mut bytes)?;
    let mut moved = original;
    moved.send_bytes_written(send, len)?;
    assert_eq!(moved.take_send_result(send)?, SendOutcome::Written);
    assert_eq!(moved.send_credit(peer)?, 3);
    Ok(())
}

#[test]
fn wholly_unsent_cancellation_restores_only_its_own_credit_once() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = owner.begin(&mut bytes)?;
    let peer = connected(&mut owner, epoch, A)?;
    let (send, _) = owner.prepare_send(peer, 0, &MESSAGE, &mut bytes)?;
    owner.cancel_unwritten(send)?;
    assert_eq!(owner.send_credit(peer)?, 4);
    assert_eq!(owner.cancel_unwritten(send), Err(Error::Conflict));
    assert_eq!(owner.take_send_result(send)?, SendOutcome::CancelledUnsent);
    assert_eq!(owner.take_send_result(send), Err(Error::Stale));
    Ok(())
}

#[test]
fn partial_cancel_drains_original_frame_and_waits_for_real_credit() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = owner.begin(&mut bytes)?;
    let peer = connected(&mut owner, epoch, A)?;
    let (send, len) = owner.prepare_send(peer, 0, &MESSAGE, &mut bytes)?;
    assert_eq!(owner.send_bytes_written(send, 3)?, None);
    assert_eq!(owner.cancel_unwritten(send), Err(Error::Conflict));
    owner.cancel_started(send)?;
    assert_eq!(owner.take_send_result(send), Err(Error::WouldBlock));
    assert_eq!(owner.send_remaining(send)?, len - 3);
    assert_eq!(
        owner.send_bytes_written(send, len - 3)?,
        Some(SendOutcome::CancelledAfterWrite)
    );
    assert_eq!(
        owner.take_send_result(send)?,
        SendOutcome::CancelledAfterWrite
    );
    assert_eq!(owner.send_credit(peer)?, 3);
    response(&mut owner, epoch, Response::SendCredit(A), &mut bytes)?;
    assert_eq!(owner.send_credit(peer)?, 4);
    Ok(())
}

#[test]
fn invalid_write_counts_and_short_send_preflight_do_not_mutate_state() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = owner.begin(&mut bytes)?;
    let peer = connected(&mut owner, epoch, A)?;
    let mut short = [0xa5; 47];
    assert_eq!(
        owner.prepare_send(peer, 0, &MESSAGE, &mut short),
        Err(Error::Capacity)
    );
    assert_eq!(owner.send_credit(peer)?, 4);
    assert_eq!(short, [0xa5; 47]);
    let (send, len) = owner.prepare_send(peer, 0, &MESSAGE, &mut bytes)?;
    assert_eq!(owner.send_bytes_written(send, 0), Err(Error::InvalidInput));
    assert_eq!(
        owner.send_bytes_written(send, len + 1),
        Err(Error::InvalidInput)
    );
    assert_eq!(owner.send_remaining(send)?, len);
    Ok(())
}

#[test]
fn receive_credit_is_explicit_atomic_and_not_duplicated() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = owner.begin(&mut bytes)?;
    connected(&mut owner, epoch, A)?;
    connected(&mut owner, epoch, B)?;
    let mut tokens = [None; 8];
    for (index, token) in tokens.iter_mut().enumerate() {
        let peer = if index < 4 { A } else { B };
        match response(
            &mut owner,
            epoch,
            Response::Received {
                peer,
                message: &MESSAGE,
            },
            &mut bytes,
        )? {
            Event::Received {
                receive, message, ..
            } => {
                assert_eq!(message, MESSAGE);
                *token = Some(receive);
            }
            _ => return Err(Error::Malformed),
        }
    }
    assert_eq!(
        response(
            &mut owner,
            epoch,
            Response::Received {
                peer: A,
                message: &MESSAGE
            },
            &mut bytes
        ),
        Err(Error::Capacity)
    );
    let token = tokens[0].ok_or(Error::NotFound)?;
    let mut short = [0xa5; 39];
    assert_eq!(
        owner.complete_receive(token, &mut short),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0xa5; 39]);
    let len = owner.complete_receive(token, &mut bytes)?;
    assert_eq!(
        Request::decode(&bytes[..len])?,
        Request::ReceiveContinue {
            peer: A,
            increase: 1
        }
    );
    assert_eq!(owner.complete_receive(token, &mut bytes), Err(Error::Stale));
    response(
        &mut owner,
        epoch,
        Response::Received {
            peer: A,
            message: &MESSAGE,
        },
        &mut bytes,
    )?;
    Ok(())
}

#[test]
fn connection_loss_reports_each_peer_and_invalidates_old_receive_and_epoch() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (old_epoch, _) = owner.begin(&mut bytes)?;
    let old_peer = connected(&mut owner, old_epoch, A)?;
    connected(&mut owner, old_epoch, B)?;
    let (send, _) = owner.prepare_send(old_peer, 0, &MESSAGE, &mut bytes)?;
    owner.send_bytes_written(send, 2)?;
    let receive = match response(
        &mut owner,
        old_epoch,
        Response::Received {
            peer: A,
            message: &MESSAGE,
        },
        &mut bytes,
    )? {
        Event::Received { receive, .. } => receive,
        _ => return Err(Error::Malformed),
    };
    owner.connection_lost(old_epoch)?;
    assert_eq!(owner.take_send_result(send)?, SendOutcome::ConnectionLost);
    assert_eq!(
        owner.complete_receive(receive, &mut bytes),
        Err(Error::Stale)
    );
    assert_eq!(owner.next_lost_peer().map(|peer| peer.identity()), Some(A));
    assert_eq!(owner.next_lost_peer().map(|peer| peer.identity()), Some(B));
    assert_eq!(owner.next_lost_peer(), None);
    let (new_epoch, _) = owner.begin(&mut bytes)?;
    assert_ne!(old_epoch, new_epoch);
    let new_peer = connected(&mut owner, new_epoch, A)?;
    assert_ne!(old_peer, new_peer);
    assert_eq!(owner.send_credit(old_peer), Err(Error::Stale));
    assert_eq!(owner.connection_lost(old_epoch), Err(Error::Stale));
    assert_eq!(owner.send_credit(new_peer)?, 4);
    Ok(())
}

#[test]
fn disconnect_one_peer_preserves_other_peers_and_late_credit_is_ignored() -> Result<(), Error> {
    let mut scope = Instance::new();
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0; 128];
    let (epoch, _) = owner.begin(&mut bytes)?;
    let a = connected(&mut owner, epoch, A)?;
    let b = connected(&mut owner, epoch, B)?;
    let (send, len) = owner.prepare_send(a, 0, &MESSAGE, &mut bytes)?;
    owner.send_bytes_written(send, 1)?;
    assert_eq!(
        response(&mut owner, epoch, Response::Disconnected(A), &mut bytes)?,
        Event::Disconnected(a)
    );
    assert_eq!(owner.send_credit(b)?, 4);
    assert_eq!(
        response(&mut owner, epoch, Response::SendCredit(A), &mut bytes)?,
        Event::LateSendCredit(A)
    );
    owner.send_bytes_written(send, len - 1)?;
    assert_eq!(owner.take_send_result(send)?, SendOutcome::PeerDisconnected);
    assert_eq!(owner.next_lost_peer(), None);
    Ok(())
}

#[test]
fn duplicate_connect_and_unearned_credit_retire_the_original_mq() -> Result<(), Error> {
    for duplicate_connect in [true, false] {
        let mut scope = Instance::new();
        let mut owner = Client::new(&mut scope, Start::new(None, true))?;
        let mut bytes = [0; 128];
        let (epoch, _) = owner.begin(&mut bytes)?;
        connected(&mut owner, epoch, A)?;
        let value = if duplicate_connect {
            Response::Connected(A)
        } else {
            Response::SendCredit(A)
        };
        assert_eq!(
            response(&mut owner, epoch, value, &mut bytes),
            Err(Error::Malformed)
        );
        assert_eq!(owner.connection_lost(epoch), Err(Error::Closed));
        assert_eq!(owner.next_lost_peer().map(|peer| peer.identity()), Some(A));
    }
    Ok(())
}

#[test]
fn unknown_frames_and_unannounced_payload_do_not_create_processing_success() -> Result<(), Error> {
    for unknown in [true, false] {
        let mut scope = Instance::new();
        let mut owner = Client::new(&mut scope, Start::new(None, true))?;
        let mut bytes = [0; 128];
        let (epoch, _) = owner.begin(&mut bytes)?;
        if unknown {
            assert_eq!(
                owner.receive(epoch, &[0, 4, 0xff, 0xff]),
                Err(Error::Unsupported)
            );
        } else {
            assert_eq!(
                response(
                    &mut owner,
                    epoch,
                    Response::Received {
                        peer: A,
                        message: &MESSAGE
                    },
                    &mut bytes
                ),
                Err(Error::Malformed)
            );
        }
        assert_eq!(owner.connection_lost(epoch), Err(Error::Closed));
        assert_eq!(owner.next_lost_peer(), None);
    }
    Ok(())
}

#[test]
fn start_preflight_and_resource_bounds_never_publish_a_partial_epoch() -> Result<(), Error> {
    let mut scope = Instance::new();
    assert!(matches!(
        TransportClient::<2, 1, 7>::new(&mut scope, Start::new(None, true)),
        Err(Error::Capacity)
    ));
    let mut owner = Client::new(&mut scope, Start::new(None, true))?;
    let mut bytes = [0xa5; 39];
    assert_eq!(owner.begin(&mut bytes), Err(Error::Capacity));
    assert_eq!(bytes, [0xa5; 39]);
    let (epoch, _) = owner.begin(&mut [0; 40])?;
    assert_eq!(epoch.value(), 1);
    assert_eq!(owner.begin(&mut [0; 40]), Err(Error::Conflict));
    Ok(())
}
