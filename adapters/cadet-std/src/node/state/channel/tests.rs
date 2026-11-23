//! Post-authentication channel input and actual retained Book frame custody.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Pure cancellation regression asserts exact original channel and Book effects without a transport or authentication claim"
)]
use super::*;
use gnunet_cadet::{connection, peer::ChannelOwner};
use gnunet_wire::official::cadet_peer::{EncryptedBody, PathPeers, PeerMessage};

#[test]
fn remote_destroy_revokes_queued_output_before_core_and_keeps_started_debt()
-> Result<(), ProtocolError> {
    for submitted in [false, true] {
        let mut instance = connection::Instance::new();
        let mut neighbors = [connection::NeighborSlot::new(); 1];
        let mut routes = [connection::RouteSlot::<2>::new(); 2];
        let mut origins = [connection::OriginSlot::new(); 1];
        let mut bytes = [[0; 512]; 4];
        let mut frames = bytes
            .each_mut()
            .map(|bytes| connection::FrameSlot::new(bytes));
        let mut book = Book::new(
            &mut instance,
            [2; 32],
            &mut neighbors,
            &mut routes,
            &mut origins,
            &mut frames,
            MonoInstant(0),
            connection::Limits::default(),
        )?;
        let neighbor = book.neighbor_up([1; 32])?;
        book.neighbor_ready(neighbor, true)?;
        let path = [[1; 32], [2; 32]];
        let mut ready = Vec::new();
        for cid in [[3; 32], [4; 32]] {
            let connection::Event::Created { route, .. } = book.receive(
                neighbor,
                PeerMessage::ConnectionCreate {
                    options_bytes: [2, 0, 0, 0],
                    has_monotime_bytes: [0; 4],
                    monotime: 0,
                    monotime_signature: [0; 64],
                    connection: cid,
                    path: PathPeers::new(&path),
                },
                MonoInstant(0),
            )?
            else {
                return Err(ProtocolError::Malformed);
            };
            let frame = book.next_frame().ok_or(ProtocolError::NotReady)?.frame;
            let attempt = book.start(frame)?;
            book.exposed(attempt)?;
            book.settle(attempt, true, MonoInstant(0))?;
            book.release_frame(frame)?;
            book.neighbor_ready(neighbor, true)?;
            ready.push(route);
        }

        let domain = peer::Instance::new();
        let mut sent_bytes = [[0; 8]; 1];
        let mut received_bytes = [[0; 8]; 1];
        let mut sends = sent_bytes
            .each_mut()
            .map(|bytes| peer::SendSlot::new(bytes));
        let mut receives = received_bytes
            .each_mut()
            .map(|bytes| peer::ReceiveSlot::new(bytes));
        let address = peer::Address {
            channel: 7,
            local_peer: [2; 32],
            remote_peer: [1; 32],
            port: [5; 64],
        };
        let mut owner = ChannelOwner::incoming(
            &domain,
            address,
            peer::hash_port(&address.port, &address.local_peer),
            &mut sends,
            &mut receives,
            MonoInstant(0),
            peer::Limits {
                window: 1,
                payload_bytes: 8,
                ..peer::Limits::default()
            },
        )?;
        let mut plaintext = [0; 128];
        let ack = owner
            .prepare_next(MonoInstant(0), &mut plaintext)?
            .ok_or(ProtocolError::NotReady)?
            .attempt();
        owner.exposed(ack)?;
        owner.settle(
            ack,
            peer::Emission::Sent {
                connection: [3; 32],
            },
            MonoInstant(0),
        )?;
        let send = owner.queue_send(&[0, 8, 0x12, 0x34, 1, 2, 3, 4], MonoInstant(0))?;
        let original = owner
            .prepare_next(MonoInstant(0), &mut plaintext)?
            .ok_or(ProtocolError::NotReady)?
            .attempt();
        let mut other_sent = [0; 8];
        let mut other_received = [0; 8];
        let mut other_sends = [peer::SendSlot::new(&mut other_sent)];
        let mut other_receives = [peer::ReceiveSlot::new(&mut other_received)];
        let other_address = peer::Address {
            channel: 8,
            ..address
        };
        let mut other = ChannelOwner::incoming(
            &domain,
            other_address,
            peer::hash_port(&other_address.port, &other_address.local_peer),
            &mut other_sends,
            &mut other_receives,
            MonoInstant(0),
            peer::Limits {
                window: 1,
                payload_bytes: 8,
                ..peer::Limits::default()
            },
        )?;
        let other_attempt = other
            .prepare_next(MonoInstant(0), &mut plaintext)?
            .ok_or(ProtocolError::NotReady)?
            .attempt();

        // Frame bytes are opaque here: this model grants no AEAD or native
        // authentication receipt. The Book enforces its real route/custody.
        let body = [0; 32];
        let original_frame = book.queue_payload(
            ready[0],
            PeerMessage::Encrypted {
                reserved: 0,
                connection: ready[0].connection(),
                header_mac: [0; 16],
                encrypted_header: [0; 40],
                body: EncryptedBody::new(&body)?,
            },
            MonoInstant(0),
        )?;
        let unrelated = book.queue_payload(
            ready[1],
            PeerMessage::Encrypted {
                reserved: 0,
                connection: ready[1].connection(),
                header_mac: [0; 16],
                encrypted_header: [0; 40],
                body: EncryptedBody::new(&body)?,
            },
            MonoInstant(0),
        )?;
        let physical = if submitted {
            let attempt = book.start(original_frame)?;
            book.exposed(attempt)?;
            owner.exposed(original)?;
            Some(attempt)
        } else {
            None
        };
        let pending = [
            Some(Pending {
                effect: Effect::Channel {
                    slot: 0,
                    attempt: original,
                    frame: original_frame,
                    route: ready[0],
                },
                started: submitted,
            }),
            Some(Pending {
                effect: Effect::Channel {
                    slot: 1,
                    attempt: other_attempt,
                    frame: unrelated,
                    route: ready[1],
                },
                started: false,
            }),
        ];
        let mut channel = Channel {
            owner: Some(owner),
            observations: None,
            free: None,
            tunnel: 0,
            crypto_generation: None,
            open: None,
            open_hard: None,
            binding: None,
            admitted: [None; 4],
            delivery: None,
            close: None,
            closing: false,
            lost: false,
        };
        assert_eq!(
            channel.receive(
                0,
                &pending,
                &mut book,
                ChannelMessage::Destroy {
                    reserved: 0,
                    channel: 7
                },
                [3; 32],
                MonoInstant(1),
            )?,
            peer::Event::Destroyed {
                pending: Some(original)
            }
        );
        assert!(channel.closing && channel.lost);
        let owner = channel.owner.as_mut().ok_or(ProtocolError::NotReady)?;
        assert_eq!(owner.pending(), Some(original));
        assert!(matches!(
            owner.completion_for(send),
            Err(ProtocolError::WouldBlock)
        ));
        if let Some(physical) = physical {
            assert!(book.completion().is_none());
            book.settle(physical, false, MonoInstant(2))?;
            book.neighbor_ready(neighbor, true)?;
        } else {
            let completion = book.completion().ok_or(ProtocolError::NotReady)?;
            assert_eq!(completion.frame, original_frame);
            assert_eq!(completion.outcome, connection::Outcome::Unsent);
            assert!(matches!(
                book.start(original_frame),
                Err(ProtocolError::WouldBlock)
            ));
        }
        owner.settle(original, peer::Emission::Failed, MonoInstant(2))?;
        assert_eq!(
            owner.completion_for(send)?.outcome,
            if submitted {
                peer::Outcome::DeliveryUnknown
            } else {
                peer::Outcome::RetiredUnsent
            }
        );
        assert_eq!(book.next_frame().map(|next| next.frame), Some(unrelated));
        assert_eq!(other.pending(), Some(other_attempt));
        assert_eq!(other.phase(), peer::Phase::Ready);
        assert!(
            owner
                .prepare_next(MonoInstant(2), &mut plaintext)?
                .is_none()
        );
    }
    Ok(())
}
