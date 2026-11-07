//! Complete official1217 extent is independent from a local64-entry ACK batch.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Wire boundaries are finite assertions with fallible encoding"
)]
use gnunet_transport::p2p::{MAX_ACKNOWLEDGEMENTS, acknowledgements, encode_acknowledgements};
use gnunet_types::Error;
#[test]
fn ack_sixty_five_and_the_full_u16_extent_preserve_every_opaque_id_and_delay() -> Result<(), Error>
{
    assert_eq!(MAX_ACKNOWLEDGEMENTS, 2730);
    for count in [1, 64, 65, MAX_ACKNOWLEDGEMENTS] {
        let entries: Vec<_> = (0..count)
            .map(|i| {
                let mut id = [0; 16];
                id[..8].copy_from_slice(&(i as u64).to_ne_bytes());
                id[8..].copy_from_slice(&(!(i as u64)).to_ne_bytes());
                (0x1020_3040_5060_7080 + (i as u64), id)
            })
            .collect();
        let mut out = vec![0; 8 + 24 * count];
        assert_eq!(
            encode_acknowledgements(u32::MAX, &entries, &mut out)?,
            out.len()
        );
        assert_eq!(
            &out[..4],
            &[(out.len() >> 8) as u8, out.len() as u8, 4, 193]
        );
        assert_eq!(&out[4..8], &u32::MAX.to_be_bytes());
        assert_eq!(&out[8..16], &entries[0].0.to_be_bytes());
        assert_eq!(acknowledgements(&out)?.collect::<Vec<_>>(), entries);
    }
    Ok(())
}
#[test]
fn ack_common_header_empty_partial_and_oversized_entries_refuse_without_changing_output()
-> Result<(), Error> {
    let mut out = [0xa5; 32];
    assert_eq!(
        encode_acknowledgements(0, &[], &mut out),
        Err(Error::Malformed)
    );
    assert_eq!(out, [0xa5; 32]);
    let too_many = vec![(0, [0; 16]); MAX_ACKNOWLEDGEMENTS + 1];
    assert_eq!(
        encode_acknowledgements(0, &too_many, &mut out),
        Err(Error::TooLarge)
    );
    assert_eq!(out, [0xa5; 32]);
    encode_acknowledgements(0, &[(0, [0; 16])], &mut out)?;
    let valid = out;
    // Bytes4..8 are an unrestricted ACK counter, not a reserved-zero field.
    out[4..8].copy_from_slice(&0x8123_4567u32.to_be_bytes());
    assert_eq!(acknowledgements(&out)?.count(), 1);
    for invalid in [
        vec![0, 8, 4, 193, 0, 0, 0, 0],
        vec![0, 7, 4, 193, 0, 0, 0],
        vec![0, 9, 4, 193, 0, 0, 0, 0, 0],
        vec![0, 32, 4, 192]
            .into_iter()
            .chain(valid[4..].iter().copied())
            .collect(),
        vec![0, 31, 4, 193]
            .into_iter()
            .chain(valid[4..].iter().copied())
            .collect(),
    ] {
        assert!(acknowledgements(&invalid).is_err());
    }
    let mut truncated = [0xa5; 31];
    assert_eq!(
        encode_acknowledgements(0, &[(0, [0; 16])], &mut truncated),
        Err(Error::Capacity)
    );
    assert_eq!(truncated, [0xa5; 31]);
    Ok(())
}

#[test]
fn reliable_wrapper_and_actual_characteristic_values_preserve_complete_noalloc_wire_extent()
-> Result<(), Error> {
    use gnunet_transport::{
        communicator::{Characteristics, Request},
        p2p::Reliable,
    };
    for (value, expected) in [
        (0u32, Characteristics::Unknown),
        (1, Characteristics::Reliable),
        (2, Characteristics::Unreliable),
    ] {
        let mut register = [0; 16];
        register[..4].copy_from_slice(&[0, 16, 4, 187]);
        register[4..8].copy_from_slice(&value.to_be_bytes());
        register[12..].copy_from_slice(b"udp\0");
        assert!(
            matches!(Request::decode(&register)?,Request::Register{characteristics,..} if characteristics==expected)
        );
        register[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(Request::decode(&register), Err(Error::Malformed));
    }
    for n in [4usize, 65511] {
        let mut inner = vec![0x73; n];
        inner[..2].copy_from_slice(&(n as u16).to_be_bytes());
        inner[2..4].copy_from_slice(&0u16.to_be_bytes());
        let mut out = vec![0; 24 + n];
        let boxed = Reliable {
            countdown: u32::MAX,
            uuid: [0x21; 16],
            message: &inner,
        };
        assert_eq!(boxed.encode(&mut out)?, 24 + n);
        assert_eq!(Reliable::decode(&out)?, boxed);
    }
    Ok(())
}
#[test]
fn reliable_wrapper_bad_inner_overflow_and_short_output_refuse_before_output_changes()
-> Result<(), Error> {
    use gnunet_transport::p2p::Reliable;
    let inner = [0, 4, 0, 0];
    let mut short = [0xa5; 27];
    assert_eq!(
        Reliable {
            countdown: 0,
            uuid: [0; 16],
            message: &inner
        }
        .encode(&mut short),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0xa5; 27]);
    let mut big = vec![0; 65512];
    big[..2].copy_from_slice(&65512u16.to_be_bytes());
    assert_eq!(
        Reliable {
            countdown: 0,
            uuid: [0; 16],
            message: &big
        }
        .encode(&mut short),
        Err(Error::TooLarge)
    );
    assert_eq!(short, [0xa5; 27]);
    assert!(
        Reliable {
            countdown: 0,
            uuid: [0; 16],
            message: &[0, 5, 0, 0]
        }
        .encode(&mut short)
        .is_err()
    );
    assert_eq!(short, [0xa5; 27]);
    for n in [4usize, 23, 24, 27] {
        let mut bad = vec![0; n];
        bad[..2].copy_from_slice(&(n as u16).to_be_bytes());
        bad[2..4].copy_from_slice(&1216u16.to_be_bytes());
        assert!(Reliable::decode(&bad).is_err());
    }
    Ok(())
}

#[test]
fn communicator_domain_mapping_borrows_official_fields_and_preserves_opaque_bits()
-> Result<(), Error> {
    use gnunet_transport::{
        PeerId,
        communicator::{Characteristics, Request},
    };
    use gnunet_wire::official::communicator::{Queue as WireQueue, Request as Wire};
    let inner = [0, 4, 0, 71];
    let peer = [0x93; 32];
    let neighbour = [0x41; 32];
    let address = [0xff, 0xfe];
    let queue = WireQueue {
        id: u32::MAX,
        peer,
        network: u32::MAX,
        mtu: u32::MAX,
        length: u64::MAX,
        priority: u32::MAX,
        status: 1,
    };
    let requests = [
        Wire::Register {
            characteristics: Characteristics::Unreliable,
            can_burst: true,
            prefix: &address,
        },
        Wire::AddAddress {
            id: u32::MAX,
            validity: u64::MAX,
            network: u32::MAX,
            address: &address,
        },
        Wire::QueueSetup(queue, &address),
        Wire::QueueUpdate(queue),
        Wire::QueueDown(u32::MAX, peer),
        Wire::Incoming {
            flow_control: true,
            flow_id: [0x8a; 8],
            validity: u64::MAX,
            peer,
            neighbour,
            message: &inner,
        },
        Wire::Backchannel {
            peer,
            message: &inner,
            communicator: &address,
        },
    ];
    for wire in requests {
        let mut bytes = vec![0; wire.encoded_len()?];
        wire.encode(&mut bytes)?;
        match (wire, Request::decode(&bytes)?) {
            (
                Wire::Register {
                    characteristics,
                    can_burst,
                    prefix,
                },
                Request::Register {
                    characteristics: actual,
                    can_burst: burst,
                    prefix: word,
                },
            ) => {
                assert_eq!((actual, burst, word), (characteristics, can_burst, prefix));
                assert_eq!(word.as_ptr(), bytes[12..].as_ptr());
            }
            (
                Wire::AddAddress {
                    id,
                    validity,
                    network,
                    address,
                },
                Request::AddAddress {
                    id: actual,
                    validity: life,
                    network: net,
                    address: word,
                },
            ) => {
                assert_eq!((actual, life, net, word), (id, validity, network, address));
                assert_eq!(word.as_ptr(), bytes[20..].as_ptr());
            }
            (
                Wire::QueueSetup(q, address),
                Request::QueueSetup {
                    queue,
                    address: word,
                },
            ) => {
                assert_eq!(
                    (
                        queue.id,
                        queue.peer,
                        queue.network,
                        queue.mtu,
                        queue.length,
                        queue.priority,
                        queue.status
                    ),
                    (
                        q.id,
                        PeerId(peer),
                        q.network,
                        q.mtu,
                        q.length,
                        q.priority,
                        q.status
                    )
                );
                assert_eq!(word, address);
                assert_eq!(word.as_ptr(), bytes[64..].as_ptr());
            }
            (Wire::QueueUpdate(q), Request::QueueUpdate(queue)) => assert_eq!(
                (queue.id, queue.peer, queue.length, queue.status),
                (q.id, PeerId(peer), q.length, q.status)
            ),
            (
                Wire::QueueDown(id, peer),
                Request::QueueDown {
                    id: actual,
                    peer: target,
                },
            ) => assert_eq!((actual, target), (id, PeerId(peer))),
            (
                Wire::Incoming {
                    flow_control,
                    flow_id,
                    validity,
                    peer,
                    neighbour,
                    message,
                },
                Request::Incoming {
                    flow_control: flag,
                    flow_id: id,
                    validity: life,
                    peer: target,
                    neighbour: carrier,
                    message: body,
                },
            ) => {
                assert_eq!(
                    (flag, id, life, target, carrier, body),
                    (
                        flow_control,
                        flow_id,
                        validity,
                        PeerId(peer),
                        PeerId(neighbour),
                        message
                    )
                );
                assert_eq!(body.as_ptr(), bytes[88..].as_ptr());
            }
            (
                Wire::Backchannel {
                    peer,
                    message,
                    communicator,
                },
                Request::Backchannel {
                    peer: target,
                    message: body,
                    communicator: word,
                },
            ) => {
                assert_eq!((target, body, word), (PeerId(peer), message, communicator));
                assert_eq!(body.as_ptr(), bytes[40..].as_ptr());
                assert_eq!(word.as_ptr(), bytes[44..].as_ptr());
            }
            _ => return Err(Error::Conflict),
        }
    }
    for status in [i32::MIN, -1, 0, 1, i32::MAX] {
        let request = Wire::Sent {
            message_id: [0xa5; 8],
            queue: u32::MAX,
            peer,
            status,
        };
        let mut bytes = vec![0; request.encoded_len()?];
        request.encode(&mut bytes)?;
        assert_eq!(
            Request::decode(&bytes)?,
            Request::Sent {
                message_id: [0xa5; 8],
                queue: u32::MAX,
                peer: PeerId(peer),
                status: status as u32
            }
        );
    }
    Ok(())
}

#[test]
fn communicator_domain_and_shared_codec_use_the_same_per_field_nul_contract() -> Result<(), Error> {
    use gnunet_transport::communicator::Request;
    use gnunet_wire::official::communicator::Request as Wire;
    for (kind, prefix) in [(1211u16, 12usize), (1200, 20), (1204, 64), (1212, 44)] {
        for word in [b"unix\0tail\0".as_slice(), &[0xff, 0, 0xfe, 0]] {
            let mut bytes = vec![0; prefix + word.len()];
            let length = bytes.len() as u16;
            bytes[..2].copy_from_slice(&length.to_be_bytes());
            bytes[2..4].copy_from_slice(&kind.to_be_bytes());
            if kind == 1204 {
                bytes[44..48].copy_from_slice(&4u32.to_be_bytes());
            }
            if kind == 1212 {
                bytes[40..44].copy_from_slice(&[0, 4, 0, 71]);
            }
            bytes[prefix..].copy_from_slice(word);
            assert_eq!(Wire::decode(&bytes).is_ok(), kind == 1212);
            assert_eq!(Request::decode(&bytes).is_ok(), kind == 1212);
            if kind == 1212 {
                let Request::Backchannel { communicator, .. } = Request::decode(&bytes)? else {
                    return Err(Error::Malformed);
                };
                let end = word.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
                assert_eq!(communicator, &word[..end]);
            }
        }
    }
    Ok(())
}
