//! Current C CORE layout boundaries and header-preview distinction.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol tests assert independently specified boundaries"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    MessageHeader,
    core::{
        self, ClassOrder, Direction, KxState, MessageTypes, PeerClass, PeerId, Request, Response,
        Traffic,
    },
    message_type,
};
const PEER: PeerId = PeerId([0x11; 32]);
const MSG: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];

#[test]
fn current_request_fields_have_exact_sizes_and_network_order() -> Result<(), Error> {
    let mut out = [0xa5; 128];
    let n = Request::Init {
        options: 4,
        types: MessageTypes::new(&[0x1234, 0x5678]),
    }
    .encode(&mut out)?;
    assert_eq!(
        &out[..n],
        &[0, 12, 0, 64, 0, 0, 0, 4, 0x12, 0x34, 0x56, 0x78]
    );
    assert_eq!(
        Request::decode(&out[..n])?,
        Request::Init {
            options: 4,
            types: MessageTypes::new(&[0x1234, 0x5678])
        }
    );
    let request = Request::SendRequest {
        priority: 0x0102_0304,
        deadline: 0x0506_0708_090a_0b0c,
        peer: PEER,
        size: 8,
        request_id: 0x1234,
    };
    let n = request.encode(&mut out)?;
    assert_eq!(n, 56);
    assert_eq!(
        &out[..16],
        &[0, 56, 0, 74, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    );
    assert_eq!(&out[48..56], &[0, 0, 0, 0, 0, 8, 0x12, 0x34]);
    assert_eq!(Request::decode(&out[..n])?, request);
    let n = Request::Monitor.encode(&mut out)?;
    assert_eq!(&out[..n], &[0, 4, 0, 78]);
    Ok(())
}

#[test]
fn class_abi_is_explicit_but_monitor_fields_are_always_network_order() -> Result<(), Error> {
    let mut out = [0; 64];
    for order in [ClassOrder::Little, ClassOrder::Big] {
        let response = Response::InitReply {
            identity: PEER,
            class: PeerClass::SERVER,
        };
        let n = response.encode(&mut out, order)?;
        assert_eq!(n, 44);
        assert_eq!(
            &out[40..44],
            match order {
                ClassOrder::Little => &[5, 0, 0, 0],
                ClassOrder::Big => &[0, 0, 0, 5],
            }
        );
        assert_eq!(Response::decode(&out[..n], order)?, response);
    }
    let notification = Response::Monitor {
        state: KxState(4),
        peer: PEER,
        timeout: 0x0102_0304_0506_0708,
    };
    let n = notification.encode(&mut out, ClassOrder::Little)?;
    assert_eq!(n, 48);
    assert_eq!(&out[4..8], &[0, 0, 0, 4]);
    assert_eq!(&out[40..48], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Response::decode(&out[..n], ClassOrder::Big)?, notification);
    Ok(())
}

#[test]
fn complete_and_header_only_traffic_remain_distinct_and_directional() -> Result<(), Error> {
    let mut out = [0; 64];
    for direction in [Direction::Inbound, Direction::Outbound] {
        for traffic in [
            Traffic::Full(&MSG),
            Traffic::Header(MessageHeader::new(message_type::TEST, 4)?),
        ] {
            let response = Response::Traffic {
                direction,
                peer: PEER,
                traffic,
            };
            let n = response.encode(&mut out, ClassOrder::Little)?;
            assert_eq!(
                n,
                if matches!(traffic, Traffic::Full(_)) {
                    44
                } else {
                    40
                }
            );
            assert_eq!(Response::decode(&out[..n], ClassOrder::Little)?, response);
        }
    }
    Response::Traffic {
        direction: Direction::Inbound,
        peer: PEER,
        traffic: Traffic::Full(&MSG),
    }
    .encode(&mut out, ClassOrder::Little)?;
    out[37] = 7;
    assert!(Response::decode(&out[..44], ClassOrder::Little).is_err());
    Ok(())
}

#[test]
fn send_allows_complete_message_sequences_and_rejects_partial_suffix_atomically()
-> Result<(), Error> {
    let mut messages = MSG.to_vec();
    messages.extend_from_slice(&[0, 4, 0x12, 0x34]);
    let mut out = [0xa5; 128];
    let request = Request::Send {
        peer: PEER,
        priority: 7,
        deadline: u64::MAX,
        messages: &messages,
    };
    let n = request.encode(&mut out)?;
    assert_eq!(n, 60);
    assert_eq!(Request::decode(&out[..n])?, request);
    out.fill(0xa5);
    messages.pop();
    assert!(
        Request::Send {
            peer: PEER,
            priority: 0,
            deadline: 0,
            messages: &messages
        }
        .encode(&mut out)
        .is_err()
    );
    assert_eq!(out, [0xa5; 128]);
    Ok(())
}

#[test]
fn full_wire_limit_and_subscription_limit_have_no_silent_truncation() -> Result<(), Error> {
    let mut payload = vec![0; core::MAX_SEND_BYTES];
    payload[..2].copy_from_slice(&(core::MAX_SEND_BYTES as u16).to_be_bytes());
    let mut out = vec![0xa5; 65535];
    assert_eq!(
        Request::Send {
            peer: PEER,
            priority: 0,
            deadline: 0,
            messages: &payload
        }
        .encode(&mut out)?,
        65535
    );
    payload.push(0);
    let len = payload.len() as u16;
    payload[..2].copy_from_slice(&len.to_be_bytes());
    out.fill(0xa5);
    assert_eq!(
        Request::Send {
            peer: PEER,
            priority: 0,
            deadline: 0,
            messages: &payload
        }
        .encode(&mut out),
        Err(Error::TooLarge)
    );
    assert!(out.iter().all(|byte| *byte == 0xa5));
    let types = vec![0x1234; 32763];
    assert_eq!(
        Request::Init {
            options: 0,
            types: MessageTypes::new(&types)
        }
        .encode(&mut out)?,
        65534
    );
    let types = vec![0; 32764];
    out.fill(0xa5);
    assert_eq!(
        Request::Init {
            options: 0,
            types: MessageTypes::new(&types)
        }
        .encode(&mut out),
        Err(Error::TooLarge)
    );
    assert!(out.iter().all(|byte| *byte == 0xa5));
    Ok(())
}

#[test]
fn fixed_message_truncation_reserved_unknown_and_odd_type_lists_are_rejected() -> Result<(), Error>
{
    let mut out = [0; 64];
    for response in [
        Response::InitReply {
            identity: PEER,
            class: PeerClass::UNKNOWN,
        },
        Response::Connected {
            peer: PEER,
            class: PeerClass::DESKTOP,
        },
        Response::Disconnected(PEER),
        Response::SendReady {
            peer: PEER,
            request_id: 1,
            size: 0,
        },
        Response::Monitor {
            peer: PEER,
            state: KxState(8),
            timeout: 0,
        },
    ] {
        let n = response.encode(&mut out, ClassOrder::Little)?;
        for cut in 0..n {
            assert!(Response::decode(&out[..cut], ClassOrder::Little).is_err());
        }
        assert!(Response::decode(&out[..n + 1], ClassOrder::Little).is_err());
    }
    Response::InitReply {
        identity: PEER,
        class: PeerClass::UNKNOWN,
    }
    .encode(&mut out, ClassOrder::Little)?;
    out[7] = 1;
    assert_eq!(
        Response::decode(&out[..44], ClassOrder::Little),
        Err(Error::Malformed)
    );
    assert_eq!(
        Request::decode(&[0, 9, 0, 64, 0, 0, 0, 0, 1]),
        Err(Error::Malformed)
    );
    for kind in [69_u16, 1811, 65535] {
        let [a, b] = kind.to_be_bytes();
        assert_eq!(
            Response::decode(&[0, 4, a, b], ClassOrder::Little),
            Err(Error::Unsupported)
        );
    }
    Ok(())
}
