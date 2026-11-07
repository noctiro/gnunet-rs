//! Independent public TRANSPORT server decoder checks the UDP client's exact IPC.
#![cfg(feature = "transport")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite cross-layer wire assertions use the existing independent transport decoder."
)]
use gnunet_transport::{
    PeerId,
    communicator::{Characteristics, Request},
};
use gnunet_types::Error;
use gnunet_udp_communicator_core::wire::Ack;
use gnunet_udp_communicator_host::transport::{self, Event, Queue};
fn message() -> [u8; 8] {
    [0, 8, 0, 0, 0, 0, 0, 1]
}
#[test]
fn udp_registration_and_original_queue_grants_decode_at_public_server() -> Result<(), Error> {
    let mut out = [0xa5; 512];
    let n = transport::register(false, &mut out)?;
    assert_eq!(
        Request::decode(&out[..n])?,
        Request::Register {
            characteristics: Characteristics::Unreliable,
            can_burst: false,
            prefix: b"udp"
        }
    );
    let queue = Queue {
        id: 7,
        peer: [3; 32],
        network: 2,
        mtu: 1300,
        length: u64::MAX,
        priority: 0,
    };
    let n = queue.setup(b"udp-127.0.0.1:1234", &mut out)?;
    assert!(
        matches!(Request::decode(&out[..n])?,Request::QueueSetup{queue:q,address:b"udp-127.0.0.1:1234"} if q.id==7&&q.peer==PeerId([3;32])&&q.mtu==1300&&q.length==u64::MAX&&q.status==0)
    );
    let update = Queue {
        length: 64,
        priority: 1,
        mtu: 1404,
        ..queue
    };
    let n = update.update(&mut out)?;
    assert!(
        matches!(Request::decode(&out[..n])?,Request::QueueUpdate(q) if q.id==7&&q.length==64&&q.mtu==1404)
    );
    let n = queue.down(&mut out)?;
    assert_eq!(
        Request::decode(&out[..n])?,
        Request::QueueDown {
            peer: PeerId([3; 32]),
            id: 7
        }
    );
    Ok(())
}
#[test]
fn exact_udp_notify_uses_actual_1212_and_1220_prefixes_not_a_clear_udp_ack() -> Result<(), Error> {
    let ack = Ack {
        allowed: 128,
        cmac: [0x37; 64],
    };
    let mut outgoing = [0xa5; 128];
    let n = transport::notify([3; 32], ack, &mut outgoing)?;
    assert_eq!(n, 116);
    let Request::Backchannel {
        peer,
        message,
        communicator,
    } = Request::decode(&outgoing[..n])?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(peer, PeerId([3; 32]));
    assert_eq!(communicator, b"udp");
    assert_eq!(Ack::decode_backchannel(message)?, ack);
    assert_eq!(&outgoing[4..8], &[0; 4]);
    let mut incoming = [0; 112];
    incoming[..2].copy_from_slice(&112u16.to_be_bytes());
    incoming[2..4].copy_from_slice(&1220u16.to_be_bytes());
    incoming[8..40].copy_from_slice(&[3; 32]);
    incoming[40..].copy_from_slice(message);
    assert_eq!(
        Event::decode(&incoming)?,
        Event::Backchannel { peer: [3; 32], ack }
    );
    incoming[4] = 1;
    assert!(matches!(Event::decode(&incoming), Err(Error::Malformed)));
    incoming[4] = 0;
    incoming[41] = 71;
    assert!(Event::decode(&incoming).is_err());
    Ok(())
}
#[test]
fn incoming_has_no_udp_flow_callback_and_local_send_outcome_keeps_original_ids() -> Result<(), Error>
{
    let mut out = [0xa5; 256];
    let n = transport::incoming([3; 32], &message(), &mut out)?;
    let Request::Incoming {
        flow_control,
        flow_id,
        validity,
        peer,
        neighbour,
        message: m,
    } = Request::decode(&out[..n])?
    else {
        return Err(Error::Malformed);
    };
    assert!(!flow_control);
    assert_eq!(flow_id, [0; 8]);
    assert_eq!(validity, 3_600_000_000);
    assert_eq!(peer, PeerId([3; 32]));
    assert_eq!(neighbour, PeerId([0; 32]));
    assert_eq!(m, message());
    let mid = [0x92; 8];
    for success in [true, false] {
        let n = transport::sent(0x01020304, mid, [3; 32], success, &mut out)?;
        assert!(
            matches!(Request::decode(&out[..n])?,Request::Sent {message_id,queue,peer,status} if message_id==mid&&queue==0x01020304&&peer==PeerId([3;32])&&status==if success{1}else{u32::MAX})
        );
    }
    Ok(())
}
#[test]
fn actual_address_publication_numeric_profiles_and_preflight_preserve_outputs() -> Result<(), Error>
{
    let mut out = [0xa5; 256];
    let address = transport::address("[::1]:1234".parse().map_err(|_| Error::InvalidInput)?);
    assert_eq!(address, "udp-[::1]:1234");
    assert_eq!(transport::parse_address(address.as_bytes())?.port(), 1234);
    let n = transport::address_add(4, address.as_bytes(), 2, 9, &mut out)?;
    assert!(
        matches!(Request::decode(&out[..n])?,Request::AddAddress{id:4,validity:9,network:2,address:a} if a==address.as_bytes())
    );
    let n = transport::address_remove(4, &mut out)?;
    assert_eq!(Request::decode(&out[..n])?, Request::DeleteAddress(4));
    let before = out;
    assert!(matches!(
        transport::notify(
            [3; 32],
            Ack {
                allowed: 128,
                cmac: [0; 64]
            },
            &mut out[..115]
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(out, before);
    assert!(matches!(
        transport::parse_address(b"tcp-127.0.0.1:1"),
        Err(Error::Unsupported)
    ));
    Ok(())
}
