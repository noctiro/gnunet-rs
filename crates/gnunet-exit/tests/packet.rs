//! Official EXIT message conversion through fixed raw IP buffers.

use gnunet_exit::{
    Address, AfProfile,
    packet::{Forward, Returned},
    policy::{Endpoint, Protocol, Tuple},
};
use gnunet_types::Error;
use gnunet_vpn::packet::{Packet, Quoted, build_parts, quote};
use gnunet_wire::official::vpn::PeerMessage;

const TCP: Tuple = Tuple {
    local: Endpoint {
        address: Address::V4([192, 0, 2, 1]),
        port: 48123,
    },
    remote: Endpoint {
        address: Address::V4([198, 51, 100, 2]),
        port: 443,
    },
    protocol: Protocol::Tcp,
};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert TCP packet and wire contracts"
)]
fn tcp_uses_physical_ports_and_preserves_options_and_data() -> Result<(), Error> {
    let mut header = [0; 20];
    header[2..4].copy_from_slice(&TCP.remote.port.to_be_bytes());
    header[4..8].copy_from_slice(&100u32.to_be_bytes());
    header[8..12].copy_from_slice(&175u32.to_be_bytes());
    header[12] = 6 << 4;
    header[13] = 0x12;
    header[16..18].fill(0xff);
    let tail = b"\x02\x04\x05\xb4data";
    let message = PeerMessage::TcpInternet {
        destination: TCP.remote.address,
        header,
        tail,
    };
    let forward = Forward::from_peer(TCP, message, AfProfile::LINUX)?;
    let mut small = [0xff; 47];
    assert_eq!(forward.encode(&mut small), Err(Error::Capacity));
    assert_eq!(small, [0xff; 47]);
    let mut bytes = [0; 48];
    assert_eq!(forward.packet_len(), bytes.len());
    assert_eq!(forward.encode(&mut bytes)?, bytes.len());
    let packet = Packet::parse(&bytes)?;
    packet.validate_checksums()?;
    assert_eq!(packet.ports()?, (TCP.local.port, TCP.remote.port));
    assert_eq!(&packet.segment()[4..16], &header[4..16]);
    assert_eq!(&packet.segment()[20..], tail);

    let mut reverse = [0; 48];
    let mut return_header = header;
    return_header[..2].copy_from_slice(&TCP.remote.port.to_be_bytes());
    return_header[2..4].copy_from_slice(&TCP.local.port.to_be_bytes());
    build_parts(
        TCP.remote.address,
        TCP.local.address,
        TCP.protocol.number(),
        &return_header,
        tail,
        &mut reverse,
    )?;
    let returned = Returned::parse(&reverse)?;
    assert_eq!(returned.tuple(), TCP);
    header[..4].fill(0);
    header[16..18].fill(0);
    assert_eq!(
        returned.message(AfProfile::LINUX),
        PeerMessage::Tcp {
            to_exit: false,
            reserved: 0,
            header,
            tail
        }
    );

    reverse[47] ^= 1;
    assert_eq!(Returned::parse(&reverse).err(), Some(Error::Malformed));
    header[12] = 15 << 4;
    assert_eq!(
        Forward::from_peer(
            TCP,
            PeerMessage::Tcp {
                to_exit: true,
                reserved: 0,
                header,
                tail,
            },
            AfProfile::LINUX
        )
        .err(),
        Some(Error::Malformed)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert ICMP quote direction and omission"
)]
fn router_return_matches_embedded_transport_and_omits_quote() -> Result<(), Error> {
    let router = Address::V4([192, 0, 2, 254]);
    let header = [3, 1, 0, 0, 0, 0, 0, 0];
    let mut embedded = [0; 28];
    quote(
        TCP.local.address,
        TCP.remote.address,
        TCP.protocol.number(),
        Some((TCP.local.port, TCP.remote.port)),
        &mut embedded,
    )?;
    let mut raw = [0; 56];
    build_parts(
        router,
        TCP.local.address,
        Protocol::Icmp.number(),
        &header,
        &embedded,
        &mut raw,
    )?;
    let returned = Returned::parse(&raw)?;
    assert_eq!(returned.tuple(), TCP);
    assert_eq!(
        returned.message(AfProfile::DARWIN),
        PeerMessage::IcmpReply {
            af: AfProfile::DARWIN.ipv4,
            header,
            payload: &[]
        }
    );
    let request = Forward::from_peer(
        TCP,
        PeerMessage::IcmpService {
            af: AfProfile::DARWIN.ipv6,
            header: [1, 1, 0, 0, 0, 0, 0, 0],
            payload: &[],
        },
        AfProfile::DARWIN,
    )?;
    assert_eq!(request.encode(&mut raw)?, 56);
    let packet = Packet::parse(&raw)?;
    packet.validate_checksums()?;
    assert_eq!(packet.segment()[0], header[0]);
    assert_eq!(
        Quoted::parse(&packet.segment()[8..])?,
        Quoted {
            source: TCP.remote.address,
            destination: TCP.local.address,
            protocol: TCP.protocol.number(),
            source_port: TCP.remote.port,
            destination_port: TCP.local.port,
        }
    );
    Ok(())
}
