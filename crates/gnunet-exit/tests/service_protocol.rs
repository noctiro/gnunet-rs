//! One pure service-selection model. Attachment, whole TUN writes and ACK calls
//! are explicit model premises, not native device/channel qualification claims.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused pure model checks same-hash TCP/UDP target selection, ambiguous duplicates and immutable original tuples"
)]
use gnunet_exit::{
    Address, AfProfile,
    engine::{Config, Effect, Engine, Limits, Service, Target},
    nat::{Entropy, Pool},
    policy::{Endpoint, Policy, Prefix, Protocol},
};
use gnunet_types::{Error, MonoInstant};
use gnunet_vpn::packet::Packet;
use gnunet_wire::official::vpn::PeerMessage;
struct ModelEntropy(u8);
impl Entropy for ModelEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        for byte in bytes {
            self.0 = self.0.wrapping_add(17);
            *byte = self.0;
        }
        Ok(())
    }
}
fn config(services: &[Service]) -> Config<'_> {
    Config {
        policy: Policy {
            ipv4: true,
            ipv6: false,
            rules: gnunet_exit::policy::InternetRules::Ordered {
                rules: &[],
                default_allow: true,
            },
        },
        ipv4: Some(Pool {
            subnet: Prefix {
                address: Address::V4([10, 29, 0, 1]),
                bits: 24,
            },
        }),
        ipv6: None,
        services,
        dns: false,
        af: AfProfile::LINUX,
    }
}
fn message(value: PeerMessage<'_>) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; value.encoded_len()?];
    value.encode_with_profile(&mut bytes, AfProfile::LINUX)?;
    Ok(bytes)
}
#[test]
fn shared_hash_selects_actual_transport_and_never_rebinds_old_tuple() -> Result<(), Error> {
    let hash = [0x37; 64];
    let tcp = Service {
        port: hash,
        protocol: Protocol::Tcp,
        target: Endpoint {
            address: Address::V4([192, 0, 2, 11]),
            port: 8080,
        },
    };
    let udp = Service {
        port: hash,
        protocol: Protocol::Udp,
        target: Endpoint {
            address: Address::V4([192, 0, 2, 22]),
            port: 5353,
        },
    };
    for entries in [
        [tcp, tcp],
        [udp, udp],
        [
            tcp,
            Service {
                target: udp.target,
                ..tcp
            },
        ],
    ] {
        assert!(matches!(
            Engine::new(config(&entries), Limits::default()),
            Err(Error::Conflict)
        ));
    }
    // UDP deliberately comes first: a hash-only first-entry lookup cannot pass
    // both real protocol selections. One shared Target/CADET port is retained.
    let services = [udp, tcp];
    let mut engine = Engine::new(config(&services), Limits::default())?;
    let source = engine.attached()?;
    let tun = engine.tun_attached()?;
    let tcp_flow = engine.accept(&source, [1; 32], Target::Service(hash), MonoInstant(1))?;
    let udp_flow = engine.accept(&source, [2; 32], Target::Service(hash), MonoInstant(2))?;
    let mut entropy = ModelEntropy(3);
    let mut header = [0; 20];
    header[2..4].copy_from_slice(&9999u16.to_be_bytes());
    header[4..8].copy_from_slice(&1u32.to_be_bytes());
    header[12] = 0x50;
    header[13] = 2;
    let input = engine.receive(
        &tcp_flow,
        &message(PeerMessage::TcpService {
            reserved: 0,
            header,
            tail: b"tcp",
        })?,
        MonoInstant(3),
        &mut entropy,
    )?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let packet = Packet::parse(output.bytes)?;
    packet.validate_checksums()?;
    assert_eq!(packet.protocol(), 6);
    assert_eq!(packet.destination(), tcp.target.address);
    assert_eq!(&packet.segment()[2..4], &tcp.target.port.to_be_bytes());
    let write = output.write;
    assert!(engine.effect().is_none());
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { flow, input: ready }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(flow, tcp_flow);
    assert_eq!(ready, input);
    engine.acknowledged(&input)?;
    let tcp_tuple = engine.info(&tcp_flow)?.tuple.ok_or(Error::NotReady)?;
    assert_eq!(tcp_tuple.protocol, Protocol::Tcp);
    assert_eq!(tcp_tuple.remote, tcp.target);
    let input = engine.receive(
        &udp_flow,
        &message(PeerMessage::UdpService {
            source: 0,
            destination: 9999,
            payload: b"udp",
        })?,
        MonoInstant(4),
        &mut entropy,
    )?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let packet = Packet::parse(output.bytes)?;
    packet.validate_checksums()?;
    assert_eq!(packet.protocol(), 17);
    assert_eq!(packet.destination(), udp.target.address);
    assert_eq!(&packet.segment()[2..4], &udp.target.port.to_be_bytes());
    let write = output.write;
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { flow, input: ready }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(flow, udp_flow);
    assert_eq!(ready, input);
    engine.acknowledged(&input)?;
    let udp_tuple = engine.info(&udp_flow)?.tuple.ok_or(Error::NotReady)?;
    assert_eq!(udp_tuple.protocol, Protocol::Udp);
    assert_eq!(udp_tuple.remote, udp.target);
    assert_eq!(engine.info(&tcp_flow)?.tuple, Some(tcp_tuple));
    // An ICMP error on the established TCP channel uses that original TCP
    // endpoint even though the shared hash's UDP entry occurs first.
    let mut error_header = [0; 8];
    error_header[0] = 3;
    error_header[1] = 3;
    let input = engine.receive(
        &tcp_flow,
        &message(PeerMessage::IcmpService {
            af: 2,
            header: error_header,
            payload: &[],
        })?,
        MonoInstant(5),
        &mut entropy,
    )?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let packet = Packet::parse(output.bytes)?;
    packet.validate_checksums()?;
    assert_eq!(packet.protocol(), 1);
    assert_eq!(packet.destination(), tcp.target.address);
    let write = output.write;
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { input: ready, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(ready, input);
    engine.acknowledged(&input)?;
    assert_eq!(engine.info(&tcp_flow)?.tuple, Some(tcp_tuple));
    // Follow-up service UDP packets retain the original endpoint/tuple even if
    // their untrusted destination field asks for the other protocol's port.
    let input = engine.receive(
        &udp_flow,
        &message(PeerMessage::UdpService {
            source: 0,
            destination: tcp.target.port,
            payload: b"next",
        })?,
        MonoInstant(6),
        &mut entropy,
    )?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let packet = Packet::parse(output.bytes)?;
    assert_eq!(packet.destination(), udp.target.address);
    let write = output.write;
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { input: ready, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(ready, input);
    engine.acknowledged(&input)?;
    assert_eq!(engine.info(&udp_flow)?.tuple, Some(udp_tuple));
    assert_eq!(
        engine.receive(
            &tcp_flow,
            &message(PeerMessage::UdpService {
                source: 0,
                destination: 0,
                payload: b"wrong"
            })?,
            MonoInstant(7),
            &mut entropy
        ),
        Err(Error::Conflict)
    );
    assert_eq!(engine.info(&tcp_flow)?.tuple, Some(tcp_tuple));
    assert_eq!(engine.info(&udp_flow)?.tuple, Some(udp_tuple));
    assert!(!engine.info(&udp_flow)?.closing);
    assert!(engine.tun_output().is_none());
    assert_eq!(
        engine.receive(
            &udp_flow,
            &message(PeerMessage::TcpService {
                reserved: 0,
                header,
                tail: &[]
            })?,
            MonoInstant(8),
            &mut entropy
        ),
        Err(Error::Conflict)
    );
    assert_eq!(engine.info(&udp_flow)?.tuple, Some(udp_tuple));
    assert!(engine.tun_output().is_none());
    // No TCP/UDP discriminator exists in an initial ICMP service message. The
    // shared hash cannot choose an arbitrary first endpoint on a fresh flow.
    let icmp_flow = engine.accept(&source, [3; 32], Target::Service(hash), MonoInstant(9))?;
    let mut icmp = [0; 8];
    icmp[0] = 8;
    assert_eq!(
        engine.receive(
            &icmp_flow,
            &message(PeerMessage::IcmpService {
                af: 2,
                header: icmp,
                payload: &[]
            })?,
            MonoInstant(10),
            &mut entropy
        ),
        Err(Error::Conflict)
    );
    assert!(engine.info(&icmp_flow)?.tuple.is_none());
    assert!(engine.tun_output().is_none());
    assert_eq!(engine.info(&tcp_flow)?.target, Target::Service(hash));
    assert_eq!(engine.info(&udp_flow)?.target, Target::Service(hash));
    engine.shutdown();
    engine.source_lost(&source)?;
    engine.tun_lost(&tun, None)?;
    assert!(engine.is_quiescent());
    Ok(())
}
