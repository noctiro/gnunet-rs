//! One meaningful pure forwarding/ownership model. Native completion calls here
//! are explicit model premises, never executed OS/TUN/CADET interoperability.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused pure model asserts NAT checksums, real response matching and original cleanup debt"
)]
use gnunet_exit::{
    Address, AfProfile, Family,
    engine::{Config, Effect, Engine, Limits, Target},
    nat::{Entropy, Pool},
    policy::{Policy, Prefix},
};
use gnunet_types::{Error, MonoInstant};
use gnunet_vpn::packet::{self, Packet};
use gnunet_wire::official::vpn::PeerMessage;
struct ModelEntropy(u8);
impl Entropy for ModelEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 = self.0.wrapping_add(17);
            *b = self.0;
        }
        Ok(())
    }
}
fn message(m: PeerMessage<'_>) -> Result<Vec<u8>, Error> {
    let mut b = vec![0; m.encoded_len()?];
    m.encode_with_profile(&mut b, AfProfile::LINUX)?;
    Ok(b)
}
fn ip(a: Address, b: Address, p: u8, s: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; 40 + s.len()];
    let n = packet::build(a, b, p, s, &mut out)?;
    out.truncate(n);
    Ok(out)
}
#[test]
fn udp_tcp_icmp_dns_and_original_packet_retirement() -> Result<(), Error> {
    let config = Config {
        policy: Policy {
            ipv4: true,
            ipv6: true,
            rules: gnunet_exit::policy::InternetRules::Ordered {
                rules: &[],
                default_allow: true,
            },
        },
        ipv4: Some(Pool {
            subnet: Prefix {
                address: Address::V4([10, 19, 0, 1]),
                bits: 24,
            },
        }),
        ipv6: Some(Pool {
            subnet: Prefix {
                address: Address::V6([0xfd, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                bits: 120,
            },
        }),
        services: &[],
        dns: true,
        af: AfProfile::LINUX,
    };
    let mut engine = Engine::new(config, Limits::default())?;
    let source = engine.attached()?;
    let tun = engine.tun_attached()?;
    let mut entropy = ModelEntropy(1);
    let udp = engine.accept(
        &source,
        [7; 32],
        Target::Internet(Family::V4),
        MonoInstant(1),
    )?;
    let remote = Address::V4([203, 0, 113, 9]);
    let input = engine.receive(
        &udp,
        &message(PeerMessage::UdpInternet {
            address: remote,
            source: 0,
            destination: 53,
            payload: b"payload",
        })?,
        MonoInstant(2),
        &mut entropy,
    )?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let token = output.write;
    let bytes = output.bytes.to_vec();
    let packet = Packet::parse(&bytes)?;
    packet.validate_checksums()?;
    assert_eq!(packet.destination(), remote);
    assert_eq!(&packet.segment()[2..4], &53u16.to_be_bytes());
    assert_eq!(packet.segment().len(), 15);
    assert!(engine.effect().is_none());
    let again = engine.tun_output().ok_or(Error::NotReady)?;
    assert_eq!(again.write, token);
    assert_eq!(again.bytes, bytes);
    engine.tun_written(&tun, &token)?;
    let Some(Effect::Processed { flow, input: ready }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(flow, udp);
    assert_eq!(ready, input);
    engine.acknowledged(&input)?;
    let tuple = engine.info(&udp)?.tuple.ok_or(Error::NotReady)?;
    let mut segment = vec![0; 10];
    segment[..2].copy_from_slice(&53u16.to_be_bytes());
    segment[2..4].copy_from_slice(&tuple.local.port.to_be_bytes());
    segment[8..].copy_from_slice(b"ok");
    assert_eq!(
        engine.from_tun(
            &tun,
            &ip(remote, tuple.local.address, 17, &segment)?,
            MonoInstant(3)
        )?,
        udp
    );
    let output = engine.peer_output().ok_or(Error::NotReady)?;
    assert!(matches!(
        PeerMessage::decode_with_profile(output.bytes, AfProfile::LINUX)?,
        PeerMessage::UdpReply {
            source: 0,
            destination: 0,
            payload: b"ok"
        }
    ));
    let token = output.write;
    engine.peer_written(&source, &token)?;
    // Actual router ICMP error is matched using its quoted original NAT tuple,
    // rather than assuming the router's outer source equals the remote target.
    let mut quote = [0; 48];
    let n = packet::quote(
        tuple.local.address,
        tuple.remote.address,
        17,
        Some((tuple.local.port, tuple.remote.port)),
        &mut quote,
    )?;
    let mut icmp = vec![0; 8 + n];
    icmp[0] = 3;
    icmp[1] = 1;
    icmp[8..].copy_from_slice(&quote[..n]);
    assert_eq!(
        engine.from_tun(
            &tun,
            &ip(
                Address::V4([198, 51, 100, 1]),
                tuple.local.address,
                1,
                &icmp
            )?,
            MonoInstant(4)
        )?,
        udp
    );
    let output = engine.peer_output().ok_or(Error::NotReady)?;
    assert!(
        matches!(PeerMessage::decode_with_profile(output.bytes,AfProfile::LINUX)?,PeerMessage::IcmpReply{af:2,header,payload}if header[0]==3&&payload.is_empty())
    );
    let token = output.write;
    engine.peer_written(&source, &token)?;
    let tcp = engine.accept(
        &source,
        [8; 32],
        Target::Internet(Family::V6),
        MonoInstant(5),
    )?;
    let remote6 = Address::V6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    let mut header = [0; 20];
    header[2..4].copy_from_slice(&443u16.to_be_bytes());
    header[4..8].copy_from_slice(&100u32.to_be_bytes());
    header[12] = 0x50;
    header[13] = 2;
    let receipt = engine.receive(
        &tcp,
        &message(PeerMessage::TcpInternet {
            destination: remote6,
            header,
            tail: &[],
        })?,
        MonoInstant(6),
        &mut entropy,
    )?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let p = Packet::parse(output.bytes)?;
    p.validate_checksums()?;
    let token = output.write;
    assert!(!engine.info(&tcp)?.tcp.established);
    engine.tun_written(&tun, &token)?;
    let Some(Effect::Processed { input, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(input, receipt);
    engine.acknowledged(&input)?;
    let tuple6 = engine.info(&tcp)?.tuple.ok_or(Error::NotReady)?;
    let mut reply = header;
    reply[..2].copy_from_slice(&443u16.to_be_bytes());
    reply[2..4].copy_from_slice(&tuple6.local.port.to_be_bytes());
    reply[8..12].copy_from_slice(&101u32.to_be_bytes());
    reply[13] = 0x12;
    assert_eq!(
        engine.from_tun(
            &tun,
            &ip(remote6, tuple6.local.address, 6, &reply)?,
            MonoInstant(7)
        )?,
        tcp
    );
    assert!(engine.info(&tcp)?.tcp.established);
    let output = engine.peer_output().ok_or(Error::NotReady)?;
    assert!(
        matches!(PeerMessage::decode_with_profile(output.bytes,AfProfile::LINUX)?,PeerMessage::Tcp{to_exit:false,header,..}if header[..4]==[0;4]&&header[16..18]==[0;2])
    );
    let token = output.write;
    engine.peer_written(&source, &token)?;
    let dns = engine.accept(&source, [9; 32], Target::Dns, MonoInstant(8))?;
    let mut query = [0; 12];
    query[..2].copy_from_slice(&[0x12, 0x34]);
    query[2] = 1;
    let receipt = engine.receive(
        &dns,
        &message(PeerMessage::Dns {
            reply: false,
            packet: &query,
        })?,
        MonoInstant(9),
        &mut entropy,
    )?;
    let Some(Effect::DnsQuery { job, packet, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    let mut response = packet.to_vec();
    response[2] |= 0x80;
    engine.dns_admitted(&job)?;
    assert!(engine.effect().is_none());
    engine.dns_written(&job)?;
    let Some(Effect::Processed { input, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(input, receipt);
    engine.acknowledged(&input)?;
    assert_eq!(engine.dns_reply(&job, &response, MonoInstant(10))?, dns);
    let output = engine.peer_output().ok_or(Error::NotReady)?;
    assert!(
        matches!(PeerMessage::decode_with_profile(output.bytes,AfProfile::LINUX)?,PeerMessage::Dns{reply:true,packet}if packet[..2]==[0x12,0x34])
    );
    let token = output.write;
    engine.peer_written(&source, &token)?;
    // The original leased raw packet cannot be discarded by logical closure.
    engine.receive(
        &udp,
        &message(PeerMessage::UdpInternet {
            address: remote,
            source: 0,
            destination: 53,
            payload: b"last",
        })?,
        MonoInstant(11),
        &mut entropy,
    )?;
    let token = engine.tun_output().ok_or(Error::NotReady)?.write;
    engine.close(&udp)?;
    let Some(Effect::Close { flow }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(flow, udp);
    engine.closed(&udp)?;
    assert!(engine.next_closed().is_none());
    engine.tun_written(&tun, &token)?;
    assert_eq!(engine.next_closed().ok_or(Error::NotReady)?.flow, udp);
    assert_eq!(engine.advance(MonoInstant(1)), Err(Error::TimeUncertain));
    engine.shutdown();
    engine.source_lost(&source)?;
    engine.tun_lost(&tun, None)?;
    assert!(engine.is_quiescent());
    assert_eq!(engine.peer_written(&source, &token), Err(Error::Stale));
    Ok(())
}
