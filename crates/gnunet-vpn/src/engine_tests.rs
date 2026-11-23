#![expect(
    clippy::panic_in_result_fn,
    reason = "Single lease/duplex-flow model checks actual bytes and explicit original port transitions; OS receipts are modeled, not claimed native proof"
)]
use super::*;
use gnunet_types::{AbsoluteTime, Error, MonoInstant};
fn settled<'id>(engine: &mut Engine<'id, '_, '_>, effect: Effect<'id>) -> Result<(), Error> {
    engine.queued(effect)?;
    engine.exposed(effect)?;
    engine.written(effect)
}

fn native_reservations<const N: usize>(
    test: impl for<'id> FnOnce(&mut Engine<'id, '_, '_>, Tun<'id>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut requests = [RequestSlot::new(); 1];
    let mut leases = [LeaseSlot::new(); N];
    let mut flows = [FlowSlot::new(); 1];
    let mut slab = [0; 1284];
    let mut packets = [PacketSlot::new(&mut slab)];
    let mut engine = Engine::new(
        &mut instance,
        Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        Limits {
            ipv4: Some(Prefix {
                network: Address::V4([192, 0, 2, 0]),
                bits: 29,
                interface: Address::V4([192, 0, 2, 1]),
            }),
            packet_bytes: 1280,
            ..Limits::default()
        },
    )?;
    let tun = engine.attach_tun()?;
    let work = engine.routing_request(tun)?.routing;
    engine.routing_queued(work)?;
    engine.route_applied(work)?;
    test(&mut engine, tun)
}

#[test]
fn original_native_reply_arms_and_retires_one_address_group() -> Result<(), Error> {
    native_reservations::<2>(|engine, tun| {
        let now = AbsoluteTime::from_micros(1);
        let expires = AbsoluteTime::from_micros(100);
        let a = Address::V4([203, 0, 113, 1]);
        let b = Address::V4([203, 0, 113, 2]);
        assert_eq!(
            engine.reserve_internet(None, Address::V6([0x22; 16]), now, expires),
            Err(Error::Unavailable)
        );
        let (first, address) = engine.reserve_internet(None, a, now, expires)?;
        let (same, second) = engine.reserve_internet(Some(first), b, now, expires)?;
        assert_eq!(first, same);
        assert_ne!(address, second);
        let mut raw = [0; 128];
        let udp = [0x1f, 0x90, 0, 53, 0, 0, 0, 0, 42];
        let size = packet::build(
            Address::V4([198, 51, 100, 7]),
            address,
            packet::UDP,
            &udp,
            &mut raw,
        )?;
        assert!(matches!(
            engine.forward_tun(tun, &raw[..size], now, MonoInstant(1)),
            Err(Error::NotFound)
        ));
        assert_eq!(engine.published_internet_address(a, now), None);
        engine.arm_reservations(first, now)?;
        engine.defer_reservations(first)?;
        assert!(matches!(
            engine.forward_tun(tun, &raw[..size], now, MonoInstant(2)),
            Err(Error::NotFound)
        ));
        assert_eq!(
            engine.arm_reservations(first, expires),
            Err(Error::Deadline)
        );
        engine.arm_reservations(first, now)?;
        // The peer can start using the address before a queued native reply's
        // completion notification reaches the task.
        engine.forward_tun(tun, &raw[..size], now, MonoInstant(3))?;
        engine.settle_reservations(first, ReservationOutcome::Submitted)?;
        assert_eq!(
            engine.published_internet_address(a, now),
            Some((address, expires))
        );
        assert_eq!(
            engine.published_internet_address(b, now),
            Some((second, expires))
        );
        assert_eq!(
            engine.settle_reservations(first, ReservationOutcome::Unsent),
            Err(Error::StaleGeneration)
        );
        Ok(())
    })
}

#[test]
fn unsent_and_uncertain_native_replies_have_distinct_reuse_rules() -> Result<(), Error> {
    native_reservations::<1>(|engine, _| {
        let start = AbsoluteTime::from_micros(1);
        let expires = AbsoluteTime::from_micros(100);
        let later = AbsoluteTime::from_micros(1000);
        let a = Address::V4([203, 0, 113, 1]);
        let b = Address::V4([203, 0, 113, 2]);
        let (partial, address) = engine.reserve_internet(None, a, start, expires)?;
        assert_eq!(
            engine.reserve_internet(Some(partial), b, start, expires),
            Err(Error::Capacity)
        );
        engine.settle_reservations(partial, ReservationOutcome::Unsent)?;
        let (queued, next_address) = engine.reserve_internet(None, b, start, expires)?;
        assert_eq!(address, next_address);
        engine.arm_reservations(queued, start)?;
        assert_eq!(engine.expire(later, MonoInstant(10))?, 0);
        assert_eq!(
            engine.reserve_internet(None, a, later, AbsoluteTime::NEVER),
            Err(Error::Deadline)
        );
        engine.settle_reservations(
            queued,
            ReservationOutcome::Uncertain {
                deadline: MonoInstant(50),
            },
        )?;
        assert_eq!(engine.expire(later, MonoInstant(49))?, 0);
        assert_eq!(
            engine.reserve_internet(None, a, later, AbsoluteTime::from_micros(2000)),
            Err(Error::Capacity)
        );
        assert_eq!(engine.expire(later, MonoInstant(50))?, 1);
        let (_, reuse) =
            engine.reserve_internet(None, a, later, AbsoluteTime::from_micros(2000))?;
        assert_eq!(reuse, address);
        Ok(())
    })
}
#[test]
fn discovered_ipv6_exit_uses_destination_gateway_and_bound_profile() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut requests = [RequestSlot::new(); 1];
    let mut leases = [LeaseSlot::new(); 1];
    let mut flows = [FlowSlot::new(); 1];
    let mut bytes = [[0; 2048]; 2];
    let mut packets = bytes.each_mut().map(|b| PacketSlot::new(b));
    let mut engine = Engine::new(
        &mut instance,
        Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        Limits {
            ipv4: Some(Prefix {
                network: Address::V4([192, 0, 2, 0]),
                bits: 29,
                interface: Address::V4([192, 0, 2, 1]),
            }),
            ipc_af: AfProfile::LINUX,
            packet_bytes: 1280,
            ..Limits::default()
        },
    )?;
    let tun = engine.attach_tun()?;
    let routing = engine.routing_request(tun)?.routing;
    engine.routing_queued(routing)?;
    engine.route_applied(routing)?;
    let client = engine.attach_client()?;
    let destination = Address::V6([0x33; 16]);
    let now = AbsoluteTime::from_micros(10);
    let request = engine.redirect(
        client,
        WireRequest::Internet {
            reserved: 0,
            expires: 100,
            result_af: AfProfile::LINUX.ipv4,
            destination,
            request_id: [1; 8],
        },
        now,
    )?;
    let response = engine.prepare_client(client)?.ok_or(Error::NotReady)?;
    let leased = Response::decode_with_profile(response.bytes, AfProfile::LINUX)?
        .address
        .ok_or(Error::NotReady)?;
    let effect = response.effect;
    settled(&mut engine, effect)?;
    engine.retire_request(request)?;
    let mut raw = [0; 128];
    let udp = [0x1f, 0x90, 0, 53, 0, 0, 0, 0, 42];
    let n = packet::build(
        Address::V4([198, 51, 100, 7]),
        leased,
        packet::UDP,
        &udp,
        &mut raw,
    )?;
    let ingress = engine.forward_tun(tun, &raw[..n], now, MonoInstant(1))?;
    assert_eq!(engine.flow_peer(ingress.flow)?, None);
    let discovery = engine.discovery_request(ingress.flow)?.discovery;
    engine.discovery_queued(discovery)?;
    let identity = [7; 32];
    engine.select_exit(discovery, identity)?;
    assert_eq!(engine.flow_peer(ingress.flow)?, Some(identity));
    engine.retire_discovery(discovery)?;
    let open = engine.open_request(ingress.flow)?;
    assert_eq!(open.port, gateway_port(Family::V6));
    engine.open_queued(open.open)?;
    assert_eq!(
        engine.bind_peer(open.open, [8; 32], AfProfile::FREEBSD),
        Err(Error::Authentication)
    );
    let peer = engine.bind_peer(open.open, identity, AfProfile::FREEBSD)?;
    assert_eq!(engine.flow_peer(ingress.flow)?, Some(identity));
    let forwarding = engine.prepare_peer(peer)?.ok_or(Error::NotReady)?;
    assert_eq!(
        &forwarding.bytes[4..8],
        &AfProfile::FREEBSD.ipv6.to_be_bytes()
    );
    assert_eq!(
        PeerMessage::decode_with_profile(forwarding.bytes, AfProfile::FREEBSD)?,
        PeerMessage::UdpInternet {
            address: destination,
            source: 8080,
            destination: 53,
            payload: &[42],
        }
    );
    let first_effect = forwarding.effect;
    engine.reject_prepared(first_effect)?;
    let retried = engine.prepare_peer(peer)?.ok_or(Error::NotReady)?;
    assert_eq!(&retried.bytes[4..8], &AfProfile::FREEBSD.ipv6.to_be_bytes());
    let retry_effect = retried.effect;
    settled(&mut engine, retry_effect)?;
    engine.release_buffer(ingress.buffer)?;
    let subsequent = engine.forward_tun(tun, &raw[..n], now, MonoInstant(2))?;
    assert!(!subsequent.new_flow);
    let forwarding = engine.prepare_peer(peer)?.ok_or(Error::NotReady)?;
    assert_eq!(
        &forwarding.bytes[4..8],
        &AfProfile::FREEBSD.ipv6.to_be_bytes()
    );
    Ok(())
}

#[test]
fn a_reused_address_has_its_own_hold_until_the_later_reply_settles() -> Result<(), Error> {
    native_reservations::<2>(|engine, _| {
        let start = AbsoluteTime::from_micros(1);
        let first_expiry = AbsoluteTime::from_micros(50);
        let later_expiry = AbsoluteTime::from_micros(100);
        let a = Address::V4([203, 0, 113, 1]);
        let b = Address::V4([203, 0, 113, 2]);
        let (first, address) = engine.reserve_internet(None, a, start, first_expiry)?;
        engine.arm_reservations(first, start)?;
        engine.settle_reservations(first, ReservationOutcome::Submitted)?;
        let (second, reused) = engine.reserve_internet(None, a, start, first_expiry)?;
        assert_eq!(reused, address);
        engine.arm_reservations(second, start)?;
        engine.settle_reservations(second, ReservationOutcome::Submitted)?;
        let (queued, reused) = engine.reserve_internet(None, a, start, later_expiry)?;
        assert_eq!(reused, address);
        engine.arm_reservations(queued, start)?;

        assert_eq!(engine.expire(later_expiry, MonoInstant(1))?, 1);
        let (other, different) =
            engine.reserve_internet(None, b, later_expiry, AbsoluteTime::from_micros(200))?;
        assert_ne!(different, address);
        engine.settle_reservations(other, ReservationOutcome::Unsent)?;
        engine.settle_reservations(queued, ReservationOutcome::Unsent)?;
        let (_, available) =
            engine.reserve_internet(None, b, later_expiry, AbsoluteTime::from_micros(200))?;
        assert_eq!(available, address);
        Ok(())
    })
}

#[test]
fn discovery_and_forwarding_use_the_icmp_destination_family() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut requests = [RequestSlot::new(); 1];
    let mut leases = [LeaseSlot::new(); 2];
    let mut flows = [FlowSlot::new(); 2];
    let mut bytes = [[0; 2048]; 2];
    let mut packets = bytes.each_mut().map(|b| PacketSlot::new(b));
    let v6_network = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut v6_interface = v6_network;
    v6_interface[15] = 1;
    let mut engine = Engine::new(
        &mut instance,
        Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        Limits {
            ipv4: Some(Prefix {
                network: Address::V4([192, 0, 2, 0]),
                bits: 29,
                interface: Address::V4([192, 0, 2, 1]),
            }),
            ipv6: Some(Prefix {
                network: Address::V6(v6_network),
                bits: 120,
                interface: Address::V6(v6_interface),
            }),
            ipc_af: AfProfile::LINUX,
            packet_bytes: 1280,
            ..Limits::default()
        },
    )?;
    let tun = engine.attach_tun()?;
    let routing = engine.routing_request(tun)?.routing;
    engine.routing_queued(routing)?;
    engine.route_applied(routing)?;
    let client = engine.attach_client()?;
    let now = AbsoluteTime::from_micros(10);
    let v4 = Address::V4([198, 51, 100, 7]);
    let v6 = Address::V6([0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    for (id, source, destination, incoming, outgoing) in [
        (1, v4, v6, (packet::ICMP, 8), (packet::ICMPV6, 128)),
        (2, v6, v4, (packet::ICMPV6, 128), (packet::ICMP, 8)),
    ] {
        let request = engine.redirect(
            client,
            WireRequest::Internet {
                reserved: 0,
                expires: 100,
                result_af: AfProfile::LINUX.value(source.family()),
                destination,
                request_id: [id; 8],
            },
            now,
        )?;
        let response = engine.prepare_client(client)?.ok_or(Error::NotReady)?;
        let leased = Response::decode_with_profile(response.bytes, AfProfile::LINUX)?
            .address
            .ok_or(Error::NotReady)?;
        let effect = response.effect;
        settled(&mut engine, effect)?;
        engine.retire_request(request)?;
        let mut raw = [0; 128];
        let echo = [incoming.1, 0, 0, 0, 0, 1, 0, 1, 23, 42];
        let n = packet::build(source, leased, incoming.0, &echo, &mut raw)?;
        let ingress = engine.forward_tun(tun, &raw[..n], now, MonoInstant(u64::from(id)))?;
        assert_eq!(engine.flow_info(ingress.flow)?.tuple.protocol, incoming.0);
        let discovery = engine.discovery_request(ingress.flow)?;
        assert_eq!(discovery.destination, destination);
        assert_eq!((discovery.protocol, discovery.port), (outgoing.0, 0));
        engine.discovery_queued(discovery.discovery)?;
        let identity = [7; 32];
        engine.select_exit(discovery.discovery, identity)?;
        engine.retire_discovery(discovery.discovery)?;
        let open = engine.open_request(ingress.flow)?;
        assert_eq!(open.port, gateway_port(destination.family()));
        engine.open_queued(open.open)?;
        let peer = engine.bind_peer(open.open, identity, AfProfile::FREEBSD)?;
        let forwarding = engine.prepare_peer(peer)?.ok_or(Error::NotReady)?;
        let PeerMessage::IcmpInternet {
            destination: encoded,
            header,
            payload,
        } = PeerMessage::decode_with_profile(forwarding.bytes, AfProfile::FREEBSD)?
        else {
            return Err(Error::Conflict);
        };
        assert_eq!(encoded, destination);
        assert_eq!(header[0], outgoing.1);
        assert_eq!(payload, &[23, 42]);
        let effect = forwarding.effect;
        settled(&mut engine, effect)?;
        engine.release_buffer(ingress.buffer)?;
    }
    Ok(())
}

#[test]
fn lease_expiry_original_udp_flow_and_independent_physical_ports() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut requests = [RequestSlot::new(); 4];
    let mut leases = [LeaseSlot::new(); 1];
    let mut flows = [FlowSlot::new(); 2];
    let mut bytes = [[0; 2048]; 5];
    let mut packets = bytes.each_mut().map(|b| PacketSlot::new(b));
    let mut engine = Engine::new(
        &mut instance,
        Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        Limits {
            ipv4: Some(Prefix {
                network: Address::V4([192, 0, 2, 0]),
                bits: 29,
                interface: Address::V4([192, 0, 2, 1]),
            }),
            packet_bytes: 1280,
            idle_micros: 1000,
            ..Limits::default()
        },
    )?;
    let client = engine.attach_client()?;
    let request = engine.redirect(
        client,
        WireRequest::Service {
            reserved: 0,
            expires: 100,
            protocol: 17,
            result_af: 0,
            peer: [1; 32],
            service: [4; 64],
            request_id: 1u64.to_ne_bytes(),
        },
        AbsoluteTime::from_micros(0),
    )?;
    let prepared = engine.prepare_client(client)?.ok_or(Error::NotReady)?;
    assert_eq!(Response::decode(prepared.bytes)?.address, None);
    let effect = prepared.effect;
    settled(&mut engine, effect)?;
    engine.retire_request(request)?;
    let tun = engine.attach_tun()?;
    assert!(!engine.tun_ready(tun)?);
    let routing = engine.routing_request(tun)?.routing;
    assert_eq!(engine.route_applied(routing), Err(Error::NotReady));
    // Explicit model port: a real native adapter must substitute its actual
    // verified device/route admission+successful kernel receipt for these calls.
    engine.routing_queued(routing)?;
    engine.route_applied(routing)?;
    let request = engine.redirect(
        client,
        WireRequest::Service {
            reserved: 0,
            expires: 100,
            protocol: 17,
            result_af: 0,
            peer: [1; 32],
            service: [4; 64],
            request_id: 2u64.to_ne_bytes(),
        },
        AbsoluteTime::from_micros(1),
    )?;
    let prepared = engine.prepare_client(client)?.ok_or(Error::NotReady)?;
    let address = Response::decode(prepared.bytes)?
        .address
        .ok_or(Error::NotReady)?;
    let effect = prepared.effect;
    settled(&mut engine, effect)?;
    let lease = engine.request_info(request)?.lease.ok_or(Error::NotReady)?;
    let local = Address::V4([10, 0, 0, 2]);
    let mut segment = [0; 11];
    segment[..2].copy_from_slice(&50000u16.to_be_bytes());
    segment[2..4].copy_from_slice(&443u16.to_be_bytes());
    segment[8..].copy_from_slice(b"one");
    let mut raw = [0; 128];
    let n = packet::build(local, address, packet::UDP, &segment, &mut raw)?;
    let original_target = Target::Service {
        peer: [1; 32],
        descriptor: [4; 64],
    };
    let rejected = engine.forward_tun_with_policy(
        tun,
        &raw[..n],
        AbsoluteTime::from_micros(9),
        MonoInstant(9),
        |_, tuple, target| {
            assert_eq!(target, original_target);
            assert_eq!(
                *tuple,
                Tuple {
                    source: local,
                    destination: address,
                    protocol: packet::UDP,
                    source_port: 50000,
                    destination_port: 443,
                }
            );
            Err(Error::PermissionDenied)
        },
    );
    assert_eq!(rejected.err(), Some(Error::PermissionDenied));
    assert!(engine.flows().next().is_none());
    assert!(engine.buffers().next().is_none());
    let ingress = engine.forward_tun(
        tun,
        &raw[..n],
        AbsoluteTime::from_micros(10),
        MonoInstant(10),
    )?;
    assert!(ingress.new_flow);
    let open = engine.open_request(ingress.flow)?;
    assert_eq!(&open.port[..2], &443u16.to_be_bytes());
    assert_eq!(&open.port[2..], &[4; 62]);
    assert_eq!(
        engine.bind_peer(open.open, [1; 32], AfProfile::native()),
        Err(Error::Closed)
    );
    engine.open_queued(open.open)?;
    assert_eq!(
        engine.bind_peer(open.open, [2; 32], AfProfile::native()),
        Err(Error::Authentication)
    );
    let peer = engine.bind_peer(open.open, [1; 32], AfProfile::LINUX)?;
    let prepared = engine.prepare_peer(peer)?.ok_or(Error::NotReady)?;
    assert_eq!(
        PeerMessage::decode(prepared.bytes)?,
        PeerMessage::UdpService {
            source: 0,
            destination: 443,
            payload: b"one"
        }
    );
    let first_effect = prepared.effect;
    settled(&mut engine, first_effect)?;
    engine.release_buffer(ingress.buffer)?;
    assert_eq!(engine.exposed(first_effect), Err(Error::StaleGeneration));
    let mut wire = [0; 128];
    let m = PeerMessage::UdpReply {
        source: 0,
        destination: 0,
        payload: b"two",
    }
    .encode(&mut wire)?;
    let delivery = engine.receive_peer(peer, &wire[..m], MonoInstant(20))?;
    assert!(!engine.delivery_ready(delivery)?);
    let prepared = engine.prepare_tun(tun)?.ok_or(Error::NotReady)?;
    let p = packet::Packet::parse(prepared.bytes)?;
    p.validate_checksums()?;
    assert_eq!(
        (p.source(), p.destination(), p.ports()?),
        (address, local, (443, 50000))
    );
    assert_eq!(&p.segment()[8..], b"two");
    let reply_effect = prepared.effect;
    engine.queued(reply_effect)?;
    engine.exposed(reply_effect)?;
    assert_eq!(engine.receive_done(delivery), Err(Error::NotReady));
    engine.written(reply_effect)?;
    assert!(engine.delivery_ready(delivery)?);
    engine.receive_done(delivery)?;
    let reply = engine
        .buffers()
        .find(|b| engine.buffer_outcome(*b) == Ok(Outcome::Written))
        .ok_or(Error::NotFound)?;
    engine.release_buffer(reply)?;
    // A named UDP service sends no AF, so the C EXIT may identify its own
    // IPv6 ICMP header independently of the configured transmit profile.
    let m = PeerMessage::IcmpReply {
        af: AfProfile::DARWIN.ipv6,
        header: [1, 0, 0, 0, 0, 0, 0, 0],
        payload: &[],
    }
    .encode_with_profile(&mut wire, AfProfile::DARWIN)?;
    let icmp = engine.receive_peer(peer, &wire[..m], MonoInstant(21))?;
    let prepared = engine.prepare_tun(tun)?.ok_or(Error::NotReady)?;
    let p = packet::Packet::parse(prepared.bytes)?;
    p.validate_checksums()?;
    assert_eq!(
        (p.source(), p.destination(), p.protocol()),
        (address, local, packet::ICMP)
    );
    assert_eq!(&p.segment()[..2], &[3, 0]);
    assert_eq!(&p.segment()[28..32], &[0xc3, 0x50, 1, 0xbb]);
    let icmp_effect = prepared.effect;
    settled(&mut engine, icmp_effect)?;
    engine.receive_done(icmp)?;
    engine.release_buffer(icmp.buffer())?;
    assert_eq!(
        engine.expire(AbsoluteTime::from_micros(101), MonoInstant(101))?,
        1
    );
    assert_eq!(engine.lease_info(lease).err(), Some(Error::StaleGeneration));
    let last_used = engine.flow_info(ingress.flow)?.last_used;
    let rejected = engine.forward_tun_with_policy(
        tun,
        &raw[..n],
        AbsoluteTime::from_micros(102),
        MonoInstant(102),
        |_, _, target| {
            assert_eq!(target, original_target);
            Err(Error::PermissionDenied)
        },
    );
    assert_eq!(rejected.err(), Some(Error::PermissionDenied));
    assert_eq!(engine.flow_info(ingress.flow)?.last_used, last_used);
    assert!(engine.buffers().next().is_none());
    let old = engine.forward_tun(
        tun,
        &raw[..n],
        AbsoluteTime::from_micros(102),
        MonoInstant(102),
    )?;
    assert!(!old.new_flow);
    assert_eq!(old.flow, ingress.flow);
    assert_eq!(engine.flow_info(old.flow)?.target, original_target);
    let replacement = engine.redirect(
        client,
        WireRequest::Service {
            reserved: 0,
            expires: 300,
            protocol: 6,
            result_af: 0,
            peer: [2; 32],
            service: [5; 64],
            request_id: 3u64.to_ne_bytes(),
        },
        AbsoluteTime::from_micros(102),
    )?;
    let other = engine
        .request_info(replacement)?
        .lease
        .ok_or(Error::NotReady)?;
    assert_ne!(engine.lease_info(other)?.address, address);
    engine.cancel_request(replacement)?;
    engine.retire_request(replacement)?;
    assert_eq!(
        engine.lease_info(other)?.target,
        Target::Service {
            peer: [2; 32],
            descriptor: [5; 64]
        }
    );
    // Both directions have an original physical attempt. Losing CADET cannot
    // pretend the independent already-queued TUN packet stopped or was replayed.
    let prepared = engine.prepare_peer(peer)?.ok_or(Error::NotReady)?;
    let outgoing = prepared.effect;
    engine.queued(outgoing)?;
    engine.exposed(outgoing)?;
    let late = engine.receive_peer(peer, &wire[..m], MonoInstant(103))?;
    let prepared = engine.prepare_tun(tun)?.ok_or(Error::NotReady)?;
    let incoming = prepared.effect;
    engine.queued(incoming)?;
    engine.exposed(incoming)?;
    let loss = engine.peer_lost(peer, Error::Io)?;
    assert_eq!(loss.delivery, Some(late));
    assert_eq!(loss.loss.exposed, 1);
    assert_eq!(
        engine.buffer_outcome(old.buffer)?,
        Outcome::Lost {
            queued: true,
            exposed: true,
            reason: Error::Io
        }
    );
    engine.release_buffer(old.buffer)?;
    assert_eq!(engine.receive_done(late), Err(Error::StaleGeneration));
    engine.written(incoming)?; // Actual original TUN receipt after peer close.
    let remaining = engine.buffers().next().ok_or(Error::NotFound)?;
    assert_eq!(engine.buffer_outcome(remaining)?, Outcome::Written);
    engine.release_buffer(remaining)?;
    engine.retire_flow(ingress.flow)?;
    let lost = engine.tun_lost(tun, Error::OutcomeUnknown)?;
    assert_eq!(lost.loss.reason, Error::OutcomeUnknown);
    assert_eq!(engine.retire_tun(tun), Err(Error::WouldBlock));
    let cleanup = engine.route_cleanup_request(tun)?.routing;
    engine.routing_queued(cleanup)?;
    engine.route_removed(cleanup)?;
    engine.retire_tun(tun)?;
    let new_tun = engine.attach_tun()?;
    assert_ne!(new_tun, tun);
    assert_eq!(
        engine.routing_request(tun).err(),
        Some(Error::StaleGeneration)
    );
    let pending = engine.routing_request(new_tun)?.routing;
    engine.routing_queued(pending)?;
    engine.tun_lost(new_tun, Error::Io)?;
    assert_eq!(engine.route_applied(pending), Err(Error::StaleGeneration));
    assert_eq!(engine.retire_tun(new_tun), Err(Error::WouldBlock));
    engine.retire_routing(pending)?;
    assert_eq!(engine.route_state(new_tun)?, RouteState::Unknown);
    let cleanup = engine.route_cleanup_request(new_tun)?.routing;
    engine.routing_queued(cleanup)?;
    engine.route_removed(cleanup)?;
    engine.retire_tun(new_tun)?;
    engine.retire_request(request)?;
    engine.client_lost(client, Error::Closed)?;
    Ok(())
}

#[test]
fn borrowed_queries_never_acquire_owned_cleanup_and_release_keeps_presence_unclaimed()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut requests = [RequestSlot::new(); 1];
    let mut leases = [LeaseSlot::new(); 1];
    let mut flows = [FlowSlot::new(); 1];
    let mut bytes = [0; 2048];
    let mut packets = [PacketSlot::new(&mut bytes)];
    let mut engine = Engine::new(
        &mut instance,
        Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        Limits {
            ipv4: Some(Prefix {
                network: Address::V4([192, 0, 2, 0]),
                bits: 29,
                interface: Address::V4([192, 0, 2, 1]),
            }),
            packet_bytes: 1280,
            ..Limits::default()
        },
    )?;
    assert!(!engine.has_tun_source());
    let tun = engine.attach_tun()?;
    assert!(engine.has_tun_source());
    let first = engine.routing_request(tun)?.routing;
    assert_eq!(engine.route_borrowed_verified(first), Err(Error::Conflict));
    engine.can_queue_borrowed_routing(first)?;
    engine.routing_borrowed_queued(first)?;
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedUnverified);
    assert_eq!(engine.route_applied(first), Err(Error::PermissionDenied));
    assert_eq!(
        engine.can_queue_routing(first),
        Err(Error::PermissionDenied)
    );
    assert!(!engine.tun_ready(tun)?);
    // Read-only query failure cannot create owned Unknown/delete authority.
    engine.route_failed(first, Error::Io)?;
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedUnverified);
    assert_eq!(
        engine.route_cleanup_request(tun).err(),
        Some(Error::PermissionDenied)
    );
    assert_eq!(
        engine.confirm_routes_absent(tun),
        Err(Error::PermissionDenied)
    );

    let verified = engine.routing_request(tun)?.routing;
    engine.routing_borrowed_queued(verified)?;
    engine.route_borrowed_verified(verified)?;
    assert!(engine.tun_ready(tun)?);
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedVerified);
    assert_eq!(
        engine.route_cleanup_request(tun).err(),
        Some(Error::PermissionDenied)
    );
    engine.route_lost(tun, Error::Unavailable)?;
    assert!(!engine.tun_ready(tun)?);
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedUnverified);

    let pending = engine.routing_request(tun)?.routing;
    engine.routing_borrowed_queued(pending)?;
    let loss = engine.tun_lost(tun, Error::Io)?;
    assert_eq!(loss.routing, Some(pending));
    assert_eq!(loss.routes, RouteState::BorrowedUnverified);
    assert!(engine.has_tun_source()); // Original dead-source tombstone remains.
    assert_eq!(engine.release_borrowed_routes(tun), Err(Error::WouldBlock));
    assert_eq!(engine.retire_tun(tun), Err(Error::WouldBlock));
    assert_eq!(
        engine.route_borrowed_verified(pending),
        Err(Error::StaleGeneration)
    );
    // Actual original query quiescence is a separate modeled provider receipt.
    engine.retire_routing(pending)?;
    let original = tun;
    let tun = engine.rebind_tun_same_interface(original)?;
    assert_ne!(original, tun);
    assert_eq!(engine.route_state(original), Err(Error::StaleGeneration));
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedUnverified);
    assert_eq!(
        engine.route_cleanup_request(tun).err(),
        Some(Error::PermissionDenied)
    );
    let verification = engine.routing_request(tun)?.routing;
    engine.routing_borrowed_queued(verification)?;
    engine.route_borrowed_verified(verification)?;
    assert!(engine.tun_ready(tun)?);
    engine.tun_lost(tun, Error::Closed)?;
    engine.release_borrowed_routes(tun)?;
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedReleased);
    assert_eq!(
        engine.confirm_routes_absent(tun),
        Err(Error::PermissionDenied)
    );
    assert!(!engine.tun_ready(tun)?);
    engine.retire_tun(tun)?;
    assert!(!engine.has_tun_source());
    let replacement = engine.attach_tun()?;
    assert_ne!(replacement, tun);
    assert_eq!(engine.route_state(replacement)?, RouteState::Absent);
    assert_eq!(
        engine.route_borrowed_verified(pending),
        Err(Error::StaleGeneration)
    );
    assert_eq!(
        engine.release_borrowed_routes(tun),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
