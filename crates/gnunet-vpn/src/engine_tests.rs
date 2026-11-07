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
    let peer = engine.bind_peer(open.open, [1; 32], AfProfile::native())?;
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
    assert_eq!(
        engine.expire(AbsoluteTime::from_micros(101), MonoInstant(101))?,
        1
    );
    assert_eq!(engine.lease_info(lease).err(), Some(Error::StaleGeneration));
    let old = engine.forward_tun(
        tun,
        &raw[..n],
        AbsoluteTime::from_micros(102),
        MonoInstant(102),
    )?;
    assert!(!old.new_flow);
    assert_eq!(old.flow, ingress.flow);
    assert_eq!(
        engine.flow_info(old.flow)?.target,
        Target::Service {
            peer: [1; 32],
            descriptor: [4; 64]
        }
    );
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
    assert_eq!(engine.route_state(tun)?, RouteState::BorrowedUnverified);
    assert_eq!(
        engine.route_cleanup_request(tun).err(),
        Some(Error::PermissionDenied)
    );
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
