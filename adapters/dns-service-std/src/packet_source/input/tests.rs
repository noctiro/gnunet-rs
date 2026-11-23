//! Raw helper and native packet fixtures; no sockets, helpers or devices run.
use super::*;
use crate::packet;
use gnunet_types::Error as Fault;
use gnunet_vpn::packet::{self as raw_packet, Address};

const DNS: [u8; 12] = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn query_packet() -> Result<OriginalInput, Fault> {
    packet_with_dns(&DNS, 53).map_err(|refused| refused.reason)
}

fn packet_with_dns(dns: &[u8], port: u16) -> Result<OriginalInput, InputRefusal> {
    let source = Address::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let destination = Address::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53]);
    let mut udp = vec![0; dns.len() + 8];
    udp[..2].copy_from_slice(&53000_u16.to_be_bytes());
    udp[2..4].copy_from_slice(&port.to_be_bytes());
    udp[8..].copy_from_slice(dns);
    let mut raw = vec![0; 40 + udp.len()];
    raw_packet::build(source, destination, raw_packet::UDP, &udp, &mut raw)?;
    raw::native(OwnedFrame::new(raw), 0)
}

fn prepare<'id>(
    permit: &ReplyPermit<'id>,
    engine: &mut core::Engine<'id>,
    request: core::Request<'id>,
    framing: packet::Framing,
    capacity: usize,
) -> Result<(core::Effect<'id>, OwnedFrame), Fault> {
    permit.prepare_with(engine, request, |dns| match &permit.owner {
        ReplyOwner::Raw(reply) => match framing {
            packet::Framing::Helper => reply.helper(dns, capacity),
            packet::Framing::Raw => reply.packet(dns, capacity),
        },
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        ReplyOwner::Flow(_) => Err(Fault::Conflict),
        #[cfg(windows)]
        ReplyOwner::Wfp(_) => Err(Fault::Conflict),
        #[cfg(target_os = "linux")]
        ReplyOwner::Transparent(_) => Err(Fault::Conflict),
    })
}

fn answer<'id>(
    engine: &mut core::Engine<'id>,
    request: core::Request<'id>,
    bytes: &[u8],
) -> Result<(), Fault> {
    if engine.next_work(request)? != core::Work::Resolve(request) {
        return Err(Fault::Conflict);
    }
    let job = engine.resolving(request)?;
    engine.resolved(job, bytes)?;
    if !matches!(engine.next_work(request)?, core::Work::Source { .. }) {
        return Err(Fault::Conflict);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure packet fixtures assert exact refusal and original byte preservation"
)]
fn unscoped_sources_refuse_either_scoped_ipv6_endpoint_without_changing_bytes()
-> Result<(), gnunet_types::Error> {
    let global = Address::V6(std::net::Ipv6Addr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]).octets());
    let link = Address::V6(std::net::Ipv6Addr::from([0xfe80, 0, 0, 0, 0, 0, 0, 53]).octets());
    let site = Address::V6(std::net::Ipv6Addr::from([0xfec0, 0, 0, 0, 0, 0, 0, 53]).octets());
    for (source, destination, unscoped, interface_scoped) in [
        (global, global, true, true),
        (link, global, false, true),
        (global, link, false, true),
        (link, link, false, true),
        (site, global, false, false),
        (global, site, false, false),
        (site, site, false, false),
    ] {
        let mut raw = [0; 60];
        let mut udp = [0; 20];
        udp[..2].copy_from_slice(&53000_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53_u16.to_be_bytes());
        raw_packet::build(source, destination, raw_packet::UDP, &udp, &mut raw)?;
        let (_, tuple) = packet::decode_query(&raw)?;
        assert_eq!(tuple.requires_scope(), !unscoped);
        assert_eq!(tuple.raw_scope_supported(false), unscoped);
        assert_eq!(tuple.raw_scope_supported(true), interface_scoped);
        let mut helper = [0; 68];
        packet::encode_helper(&raw, &mut helper)?;
        for input in [
            raw::helper(OwnedFrame::copy_from(&helper)?),
            raw::native(OwnedFrame::copy_from(&raw)?, 0),
        ] {
            assert_eq!(
                input.as_ref().map(|_| ()).map_err(|r| r.reason),
                if unscoped {
                    Ok(())
                } else {
                    Err(Fault::Unsupported)
                }
            );
            let instance = core::Instance::new();
            let mut engine = core::Engine::new(&instance, core::Limits::default())?;
            let source = engine.attach_source()?;
            if let Ok(input) = input {
                assert_eq!(input.storage.bytes()[input.dns.clone()], [0; 12]);
                input
                    .admit(&mut engine, source, 1, 100)
                    .map_err(|refused| refused.reason)?;
            }
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure packet fixtures assert raw endpoint refusal before request admission"
)]
fn raw_sources_require_unicast_endpoints_in_the_original_wire_family() -> Result<(), Fault> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let global4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let global6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53));
    let cases = [
        (IpAddr::V4(Ipv4Addr::LOCALHOST), true),
        (global4, true),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), true),
        (global6, true),
        (
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 53)),
            true,
        ),
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), false),
        (IpAddr::V4(Ipv4Addr::BROADCAST), false),
        (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 53)), false),
        (IpAddr::V4(Ipv4Addr::new(239, 255, 255, 53)), false),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), false),
        (
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 53)),
            false,
        ),
        (
            IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 53)),
            false,
        ),
        (
            IpAddr::V6(Ipv4Addr::new(192, 0, 2, 53).to_ipv6_mapped()),
            false,
        ),
        (
            IpAddr::V6(Ipv4Addr::new(224, 0, 0, 53).to_ipv6_mapped()),
            false,
        ),
        (IpAddr::V6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()), false),
        (IpAddr::V6(Ipv4Addr::BROADCAST.to_ipv6_mapped()), false),
    ];
    let wire = |ip| match ip {
        IpAddr::V4(ip) => Address::V4(ip.octets()),
        IpAddr::V6(ip) => Address::V6(ip.octets()),
    };
    for (address, allowed) in cases {
        let peer = if address.is_ipv4() { global4 } else { global6 };
        for (source, destination) in [(address, peer), (peer, address)] {
            let mut udp = [0; 20];
            udp[..2].copy_from_slice(&53000_u16.to_be_bytes());
            udp[2..4].copy_from_slice(&53_u16.to_be_bytes());
            let mut bytes = [0; 60];
            let length = raw_packet::build(
                wire(source),
                wire(destination),
                raw_packet::UDP,
                &udp,
                &mut bytes,
            )?;
            let bytes = &bytes[..length];
            let mut helper = vec![0; packet::HELPER_PREFIX + length];
            packet::encode_helper(bytes, &mut helper)?;
            for input in [
                raw::helper(OwnedFrame::copy_from(&helper)?),
                raw::native(OwnedFrame::copy_from(bytes)?, 0),
            ] {
                assert_eq!(
                    input.as_ref().map(|_| ()).map_err(|r| r.reason),
                    if allowed {
                        Ok(())
                    } else {
                        Err(Fault::Unsupported)
                    },
                    "source={source}, destination={destination}"
                );
            }
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure capability fixtures assert independent namespaces and failure atomicity"
)]
fn reply_permits_reject_foreign_requests_and_sources_without_reserving_output() -> Result<(), Fault>
{
    let a = core::Instance::new();
    let b = core::Instance::new();
    let mut first = core::Engine::new(&a, core::Limits::default())?;
    let mut second = core::Engine::new(&b, core::Limits::default())?;
    let source = first.attach_source()?;
    let other_source = second.attach_source()?;
    let (request, permit) = query_packet()?
        .admit(&mut first, source, 1, 100)
        .map_err(|refused| refused.reason)?;
    let (other_request, other_permit) = query_packet()?
        .admit(&mut second, other_source, 1, 100)
        .map_err(|refused| refused.reason)?;
    let mut response = DNS;
    response[2] |= 0x80;
    answer(&mut first, request, &response)?;
    answer(&mut second, other_request, &response)?;
    assert!(matches!(
        prepare(
            &permit,
            &mut second,
            other_request,
            packet::Framing::Raw,
            65575
        ),
        Err(Fault::StaleGeneration)
    ));
    let (identity, owner) = permit.into_parts();
    let foreign_source = ReplyPermit {
        source: other_source,
        request,
        owner,
    };
    assert!(matches!(
        prepare(
            &foreign_source,
            &mut first,
            request,
            packet::Framing::Raw,
            65575
        ),
        Err(Fault::StaleGeneration)
    ));
    let permit = identity.with_owner(foreign_source.owner);
    assert_eq!(
        first.next_work(request)?,
        core::Work::Source { request, source }
    );
    let (effect, output) = prepare(&permit, &mut first, request, packet::Framing::Raw, 65575)?;
    let (identity, route) = permit.into_parts();
    let permit = identity.with_owner(route);
    assert_eq!(other_permit.check(effect), Err(Fault::StaleGeneration));
    assert_eq!(permit.check(effect), Ok(()));
    assert_eq!(effect.destination(), core::Destination::Source(source));
    assert_eq!(
        raw_packet::Packet::parse(output.bytes())?.segment()[8..],
        response
    );
    assert_eq!(
        second.next_work(other_request)?,
        core::Work::Source {
            request: other_request,
            source: other_source
        }
    );
    first.queued(effect)?;
    first.written(effect)?;
    assert_eq!(first.next_work(request)?, core::Work::Retire(request));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Owned admission fixtures assert no request leakage and original diagnostic classification"
)]
fn refused_input_preserves_source_capacity_and_non_dns_diagnostics() -> Result<(), Fault> {
    let instance = core::Instance::new();
    let mut engine = core::Engine::new(&instance, core::Limits::default())?;
    let source = engine.attach_source()?;
    let mut response = DNS;
    response[2] |= 0x80;
    for (dns, port, reason, non_dns_udp) in [
        (&DNS[..11], 53, Fault::Truncated, true),
        (&DNS[..], 54, Fault::Unsupported, true),
        (&response[..], 53, Fault::Malformed, false),
    ] {
        let refused = match packet_with_dns(dns, port) {
            Ok(input) => match input.admit(&mut engine, source, 1, 100) {
                Ok(_) => return Err(Fault::Conflict),
                Err(refused) => refused,
            },
            Err(refused) => refused,
        };
        assert_eq!(refused.reason, reason);
        assert_eq!(refused.non_dns_udp, non_dns_udp);
        assert_eq!(engine.requests().count(), 0);
        assert_eq!(engine.payload_bytes(), 0);
    }
    let (request, _) = query_packet()?
        .admit(&mut engine, source, 1, 100)
        .map_err(|refused| refused.reason)?;
    assert_eq!(engine.payload(request)?, DNS);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure capacity fixtures assert transport refusal before effect reservation"
)]
fn transport_capacity_refusal_preserves_dns_and_unprepared_source_output() -> Result<(), Fault> {
    let instance = core::Instance::new();
    let mut engine = core::Engine::new(&instance, core::Limits::default())?;
    let source = engine.attach_source()?;
    let (request, permit) = query_packet()?
        .admit(&mut engine, source, 1, 100)
        .map_err(|refused| refused.reason)?;
    let mut response = vec![0; core::MAX_DNS_BYTES];
    response[..DNS.len()].copy_from_slice(&DNS);
    response[2] |= 0x80;
    answer(&mut engine, request, &response)?;
    for (framing, capacity) in [
        (packet::Framing::Helper, 65535),
        (packet::Framing::Raw, 65535),
    ] {
        assert!(matches!(
            prepare(&permit, &mut engine, request, framing, capacity),
            Err(Fault::TooLarge)
        ));
        assert_eq!(engine.payload(request)?, response);
        assert_eq!(
            engine.next_work(request)?,
            core::Work::Source { request, source }
        );
    }
    let (effect, output) = prepare(&permit, &mut engine, request, packet::Framing::Raw, 65575)?;
    assert_eq!(output.len(), response.len() + 48);
    let parsed = raw_packet::Packet::parse(output.bytes())?;
    parsed.validate_checksums()?;
    assert_eq!(&parsed.segment()[8..], response);
    engine.queued(effect)?;
    engine.written(effect)?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Real raw input verifies zero-copy DNS view and original effect framing"
)]
fn prefixed_padded_storage_admits_only_dns_and_preserves_reply_authority() -> Result<(), Fault> {
    let input = query_packet()?;
    let mut raw = input.storage.into_bytes();
    raw.extend_from_slice(&[0xa7; 7]);
    let payload_len = u16::try_from(raw.len() - 40).map_err(|_| Fault::Overflow)?;
    raw[4..6].copy_from_slice(&payload_len.to_be_bytes());
    // UDP length and checksum still cover the original segment; the additional
    // bytes belong to IP and must not enter the DNS view or reconstructed reply.
    raw_packet::Packet::parse(&raw)?.validate_checksums()?;
    let mut bytes = vec![0xa5; 4];
    bytes.extend_from_slice(&raw);
    let original = bytes.as_ptr();
    let input = raw::native(OwnedFrame::new(bytes), 4).map_err(|refused| refused.reason)?;
    assert_eq!(input.storage.bytes().as_ptr(), original);
    assert_eq!(input.storage.bytes()[input.dns.clone()], DNS);
    let instance = core::Instance::new();
    let mut engine = core::Engine::new(&instance, core::Limits::default())?;
    let source = engine.attach_source()?;
    let (request, permit) = input
        .admit(&mut engine, source, 1, 100)
        .map_err(|refused| refused.reason)?;
    assert_eq!(engine.payload(request)?, DNS);
    let mut response = DNS;
    response[2] |= 0x80;
    answer(&mut engine, request, &response)?;
    let (effect, output) = prepare(
        &permit,
        &mut engine,
        request,
        packet::Framing::Helper,
        65535,
    )?;
    let decoded = packet::helper_packet(output.bytes())?;
    let reply = raw_packet::Packet::parse(decoded)?;
    reply.validate_checksums()?;
    assert_eq!(reply.ports()?, (53, 53000));
    assert_eq!(&reply.segment()[8..], response);
    engine.queued(effect)?;
    engine.written(effect)?;
    assert_eq!(engine.next_work(request)?, core::Work::Retire(request));
    engine.retire(request)?;
    assert_eq!(engine.payload_bytes(), 0);
    Ok(())
}
