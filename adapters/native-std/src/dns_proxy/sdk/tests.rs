//! Real endpoint/data objects only; no flow, provider, socket or lookup is opened.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert original SDK endpoint identity and unchanged numeric qualification"
)]
use super::*;
use std::ffi::CStr;

unsafe extern "C" {
    fn nw_endpoint_create_host(host: *const libc::c_char, port: *const libc::c_char)
    -> *mut c_void;
    fn nw_endpoint_create_bonjour_service(
        name: *const libc::c_char,
        kind: *const libc::c_char,
        domain: *const libc::c_char,
    ) -> *mut c_void;
    fn nw_endpoint_create_url(url: *const libc::c_char) -> *mut c_void;
    fn nw_endpoint_create_address(address: *const libc::sockaddr) -> *mut c_void;
}
fn owned(raw: *mut c_void) -> io::Result<Endpoint> {
    // SAFETY: Each caller transfers the +1 result of an endpoint constructor.
    let object = unsafe { Retained::from_raw(raw.cast::<AnyObject>()) }
        .ok_or_else(|| io::Error::other("endpoint constructor failed"))?;
    Endpoint::from_retained(object)
}
fn host(value: &CStr) -> io::Result<Endpoint> {
    // SAFETY: Static terminated strings remain live; creating a static endpoint
    // object performs no name lookup or connection attempt.
    owned(unsafe { nw_endpoint_create_host(value.as_ptr(), c"53".as_ptr()) })
}
fn address(value: std::net::Ipv6Addr, zone: u32) -> io::Result<Endpoint> {
    let address = libc::sockaddr_in6 {
        sin6_len: size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 53_u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: value.octets(),
        },
        sin6_scope_id: zone,
    };
    // SAFETY: The complete initialized sockaddr_in6 remains live for this
    // synchronous SDK constructor, which copies the address without opening I/O.
    owned(unsafe { nw_endpoint_create_address((&raw const address).cast()) })
}

#[test]
fn opaque_original_endpoints_survive_reply_arrays_without_resolution() -> io::Result<()> {
    // SAFETY: All inputs are terminated static strings and construction only
    // owns a static endpoint; no discovery or network operation is started.
    let endpoints = [
        host(c"example.invalid")?,
        owned(unsafe {
            nw_endpoint_create_bonjour_service(
                c"gnunet-test".as_ptr(),
                c"_domain._udp".as_ptr(),
                c"local.".as_ptr(),
            )
        })?,
        owned(unsafe { nw_endpoint_create_url(c"https://example.invalid/dns-query".as_ptr()) })?,
    ];
    for (endpoint, kind) in endpoints.into_iter().zip([2, 3, 4]) {
        assert_eq!(endpoint.kind(), kind);
        assert_eq!(
            endpoint.scope_for(EndpointRole::UdpReply)?,
            EndpointScope::Unscoped
        );
        assert_eq!(
            endpoint.socket_addr().map_err(|e| e.kind()),
            Err(io::ErrorKind::Unsupported)
        );
        let original = Retained::as_ptr(&endpoint.0);
        let reply = WriteObjects::new(b"original-dns", &endpoint);
        drop(endpoint);
        assert_eq!(
            Retained::as_ptr(&reply.endpoints.objectAtIndex(0)),
            original
        );
        let mut payload = Vec::new();
        copy_data(&reply.data.objectAtIndex(0), &mut payload);
        assert_eq!(payload, b"original-dns");
    }
    Ok(())
}

#[test]
fn numeric_scope_refusals_remain_independent_from_opaque_admission() -> io::Result<()> {
    assert_eq!(
        host(c"127.0.0.1")?.scope_for(EndpointRole::UdpReply)?,
        EndpointScope::Unscoped
    );
    for address in [c"fe80::1", c"ff02::1", c"fec0::1"] {
        let endpoint = host(address)?;
        assert_eq!(endpoint.kind(), 1);
        assert_eq!(
            endpoint
                .scope_for(EndpointRole::UdpReply)
                .map_err(|e| e.kind()),
            Err(io::ErrorKind::Unsupported)
        );
    }
    Ok(())
}

#[test]
fn explicit_native_site_zone_survives_qualification_and_reply_retention() -> io::Result<()> {
    let site = std::net::Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 53);
    let endpoint = address(site, 7)?;
    assert_eq!(endpoint.kind(), 1);
    for role in [
        EndpointRole::Local,
        EndpointRole::UdpReply,
        EndpointRole::TcpRemote,
    ] {
        let scope = endpoint.scope_for(role)?;
        assert_eq!(scope, EndpointScope::LegacySiteLocal);
        assert!(scope.requires_local_endpoint());
    }
    let original = Retained::as_ptr(&endpoint.0);
    let reply = WriteObjects::new(b"original-site-dns", &endpoint);
    drop(endpoint);
    let retained = Endpoint::from_retained(reply.endpoints.objectAtIndex(0))?;
    assert_eq!(Retained::as_ptr(&retained.0), original);
    assert_eq!(
        retained.socket_addr()?,
        std::net::SocketAddr::V6(std::net::SocketAddrV6::new(site, 53, 0, 7))
    );
    assert_eq!(
        address(site, 0)?
            .scope_for(EndpointRole::UdpReply)
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn scoped_flow_peers_require_consistent_original_zones() -> io::Result<()> {
    use std::net::Ipv6Addr;

    let link = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 53);
    let site = Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 53);
    let wildcard = address(Ipv6Addr::UNSPECIFIED, 0)?;
    let opaque = host(c"example.invalid")?;
    for ip in [link, site] {
        let peer = address(ip, 7)?;
        let matching = address(ip, 7)?;
        let conflicting = address(ip, 8)?;
        let other_scope = address(if ip == link { site } else { link }, 8)?;
        for role in [EndpointRole::TcpRemote, EndpointRole::UdpReply] {
            assert_eq!(
                peer.qualify_flow_peer(role, None)
                    .map_err(|error| error.kind()),
                Err(io::ErrorKind::Unsupported)
            );
            assert_eq!(
                peer.qualify_flow_peer(role, Some(&conflicting))
                    .map_err(|error| error.kind()),
                Err(io::ErrorKind::InvalidData)
            );
            peer.qualify_flow_peer(role, Some(&matching))?;
            peer.qualify_flow_peer(role, Some(&other_scope))?;
            peer.qualify_flow_peer(role, Some(&wildcard))?;
            peer.qualify_flow_peer(role, Some(&opaque))?;
        }
    }
    Ok(())
}

#[test]
fn multicast_peer_and_reply_source_have_separate_native_roles() -> io::Result<()> {
    for group in [c"224.0.0.251", c"239.255.255.250"] {
        let endpoint = host(group)?;
        assert_eq!(endpoint.kind(), 1);
        for role in [
            EndpointRole::Local,
            EndpointRole::TcpRemote,
            EndpointRole::UdpReply,
        ] {
            assert_eq!(
                endpoint.scope_for(role).map_err(|error| error.kind()),
                Err(io::ErrorKind::Unsupported)
            );
        }
    }
    for scope in [1, 2, 5, 8, 14] {
        let group = std::net::Ipv6Addr::new(0xff00 | scope, 0, 0, 0, 0, 0, 0, 53);
        let endpoint = address(group, 7)?;
        for role in [
            EndpointRole::Local,
            EndpointRole::TcpRemote,
            EndpointRole::UdpReply,
        ] {
            assert_eq!(
                endpoint.scope_for(role).map_err(|error| error.kind()),
                Err(io::ErrorKind::Unsupported)
            );
        }
    }
    for scope in [0, 15] {
        let endpoint = address(
            std::net::Ipv6Addr::new(0xff00 | scope, 0, 0, 0, 0, 0, 0, 53),
            7,
        )?;
        assert_eq!(
            endpoint
                .scope_for(EndpointRole::UdpReply)
                .map_err(|error| error.kind()),
            Err(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}

#[test]
fn captured_group_is_only_available_as_a_multicast_request() -> io::Result<()> {
    use crate::dns_proxy::{
        FlowId, Read, ReadDatagram, ReadLimits,
        input::{Destinations, Reservation},
    };

    let target = host(c"239.1.2.3")?;
    let endpoints = NSArray::from_slice(&[target.object()]);
    let message = NSData::with_bytes(b"original");
    let messages = NSArray::from_slice(&[&*message]);
    let id = FlowId::next()?;
    let limits = ReadLimits {
        datagrams: 1,
        datagram_bytes: 32,
        batch_bytes: 32,
    };
    let read = |destinations| {
        Reservation::new(limits, destinations)?.complete(
            id,
            None,
            Retained::as_ptr(&messages).cast_mut(),
            Retained::as_ptr(&endpoints).cast_mut(),
            std::ptr::null_mut(),
        )
    };
    let Read::Datagrams(denied) = read(Destinations::Unicast)? else {
        return Err(io::Error::other("native group batch unexpectedly ended"));
    };
    let (data, refused, reason) = denied.into_parts();
    assert!(data.is_empty());
    assert_eq!(refused, 1);
    assert!(reason.is_some());

    let Read::Datagrams(accepted) = read(Destinations::UnicastAndMulticast)? else {
        return Err(io::Error::other("native group batch unexpectedly ended"));
    };
    let (data, refused, reason) = accepted.into_parts();
    assert_eq!(refused, 0);
    assert!(reason.is_none());
    assert!(matches!(
        data.as_slice(),
        [ReadDatagram::Multicast(request)] if request.flow_id() == id && request.bytes() == b"original"
    ));
    Ok(())
}
