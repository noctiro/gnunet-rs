use super::*;
use crate::Error;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert reachability class and per-binding port projection"
)]
fn local_observations_follow_each_registration_and_binding() -> Result<(), Error> {
    let loopback = SocketAddress::V4 {
        ip: [127, 0, 0, 2],
        port: 0,
    };
    let observation =
        Advertised::interface(loopback, AddressClass::LOOPBACK).ok_or(Error::InvalidInput)?;
    let wildcard = SocketAddress::V4 {
        ip: [0; 4],
        port: 3_210,
    };
    let default = AddressPolicy::default();
    assert_eq!(default.select(wildcard, observation), None);
    assert_eq!(
        default.select(loopback.with_port(123), observation),
        Some(Advertised {
            address: loopback.with_port(123),
            class: AddressClass::LOOPBACK,
        })
    );

    let local = AddressPolicy {
        return_local_addresses: true,
        ..default
    };
    for port in [3_210, 7_654] {
        assert_eq!(
            local.select(wildcard.with_port(port), observation),
            Some(Advertised {
                address: loopback.with_port(port),
                class: AddressClass::LOOPBACK,
            })
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert IPv6 scope and advertised endpoint fields"
)]
fn an_explicit_ipv6_zone_cannot_select_another_interface() -> Result<(), Error> {
    let ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0, 1];
    let scoped = |port, scope, flow| SocketAddress::V6 {
        ip,
        port,
        scope,
        flow,
    };
    let observation =
        Advertised::interface(scoped(53, 7, 123), AddressClass::WLAN).ok_or(Error::InvalidInput)?;
    let policy = AddressPolicy::default();
    assert_eq!(policy.select(scoped(2_086, 8, 0), observation), None);
    assert_eq!(
        policy.select(scoped(2_086, 7, 0), observation),
        Some(Advertised {
            address: scoped(2_086, 7, 123),
            class: AddressClass(AddressClass::WLAN.0 | AddressClass::PRIVATE.0),
        })
    );
    let wildcard = SocketAddress::V6 {
        ip: [0; 16],
        port: 2_086,
        scope: 0,
        flow: 0,
    };
    assert_eq!(policy.select(wildcard, observation), None);
    let v4_only = AddressPolicy {
        return_local_addresses: true,
        disable_v6: true,
    };
    assert_eq!(v4_only.select(wildcard, observation), None);
    Ok(())
}

#[test]
fn only_unicast_interface_observations_carry_valid_link_classes() {
    for ip in [[0; 4], [224, 0, 0, 1], [255; 4]] {
        assert_eq!(
            Advertised::interface(SocketAddress::V4 { ip, port: 0 }, AddressClass::LAN),
            None,
            "unexpected IPv4 observation for {ip:?}"
        );
    }
    assert_eq!(
        Advertised::interface(
            SocketAddress::V4 {
                ip: [192, 168, 0, 2],
                port: 0,
            },
            AddressClass::EXTERN,
        ),
        None
    );
}
