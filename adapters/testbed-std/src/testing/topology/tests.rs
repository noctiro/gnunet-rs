use super::*;

const STOCK: &[u8] = br"[DEFAULTS]
SUBNETS = 1
CARRIER_SETUP_PROGRAMMS = iptables -A INPUT -p icmp -j DROP;tc qdisc add dev $UPLINK root netm delay 100ms 10ms;
SUBNET_SETUP_PROGRAMMS = iptables -A INPUT -p icmp -j DROP;tc qdisc add dev $UPLINK root netm delay 100ms 10ms;
PEER_SETUP_PROGRAMMS = iptables -A INPUT -p icmp -j DROP;tc qdisc add dev $UPLINK root netm delay 100ms 10ms;
TESTBED_PLUGIN = libgnunet_test_testing_plugin_ping
CARRIER_PEERS = 1
SUBNET_PEERS = 1

[BACKBONE]
CARRIERS = 1
BACKBONE_PEERS = 1
";

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert typed layout and original memory-only helper input"
)]
fn stock_topology_keeps_native_numbering() -> Result<(), Error> {
    let topology = Topology::parse(STOCK)?;
    let one = NonZeroU8::MIN;
    let expected = [
        Role::BackbonePeer { peer: one },
        Role::Carrier { carrier: one },
        Role::CarrierPeer {
            carrier: one,
            peer: one,
        },
        Role::Subnet {
            carrier: one,
            subnet: one,
        },
        Role::SubnetPeer {
            carrier: one,
            subnet: one,
            peer: one,
        },
    ];
    assert_eq!(topology.source().to_bytes(), STOCK);
    assert_eq!(topology.source().to_bytes_with_nul().last(), Some(&0));
    assert_eq!(
        topology.nodes().iter().map(Node::role).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        topology
            .peers()
            .map(|node| node.id().namespace_index())
            .collect::<Vec<_>>(),
        [0, 2, 4]
    );
    assert_eq!(topology.gateway_namespace_index(), 5);
    assert_eq!(topology.peer_count(), 3);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert nested one-based selectors and the exact plugin and setup defaults"
)]
fn local_counts_and_defaults_resolve_in_launcher_order() -> Result<(), Error> {
    let input = br"[DEFAULTs]
TESTBED_PLUGIN = default
CARRIER_SETUP_PROGRAMMS = carrier-default
SUBNET_SETUP_PROGRAMMS = subnet-default
PEER_SETUP_PROGRAMMS = command $DOWNLINK; other $UPLINK;
SUBNETS = 0
CARRIER_PEERS = 1
SUBNET_PEERS = 1

[BACKBONE]
CARRIERS = 2
BACKBONE_PEERS = 2

[backbone-peer-1]
testbed_plugin = backbone

[CARRIER-1]
CARRIER_PEERS = 2
SUBNETS = 2

[CARRIER-1-SUBNET-1]
SUBNET = 8.8.0.0/16
SUBNET_PEERS = 0

[CARRIER-1-SUBNET-2]
SUBNET_PEERS = 2

[CARRIER-1-SUBNET-2-PEER-1]
TESTBED_PLUGIN = local
SETUP_PROGRAMMS = peer-override

[CARRIER-2]
TESTBED_PLUGIN = carrier
SETUP_PROGRAMMS = carrier-override

[CARRIER-2-PEER-1]
TESTBED_PLUGIN = direct
";
    let topology = Topology::parse(input)?;
    let records = topology
        .nodes()
        .iter()
        .map(|node| {
            (
                node.id().number(),
                node.testbed_plugin(),
                node.setup_programs(),
            )
        })
        .collect::<Vec<_>>();
    type NodeRecord<'a> = (u32, &'a [u8], Option<&'a [u8]>);
    let expected: [NodeRecord<'_>; 11] = [
        (1, b"backbone", None),
        (2, b"default", None),
        (3, b"default", Some(b"carrier-default")),
        (4, b"default", None),
        (5, b"default", None),
        (6, b"default", Some(b"subnet-default")),
        (7, b"default", Some(b"subnet-default")),
        (8, b"local", Some(b"peer-override")),
        (9, b"default", Some(b"command $DOWNLINK; other $UPLINK;")),
        (10, b"carrier", Some(b"carrier-override")),
        (11, b"direct", None),
    ];
    assert_eq!(records, expected);
    let subnets = topology
        .nodes()
        .iter()
        .filter_map(Node::subnet)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        subnets,
        [
            SubnetSetting::Default(Ipv4Addr::new(10, 1, 0, 0)),
            SubnetSetting::Configured((&b"8.8.0.0/16"[..]).into()),
            SubnetSetting::Default(Ipv4Addr::new(10, 1, 2, 0)),
            SubnetSetting::Default(Ipv4Addr::new(10, 2, 0, 0))
        ]
    );
    assert_eq!(topology.default_plugin(), b"default");
    assert_eq!(topology.gateway_namespace_index(), 11);
    assert_eq!(
        topology
            .peers()
            .map(|node| node.id().number())
            .collect::<Vec<_>>(),
        [1, 2, 4, 5, 8, 9, 11]
    );
    Ok(())
}

#[test]
fn invalid_selectors_counts_and_file_directives_are_rejected() {
    let append = |suffix: &[u8]| Topology::parse(&[STOCK, suffix].concat());
    assert!(matches!(
        append(b"\n[CARRIER-0]\nTESTBED_PLUGIN = ignored\n"),
        Err(Error::InvalidSection(_))
    ));
    assert!(matches!(
        append(b"\n[CARRIER-1-SUBNET-1-PEER-2]\nTESTBED_PLUGIN = absent\n"),
        Err(Error::UnmatchedSection(_))
    ));
    assert!(matches!(
        append(b"\n[BACKBONE]\nCARRIERS = 254\n"),
        Err(Error::InvalidCount {
            option: "CARRIERS",
            ..
        })
    ));
    assert!(matches!(
        append(b"\n[CARRIER-1]\nCARRIER_PEERS = 255\nSUBNETS = 1\n"),
        Err(Error::InvalidCount {
            option: "SUBNETS",
            ..
        })
    ));
    assert!(matches!(
        append(b"\n[CARRIER-1-SUBNET-1]\nSUBNET_PEERS = 254\n"),
        Err(Error::InvalidCount {
            option: "SUBNET_PEERS",
            ..
        })
    ));
    assert!(matches!(
        append(b"\n[BACKBONE]\nCARRIERS = -18446744073709551615\n"),
        Err(Error::InvalidCount {
            option: "CARRIERS",
            ..
        })
    ));
    assert!(matches!(
        Topology::parse_with_node_limit(STOCK, 4),
        Err(Error::NodeLimit(4))
    ));
    assert!(matches!(
        append(b"\n@INLINE@ path\n"),
        Err(Error::Configuration(_))
    ));
}
