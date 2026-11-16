//! Atomic installation below the native projection builder. Interface metadata
//! is synthetic; owned sockets are private loopback and no discovery I/O is run.
use super::*;
use crate::addresses::Addresses;
use gnunet_service_runtime::connection::Connection;
use gnunet_udp_communicator_host::{
    communicator::{Communicator, Configuration},
    discovery::{Configuration as DiscoveryConfiguration, Interface},
    driver::Capacity,
    socket::DatagramSocket,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio::net::{TcpListener, TcpStream};

fn snapshot(indices: &[u8]) -> Snapshot {
    let mut rows = Vec::new();
    let mut advertised = Vec::new();
    let mut discovery = Vec::new();
    for &index in indices {
        let address = SocketAddr::from((Ipv4Addr::new(10, index, 0, 1), 2086));
        // Neutral raw flag words: this fixture bypasses is_usable/projection
        // and tests neither OS interface enumeration nor native flag mappings.
        #[cfg(unix)]
        let state = interfaces::InterfaceState::UnixFlags(0);
        #[cfg(windows)]
        let state = interfaces::InterfaceState::Windows {
            flags: 0,
            oper_status: 0,
            access_type: 0,
            if_type: 0,
            dad_state: 0,
        };
        rows.push(InterfaceAddress {
            name: Vec::new(),
            index: u32::from(index),
            state,
            address,
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
        });
        advertised.push(address);
        discovery.push(Interface {
            source: address,
            index: u32::from(index),
            broadcast: Some(Ipv4Addr::new(10, index, 0, 255)),
        });
    }
    Snapshot {
        rows,
        advertised,
        discovery: Some(discovery),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_preflight_failure_preserves_all_preceding_snapshot_consumers()
-> Result<(), crate::Cause> {
    let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let original_socket = socket.local_address();
    let transmit = socket.profile().sender_policy();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (client, service) = tokio::join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept()
    );
    let _service = service?;
    let mut comm = Communicator::new(
        Connection::from_tcp(client?),
        vec![socket],
        Configuration {
            local: gnunet_udp_communicator_core::Identity::from_seed([3; 32]).peer(),
            peers: 2,
            endpoints: 2,
            capacity: Capacity::default(),
            transmit,
        },
        100,
    )?;
    comm.enable_discovery(DiscoveryConfiguration {
        interfaces: 1,
        ..Default::default()
    })?;
    let mut addresses = Addresses::new(4, 1024, Duration::from_secs(30))?;
    let rows = snapshot(&[1]).install(&mut addresses, &mut comm)?;
    let mut scanner = Scanner {
        rows,
        discovery: true,
        alarm: Box::pin(tokio::time::sleep(Duration::from_secs(300))),
    };
    let first = "10.1.0.2:2086".parse()?;
    let next = "10.2.0.2:2086".parse()?;
    // Address planning fits its independent capacity; discovery planning fails
    // later, after the address guard has already been constructed.
    if scanner
        .install(snapshot(&[2, 3]), &mut addresses, &mut comm)
        .is_ok()
        || addresses.report().claims != 1
        || scanner.rows[0].index != 1
        || scanner.classify(first)? != 2
        || scanner.classify(next)? != 3
    {
        return Err("late discovery refusal partially replaced the snapshot".into());
    }
    scanner.install(snapshot(&[2]), &mut addresses, &mut comm)?;
    if addresses.report().claims != 1
        || scanner.rows[0].index != 2
        || scanner.classify(first)? != 3
        || scanner.classify(next)? != 2
        || !comm
            .local_addresses()
            .any(|address| address == original_socket)
        || !comm.transport_attached()
        || comm.is_closed()
    {
        return Err("prepared snapshot did not install on the original owners".into());
    }
    comm.close();
    Ok(())
}
