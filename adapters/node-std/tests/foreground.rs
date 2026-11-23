//! Native node startup and retirement over private IPC and a loopback listener.
#![cfg(unix)]

use gnunet_config::Configuration;
use gnunet_hello::{Hello, Limits, SignatureProfile};
use gnunet_node_host::{
    Exit, MachineInputs, Node, Paths, Ready, Settings, TcpBind, Timing, UdpBind,
};
use gnunet_service_runtime::clock::SystemClock;
use gnunet_wire::official::cadet::{Request as CadetRequest, Response as CadetResponse};
use gnunet_wire::official::dht::ipc as dht;
use gnunet_wire::official::nse;
use gnunet_wire::official::pils::PeerUpdate;
use std::{
    error::Error,
    fs::{self, DirBuilder},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::{DirBuilderExt, FileTypeExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::oneshot,
    time,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Scratch(PathBuf);

impl Scratch {
    fn create() -> io::Result<Self> {
        let mut nonce = [0; 8];
        gnunet_native::entropy::fill(&mut nonce)?;
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let root = base.join(format!("gn-node-{:016x}", u64::from_ne_bytes(nonce)));
        DirBuilder::new().mode(0o700).create(&root)?;
        Ok(Self(root))
    }

    fn node(&self, profile: Option<&[u8]>) -> Result<Node, Box<dyn Error>> {
        self.node_with(profile, |_| Ok(()))
    }

    fn node_with(
        &self,
        profile: Option<&[u8]>,
        configure: impl FnOnce(&mut Configuration) -> TestResult,
    ) -> TestResult<Node> {
        let mut config = Configuration::default();
        config.set_value(b"pils", b"PROFILE", profile)?;
        config.set_value(b"nat", b"ENABLE_UPNP", Some(b"NO"))?;
        config.set_value(b"nat", b"USE_STUN", Some(b"NO"))?;
        config.set_number(b"nse", b"WORKBITS", 0)?;
        config.set_value(b"communicator-udp", b"DISABLE_BROADCAST", Some(b"YES"))?;
        configure(&mut config)?;
        Node::new(Settings {
            config,
            bootstrap_data_dir: None,
            paths: Paths {
                state: self.0.clone(),
                ipc: self.0.clone(),
            },
            peers: gnunet_node_host::PeerTransport::Listening {
                tcp: TcpBind::Address(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                udp: UdpBind {
                    ipv4: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
                    ipv6: None,
                },
            },
            vpn: None,
            socket_policy: Default::default(),
            resolver: gnunet_node_host::ResolverInputs::Datagram(MachineInputs::default()),
            nat_helpers: None,
            timing: Timing::new(Duration::from_secs(5), Duration::from_secs(1))?,
        })
    }

    fn require_retired(&self, exit: Exit) -> TestResult {
        if !matches!(exit, Exit::AfterReady(_)) || !self.0.join("peer.key").is_file() {
            return Err("normal node did not establish its original peer identity".into());
        }
        for name in [
            "resolver",
            "pils",
            "transport",
            "peerstore",
            "core",
            "nat",
            "nse",
            "dht",
            "cadet",
        ] {
            if self.0.join(name).try_exists()? {
                return Err(format!("{name} IPC survived node retirement").into());
            }
        }
        Ok(())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn requested_stop_precedes_startup() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::create()?;
    let exit = scratch
        .node(None)?
        .run(
            Arc::new(SystemClock),
            Default::default(),
            std::future::ready(Ok(())),
            |_| Err(io::Error::other("readiness ran after stop")),
        )
        .await?;
    if !matches!(exit, Exit::BeforeReady) || scratch.0.read_dir()?.next().is_some() {
        return Err("stop opened a node resource".into());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn official_services_start_and_retire_in_one_host() -> Result<(), Box<dyn Error>> {
    let scratch = Scratch::create()?;
    let (stop, stopped) = oneshot::channel();
    let exit = scratch
        .node(None)?
        .run(
            Arc::new(SystemClock),
            Default::default(),
            async { stopped.await.map_err(io::Error::other) },
            |ready| {
                loopback_endpoints(ready)?;
                if ready.quic_address.is_some()
                    || ready.http3_address.is_some()
                    || ready.unix_mtu.is_some()
                {
                    return Err(io::Error::other("an unconfigured communicator started"));
                }
                stop.send(()).map_err(|()| io::ErrorKind::BrokenPipe.into())
            },
        )
        .await?;
    scratch.require_retired(exit)
}

#[tokio::test(flavor = "current_thread")]
async fn application_ipc_and_unix_datagrams_share_node_lifecycle() -> TestResult {
    let scratch = Scratch::create()?;
    let datagram = scratch.0.join("datagram");
    let node = scratch.node_with(None, |config| {
        config.set_value(
            b"communicator-unix",
            b"UNIXPATH",
            Some(datagram.as_os_str().as_encoded_bytes()),
        )?;
        Ok(())
    })?;
    let (ready, started) = oneshot::channel();
    let (stop, stopped) = oneshot::channel();
    let use_services = async {
        let result = time::timeout(Duration::from_secs(7), async {
            started.await?;
            if !fs::symlink_metadata(&datagram)?.file_type().is_socket() {
                return Err("UNIX readiness did not identify the bound socket".into());
            }
            let mut estimator = UnixStream::connect(scratch.0.join("nse")).await?;
            let mut start = [0; nse::START_LEN];
            nse::encode_start(&mut start)?;
            estimator.write_all(&start).await?;
            let mut estimate = [0; nse::ESTIMATE_LEN];
            estimator.read_exact(&mut estimate).await?;
            let estimate = nse::Estimate::decode(&estimate)?;
            if !estimate.log2_size.value().is_finite() {
                return Err("NSE did not provide an initial estimate".into());
            }

            let mut discovery = UnixStream::connect(scratch.0.join("dht")).await?;
            let mut header = [0; 4];
            dht::encode_hello(None, true, &mut header)?;
            discovery.write_all(&header).await?;
            discovery.read_exact(&mut header).await?;
            let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
            if size < header.len() {
                return Err("DHT returned an invalid frame size".into());
            }
            let mut reply = vec![0; size];
            reply[..4].copy_from_slice(&header);
            discovery.read_exact(&mut reply[4..]).await?;
            if !matches!(dht::Request::decode(&reply)?, dht::Request::HelloUrl(_)) {
                return Err("DHT did not complete the original IPC request".into());
            }

            let mut stream = UnixStream::connect(scratch.0.join("cadet")).await?;
            CadetRequest::ListPeers.encode(&mut header)?;
            stream.write_all(&header).await?;
            stream.read_exact(&mut header).await?;
            if CadetResponse::decode(&header)? != CadetResponse::PeersEnd {
                return Err("CADET did not complete the original IPC request".into());
            }
            Ok::<_, Box<dyn Error>>(())
        })
        .await;
        let _requested = stop.send(());
        result?
    };
    let run = node.run(
        Arc::new(SystemClock),
        Default::default(),
        async { stopped.await.map_err(io::Error::other) },
        |original| {
            if original.unix_mtu.is_none() {
                return Err(io::Error::other("configured UNIX communicator has no MTU"));
            }
            ready
                .send(())
                .map_err(|()| io::ErrorKind::BrokenPipe.into())
        },
    );
    let (services, exit) = tokio::join!(biased; use_services, run);
    scratch.require_retired(exit?)?;
    services?;
    if datagram.try_exists()? {
        return Err("UNIX datagram survived node retirement".into());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn address_derived_profile_publishes_tcp_and_udp_then_retires() -> TestResult {
    let scratch = Scratch::create()?;
    let endpoint = scratch.0.join("pils");
    let (ready, started) = oneshot::channel();
    let (stop, stopped) = oneshot::channel();
    let observing = async {
        let publication = time::timeout(Duration::from_secs(12), async {
            let mut pils = loop {
                match UnixStream::connect(&endpoint).await {
                    Ok(stream) => break stream,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            let initial = read_pils_announcement(&mut pils).await?;
            let (peer, [tcp, udp]) = started.await?;
            if initial.peer != peer || !initial.addresses.is_empty() {
                return Err(
                    "local readiness did not precede the first address-derived identity".into(),
                );
            }
            let tcp = format!("tcp://{tcp}");
            let udp = format!("udp://{udp}");
            let replacement = loop {
                let update = read_pils_announcement(&mut pils).await?;
                if update.peer != peer && update.has_address(&tcp) && update.has_address(&udp) {
                    break update.peer;
                }
            };
            // Wait past another publication interval. Reopening TCP's
            // communicator connection would withdraw then publish its address.
            let unstable = time::timeout(Duration::from_millis(3250), async {
                loop {
                    let update = read_pils_announcement(&mut pils).await?;
                    if update.peer != replacement
                        || !update.has_address(&tcp)
                        || !update.has_address(&udp)
                    {
                        return Err::<(), Box<dyn Error>>(
                            "the embedded identity lost an original communicator address".into(),
                        );
                    }
                }
            })
            .await;
            match unstable {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        })
        .await;
        let _sent = stop.send(());
        publication.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "PILS did not publish both local communicators",
            )
        })?
    };
    let driving = Box::pin(scratch.node(Some(b"reference-deterministic"))?.run(
        Arc::new(SystemClock),
        Default::default(),
        async { stopped.await.map_err(io::Error::other) },
        |original| {
            ready
                .send((original.peer, loopback_endpoints(original)?))
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
        },
    ));
    let (publication, exit) = tokio::join!(biased; observing, driving);
    let exit = exit?;
    publication?;
    scratch.require_retired(exit)
}

#[tokio::test(flavor = "current_thread")]
async fn quic_and_http3_publish_their_bound_sockets_and_retire_with_the_node() -> TestResult {
    let scratch = Scratch::create()?;
    let node = scratch.node_with(Some(b"reference-deterministic"), |config| {
        for section in [b"communicator-quic".as_slice(), b"communicator-http3"] {
            config.set_value(section, b"BINDTO", Some(b"127.0.0.1:0"))?;
            config.set_number(section, b"PORT", 0)?;
        }
        Ok(())
    })?;
    let endpoint = scratch.0.join("pils");
    let (ready, started) = oneshot::channel();
    let (stop, stopped) = oneshot::channel();
    let (network, changes) = gnunet_node_host::network_changes();
    let observe = async {
        let result = time::timeout(Duration::from_secs(12), async {
            let (initial_peer, [quic, http3]) = started.await?;
            if quic == http3
                || [quic, http3]
                    .iter()
                    .any(|a: &SocketAddr| !a.ip().is_loopback() || a.port() == 0)
            {
                return Err("missing original QUIC-family loopback bindings".into());
            }
            network.notify();
            let mut pils = UnixStream::connect(&endpoint).await?;
            let quic_uri = format!("quic://{quic}");
            let http3_uri = format!("http3://{http3}");
            loop {
                let update = read_pils_announcement(&mut pils).await?;
                if update.peer != initial_peer
                    && update.has_address(&quic_uri)
                    && update.has_address(&http3_uri)
                {
                    return Ok::<_, Box<dyn Error>>([quic, http3]);
                }
            }
        })
        .await;
        let _sent = stop.send(());
        result?
    };
    let run = node.run(
        Arc::new(SystemClock),
        changes,
        async { stopped.await.map_err(io::Error::other) },
        |original| {
            let quic = original
                .quic_address
                .ok_or_else(|| io::Error::other("QUIC not ready"))?;
            let http3 = original
                .http3_address
                .ok_or_else(|| io::Error::other("HTTP/3 not ready"))?;
            ready
                .send((original.peer, [quic, http3]))
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
        },
    );
    let (addresses, exit) = tokio::join!(biased; observe, run);
    scratch.require_retired(exit?)?;
    for address in addresses? {
        let socket = std::net::UdpSocket::bind(address)?;
        drop(socket);
    }
    Ok(())
}

fn loopback_endpoints(ready: &Ready) -> io::Result<[SocketAddr; 2]> {
    match (
        ready.tcp_addresses.as_slice(),
        ready.udp_addresses.as_slice(),
    ) {
        ([tcp], [udp])
            if [tcp, udp]
                .iter()
                .all(|address| address.ip().is_loopback() && address.port() != 0) =>
        {
            Ok([*tcp, *udp])
        }
        _ => Err(io::Error::other(
            "missing original loopback communicator socket",
        )),
    }
}

struct PilsAnnouncement {
    peer: [u8; 32],
    addresses: Vec<u8>,
}

impl PilsAnnouncement {
    fn has_address(&self, uri: &str) -> bool {
        self.addresses
            .split(|byte| *byte == 0)
            .any(|part| part == uri.as_bytes())
    }
}

async fn read_pils_announcement(stream: &mut UnixStream) -> TestResult<PilsAnnouncement> {
    const PROFILE: SignatureProfile = SignatureProfile::DeterministicPidDerivation;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < header.len() {
        return Err("invalid PILS frame length".into());
    }
    let mut frame = vec![0; length];
    frame[..header.len()].copy_from_slice(&header);
    stream.read_exact(&mut frame[header.len()..]).await?;
    let update = PeerUpdate::decode(&frame)?;
    let mut addresses = vec![0; update.block.len()];
    let hello = Hello::parse_block(
        update.block,
        &mut addresses,
        Limits {
            maximum_input_bytes: usize::from(u16::MAX),
            maximum_address_bytes: 4096,
            maximum_addresses: 64,
        },
    )?;
    hello.verify_signature(PROFILE)?;
    if update.hash != hello.address_hash(PROFILE) {
        return Err("PILS announced a different address hash".into());
    }
    Ok(PilsAnnouncement {
        peer: *hello.peer().as_bytes(),
        addresses: hello.address_bytes().to_vec(),
    })
}
